"""Truth-free Finding-to-defender-action policy and closed-loop controller."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .config import ThreatHuntingRunConfig
from .engine import ThreatHuntingEngine
from .feedback import ThreatHuntingFeedback
from .models import Finding, HuntEvent
from .recipes import ThreatHuntingRecipe


@dataclass(frozen=True)
class FeedbackPolicyConfig:
    minimum_score: float = 0.5
    monitoring_duration_steps: int = 3
    blocking_duration_steps: int = 2
    redirect_duration_steps: int = 2
    authentication_duration_steps: int = 3

    def __post_init__(self) -> None:
        if isinstance(self.minimum_score, bool) or not isinstance(self.minimum_score, (int, float)):
            raise ValueError("minimum_score must be between 0 and 1")
        if not 0.0 <= float(self.minimum_score) <= 1.0:
            raise ValueError("minimum_score must be between 0 and 1")
        for name in (
            "monitoring_duration_steps",
            "blocking_duration_steps",
            "redirect_duration_steps",
            "authentication_duration_steps",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


class ThreatHuntingFeedbackPolicy:
    """Map observable evidence to typed defender feedback without truth labels."""

    def __init__(self, config: FeedbackPolicyConfig | None = None):
        self.config = config or FeedbackPolicyConfig()

    def decide(
        self,
        finding: Finding,
        *,
        events: Mapping[str, HuntEvent],
        current_step: int,
    ) -> ThreatHuntingFeedback | None:
        if not isinstance(finding, Finding):
            raise TypeError("finding must be a Finding")
        if finding.score < self.config.minimum_score:
            return None
        evidence = [events[event_id] for event_id in finding.evidence_event_ids if event_id in events]
        if not evidence:
            return None
        event_types = {event.event_type for event in evidence}
        targets = tuple(sorted({event.target_node for event in evidence if event.target_node is not None}))
        edges = tuple(
            sorted(
                {
                    (event.source_node, event.target_node)
                    for event in evidence
                    if event.source_node is not None and event.target_node is not None
                }
            )
        )
        if "credential_use" in event_types:
            action_type = "require_additional_auth"
            duration = self.config.authentication_duration_steps
        elif "lateral_move" in event_types and edges:
            action_type = "block_edge"
            duration = self.config.blocking_duration_steps
        elif event_types.intersection(
            {"critical_probe", "critical_path_near_target", "critical_asset_reach", "objective_action"}
        ):
            action_type = "redirect_to_decoy"
            duration = self.config.redirect_duration_steps
        else:
            action_type = "increase_monitoring"
            duration = self.config.monitoring_duration_steps
        return ThreatHuntingFeedback.create(
            finding_id=finding.finding_id,
            action_type=action_type,
            effective_step=current_step + 1,
            duration_steps=duration,
            target_nodes=targets,
            target_edges=edges if action_type == "block_edge" else (),
            confidence=finding.score,
            reason=f"Observable evidence triggered {action_type}",
        )


class ClosedLoopThreatHuntingController:
    """Run recipes over observations and queue future-effective defender actions."""

    def __init__(
        self,
        recipes: Iterable[ThreatHuntingRecipe],
        *,
        policy: ThreatHuntingFeedbackPolicy | None = None,
        run_config: ThreatHuntingRunConfig | None = None,
    ) -> None:
        values = tuple(recipes)
        if not values or any(not isinstance(recipe, ThreatHuntingRecipe) for recipe in values):
            raise ValueError("recipes must contain at least one ThreatHuntingRecipe")
        self._recipes = values
        self._policy = policy or ThreatHuntingFeedbackPolicy()
        self._engine = ThreatHuntingEngine(run_config or ThreatHuntingRunConfig())
        self._events: dict[str, HuntEvent] = {}
        self._finding_ids: set[str] = set()
        self._feedback: list[ThreatHuntingFeedback] = []

    @property
    def events(self) -> tuple[HuntEvent, ...]:
        return tuple(sorted(self._events.values(), key=lambda event: (event.step, event.event_id)))

    @property
    def feedback(self) -> tuple[ThreatHuntingFeedback, ...]:
        return tuple(self._feedback)

    def observe(self, events: Iterable[HuntEvent], *, current_step: int) -> tuple[ThreatHuntingFeedback, ...]:
        for event in events:
            if not isinstance(event, HuntEvent):
                raise TypeError("events must contain HuntEvent observations")
            self._events[event.event_id] = event
        created: list[ThreatHuntingFeedback] = []
        ordered_events = self.events
        for recipe in self._recipes:
            for finding in self._engine.run(recipe, ordered_events):
                if finding.finding_id in self._finding_ids:
                    continue
                self._finding_ids.add(finding.finding_id)
                feedback = self._policy.decide(
                    finding,
                    events=self._events,
                    current_step=current_step,
                )
                if feedback is not None:
                    self._feedback.append(feedback)
                    created.append(feedback)
        self._feedback.sort(key=lambda value: (value.effective_step, value.feedback_id))
        return tuple(created)

    def active_at(self, step: int) -> tuple[ThreatHuntingFeedback, ...]:
        return tuple(
            feedback
            for feedback in self._feedback
            if feedback.effective_step <= step < feedback.effective_step + feedback.duration_steps
        )


@dataclass(frozen=True)
class DefenderActionEffects:
    monitoring: bool = False
    blocked: bool = False
    redirected: bool = False
    additional_auth: bool = False
    paused: bool = False
    terminated: bool = False
    quarantined: bool = False
    identity_revoked: bool = False
    shared_service_disabled: bool = False
    egress_blocked: bool = False
    evidence_preserved: bool = False
    third_party_notification: bool = False
    confidence: float = 0.0


def summarize_feedback_effects(
    feedback: Iterable[ThreatHuntingFeedback],
    *,
    source_node: int | None,
    target_node: int | None,
) -> DefenderActionEffects:
    monitoring = blocked = redirected = additional_auth = False
    paused = terminated = quarantined = identity_revoked = False
    shared_service_disabled = egress_blocked = evidence_preserved = False
    third_party_notification = False
    confidence = 0.0
    for item in feedback:
        target_match = not item.target_nodes or target_node in item.target_nodes
        edge_match = not item.target_edges or (source_node, target_node) in item.target_edges
        if not target_match or not edge_match:
            continue
        confidence = max(confidence, item.confidence)
        monitoring = monitoring or item.action_type == "increase_monitoring"
        blocked = blocked or item.action_type == "block_edge"
        redirected = redirected or item.action_type == "redirect_to_decoy"
        additional_auth = additional_auth or item.action_type == "require_additional_auth"
        paused = paused or item.action_type == "pause_workload"
        terminated = terminated or item.action_type == "terminate_evaluation"
        quarantined = quarantined or item.action_type == "quarantine_zone"
        identity_revoked = identity_revoked or item.action_type == "revoke_identity"
        shared_service_disabled = shared_service_disabled or item.action_type == "disable_shared_service"
        egress_blocked = egress_blocked or item.action_type == "block_egress"
        evidence_preserved = evidence_preserved or item.action_type == "preserve_evidence"
        third_party_notification = third_party_notification or item.action_type == "notify_third_party"
    return DefenderActionEffects(
        monitoring=monitoring,
        blocked=blocked,
        redirected=redirected,
        additional_auth=additional_auth,
        paused=paused,
        terminated=terminated,
        quarantined=quarantined,
        identity_revoked=identity_revoked,
        shared_service_disabled=shared_service_disabled,
        egress_blocked=egress_blocked,
        evidence_preserved=evidence_preserved,
        third_party_notification=third_party_notification,
        confidence=confidence,
    )


__all__ = [
    "ClosedLoopThreatHuntingController",
    "DefenderActionEffects",
    "FeedbackPolicyConfig",
    "ThreatHuntingFeedbackPolicy",
    "summarize_feedback_effects",
]
