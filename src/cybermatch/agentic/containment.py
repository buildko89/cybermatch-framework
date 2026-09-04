"""Fail-closed containment policy for observable agentic-security findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from src.cybermatch.threat_hunting.feedback import ThreatHuntingFeedback
from src.cybermatch.threat_hunting.models import Finding, HuntEvent


@dataclass(frozen=True)
class AgenticContainmentPolicyConfig:
    minimum_score: float = 0.5
    action_duration_steps: int = 5
    fail_closed: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.minimum_score, bool) or not isinstance(self.minimum_score, (int, float)):
            raise ValueError("minimum_score must be between 0 and 1")
        if not 0.0 <= float(self.minimum_score) <= 1.0:
            raise ValueError("minimum_score must be between 0 and 1")
        if (
            isinstance(self.action_duration_steps, bool)
            or not isinstance(self.action_duration_steps, int)
            or self.action_duration_steps <= 0
        ):
            raise ValueError("action_duration_steps must be a positive integer")
        if not isinstance(self.fail_closed, bool):
            raise ValueError("fail_closed must be boolean")

    @classmethod
    def from_dict(cls, payload: Mapping[str, object] | None) -> "AgenticContainmentPolicyConfig":
        if payload is None:
            return cls()
        if not isinstance(payload, Mapping):
            raise ValueError("agentic containment must be an object")
        unknown = sorted(set(payload) - set(cls.__dataclass_fields__))
        if unknown:
            raise ValueError("agentic containment has unknown fields: " + ", ".join(unknown))
        return cls(**dict(payload))


class AgenticContainmentPolicy:
    """Map finding evidence to one or more independent containment actions."""

    _ACTION_ORDER = (
        "increase_monitoring",
        "disable_shared_service",
        "block_egress",
        "revoke_identity",
        "quarantine_zone",
        "pause_workload",
        "terminate_evaluation",
        "preserve_evidence",
        "notify_third_party",
    )

    def __init__(self, config: AgenticContainmentPolicyConfig | None = None):
        self.config = config or AgenticContainmentPolicyConfig()

    def decide(
        self,
        finding: Finding,
        *,
        events: Mapping[str, HuntEvent],
        current_step: int,
    ) -> tuple[ThreatHuntingFeedback, ...]:
        if not isinstance(finding, Finding):
            raise TypeError("finding must be a Finding")
        if finding.score < self.config.minimum_score:
            return ()
        evidence = [events[event_id] for event_id in finding.evidence_event_ids if event_id in events]
        if not evidence:
            return ()
        event_types = {event.event_type for event in evidence}
        actions: set[str] = {"increase_monitoring"}
        if event_types.intersection({"shared_service_write", "unauthorized_agent_coordination"}):
            actions.update({"disable_shared_service", "preserve_evidence"})
        if "transitive_egress" in event_types:
            actions.update({"block_egress", "pause_workload", "preserve_evidence"})
        if event_types.intersection({"secret_discovery", "credential_reuse", "token_mint"}):
            actions.update({"revoke_identity", "preserve_evidence"})
        if event_types.intersection({"sandbox_escape", "privilege_escalation"}):
            actions.update({"block_egress", "quarantine_zone", "pause_workload", "preserve_evidence"})
        if event_types.intersection({"control_plane_access", "log_tampering", "third_party_access"}):
            actions.update({"terminate_evaluation", "quarantine_zone", "preserve_evidence"})
        if "third_party_access" in event_types:
            actions.add("notify_third_party")
        if self.config.fail_closed and event_types.intersection(
            {"sandbox_escape", "control_plane_access", "log_tampering", "third_party_access"}
        ):
            actions.add("terminate_evaluation")

        targets = tuple(sorted({event.target_node for event in evidence if event.target_node is not None}))
        result = []
        for action in self._ACTION_ORDER:
            if action not in actions:
                continue
            result.append(
                ThreatHuntingFeedback.create(
                    finding_id=finding.finding_id,
                    action_type=action,
                    effective_step=current_step + 1,
                    duration_steps=self.config.action_duration_steps,
                    target_nodes=targets,
                    confidence=finding.score,
                    reason=f"Agentic evidence triggered {action}",
                )
            )
        return tuple(result)


__all__ = ["AgenticContainmentPolicy", "AgenticContainmentPolicyConfig"]
