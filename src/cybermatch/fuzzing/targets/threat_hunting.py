"""In-process target adapter for the deterministic threat-hunting engine."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable, Mapping, Protocol, Sequence

from src.cybermatch.threat_hunting import (
    ClosedLoopThreatHuntingController,
    HuntEvent,
    ThreatHuntingFeedback,
    ThreatHuntingFeedbackPolicy,
    ThreatHuntingEngine,
    ThreatHuntingEngineError,
    ThreatHuntingLimitError,
    ThreatHuntingRecipe,
    ThreatHuntingRecipeLoader,
    ThreatHuntingRunConfig,
    default_recipe_root,
    canonical_json,
    summarize_feedback_effects,
)

from ..models import ExecutionLimits, MutationRecord, TargetResult


@dataclass(frozen=True)
class TargetManifest:
    target_id: str
    version: str
    recipes: tuple[dict[str, str], ...]
    configuration: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        result = {
            "target_id": self.target_id,
            "version": self.version,
            "recipes": [dict(recipe) for recipe in self.recipes],
        }
        if self.configuration:
            result["configuration"] = dict(self.configuration)
        return result


@dataclass(frozen=True)
class PairedTargetResult:
    """Results from one identical potential sequence in open and closed modes."""

    open_loop: TargetResult
    closed_loop: TargetResult


class FuzzTarget(Protocol):
    @property
    def manifest(self) -> TargetManifest: ...

    def execute(
        self,
        events: Sequence[HuntEvent],
        limits: ExecutionLimits,
    ) -> TargetResult: ...


class ThreatHuntingEngineTarget:
    """Run one or more allowlisted recipes over observable events only."""

    def __init__(
        self,
        recipe_paths: Sequence[str],
        *,
        repository_root: str | Path,
        run_config: ThreatHuntingRunConfig | None = None,
    ):
        root = Path(repository_root).resolve()
        recipe_root = default_recipe_root().resolve()
        if recipe_root != root / "recipes" / "threat_hunting":
            raise ValueError("repository_root does not match the installed recipe root")
        loader = ThreatHuntingRecipeLoader(recipe_root)
        recipes: list[ThreatHuntingRecipe] = []
        for value in recipe_paths:
            requested = Path(value)
            if requested.is_absolute():
                raise ValueError("recipe paths must be repository-relative")
            path = (root / requested).resolve()
            if not path.is_relative_to(recipe_root):
                raise ValueError(f"recipe path escapes recipe root: {value}")
            recipes.append(loader.load(path.relative_to(recipe_root)))
        if not recipes:
            raise ValueError("at least one threat-hunting recipe is required")
        self._recipes = tuple(recipes)
        self._run_config = run_config or ThreatHuntingRunConfig()
        self._manifest = TargetManifest(
            target_id="threat_hunting_engine",
            version="1.0",
            recipes=tuple(
                {
                    "id": recipe.recipe_id,
                    "version": recipe.version,
                    "sha256": recipe.recipe_hash,
                }
                for recipe in self._recipes
            ),
        )

    @property
    def manifest(self) -> TargetManifest:
        return self._manifest

    def execute(
        self,
        events: Sequence[HuntEvent],
        limits: ExecutionLimits,
    ) -> TargetResult:
        started = time.perf_counter()
        if len(events) > limits.max_events_per_case:
            return TargetResult(
                status="limit_exceeded",
                findings=(),
                duration_ms=0.0,
                error_type="max_events_per_case",
                error_message=(
                    f"max_events_per_case={limits.max_events_per_case} exceeded by {len(events)}"
                ),
            )
        findings = []
        status = "completed"
        error_type = None
        error_message = None
        try:
            engine = ThreatHuntingEngine(self._run_config)
            for recipe in self._recipes:
                findings.extend(engine.run(recipe, events))
        except ThreatHuntingLimitError as exc:
            status = "limit_exceeded"
            error_type = exc.limit_name
            error_message = str(exc)
            findings = []
        except ThreatHuntingEngineError as exc:
            status = "rejected"
            error_type = type(exc).__name__
            error_message = str(exc)
            findings = []
        except Exception as exc:  # pragma: no cover - safety classification boundary
            status = "crashed"
            error_type = type(exc).__name__
            error_message = str(exc)
            findings = []
        duration_ms = (time.perf_counter() - started) * 1000.0
        if status == "completed" and duration_ms > limits.max_runtime_seconds * 1000.0:
            status = "timeout"
            error_type = "execution_budget_exceeded"
            error_message = f"execution exceeded {limits.max_runtime_seconds} seconds"
        ordered_findings = tuple(
            sorted(findings, key=lambda finding: (finding.start_step, finding.finding_id))
        )
        event_types = sorted({event.event_type for event in events})
        operations = sorted(
            {
                f"{recipe.recipe_id}:{index}:{operation.operator}"
                for recipe in self._recipes
                for index, operation in enumerate(recipe.operations)
            }
        )
        return TargetResult(
            status=status,
            findings=ordered_findings,
            duration_ms=duration_ms,
            error_type=error_type,
            error_message=error_message,
            coverage={
                "event_types": event_types,
                "recipe_operations": operations,
                "finding_recipe_ids": sorted({finding.recipe_id for finding in ordered_findings}),
            },
            state_observations={
                "event_count": len(events),
                "finding_count": len(ordered_findings),
            },
        )


class _DelayedFeedbackPolicy(ThreatHuntingFeedbackPolicy):
    def __init__(self, delay_steps: int):
        super().__init__()
        self._delay_steps = delay_steps

    def decide(self, finding, *, events, current_step):
        feedback = super().decide(finding, events=events, current_step=current_step)
        if feedback is None or self._delay_steps == 0:
            return feedback
        return ThreatHuntingFeedback.create(
            finding_id=feedback.finding_id,
            action_type=feedback.action_type,
            effective_step=feedback.effective_step + self._delay_steps,
            duration_steps=feedback.duration_steps,
            target_nodes=feedback.target_nodes,
            target_edges=feedback.target_edges,
            confidence=feedback.confidence,
            reason=f"{feedback.reason}; fuzz delay={self._delay_steps}",
        )


def _events_hash(events: Sequence[HuntEvent]) -> str:
    payload = [event.to_dict() for event in sorted(events, key=lambda item: (item.step, item.event_id))]
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _profile(mutations: Sequence[MutationRecord]) -> tuple[int, frozenset[str], int | None, str]:
    delay = 0
    failed_domains: set[str] = set()
    blast_radius_limit: int | None = None
    for mutation in mutations:
        parameters = mutation.parameters
        if mutation.mutator_id == "feedback_timing":
            delay += int(parameters.get("delay_steps", 0))
        elif mutation.mutator_id == "defense_failure_domain":
            values = parameters.get("failed_domains", [])
            if isinstance(values, list):
                failed_domains.update(str(value) for value in values)
        elif mutation.mutator_id == "topology_path":
            value = parameters.get("max_post_alert_blast_radius")
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                blast_radius_limit = value
    profile_payload = [mutation.to_dict() for mutation in mutations]
    profile_hash = hashlib.sha256(canonical_json(profile_payload).encode("utf-8")).hexdigest()
    return delay, frozenset(failed_domains), blast_radius_limit, profile_hash


def _without_failed_domains(
    feedback: Iterable[ThreatHuntingFeedback], failed_domains: frozenset[str]
) -> tuple[ThreatHuntingFeedback, ...]:
    action_domains = {
        "increase_monitoring": "monitoring",
        "block_edge": "edge_blocking",
        "redirect_to_decoy": "redirect",
        "require_additional_auth": "additional_auth",
    }
    return tuple(
        item for item in feedback if action_domains.get(item.action_type) not in failed_domains
    )


def _is_prevented(
    event: HuntEvent, feedback: Sequence[ThreatHuntingFeedback]
) -> tuple[bool, str | None]:
    effects = summarize_feedback_effects(
        feedback,
        source_node=event.source_node,
        target_node=event.target_node,
    )
    if effects.blocked and event.event_type == "lateral_move":
        return True, "block_edge"
    if effects.redirected and event.event_type in {
        "critical_probe",
        "critical_path_near_target",
        "critical_asset_reach",
        "objective_action",
    }:
        return True, "redirect_to_decoy"
    if effects.additional_auth and event.event_type == "credential_use":
        return True, "require_additional_auth"
    return False, None


def _prohibited_crossings(events: Sequence[HuntEvent], *, after_step: int | None = None) -> int:
    return sum(
        bool(event.attributes.get("fuzz_prohibited_boundary_crossing"))
        and (after_step is None or event.step > after_step)
        for event in events
    )


def _blast_radius(events: Sequence[HuntEvent], *, after_step: int | None) -> int:
    if after_step is None:
        return 0
    return len(
        {
            event.target_node
            for event in events
            if event.step > after_step
            and event.target_node is not None
            and not bool(event.attributes.get("fuzz_generated_benign"))
        }
    )


class ThreatHuntingClosedLoopTarget(ThreatHuntingEngineTarget):
    """Replay a potential event sequence in paired open/closed containment modes."""

    def __init__(self, recipe_paths: Sequence[str], *, repository_root: str | Path):
        super().__init__(recipe_paths, repository_root=repository_root)
        self._manifest = replace(
            self._manifest,
            target_id="threat_hunting_closed_loop",
            version="1.0",
        )

    def execute_pair(
        self,
        events: Sequence[HuntEvent],
        limits: ExecutionLimits,
        mutations: Sequence[MutationRecord] = (),
    ) -> PairedTargetResult:
        potential_events = tuple(sorted(events, key=lambda item: (item.step, item.event_id)))
        potential_hash = _events_hash(potential_events)
        delay, failed_domains, blast_radius_limit, profile_hash = _profile(mutations)
        open_result = super().execute(potential_events, limits)
        alert_step = min((finding.end_step for finding in open_result.findings), default=None)
        open_state = {
            **dict(open_result.state_observations),
            "loop_mode": "open_loop",
            "potential_sequence_hash": potential_hash,
            "observed_sequence_hash": potential_hash,
            "potential_event_count": len(potential_events),
            "observed_event_count": len(potential_events),
            "feedback_action_count": 0,
            "effective_feedback_action_count": 0,
            "prevented_event_count": 0,
            "prevented_event_ids": [],
            "prohibited_boundary_crossing_count": _prohibited_crossings(potential_events),
            "post_alert_prohibited_boundary_crossing_count": _prohibited_crossings(
                potential_events, after_step=alert_step
            ),
            "post_alert_blast_radius": _blast_radius(potential_events, after_step=alert_step),
            "first_alert_step": alert_step,
            "feedback_delay_steps": delay,
            "failed_defense_domains": sorted(failed_domains),
            "max_post_alert_blast_radius": blast_radius_limit,
            "mutation_profile_hash": profile_hash,
        }
        open_result = replace(open_result, state_observations=open_state)
        if open_result.status != "completed":
            closed_state = {**open_state, "loop_mode": "closed_loop"}
            return PairedTargetResult(
                open_loop=open_result,
                closed_loop=replace(open_result, state_observations=closed_state),
            )

        controller = ClosedLoopThreatHuntingController(
            self._recipes,
            policy=_DelayedFeedbackPolicy(delay),
        )
        observed: list[HuntEvent] = []
        prevented_ids: list[str] = []
        prevention_reasons: dict[str, str] = {}
        effective_feedback_ids: set[str] = set()
        for step in sorted({event.step for event in potential_events}):
            active = _without_failed_domains(controller.active_at(step), failed_domains)
            effective_feedback_ids.update(item.feedback_id for item in active)
            current: list[HuntEvent] = []
            for event in (item for item in potential_events if item.step == step):
                prevented, reason = _is_prevented(event, active)
                if prevented:
                    prevented_ids.append(event.event_id)
                    prevention_reasons[event.event_id] = str(reason)
                else:
                    current.append(event)
            observed.extend(current)
            controller.observe(current, current_step=step)

        closed_result = super().execute(tuple(observed), limits)
        feedback_trace = [item.to_dict() for item in controller.feedback]
        closed_state = {
            **dict(closed_result.state_observations),
            "loop_mode": "closed_loop",
            "potential_sequence_hash": potential_hash,
            "observed_sequence_hash": _events_hash(tuple(observed)),
            "potential_event_count": len(potential_events),
            "observed_event_count": len(observed),
            "feedback_action_count": len(controller.feedback),
            "effective_feedback_action_count": len(effective_feedback_ids),
            "prevented_event_count": len(prevented_ids),
            "prevented_event_ids": prevented_ids,
            "prevention_reasons": prevention_reasons,
            "feedback_trace": feedback_trace,
            "prohibited_boundary_crossing_count": _prohibited_crossings(tuple(observed)),
            "post_alert_prohibited_boundary_crossing_count": _prohibited_crossings(
                tuple(observed), after_step=alert_step
            ),
            "post_alert_blast_radius": _blast_radius(tuple(observed), after_step=alert_step),
            "first_alert_step": alert_step,
            "feedback_delay_steps": delay,
            "failed_defense_domains": sorted(failed_domains),
            "max_post_alert_blast_radius": blast_radius_limit,
            "mutation_profile_hash": profile_hash,
        }
        return PairedTargetResult(
            open_loop=open_result,
            closed_loop=replace(closed_result, state_observations=closed_state),
        )


__all__ = [
    "FuzzTarget",
    "PairedTargetResult",
    "TargetManifest",
    "ThreatHuntingClosedLoopTarget",
    "ThreatHuntingEngineTarget",
]
