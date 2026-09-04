"""Deterministic, constraint-aware HuntEvent mutators."""

from __future__ import annotations

import hashlib
import random
from dataclasses import replace
from typing import Iterable, Sequence

from src.cybermatch.threat_hunting import HuntEvent, canonical_json, stable_identifier

from ..models import MutationRecord
from ..specs import MutatorSpec


MUTATOR_VERSION = "1.0"
BENIGN_EVENT_TYPES = ("authentication", "dns_query", "process_start", "scan")


class MutationError(ValueError):
    """Raised when a configured mutation cannot preserve its lane contract."""


def events_hash(events: Iterable[HuntEvent]) -> str:
    payload = [event.to_dict() for event in sorted(events, key=lambda item: (item.step, item.event_id))]
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _integer(value: object, name: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MutationError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise MutationError(f"{name} must be at least {minimum}")
    return value


def _count(parameters: dict[str, object], rng: random.Random, event_count: int) -> int:
    maximum = _integer(parameters.get("max_count", 1), "max_count", minimum=1)
    return min(rng.randint(1, maximum), max(event_count, 1))


def _shift_step(
    events: list[HuntEvent], parameters: dict[str, object], rng: random.Random
) -> tuple[list[HuntEvent], tuple[str, ...], dict[str, object]]:
    target = rng.choice(events)
    if "values" in parameters:
        raw_values = parameters["values"]
        if not isinstance(raw_values, list) or not raw_values:
            raise MutationError("shift_step.values must be a non-empty array")
        values = [_integer(value, "shift_step.values") for value in raw_values]
        effective = [value for value in values if value != 0]
        delta = rng.choice(effective or values)
    else:
        raw_range = parameters.get("range", [-1, 1])
        if not isinstance(raw_range, list) or len(raw_range) != 2:
            raise MutationError("shift_step.range must contain two integers")
        low = _integer(raw_range[0], "shift_step.range[0]")
        high = _integer(raw_range[1], "shift_step.range[1]")
        if low > high:
            raise MutationError("shift_step.range lower bound must not exceed upper bound")
        values = [value for value in range(low, high + 1) if value != 0]
        delta = rng.choice(values) if values else 0
    shifted = replace(target, step=max(0, target.step + delta))
    result = [shifted if event.event_id == target.event_id else event for event in events]
    return result, (target.event_id,), {"delta": delta, "result_step": shifted.step}


def _drop_event(
    events: list[HuntEvent], parameters: dict[str, object], rng: random.Random
) -> tuple[list[HuntEvent], tuple[str, ...], dict[str, object]]:
    if len(events) <= 1:
        return list(events), (), {"requested": 1, "applied": 0, "reason": "last_event_preserved"}
    count = min(_count(parameters, rng, len(events)), len(events) - 1)
    selected = tuple(sorted(rng.sample([event.event_id for event in events], count)))
    selected_set = set(selected)
    return [event for event in events if event.event_id not in selected_set], selected, {"applied": count}


def _duplicate_semantic_event(
    events: list[HuntEvent], parameters: dict[str, object], rng: random.Random
) -> tuple[list[HuntEvent], tuple[str, ...], dict[str, object]]:
    count = _count(parameters, rng, len(events))
    selected = rng.sample(events, min(count, len(events)))
    result = list(events)
    for ordinal, event in enumerate(selected):
        duplicate_id = stable_identifier(
            "mutation-event",
            {"event_id": event.event_id, "kind": "semantic_duplicate", "ordinal": ordinal},
        )
        result.append(
            replace(
                event,
                event_id=duplicate_id,
                attributes={**dict(event.attributes), "fuzz_semantic_duplicate": True},
            )
        )
    return result, tuple(sorted(event.event_id for event in selected)), {"applied": len(selected)}


def _insert_benign_noise(
    events: list[HuntEvent], parameters: dict[str, object], rng: random.Random
) -> tuple[list[HuntEvent], tuple[str, ...], dict[str, object]]:
    count = _count(parameters, rng, len(events))
    raw_types = parameters.get("event_types", list(BENIGN_EVENT_TYPES))
    if not isinstance(raw_types, list) or not raw_types or any(
        not isinstance(value, str) or not value.strip() for value in raw_types
    ):
        raise MutationError("insert_benign_noise.event_types must contain non-empty strings")
    base = events[0]
    max_step = max(event.step for event in events)
    inserted: list[HuntEvent] = []
    for ordinal in range(count):
        event_type = rng.choice(raw_types)
        step = rng.randint(0, max_step)
        attributes: dict[str, object] = {
            "telemetry_family": "dns" if event_type == "dns_query" else "process" if event_type == "process_start" else "authentication" if event_type == "authentication" else "network",
            "fuzz_generated_benign": True,
            "ordinal": ordinal,
        }
        if event_type == "dns_query":
            attributes.update({"query_length": 12, "query_type": "A", "domain_shape": "ordinary"})
        elif event_type == "process_start":
            attributes.update({"process_name": "notepad.exe", "parent_process": "explorer.exe", "process_signed": True})
        elif event_type == "authentication":
            attributes.update({"auth_method": "interactive", "auth_result": "success", "credential_present": False})
        else:
            attributes.update({"protocol": "tcp", "bytes": 64})
        event_id = stable_identifier(
            "mutation-event",
            {
                "base_event_id": base.event_id,
                "kind": "benign_noise",
                "step": step,
                "ordinal": ordinal,
                "event_type": event_type,
            },
        )
        inserted.append(
            HuntEvent(
                schema_version=base.schema_version,
                event_id=event_id,
                step=step,
                campaign_id=base.campaign_id,
                scenario_id=base.scenario_id,
                seed=base.seed,
                actor_id="benign-fuzz-actor",
                coalition_id=None,
                event_type=event_type,
                source_node=base.source_node,
                target_node=base.target_node,
                source_role=base.source_role,
                target_role=base.target_role,
                signal_class="telemetry",
                attributes=attributes,
            )
        )
    return events + inserted, tuple(event.event_id for event in inserted), {"applied": len(inserted)}


def _boundary_numeric_attribute(
    events: list[HuntEvent], parameters: dict[str, object], rng: random.Random
) -> tuple[list[HuntEvent], tuple[str, ...], dict[str, object]]:
    candidates = [
        (event, key, value)
        for event in events
        for key, value in event.attributes.items()
        if key != "ordinal" and isinstance(value, (int, float)) and not isinstance(value, bool)
    ]
    if not candidates:
        return list(events), (), {"applied": 0, "reason": "no_numeric_attribute"}
    event, key, old_value = rng.choice(candidates)
    raw_values = parameters.get("values")
    if raw_values is None:
        epsilon = 1 if isinstance(old_value, int) else 0.001
        values: list[int | float] = [0, old_value - epsilon, old_value + epsilon]
    else:
        if not isinstance(raw_values, list) or not raw_values or any(
            isinstance(value, bool) or not isinstance(value, (int, float)) for value in raw_values
        ):
            raise MutationError("boundary_numeric_attribute.values must contain numbers")
        values = list(raw_values)
    effective_values = [value for value in values if value != old_value]
    new_value = rng.choice(effective_values or values)
    if isinstance(old_value, int):
        new_value = int(new_value)
    if key in {"bytes", "ordinal", "query_length"}:
        new_value = max(0, new_value)
    elif key == "c2_jitter_ratio":
        new_value = min(max(float(new_value), 0.0), 1.0)
    attributes = dict(event.attributes)
    attributes[key] = new_value
    changed = replace(event, attributes=attributes)
    result = [changed if item.event_id == event.event_id else item for item in events]
    return result, (event.event_id,), {"attribute": key, "before": old_value, "after": new_value}


def _feedback_timing(
    events: list[HuntEvent], parameters: dict[str, object], rng: random.Random
) -> tuple[list[HuntEvent], tuple[str, ...], dict[str, object]]:
    raw_delays = parameters.get("delays")
    if not isinstance(raw_delays, list) or not raw_delays:
        raise MutationError("feedback_timing.delays must be a non-empty array")
    delays = [_integer(value, "feedback_timing.delays", minimum=0) for value in raw_delays]
    delay = rng.choice(delays)
    return list(events), (), {"delay_steps": delay}


def _topology_path(
    events: list[HuntEvent], parameters: dict[str, object], rng: random.Random
) -> tuple[list[HuntEvent], tuple[str, ...], dict[str, object]]:
    candidates = [
        event
        for event in events
        if event.source_node is not None and event.target_node is not None
    ]
    if not candidates:
        return list(events), (), {"applied": 0, "reason": "no_routable_event"}
    raw_paths = parameters.get("paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        raise MutationError("topology_path.paths must be a non-empty array")
    selected_path = rng.choice(raw_paths)
    if not isinstance(selected_path, dict):
        raise MutationError("topology_path.paths must contain objects")
    source_node = _integer(selected_path.get("source_node"), "source_node", minimum=0)
    target_node = _integer(selected_path.get("target_node"), "target_node", minimum=0)
    boundary_id = selected_path.get("boundary_id")
    prohibited = selected_path.get("prohibited")
    if not isinstance(boundary_id, str) or not boundary_id.strip():
        raise MutationError("topology path boundary_id must be a non-empty string")
    if not isinstance(prohibited, bool):
        raise MutationError("topology path prohibited must be a boolean")
    target = rng.choice(candidates)
    attributes = {
        **dict(target.attributes),
        "fuzz_topology_boundary_id": boundary_id,
        "fuzz_prohibited_boundary_crossing": prohibited,
    }
    changed = replace(
        target,
        source_node=source_node,
        target_node=target_node,
        attributes=attributes,
    )
    result = [changed if event.event_id == target.event_id else event for event in events]
    return result, (target.event_id,), {
        "applied": 1,
        "source_node": source_node,
        "target_node": target_node,
        "boundary_id": boundary_id,
        "prohibited": prohibited,
        "max_post_alert_blast_radius": parameters.get("max_post_alert_blast_radius", 0),
    }


def _defense_failure_domain(
    events: list[HuntEvent], parameters: dict[str, object], rng: random.Random
) -> tuple[list[HuntEvent], tuple[str, ...], dict[str, object]]:
    raw_domains = parameters.get("domains")
    if not isinstance(raw_domains, list) or not raw_domains:
        raise MutationError("defense_failure_domain.domains must be a non-empty array")
    if any(not isinstance(value, str) or not value for value in raw_domains):
        raise MutationError("defense_failure_domain.domains must contain strings")
    maximum = _integer(parameters.get("max_count", 1), "max_count", minimum=1)
    count = min(rng.randint(1, maximum), len(raw_domains))
    selected = tuple(sorted(rng.sample(raw_domains, count)))
    return list(events), (), {"failed_domains": list(selected), "applied": len(selected)}


def apply_mutation(
    events: Sequence[HuntEvent],
    spec: MutatorSpec,
    rng: random.Random,
    operation_index: int,
) -> tuple[tuple[HuntEvent, ...], MutationRecord]:
    """Apply one configured mutation and retain an auditable before/after record."""

    current = list(events)
    if not current:
        raise MutationError("cannot mutate an empty event sequence")
    before = events_hash(current)
    parameters = dict(spec.parameters)
    functions = {
        "shift_step": _shift_step,
        "drop_event": _drop_event,
        "duplicate_semantic_event": _duplicate_semantic_event,
        "insert_benign_noise": _insert_benign_noise,
        "boundary_numeric_attribute": _boundary_numeric_attribute,
        "feedback_timing": _feedback_timing,
        "topology_path": _topology_path,
        "defense_failure_domain": _defense_failure_domain,
    }
    function = functions.get(spec.mutator_id)
    if function is None:
        raise MutationError(f"unsupported mutator: {spec.mutator_id}")
    mutated, targets, applied = function(current, parameters, rng)
    ordered = tuple(sorted(mutated, key=lambda event: (event.step, event.event_id)))
    record = MutationRecord(
        mutator_id=spec.mutator_id,
        mutator_version=MUTATOR_VERSION,
        operation_index=operation_index,
        target_event_ids=targets,
        parameters={**parameters, **applied},
        before_hash=before,
        after_hash=events_hash(ordered),
    )
    return ordered, record


def reidentify_events(events: Sequence[HuntEvent], case_id: str) -> tuple[HuntEvent, ...]:
    """Assign case-local stable IDs after every mutation has been applied."""

    ordered = sorted(events, key=lambda event: (event.step, event.event_id))
    result: list[HuntEvent] = []
    for event in ordered:
        payload = event.to_dict()
        payload.pop("event_id", None)
        payload.pop("campaign_id", None)
        event_id = stable_identifier(
            "fuzz-event",
            {
                "case_id": case_id,
                "source_event_id": event.event_id,
                "event": payload,
            },
        )
        result.append(replace(event, event_id=event_id, campaign_id=case_id))
    return tuple(result)


__all__ = [
    "BENIGN_EVENT_TYPES",
    "MUTATOR_VERSION",
    "MutationError",
    "apply_mutation",
    "events_hash",
    "reidentify_events",
]
