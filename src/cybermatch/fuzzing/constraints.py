"""Semantic-lane constraints and explicit oracle-isolation checks."""

from __future__ import annotations

from typing import Sequence

from src.cybermatch.threat_hunting import GROUND_TRUTH_HISTORY_KEYS, HuntEvent


FORBIDDEN_OBSERVATION_FIELDS = frozenset(GROUND_TRUTH_HISTORY_KEYS) | frozenset(
    {"ground_truth", "true_mission", "oracle_label", "truth_label"}
)


class FuzzConstraintError(ValueError):
    """Raised when a semantic fuzz case violates its observation contract."""


def validate_semantic_events(events: Sequence[HuntEvent], *, max_events: int) -> None:
    if not events:
        raise FuzzConstraintError("semantic event sequence must not be empty")
    if len(events) > max_events:
        raise FuzzConstraintError(f"semantic event sequence exceeds max_events={max_events}")
    if any(not isinstance(event, HuntEvent) for event in events):
        raise FuzzConstraintError("semantic sequence must contain HuntEvent values only")
    identifiers = [event.event_id for event in events]
    if len(set(identifiers)) != len(identifiers):
        raise FuzzConstraintError("semantic event IDs must be unique")
    for event in events:
        if event.event_type.startswith(("fake_", "noise_")):
            raise FuzzConstraintError("truth-bearing internal event types must not be observable")
        leaked = sorted(set(event.attributes) & FORBIDDEN_OBSERVATION_FIELDS)
        if leaked:
            raise FuzzConstraintError(
                "ground-truth fields leaked into observable attributes: " + ", ".join(leaked)
            )


__all__ = ["FORBIDDEN_OBSERVATION_FIELDS", "FuzzConstraintError", "validate_semantic_events"]
