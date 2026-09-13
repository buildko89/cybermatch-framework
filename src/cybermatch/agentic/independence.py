"""Cross-cutting checks that keep detector inputs independent from evaluator truth."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from src.cybermatch.threat_hunting.models import Finding, HuntEvent


FORBIDDEN_INPUT_TOKENS = frozenset(
    {"ground_truth", "oracle", "expected_label", "true_label", "future_event", "corrected_step"}
)


class EvaluationIndependenceError(ValueError):
    """Raised when evaluator-only information crosses into a detector input."""


def _scan(value: object, path: str) -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key).lower()
            if any(token in key for token in FORBIDDEN_INPUT_TOKENS):
                raise EvaluationIndependenceError(f"forbidden evaluator field at {path}.{raw_key}")
            _scan(child, f"{path}.{raw_key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, child in enumerate(value):
            _scan(child, f"{path}[{index}]")


def audit_detector_inputs(events: Sequence[HuntEvent]) -> dict[str, object]:
    identifiers: set[str] = set()
    for index, event in enumerate(events):
        if not isinstance(event, HuntEvent):
            raise EvaluationIndependenceError(f"detector input {index} is not a HuntEvent")
        _scan(event.to_dict(), f"events[{index}]")
        if event.event_id in identifiers:
            raise EvaluationIndependenceError("detector event IDs must be unique")
        identifiers.add(event.event_id)
        if event.event_type.lower() in event.event_id.lower():
            raise EvaluationIndependenceError("event ID leaks the configured event label")
    return {
        "status": "passed",
        "event_count": len(events),
        "checks": ["oracle_fields", "future_information", "id_leakage", "configured_labels"],
    }


def audit_finding_causality(
    findings: Sequence[Finding], events: Sequence[HuntEvent]
) -> dict[str, object]:
    index = {event.event_id: event for event in events}
    for finding in findings:
        for event_id in finding.evidence_event_ids:
            event = index.get(event_id)
            if event is None:
                raise EvaluationIndependenceError(
                    f"finding {finding.finding_id} references non-observable event {event_id}"
                )
            if event.step > finding.end_step:
                raise EvaluationIndependenceError(
                    f"finding {finding.finding_id} references future event {event_id}"
                )
    return {"status": "passed", "finding_count": len(findings)}


__all__ = [
    "EvaluationIndependenceError",
    "FORBIDDEN_INPUT_TOKENS",
    "audit_detector_inputs",
    "audit_finding_causality",
]
