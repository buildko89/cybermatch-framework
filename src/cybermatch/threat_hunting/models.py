"""Public data contracts for defender-side threat hunting.

The contracts in this module deliberately separate observations and findings
from simulator ground truth. Detection code consumes :class:`HuntEvent` only;
ground truth is reserved for evaluator code added in a later phase.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, TypeAlias

from src.cybermatch.contracts import canonical_json


SCHEMA_VERSION = "1.0"
OBSERVABLE_SIGNAL_CLASSES = frozenset({"unknown", "telemetry", "derived_signal"})
FINDING_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
GROUND_TRUTH_SEVERITIES = FINDING_SEVERITIES

JsonScalar: TypeAlias = str | int | float | bool | None


def _require_non_empty_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _require_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _require_optional_non_negative_int(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    return _require_non_negative_int(value, field_name)


def _require_finite_number(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{field_name} must be a finite number")
    return result


def _require_optional_finite_number(value: object, field_name: str) -> float | None:
    if value is None:
        return None
    return _require_finite_number(value, field_name)


def _freeze_attributes(attributes: Mapping[str, JsonScalar] | None) -> Mapping[str, JsonScalar]:
    if attributes is None:
        return MappingProxyType({})
    if not isinstance(attributes, Mapping):
        raise ValueError("attributes must be a mapping")

    frozen: dict[str, JsonScalar] = {}
    for key, value in attributes.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError("attribute keys must be non-empty strings")
        if value is not None and not isinstance(value, (str, int, float, bool)):
            raise ValueError(f"attribute {key!r} must contain a JSON scalar")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError(f"attribute {key!r} must be finite")
        frozen[key] = value
    return MappingProxyType(frozen)


def stable_identifier(namespace: str, payload: Mapping[str, object], length: int = 24) -> str:
    """Build a deterministic, human-readable identifier from canonical JSON."""

    namespace = _require_non_empty_string(namespace, "namespace").strip().lower().replace(" ", "_")
    if isinstance(length, bool) or not isinstance(length, int) or length < 8 or length > 64:
        raise ValueError("length must be an integer between 8 and 64")
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"{namespace}_{digest[:length]}"


@dataclass(frozen=True)
class HuntEvent:
    """One defender-observable event supplied to a threat hunting engine."""

    schema_version: str
    event_id: str
    step: int
    campaign_id: str
    scenario_id: str
    seed: int | None
    actor_id: str | None
    coalition_id: str | None
    event_type: str
    source_node: int | None
    target_node: int | None
    source_role: str | None
    target_role: str | None
    signal_class: str = "unknown"
    attributes: Mapping[str, JsonScalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_string(self.schema_version, "schema_version")
        _require_non_empty_string(self.event_id, "event_id")
        _require_non_negative_int(self.step, "step")
        _require_non_empty_string(self.campaign_id, "campaign_id")
        _require_non_empty_string(self.scenario_id, "scenario_id")
        _require_optional_non_negative_int(self.seed, "seed")
        for field_name in ("actor_id", "coalition_id", "source_role", "target_role"):
            value = getattr(self, field_name)
            if value is not None:
                _require_non_empty_string(value, field_name)
        _require_non_empty_string(self.event_type, "event_type")
        _require_optional_non_negative_int(self.source_node, "source_node")
        _require_optional_non_negative_int(self.target_node, "target_node")
        if self.signal_class not in OBSERVABLE_SIGNAL_CLASSES:
            allowed = ", ".join(sorted(OBSERVABLE_SIGNAL_CLASSES))
            raise ValueError(f"signal_class must be one of: {allowed}")
        object.__setattr__(self, "attributes", _freeze_attributes(self.attributes))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "step": self.step,
            "campaign_id": self.campaign_id,
            "scenario_id": self.scenario_id,
            "seed": self.seed,
            "actor_id": self.actor_id,
            "coalition_id": self.coalition_id,
            "event_type": self.event_type,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "source_role": self.source_role,
            "target_role": self.target_role,
            "signal_class": self.signal_class,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "HuntEvent":
        if not isinstance(payload, Mapping):
            raise ValueError("HuntEvent payload must be a mapping")
        return cls(**dict(payload))


@dataclass(frozen=True)
class Finding:
    """A reproducible result produced from one or more observable events."""

    schema_version: str
    finding_id: str
    recipe_id: str
    recipe_version: str
    severity: str
    score: float
    campaign_id: str
    actor_id: str | None
    start_step: int
    end_step: int
    title: str
    reason: str
    evidence_event_ids: tuple[str, ...]
    observed_value: float | None = None
    baseline_value: float | None = None
    threshold: float | None = None
    attributes: Mapping[str, JsonScalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in (
            "schema_version",
            "finding_id",
            "recipe_id",
            "recipe_version",
            "campaign_id",
            "title",
            "reason",
        ):
            _require_non_empty_string(getattr(self, field_name), field_name)
        if self.severity not in FINDING_SEVERITIES:
            allowed = ", ".join(sorted(FINDING_SEVERITIES))
            raise ValueError(f"severity must be one of: {allowed}")
        score = _require_finite_number(self.score, "score")
        if not 0.0 <= score <= 1.0:
            raise ValueError("score must be between 0 and 1")
        object.__setattr__(self, "score", score)
        if self.actor_id is not None:
            _require_non_empty_string(self.actor_id, "actor_id")
        _require_non_negative_int(self.start_step, "start_step")
        _require_non_negative_int(self.end_step, "end_step")
        if self.end_step < self.start_step:
            raise ValueError("end_step must be greater than or equal to start_step")

        evidence = tuple(self.evidence_event_ids)
        if not evidence:
            raise ValueError("evidence_event_ids must not be empty")
        if any(not isinstance(event_id, str) or not event_id.strip() for event_id in evidence):
            raise ValueError("evidence_event_ids must contain non-empty strings")
        if len(set(evidence)) != len(evidence):
            raise ValueError("evidence_event_ids must not contain duplicates")
        object.__setattr__(self, "evidence_event_ids", evidence)

        for field_name in ("observed_value", "baseline_value", "threshold"):
            object.__setattr__(
                self,
                field_name,
                _require_optional_finite_number(getattr(self, field_name), field_name),
            )
        object.__setattr__(self, "attributes", _freeze_attributes(self.attributes))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "finding_id": self.finding_id,
            "recipe_id": self.recipe_id,
            "recipe_version": self.recipe_version,
            "severity": self.severity,
            "score": self.score,
            "campaign_id": self.campaign_id,
            "actor_id": self.actor_id,
            "start_step": self.start_step,
            "end_step": self.end_step,
            "title": self.title,
            "reason": self.reason,
            "evidence_event_ids": list(self.evidence_event_ids),
            "observed_value": self.observed_value,
            "baseline_value": self.baseline_value,
            "threshold": self.threshold,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "Finding":
        if not isinstance(payload, Mapping):
            raise ValueError("Finding payload must be a mapping")
        data = dict(payload)
        data["evidence_event_ids"] = tuple(data.get("evidence_event_ids", ()))
        return cls(**data)


@dataclass(frozen=True)
class GroundTruthLabel:
    """Evaluator-only label; this type must never be accepted by the engine."""

    label_id: str
    campaign_id: str
    label_type: str
    start_step: int
    end_step: int
    actor_id: str | None
    target_node: int | None
    severity: str
    attributes: Mapping[str, JsonScalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("label_id", "campaign_id", "label_type"):
            _require_non_empty_string(getattr(self, field_name), field_name)
        _require_non_negative_int(self.start_step, "start_step")
        _require_non_negative_int(self.end_step, "end_step")
        if self.end_step < self.start_step:
            raise ValueError("end_step must be greater than or equal to start_step")
        if self.actor_id is not None:
            _require_non_empty_string(self.actor_id, "actor_id")
        _require_optional_non_negative_int(self.target_node, "target_node")
        if self.severity not in GROUND_TRUTH_SEVERITIES:
            allowed = ", ".join(sorted(GROUND_TRUTH_SEVERITIES))
            raise ValueError(f"severity must be one of: {allowed}")
        object.__setattr__(self, "attributes", _freeze_attributes(self.attributes))

    def to_dict(self) -> dict[str, object]:
        return {
            "label_id": self.label_id,
            "campaign_id": self.campaign_id,
            "label_type": self.label_type,
            "start_step": self.start_step,
            "end_step": self.end_step,
            "actor_id": self.actor_id,
            "target_node": self.target_node,
            "severity": self.severity,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "GroundTruthLabel":
        if not isinstance(payload, Mapping):
            raise ValueError("GroundTruthLabel payload must be a mapping")
        return cls(**dict(payload))


__all__ = [
    "FINDING_SEVERITIES",
    "GROUND_TRUTH_SEVERITIES",
    "OBSERVABLE_SIGNAL_CLASSES",
    "SCHEMA_VERSION",
    "Finding",
    "GroundTruthLabel",
    "HuntEvent",
    "JsonScalar",
    "canonical_json",
    "stable_identifier",
]
