"""Stable contracts for deterministic CyberMatch fuzzing campaigns."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, TypeAlias

from src.cybermatch.threat_hunting import Finding, GroundTruthLabel, HuntEvent, canonical_json


FUZZING_SCHEMA_VERSION = "1.0"
JsonValue: TypeAlias = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
TARGET_STATUSES = frozenset(
    {"completed", "rejected", "timeout", "crashed", "limit_exceeded", "infrastructure_error"}
)
ORACLE_VERDICTS = frozenset({"pass", "fail", "interesting", "inconclusive"})
ORACLE_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


def _non_empty(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _non_negative_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _positive_int(value: object, name: str) -> int:
    result = _non_negative_int(value, name)
    if result == 0:
        raise ValueError(f"{name} must be a positive integer")
    return result


def _finite_non_negative(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite non-negative number")
    result = float(value)
    if not math.isfinite(result) or result < 0.0:
        raise ValueError(f"{name} must be a finite non-negative number")
    return result


def json_copy(value: object, name: str) -> JsonValue:
    """Validate a JSON value and return a detached canonical copy."""

    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain JSON values") from exc


def frozen_json_mapping(value: Mapping[str, object], name: str) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    copied = json_copy(dict(value), name)
    assert isinstance(copied, dict)
    return MappingProxyType(copied)


@dataclass(frozen=True)
class ExecutionLimits:
    max_cases: int = 20
    max_events_per_case: int = 10_000
    max_mutations_per_case: int = 8
    max_runtime_seconds: float = 10.0

    def __post_init__(self) -> None:
        _positive_int(self.max_cases, "max_cases")
        _positive_int(self.max_events_per_case, "max_events_per_case")
        _positive_int(self.max_mutations_per_case, "max_mutations_per_case")
        value = _finite_non_negative(self.max_runtime_seconds, "max_runtime_seconds")
        if value == 0.0:
            raise ValueError("max_runtime_seconds must be positive")
        object.__setattr__(self, "max_runtime_seconds", value)

    def to_dict(self) -> dict[str, object]:
        return {
            "max_cases": self.max_cases,
            "max_events_per_case": self.max_events_per_case,
            "max_mutations_per_case": self.max_mutations_per_case,
            "max_runtime_seconds": self.max_runtime_seconds,
        }


@dataclass(frozen=True)
class MutationRecord:
    mutator_id: str
    mutator_version: str
    operation_index: int
    target_event_ids: tuple[str, ...]
    parameters: Mapping[str, JsonValue]
    before_hash: str
    after_hash: str

    def __post_init__(self) -> None:
        for name in ("mutator_id", "mutator_version", "before_hash", "after_hash"):
            _non_empty(getattr(self, name), name)
        _non_negative_int(self.operation_index, "operation_index")
        targets = tuple(self.target_event_ids)
        if any(not isinstance(value, str) or not value for value in targets):
            raise ValueError("target_event_ids must contain non-empty strings")
        if len(set(targets)) != len(targets):
            raise ValueError("target_event_ids must not contain duplicates")
        object.__setattr__(self, "target_event_ids", targets)
        object.__setattr__(self, "parameters", frozen_json_mapping(self.parameters, "parameters"))

    def to_dict(self) -> dict[str, object]:
        return {
            "mutator_id": self.mutator_id,
            "mutator_version": self.mutator_version,
            "operation_index": self.operation_index,
            "target_event_ids": list(self.target_event_ids),
            "parameters": json_copy(dict(self.parameters), "parameters"),
            "before_hash": self.before_hash,
            "after_hash": self.after_hash,
        }


@dataclass(frozen=True)
class SeedInput:
    seed_id: str
    source_path: str
    source_hash: str
    scenario_id: str
    seed: int
    events: tuple[HuntEvent, ...]
    ground_truth: tuple[GroundTruthLabel, ...]
    analysis: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("seed_id", "source_path", "source_hash", "scenario_id"):
            _non_empty(getattr(self, name), name)
        _non_negative_int(self.seed, "seed")
        events = tuple(self.events)
        truth = tuple(self.ground_truth)
        if not events or any(not isinstance(value, HuntEvent) for value in events):
            raise ValueError("events must contain at least one HuntEvent")
        if any(not isinstance(value, GroundTruthLabel) for value in truth):
            raise ValueError("ground_truth must contain GroundTruthLabel values only")
        if len({event.event_id for event in events}) != len(events):
            raise ValueError("seed event IDs must be unique")
        object.__setattr__(self, "events", tuple(sorted(events, key=lambda event: (event.step, event.event_id))))
        object.__setattr__(self, "ground_truth", truth)
        object.__setattr__(self, "analysis", frozen_json_mapping(self.analysis, "analysis"))


@dataclass(frozen=True)
class FuzzCase:
    schema_version: str
    campaign_id: str
    case_id: str
    campaign_seed: int
    case_seed: int
    base_input_id: str
    base_input_hash: str
    analysis_guidance: Mapping[str, JsonValue]
    mutations: tuple[MutationRecord, ...]
    events: tuple[HuntEvent, ...]
    ground_truth: tuple[GroundTruthLabel, ...]
    control_events: tuple[HuntEvent, ...] = ()
    control_ground_truth: tuple[GroundTruthLabel, ...] = ()

    def __post_init__(self) -> None:
        for name in ("schema_version", "campaign_id", "case_id", "base_input_id", "base_input_hash"):
            _non_empty(getattr(self, name), name)
        if self.schema_version != FUZZING_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {FUZZING_SCHEMA_VERSION!r}")
        _non_negative_int(self.campaign_seed, "campaign_seed")
        _non_negative_int(self.case_seed, "case_seed")
        mutations = tuple(self.mutations)
        events = tuple(self.events)
        truth = tuple(self.ground_truth)
        control_events = tuple(self.control_events)
        control_truth = tuple(self.control_ground_truth)
        if not mutations or any(not isinstance(value, MutationRecord) for value in mutations):
            raise ValueError("mutations must contain at least one MutationRecord")
        if not events or any(not isinstance(value, HuntEvent) for value in events):
            raise ValueError("events must contain at least one HuntEvent")
        if any(not isinstance(value, GroundTruthLabel) for value in truth):
            raise ValueError("ground_truth must contain GroundTruthLabel values only")
        if len({event.event_id for event in events}) != len(events):
            raise ValueError("case event IDs must be unique")
        if any(event.campaign_id != self.case_id for event in events):
            raise ValueError("case events must use case_id as campaign_id")
        if any(label.campaign_id != self.case_id for label in truth):
            raise ValueError("case ground truth must use case_id as campaign_id")
        if any(not isinstance(value, HuntEvent) for value in control_events):
            raise ValueError("control_events must contain HuntEvent values only")
        if any(not isinstance(value, GroundTruthLabel) for value in control_truth):
            raise ValueError("control_ground_truth must contain GroundTruthLabel values only")
        if len({event.event_id for event in control_events}) != len(control_events):
            raise ValueError("control event IDs must be unique")
        if any(event.campaign_id != self.case_id for event in control_events):
            raise ValueError("control events must use case_id as campaign_id")
        if any(label.campaign_id != self.case_id for label in control_truth):
            raise ValueError("control ground truth must use case_id as campaign_id")
        object.__setattr__(self, "mutations", mutations)
        object.__setattr__(self, "events", tuple(sorted(events, key=lambda event: (event.step, event.event_id))))
        object.__setattr__(self, "ground_truth", truth)
        object.__setattr__(
            self,
            "control_events",
            tuple(sorted(control_events, key=lambda event: (event.step, event.event_id))),
        )
        object.__setattr__(self, "control_ground_truth", control_truth)
        object.__setattr__(
            self,
            "analysis_guidance",
            frozen_json_mapping(self.analysis_guidance, "analysis_guidance"),
        )

    def manifest_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "case_id": self.case_id,
            "campaign_seed": self.campaign_seed,
            "case_seed": self.case_seed,
            "base_input_id": self.base_input_id,
            "base_input_hash": self.base_input_hash,
            "analysis_guidance": json_copy(dict(self.analysis_guidance), "analysis_guidance"),
            "mutations": [mutation.to_dict() for mutation in self.mutations],
            "event_count": len(self.events),
            "ground_truth_count": len(self.ground_truth),
            "control_event_count": len(self.control_events),
            "control_ground_truth_count": len(self.control_ground_truth),
        }


@dataclass(frozen=True)
class TargetResult:
    status: str
    findings: tuple[Finding, ...]
    duration_ms: float
    exit_code: int | None = None
    error_type: str | None = None
    error_message: str | None = None
    coverage: Mapping[str, JsonValue] = field(default_factory=dict)
    state_observations: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in TARGET_STATUSES:
            raise ValueError(f"status must be one of: {', '.join(sorted(TARGET_STATUSES))}")
        findings = tuple(self.findings)
        if any(not isinstance(value, Finding) for value in findings):
            raise ValueError("findings must contain Finding values only")
        if len({finding.finding_id for finding in findings}) != len(findings):
            raise ValueError("finding IDs must be unique")
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "duration_ms", _finite_non_negative(self.duration_ms, "duration_ms"))
        if self.exit_code is not None and (isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)):
            raise ValueError("exit_code must be an integer or None")
        for name in ("error_type", "error_message"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name} must be a string or None")
        object.__setattr__(self, "coverage", frozen_json_mapping(self.coverage, "coverage"))
        object.__setattr__(
            self,
            "state_observations",
            frozen_json_mapping(self.state_observations, "state_observations"),
        )

    def comparable_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
            "exit_code": self.exit_code,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "coverage": json_copy(dict(self.coverage), "coverage"),
            "state_observations": json_copy(dict(self.state_observations), "state_observations"),
        }

    def to_dict(self) -> dict[str, object]:
        return {**self.comparable_dict(), "duration_ms": self.duration_ms}


@dataclass(frozen=True)
class OracleResult:
    oracle_id: str
    verdict: str
    severity: str
    fingerprint: str
    evidence: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("oracle_id", "fingerprint"):
            _non_empty(getattr(self, name), name)
        if self.verdict not in ORACLE_VERDICTS:
            raise ValueError(f"verdict must be one of: {', '.join(sorted(ORACLE_VERDICTS))}")
        if self.severity not in ORACLE_SEVERITIES:
            raise ValueError(f"severity must be one of: {', '.join(sorted(ORACLE_SEVERITIES))}")
        object.__setattr__(self, "evidence", frozen_json_mapping(self.evidence, "evidence"))

    def to_dict(self) -> dict[str, object]:
        return {
            "oracle_id": self.oracle_id,
            "verdict": self.verdict,
            "severity": self.severity,
            "fingerprint": self.fingerprint,
            "evidence": json_copy(dict(self.evidence), "evidence"),
        }


__all__ = [
    "ExecutionLimits",
    "FUZZING_SCHEMA_VERSION",
    "FuzzCase",
    "JsonValue",
    "MutationRecord",
    "ORACLE_SEVERITIES",
    "ORACLE_VERDICTS",
    "OracleResult",
    "SeedInput",
    "TARGET_STATUSES",
    "TargetResult",
    "frozen_json_mapping",
    "json_copy",
]
