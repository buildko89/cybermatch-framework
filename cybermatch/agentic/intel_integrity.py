"""Evidence-based integrity gate for LLM-generated vulnerability intelligence."""

from __future__ import annotations

import math
from dataclasses import dataclass
from statistics import fmean
from typing import Mapping, Sequence


ADVISORY_STATUSES = frozenset({"published", "confirmed", "disputed", "rejected", "withdrawn"})
INTEGRITY_DECISIONS = frozenset({"accept", "quarantine", "reject"})
GROUND_TRUTH_LABELS = frozenset({"valid", "fabricated", "unknown"})


def _probability(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be between 0 and 1")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")
    return result


@dataclass(frozen=True)
class ThreatIntelAdvisory:
    advisory_id: str
    source_identity: str
    source_trust: float
    vendor_corroboration: bool
    affected_version_consistency: bool
    code_reference_validity: bool
    fix_commit_present: bool
    poc_present: bool
    poc_reproduced: bool
    independent_source_count: int
    status: str = "published"

    def __post_init__(self) -> None:
        for name in ("advisory_id", "source_identity"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        object.__setattr__(self, "source_trust", _probability(self.source_trust, "source_trust"))
        for name in (
            "vendor_corroboration",
            "affected_version_consistency",
            "code_reference_validity",
            "fix_commit_present",
            "poc_present",
            "poc_reproduced",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be boolean")
        if (
            isinstance(self.independent_source_count, bool)
            or not isinstance(self.independent_source_count, int)
            or self.independent_source_count < 0
        ):
            raise ValueError("independent_source_count must be a non-negative integer")
        if self.status not in ADVISORY_STATUSES:
            raise ValueError("status must be one of: " + ", ".join(sorted(ADVISORY_STATUSES)))
        if self.poc_reproduced and not self.poc_present:
            raise ValueError("poc_reproduced requires poc_present")

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ThreatIntelAdvisory":
        if not isinstance(payload, Mapping):
            raise ValueError("advisory must be an object")
        unknown = sorted(set(payload) - set(cls.__dataclass_fields__))
        if unknown:
            raise ValueError("advisory has unknown fields: " + ", ".join(unknown))
        try:
            return cls(**dict(payload))
        except TypeError as exc:
            raise ValueError(f"invalid advisory: {exc}") from exc

    def to_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True)
class IntegrityGateConfig:
    accept_threshold: float = 0.75
    quarantine_threshold: float = 0.40

    def __post_init__(self) -> None:
        accept = _probability(self.accept_threshold, "accept_threshold")
        quarantine = _probability(self.quarantine_threshold, "quarantine_threshold")
        if quarantine >= accept:
            raise ValueError("quarantine_threshold must be less than accept_threshold")

    @classmethod
    def from_dict(cls, payload: Mapping[str, object] | None) -> "IntegrityGateConfig":
        if payload is None:
            return cls()
        if not isinstance(payload, Mapping):
            raise ValueError("integrity gate must be an object")
        unknown = sorted(set(payload) - set(cls.__dataclass_fields__))
        if unknown:
            raise ValueError("integrity gate has unknown fields: " + ", ".join(unknown))
        try:
            return cls(**dict(payload))
        except TypeError as exc:
            raise ValueError(f"invalid integrity gate: {exc}") from exc


@dataclass(frozen=True)
class IntegrityDecision:
    advisory_id: str
    decision: str
    evidence_score: float
    failed_checks: tuple[str, ...]
    checks_performed: int
    checks_passed: int

    def to_dict(self) -> dict[str, object]:
        return {
            "advisory_id": self.advisory_id,
            "decision": self.decision,
            "evidence_score": self.evidence_score,
            "failed_checks": list(self.failed_checks),
            "checks_performed": self.checks_performed,
            "checks_passed": self.checks_passed,
        }


class ThreatIntelIntegrityGate:
    """Score corroborating evidence; never use a ground-truth label to decide."""

    _WEIGHTS = {
        "source_trust": 0.15,
        "vendor_corroboration": 0.20,
        "affected_version_consistency": 0.15,
        "code_reference_validity": 0.15,
        "fix_commit_present": 0.10,
        "poc_present": 0.05,
        "poc_reproduced": 0.10,
        "independent_sources": 0.10,
    }

    def __init__(self, config: IntegrityGateConfig | None = None):
        self.config = config or IntegrityGateConfig()

    def evaluate(self, advisory: ThreatIntelAdvisory) -> IntegrityDecision:
        if not isinstance(advisory, ThreatIntelAdvisory):
            raise TypeError("advisory must be a ThreatIntelAdvisory")
        checks = {
            "source_trust": advisory.source_trust >= 0.5,
            "vendor_corroboration": advisory.vendor_corroboration,
            "affected_version_consistency": advisory.affected_version_consistency,
            "code_reference_validity": advisory.code_reference_validity,
            "fix_commit_present": advisory.fix_commit_present,
            "poc_present": advisory.poc_present,
            "poc_reproduced": advisory.poc_reproduced,
            "independent_sources": advisory.independent_source_count >= 2,
        }
        score = (
            self._WEIGHTS["source_trust"] * advisory.source_trust
            + self._WEIGHTS["vendor_corroboration"] * float(advisory.vendor_corroboration)
            + self._WEIGHTS["affected_version_consistency"] * float(advisory.affected_version_consistency)
            + self._WEIGHTS["code_reference_validity"] * float(advisory.code_reference_validity)
            + self._WEIGHTS["fix_commit_present"] * float(advisory.fix_commit_present)
            + self._WEIGHTS["poc_present"] * float(advisory.poc_present)
            + self._WEIGHTS["poc_reproduced"] * float(advisory.poc_reproduced)
            + self._WEIGHTS["independent_sources"] * min(advisory.independent_source_count / 2.0, 1.0)
        )
        if advisory.status in {"rejected", "withdrawn"}:
            decision = "reject"
        elif score >= self.config.accept_threshold and advisory.status == "confirmed":
            decision = "accept"
        elif score >= self.config.quarantine_threshold:
            decision = "quarantine"
        else:
            decision = "reject"
        return IntegrityDecision(
            advisory_id=advisory.advisory_id,
            decision=decision,
            evidence_score=float(score),
            failed_checks=tuple(sorted(name for name, passed in checks.items() if not passed)),
            checks_performed=len(checks),
            checks_passed=sum(checks.values()),
        )


def evaluate_integrity_outcomes(
    decisions: Sequence[IntegrityDecision],
    cases: Sequence[Mapping[str, object]],
) -> dict[str, int | float | None]:
    """Evaluate decisions against labels kept outside the integrity gate."""

    labels: dict[str, str] = {}
    correction_delays: list[int] = []
    for case in cases:
        advisory_id = case.get("advisory_id")
        label = case.get("ground_truth", "unknown")
        if not isinstance(advisory_id, str) or label not in GROUND_TRUTH_LABELS:
            raise ValueError("integrity evaluation cases require advisory_id and valid ground_truth")
        labels[advisory_id] = str(label)
        first_seen = case.get("first_seen_step")
        corrected = case.get("corrected_step")
        if corrected is not None:
            if (
                isinstance(first_seen, bool)
                or not isinstance(first_seen, int)
                or isinstance(corrected, bool)
                or not isinstance(corrected, int)
                or corrected < first_seen
            ):
                raise ValueError("corrected_step must be >= first_seen_step")
            correction_delays.append(corrected - first_seen)
    fabricated = [decision for decision in decisions if labels.get(decision.advisory_id) == "fabricated"]
    valid = [decision for decision in decisions if labels.get(decision.advisory_id) == "valid"]
    accepted_fabricated = sum(decision.decision == "accept" for decision in fabricated)
    accepted_valid = sum(decision.decision == "accept" for decision in valid)
    checks = sum(decision.checks_performed for decision in decisions)
    passed = sum(decision.checks_passed for decision in decisions)
    return {
        "advisory_count": len(decisions),
        "fabricated_advisory_acceptance_rate": accepted_fabricated / len(fabricated) if fabricated else 0.0,
        "valid_advisory_acceptance_rate": accepted_valid / len(valid) if valid else 0.0,
        "verification_coverage": checks / (len(decisions) * len(ThreatIntelIntegrityGate._WEIGHTS)) if decisions else 0.0,
        "evidence_pass_rate": passed / checks if checks else 0.0,
        "unnecessary_remediation_count": accepted_fabricated,
        "mean_correction_latency_steps": fmean(correction_delays) if correction_delays else None,
    }


__all__ = [
    "ADVISORY_STATUSES",
    "GROUND_TRUTH_LABELS",
    "INTEGRITY_DECISIONS",
    "IntegrityDecision",
    "IntegrityGateConfig",
    "ThreatIntelAdvisory",
    "ThreatIntelIntegrityGate",
    "evaluate_integrity_outcomes",
]
