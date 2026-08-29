"""Ground-truth evaluation and analyst-burden metrics for threat hunting.

This module is the only threat-hunting component that consumes both public
``Finding`` values and evaluator-only ``GroundTruthLabel`` values.  Matching is
deterministic and one-to-one so duplicate findings cannot inflate precision.
"""

from __future__ import annotations

import hashlib
import math
import statistics
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .models import Finding, GroundTruthLabel, HuntEvent, SCHEMA_VERSION, canonical_json


DEFAULT_EVALUATED_LABEL_TYPES = (
    "attacker_success",
    "critical_compromise",
    "critical_true_gain",
)
HIGH_SEVERITIES = frozenset({"high", "critical"})


def _non_empty_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _finite_non_negative(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a finite non-negative number")
    result = float(value)
    if not math.isfinite(result) or result < 0.0:
        raise ValueError(f"{field_name} must be a finite non-negative number")
    return result


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _optional_delta(current: float, reference: float | None) -> float | None:
    if reference is None:
        return None
    if isinstance(reference, bool) or not isinstance(reference, (int, float)):
        raise ValueError("robustness reference values must be finite numbers")
    value = float(reference)
    if not math.isfinite(value):
        raise ValueError("robustness reference values must be finite numbers")
    return current - value


@dataclass(frozen=True)
class AnalystCostProfile:
    """Explicit weights used for operational and evaluator-only burden.

    There are intentionally no implicit defaults for a complete profile.  A
    caller must provide every weight before a weighted score is produced.
    """

    profile_id: str
    w_triage: float
    w_evidence: float
    w_context: float
    w_escalation: float
    w_false_positive: float
    w_false_evidence: float
    version: str = "1.0"

    def __post_init__(self) -> None:
        _non_empty_string(self.profile_id, "profile_id")
        _non_empty_string(self.version, "version")
        for field_name in (
            "w_triage",
            "w_evidence",
            "w_context",
            "w_escalation",
            "w_false_positive",
            "w_false_evidence",
        ):
            object.__setattr__(
                self,
                field_name,
                _finite_non_negative(getattr(self, field_name), field_name),
            )

    @property
    def profile_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "version": self.version,
            "weights": {
                "triage": self.w_triage,
                "evidence": self.w_evidence,
                "context": self.w_context,
                "escalation": self.w_escalation,
                "false_positive": self.w_false_positive,
                "false_evidence": self.w_false_evidence,
            },
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "AnalystCostProfile":
        if not isinstance(payload, Mapping):
            raise ValueError("AnalystCostProfile payload must be a mapping")
        weights = payload.get("weights")
        if not isinstance(weights, Mapping):
            raise ValueError("AnalystCostProfile weights must be a mapping")
        return cls(
            profile_id=payload.get("profile_id"),
            version=payload.get("version", "1.0"),
            w_triage=weights.get("triage"),
            w_evidence=weights.get("evidence"),
            w_context=weights.get("context"),
            w_escalation=weights.get("escalation"),
            w_false_positive=weights.get("false_positive"),
            w_false_evidence=weights.get("false_evidence"),
        )


@dataclass(frozen=True)
class TruthMatchingPolicy:
    """Serializable policy controlling Finding-to-truth matching."""

    policy_id: str = "threat_hunting_truth_v1"
    version: str = "1.0"
    evaluated_label_types: tuple[str, ...] = DEFAULT_EVALUATED_LABEL_TYPES
    max_lead_steps: int = 0
    max_lag_steps: int = 0
    require_campaign_match: bool = True
    match_actor_when_known: bool = True
    match_target_when_known: bool = True
    require_declared_event_match: bool = True
    compromise_label_type: str = "critical_compromise"

    def __post_init__(self) -> None:
        _non_empty_string(self.policy_id, "policy_id")
        _non_empty_string(self.version, "version")
        _non_empty_string(self.compromise_label_type, "compromise_label_type")
        label_types = tuple(self.evaluated_label_types)
        if not label_types or any(
            not isinstance(value, str) or not value.strip() for value in label_types
        ):
            raise ValueError("evaluated_label_types must contain non-empty strings")
        if len(set(label_types)) != len(label_types):
            raise ValueError("evaluated_label_types must not contain duplicates")
        object.__setattr__(self, "evaluated_label_types", label_types)
        _non_negative_int(self.max_lead_steps, "max_lead_steps")
        _non_negative_int(self.max_lag_steps, "max_lag_steps")
        for field_name in (
            "require_campaign_match",
            "match_actor_when_known",
            "match_target_when_known",
            "require_declared_event_match",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise ValueError(f"{field_name} must be a boolean")

    @property
    def policy_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "evaluated_label_types": list(self.evaluated_label_types),
            "max_lead_steps": self.max_lead_steps,
            "max_lag_steps": self.max_lag_steps,
            "require_campaign_match": self.require_campaign_match,
            "match_actor_when_known": self.match_actor_when_known,
            "match_target_when_known": self.match_target_when_known,
            "require_declared_event_match": self.require_declared_event_match,
            "compromise_label_type": self.compromise_label_type,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "TruthMatchingPolicy":
        if not isinstance(payload, Mapping):
            raise ValueError("TruthMatchingPolicy payload must be a mapping")
        data = dict(payload)
        data["evaluated_label_types"] = tuple(
            data.get("evaluated_label_types", DEFAULT_EVALUATED_LABEL_TYPES)
        )
        return cls(**data)


@dataclass(frozen=True)
class TruthMatch:
    finding_id: str
    label_id: str
    detection_delay_steps: int
    matched_on: tuple[str, ...]

    def __post_init__(self) -> None:
        _non_empty_string(self.finding_id, "finding_id")
        _non_empty_string(self.label_id, "label_id")
        if isinstance(self.detection_delay_steps, bool) or not isinstance(
            self.detection_delay_steps, int
        ):
            raise ValueError("detection_delay_steps must be an integer")
        matched_on = tuple(self.matched_on)
        if not matched_on or any(not isinstance(value, str) for value in matched_on):
            raise ValueError("matched_on must contain strings")
        object.__setattr__(self, "matched_on", matched_on)

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "label_id": self.label_id,
            "detection_delay_steps": self.detection_delay_steps,
            "matched_on": list(self.matched_on),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "TruthMatch":
        if not isinstance(payload, Mapping):
            raise ValueError("TruthMatch payload must be a mapping")
        data = dict(payload)
        data["matched_on"] = tuple(data.get("matched_on", ()))
        return cls(**data)


@dataclass(frozen=True)
class ThreatHuntingEvaluation:
    """Immutable evaluator output ready for JSON/report serialization."""

    schema_version: str
    total_steps: int
    metrics: Mapping[str, int | float | None]
    matches: tuple[TruthMatch, ...]
    unmatched_finding_ids: tuple[str, ...]
    unmatched_label_ids: tuple[str, ...]
    matching_policy: TruthMatchingPolicy
    cost_profile: AnalystCostProfile | None = None

    def __post_init__(self) -> None:
        _non_empty_string(self.schema_version, "schema_version")
        _non_negative_int(self.total_steps, "total_steps")
        frozen_metrics: dict[str, int | float | None] = {}
        for key, value in self.metrics.items():
            _non_empty_string(key, "metric name")
            if value is not None:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError(f"metric {key!r} must be numeric or None")
                if isinstance(value, float) and not math.isfinite(value):
                    raise ValueError(f"metric {key!r} must be finite")
            frozen_metrics[key] = value
        object.__setattr__(self, "metrics", MappingProxyType(frozen_metrics))
        matches = tuple(self.matches)
        if any(not isinstance(match, TruthMatch) for match in matches):
            raise ValueError("matches must contain TruthMatch values only")
        matched_finding_ids = [match.finding_id for match in matches]
        matched_label_ids = [match.label_id for match in matches]
        if len(set(matched_finding_ids)) != len(matched_finding_ids):
            raise ValueError("a finding must not match more than one truth label")
        if len(set(matched_label_ids)) != len(matched_label_ids):
            raise ValueError("a truth label must not match more than one finding")
        unmatched_finding_ids = tuple(self.unmatched_finding_ids)
        unmatched_label_ids = tuple(self.unmatched_label_ids)
        for values, field_name in (
            (unmatched_finding_ids, "unmatched_finding_ids"),
            (unmatched_label_ids, "unmatched_label_ids"),
        ):
            if any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError(f"{field_name} must contain non-empty strings")
            if len(set(values)) != len(values):
                raise ValueError(f"{field_name} must not contain duplicates")
        if set(matched_finding_ids).intersection(unmatched_finding_ids):
            raise ValueError("matched and unmatched finding IDs must be disjoint")
        if set(matched_label_ids).intersection(unmatched_label_ids):
            raise ValueError("matched and unmatched truth label IDs must be disjoint")
        object.__setattr__(self, "matches", matches)
        object.__setattr__(self, "unmatched_finding_ids", unmatched_finding_ids)
        object.__setattr__(self, "unmatched_label_ids", unmatched_label_ids)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "total_steps": self.total_steps,
            "metrics": dict(self.metrics),
            "matches": [match.to_dict() for match in self.matches],
            "unmatched_finding_ids": list(self.unmatched_finding_ids),
            "unmatched_label_ids": list(self.unmatched_label_ids),
            "matching_policy": self.matching_policy.to_dict(),
            "matching_policy_hash": self.matching_policy.policy_hash,
            "cost_profile": self.cost_profile.to_dict() if self.cost_profile else None,
            "cost_profile_hash": self.cost_profile.profile_hash if self.cost_profile else None,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ThreatHuntingEvaluation":
        if not isinstance(payload, Mapping):
            raise ValueError("ThreatHuntingEvaluation payload must be a mapping")
        metrics = payload.get("metrics")
        matches = payload.get("matches")
        policy = payload.get("matching_policy")
        cost_profile = payload.get("cost_profile")
        if not isinstance(metrics, Mapping):
            raise ValueError("evaluation metrics must be a mapping")
        if not isinstance(matches, list):
            raise ValueError("evaluation matches must be a list")
        if not isinstance(policy, Mapping):
            raise ValueError("evaluation matching_policy must be a mapping")
        if cost_profile is not None and not isinstance(cost_profile, Mapping):
            raise ValueError("evaluation cost_profile must be a mapping or None")
        result = cls(
            schema_version=payload.get("schema_version"),
            total_steps=payload.get("total_steps"),
            metrics=dict(metrics),
            matches=tuple(TruthMatch.from_dict(value) for value in matches),
            unmatched_finding_ids=tuple(payload.get("unmatched_finding_ids", ())),
            unmatched_label_ids=tuple(payload.get("unmatched_label_ids", ())),
            matching_policy=TruthMatchingPolicy.from_dict(policy),
            cost_profile=(
                AnalystCostProfile.from_dict(cost_profile) if cost_profile is not None else None
            ),
        )
        recorded_policy_hash = payload.get("matching_policy_hash")
        if recorded_policy_hash is not None and recorded_policy_hash != result.matching_policy.policy_hash:
            raise ValueError("evaluation matching_policy_hash verification failed")
        recorded_cost_hash = payload.get("cost_profile_hash")
        expected_cost_hash = result.cost_profile.profile_hash if result.cost_profile else None
        if recorded_cost_hash != expected_cost_hash:
            raise ValueError("evaluation cost_profile_hash verification failed")
        return result


@dataclass(frozen=True)
class _FindingContext:
    finding: Finding
    target_nodes: frozenset[int] = field(default_factory=frozenset)
    resolved_evidence_count: int = 0


class ThreatHuntingEvaluator:
    """Deterministically match findings to truth and calculate H2 metrics."""

    def __init__(self, policy: TruthMatchingPolicy | None = None):
        if policy is not None and not isinstance(policy, TruthMatchingPolicy):
            raise ValueError("policy must be a TruthMatchingPolicy or None")
        self._policy = policy or TruthMatchingPolicy()

    @property
    def policy(self) -> TruthMatchingPolicy:
        return self._policy

    def evaluate(
        self,
        findings: Iterable[Finding],
        ground_truth: Iterable[GroundTruthLabel],
        *,
        events: Iterable[HuntEvent] = (),
        total_steps: int,
        cost_profile: AnalystCostProfile | None = None,
        duplicate_suppressed_count: int = 0,
        protection_delta: float | None = None,
        noise_reference_f1: float | None = None,
        adversarial_reference_f1: float | None = None,
    ) -> ThreatHuntingEvaluation:
        _non_negative_int(total_steps, "total_steps")
        _non_negative_int(duplicate_suppressed_count, "duplicate_suppressed_count")
        if cost_profile is not None and not isinstance(cost_profile, AnalystCostProfile):
            raise ValueError("cost_profile must be an AnalystCostProfile or None")
        if protection_delta is not None:
            if isinstance(protection_delta, bool) or not isinstance(protection_delta, (int, float)):
                raise ValueError("protection_delta must be a finite number or None")
            protection_delta = float(protection_delta)
            if not math.isfinite(protection_delta):
                raise ValueError("protection_delta must be a finite number or None")

        finding_values = tuple(findings)
        truth_values = tuple(ground_truth)
        event_values = tuple(events)
        self._validate_inputs(finding_values, truth_values, event_values)
        event_by_id = {event.event_id: event for event in event_values}
        contexts = tuple(self._context(finding, event_by_id) for finding in finding_values)
        eligible_truth = tuple(
            label
            for label in truth_values
            if label.label_type in self._policy.evaluated_label_types
        )

        matches = self._match(contexts, eligible_truth)
        matched_findings = {match.finding_id for match in matches}
        matched_labels = {match.label_id for match in matches}
        false_positive_findings = tuple(
            context for context in contexts if context.finding.finding_id not in matched_findings
        )
        unmatched_labels = tuple(
            label for label in eligible_truth if label.label_id not in matched_labels
        )

        finding_count = len(contexts)
        true_positive_count = len(matched_findings)
        false_positive_count = len(false_positive_findings)
        false_negative_count = len(unmatched_labels)
        precision = _ratio(true_positive_count, finding_count)
        recall = _ratio(len(matched_labels), len(eligible_truth))
        f1 = _ratio(2.0 * precision * recall, precision + recall)
        evidence_ids = {
            event_id
            for context in contexts
            for event_id in context.finding.evidence_event_ids
        }
        evidence_references = sum(
            len(context.finding.evidence_event_ids) for context in contexts
        )
        resolved_evidence = sum(context.resolved_evidence_count for context in contexts)
        false_positive_evidence_count = sum(
            len(context.finding.evidence_event_ids) for context in false_positive_findings
        )
        high_severity_count = sum(
            context.finding.severity in HIGH_SEVERITIES for context in contexts
        )
        actors = {
            context.finding.actor_id
            for context in contexts
            if context.finding.actor_id is not None
        }
        targets = {target for context in contexts for target in context.target_nodes}
        context_switch_count = self._context_switch_count(contexts)
        operational_burden = None
        wasted_burden = None
        if cost_profile is not None:
            operational_burden = (
                cost_profile.w_triage * finding_count
                + cost_profile.w_evidence * evidence_references
                + cost_profile.w_context * context_switch_count
                + cost_profile.w_escalation * high_severity_count
            )
            wasted_burden = (
                cost_profile.w_false_positive * false_positive_count
                + cost_profile.w_false_evidence * false_positive_evidence_count
            )

        delays = [max(match.detection_delay_steps, 0) for match in matches]
        pre_compromise_rate = self._pre_compromise_detection_rate(contexts, truth_values)
        campaign_coverage = self._coverage(
            eligible_truth,
            matched_labels,
            lambda label: label.campaign_id,
        )
        actor_coverage = self._coverage(
            eligible_truth,
            matched_labels,
            lambda label: label.actor_id,
            omit_none=True,
        )
        target_coverage = self._coverage(
            eligible_truth,
            matched_labels,
            lambda label: label.target_node,
            omit_none=True,
        )
        window_coverage = _ratio(len(matched_labels), len(eligible_truth))
        operational_per_100 = (
            operational_burden / max(total_steps, 1) * 100.0
            if operational_burden is not None
            else None
        )
        hunting_value_score = (
            protection_delta / (1.0 + operational_per_100)
            if protection_delta is not None and operational_per_100 is not None
            else None
        )

        metrics: dict[str, int | float | None] = {
            "true_positive_finding_count": true_positive_count,
            "false_positive_finding_count": false_positive_count,
            "false_negative_label_count": false_negative_count,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positives_per_100_steps": false_positive_count / max(total_steps, 1) * 100.0,
            "mean_time_to_detect_steps": statistics.fmean(delays) if delays else None,
            "median_time_to_detect_steps": statistics.median(delays) if delays else None,
            "pre_compromise_detection_rate": pre_compromise_rate,
            "campaign_coverage": campaign_coverage,
            "actor_coverage": actor_coverage,
            "target_coverage": target_coverage,
            "window_coverage": window_coverage,
            "noise_robustness_delta": _optional_delta(f1, noise_reference_f1),
            "adversarial_robustness_delta": _optional_delta(f1, adversarial_reference_f1),
            "evidence_completeness": _ratio(resolved_evidence, evidence_references),
            "finding_count": finding_count,
            "unique_evidence_event_count": len(evidence_ids),
            "total_evidence_references": evidence_references,
            "distinct_actor_count": len(actors),
            "distinct_target_count": len(targets),
            "high_severity_finding_count": high_severity_count,
            "duplicate_suppressed_count": duplicate_suppressed_count,
            "findings_per_100_steps": finding_count / max(total_steps, 1) * 100.0,
            "evidence_events_per_finding": _ratio(evidence_references, finding_count),
            "context_switch_count": context_switch_count,
            "false_positive_evidence_count": false_positive_evidence_count,
            "operational_burden": operational_burden,
            "operational_burden_per_100_steps": operational_per_100,
            "wasted_burden": wasted_burden,
            "protection_delta": protection_delta,
            "hunting_value_score": hunting_value_score,
        }
        return ThreatHuntingEvaluation(
            schema_version=SCHEMA_VERSION,
            total_steps=total_steps,
            metrics=metrics,
            matches=matches,
            unmatched_finding_ids=tuple(
                sorted(context.finding.finding_id for context in false_positive_findings)
            ),
            unmatched_label_ids=tuple(sorted(label.label_id for label in unmatched_labels)),
            matching_policy=self._policy,
            cost_profile=cost_profile,
        )

    @staticmethod
    def _validate_inputs(
        findings: tuple[Finding, ...],
        truth: tuple[GroundTruthLabel, ...],
        events: tuple[HuntEvent, ...],
    ) -> None:
        if any(not isinstance(value, Finding) for value in findings):
            raise ValueError("findings must contain Finding values only")
        if any(not isinstance(value, GroundTruthLabel) for value in truth):
            raise ValueError("ground_truth must contain GroundTruthLabel values only")
        if any(not isinstance(value, HuntEvent) for value in events):
            raise ValueError("events must contain HuntEvent values only")
        for values, field_name in (
            (findings, "finding_id"),
            (truth, "label_id"),
            (events, "event_id"),
        ):
            identifiers = [getattr(value, field_name) for value in values]
            if len(set(identifiers)) != len(identifiers):
                raise ValueError(f"{field_name} values must be unique")

    @staticmethod
    def _context(
        finding: Finding,
        event_by_id: Mapping[str, HuntEvent],
    ) -> _FindingContext:
        target_nodes: set[int] = set()
        declared_target = finding.attributes.get("target_node")
        if isinstance(declared_target, int) and not isinstance(declared_target, bool):
            target_nodes.add(declared_target)
        resolved = 0
        for event_id in finding.evidence_event_ids:
            event = event_by_id.get(event_id)
            if event is None:
                continue
            resolved += 1
            if event.target_node is not None:
                target_nodes.add(event.target_node)
        return _FindingContext(finding, frozenset(target_nodes), resolved)

    def _match(
        self,
        contexts: tuple[_FindingContext, ...],
        truth: tuple[GroundTruthLabel, ...],
    ) -> tuple[TruthMatch, ...]:
        candidates: list[tuple[tuple[object, ...], _FindingContext, GroundTruthLabel, tuple[str, ...]]] = []
        for context in contexts:
            for label in truth:
                matched_on = self._matched_on(context, label)
                if matched_on is None:
                    continue
                finding = context.finding
                if finding.end_step < label.start_step:
                    distance = label.start_step - finding.end_step
                elif finding.start_step > label.end_step:
                    distance = finding.start_step - label.end_step
                else:
                    distance = 0
                specificity = -len(matched_on)
                key = (
                    distance,
                    specificity,
                    finding.start_step,
                    label.start_step,
                    finding.finding_id,
                    label.label_id,
                )
                candidates.append((key, context, label, matched_on))
        used_findings: set[str] = set()
        used_labels: set[str] = set()
        matches: list[TruthMatch] = []
        for _, context, label, matched_on in sorted(candidates, key=lambda value: value[0]):
            finding = context.finding
            if finding.finding_id in used_findings or label.label_id in used_labels:
                continue
            used_findings.add(finding.finding_id)
            used_labels.add(label.label_id)
            matches.append(
                TruthMatch(
                    finding_id=finding.finding_id,
                    label_id=label.label_id,
                    detection_delay_steps=finding.start_step - label.start_step,
                    matched_on=matched_on,
                )
            )
        return tuple(sorted(matches, key=lambda match: (match.finding_id, match.label_id)))

    def _matched_on(
        self,
        context: _FindingContext,
        label: GroundTruthLabel,
    ) -> tuple[str, ...] | None:
        finding = context.finding
        matched_on: list[str] = []
        if self._policy.require_campaign_match:
            if finding.campaign_id != label.campaign_id:
                return None
            matched_on.append("campaign")
        earliest = label.start_step - self._policy.max_lead_steps
        latest = label.end_step + self._policy.max_lag_steps
        if finding.end_step < earliest or finding.start_step > latest:
            return None
        matched_on.append("overlapping_window")
        if (
            self._policy.match_actor_when_known
            and finding.actor_id is not None
            and label.actor_id is not None
        ):
            if finding.actor_id != label.actor_id:
                return None
            matched_on.append("actor")
        if (
            self._policy.match_target_when_known
            and label.target_node is not None
            and context.target_nodes
        ):
            if label.target_node not in context.target_nodes:
                return None
            matched_on.append("target")
        declared_events = self._declared_truth_events(label)
        if self._policy.require_declared_event_match and declared_events:
            if not declared_events.intersection(finding.evidence_event_ids):
                return None
            matched_on.append("event")
        return tuple(matched_on)

    @staticmethod
    def _declared_truth_events(label: GroundTruthLabel) -> frozenset[str]:
        result: set[str] = set()
        for key in ("event_id", "source_event_id"):
            value = label.attributes.get(key)
            if isinstance(value, str) and value:
                result.add(value)
        value = label.attributes.get("event_ids")
        if isinstance(value, str):
            result.update(part.strip() for part in value.split(",") if part.strip())
        return frozenset(result)

    @staticmethod
    def _context_switch_count(contexts: tuple[_FindingContext, ...]) -> int:
        ordered = sorted(
            contexts,
            key=lambda context: (
                context.finding.start_step,
                context.finding.end_step,
                context.finding.finding_id,
            ),
        )
        keys = [
            (context.finding.actor_id, tuple(sorted(context.target_nodes)))
            for context in ordered
        ]
        return sum(previous != current for previous, current in zip(keys, keys[1:]))

    def _pre_compromise_detection_rate(
        self,
        contexts: tuple[_FindingContext, ...],
        truth: tuple[GroundTruthLabel, ...],
    ) -> float:
        compromises = [
            label
            for label in truth
            if label.label_type == self._policy.compromise_label_type
        ]
        detected = 0
        for label in compromises:
            if any(
                context.finding.campaign_id == label.campaign_id
                and context.finding.end_step < label.start_step
                and (
                    label.actor_id is None
                    or context.finding.actor_id is None
                    or context.finding.actor_id == label.actor_id
                )
                and (
                    label.target_node is None
                    or not context.target_nodes
                    or label.target_node in context.target_nodes
                )
                for context in contexts
            ):
                detected += 1
        return _ratio(detected, len(compromises))

    @staticmethod
    def _coverage(
        truth: tuple[GroundTruthLabel, ...],
        matched_label_ids: set[str],
        key,
        *,
        omit_none: bool = False,
    ) -> float:
        all_values = {key(label) for label in truth}
        matched_values = {
            key(label) for label in truth if label.label_id in matched_label_ids
        }
        if omit_none:
            all_values.discard(None)
            matched_values.discard(None)
        return _ratio(len(matched_values), len(all_values))


__all__ = [
    "DEFAULT_EVALUATED_LABEL_TYPES",
    "AnalystCostProfile",
    "ThreatHuntingEvaluation",
    "ThreatHuntingEvaluator",
    "TruthMatch",
    "TruthMatchingPolicy",
]
