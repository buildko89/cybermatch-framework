"""Independent oracle evaluation for fuzz target results."""

from __future__ import annotations

import hashlib
from typing import Sequence

from src.cybermatch.threat_hunting import ThreatHuntingEvaluator, canonical_json

from ..models import FuzzCase, OracleResult, TargetResult


def _fingerprint(oracle_id: str, target_id: str, payload: object) -> str:
    digest = hashlib.sha256(
        canonical_json({"oracle_id": oracle_id, "target_id": target_id, "payload": payload}).encode(
            "utf-8"
        )
    ).hexdigest()
    return f"fuzz-failure_{digest[:24]}"


def no_unhandled_exception_oracle(result: TargetResult, target_id: str) -> OracleResult:
    failed = result.status in {"crashed", "timeout"}
    payload = {"status": result.status, "error_type": result.error_type}
    return OracleResult(
        oracle_id="no_unhandled_exception",
        verdict="fail" if failed else "pass",
        severity="high" if failed else "info",
        fingerprint=_fingerprint("no_unhandled_exception", target_id, payload),
        evidence=payload,
    )


def external_execution_health_oracle(
    result: TargetResult, target_id: str
) -> OracleResult:
    payload = {
        "status": result.status,
        "error_type": result.error_type,
        "attempt_count": result.state_observations.get("attempt_count"),
        "detection_verdict_eligible": result.state_observations.get(
            "detection_verdict_eligible"
        ),
    }
    if result.status == "completed":
        verdict, severity = "pass", "info"
    elif result.status in {"infrastructure_error", "timeout", "limit_exceeded"}:
        verdict, severity = "inconclusive", "medium"
    else:
        verdict, severity = "fail", "high"
    return OracleResult(
        oracle_id="external_execution_health",
        verdict=verdict,
        severity=severity,
        fingerprint=_fingerprint("external_execution_health", target_id, payload),
        evidence=payload,
    )


def deterministic_replay_oracle(
    result: TargetResult,
    replay: TargetResult | None,
    target_id: str,
) -> OracleResult:
    if replay is None:
        payload = {"reason": "replay result unavailable"}
        return OracleResult(
            oracle_id="deterministic_replay",
            verdict="inconclusive",
            severity="medium",
            fingerprint=_fingerprint("deterministic_replay", target_id, payload),
            evidence=payload,
        )
    first = result.comparable_dict()
    second = replay.comparable_dict()
    same = first == second
    payload = {
        "equivalent": same,
        "first_status": result.status,
        "replay_status": replay.status,
    }
    return OracleResult(
        oracle_id="deterministic_replay",
        verdict="pass" if same else "fail",
        severity="info" if same else "high",
        fingerprint=_fingerprint("deterministic_replay", target_id, payload),
        evidence=payload,
    )


def _detection_evaluation(
    events,
    ground_truth,
    result: TargetResult,
):
    if not ground_truth or result.status != "completed":
        return None
    total_steps = max((event.step + 1 for event in events), default=0)
    return ThreatHuntingEvaluator().evaluate(
        result.findings,
        ground_truth,
        events=events,
        total_steps=total_steps,
    )


def ground_truth_detection_oracle(
    case: FuzzCase,
    result: TargetResult,
    target_id: str,
    control_result: TargetResult | None = None,
) -> OracleResult:
    evaluation = _detection_evaluation(case.events, case.ground_truth, result)
    if evaluation is None:
        payload = {
            "reason": "ground truth unavailable" if not case.ground_truth else "target did not complete",
            "status": result.status,
        }
        return OracleResult(
            oracle_id="ground_truth_detection",
            verdict="inconclusive",
            severity="medium",
            fingerprint=_fingerprint("ground_truth_detection", target_id, payload),
            evidence=payload,
        )
    metrics = dict(evaluation.metrics)
    false_negatives = int(metrics["false_negative_label_count"] or 0)
    false_positives = int(metrics["false_positive_finding_count"] or 0)
    control_evaluation = (
        _detection_evaluation(case.control_events, case.control_ground_truth, control_result)
        if control_result is not None and case.control_events
        else None
    )
    control_metrics = dict(control_evaluation.metrics) if control_evaluation is not None else None
    control_false_negatives = (
        int(control_metrics["false_negative_label_count"] or 0)
        if control_metrics is not None
        else 0
    )
    control_false_positives = (
        int(control_metrics["false_positive_finding_count"] or 0)
        if control_metrics is not None
        else 0
    )
    false_negative_delta = false_negatives - control_false_negatives
    false_positive_delta = false_positives - control_false_positives
    interesting = (
        false_negative_delta > 0 or false_positive_delta > 0
        if control_metrics is not None
        else false_negatives > 0 or false_positives > 0
    )
    payload = {
        "false_negative_label_count": false_negatives,
        "false_positive_finding_count": false_positives,
        "control_false_negative_label_count": control_false_negatives if control_metrics is not None else None,
        "control_false_positive_finding_count": control_false_positives if control_metrics is not None else None,
        "false_negative_delta": false_negative_delta if control_metrics is not None else None,
        "false_positive_delta": false_positive_delta if control_metrics is not None else None,
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "unmatched_finding_ids": list(evaluation.unmatched_finding_ids),
        "unmatched_label_ids": list(evaluation.unmatched_label_ids),
        "matching_policy_hash": evaluation.matching_policy.policy_hash,
    }
    unmatched_label_ids = set(evaluation.unmatched_label_ids)
    unmatched_finding_ids = set(evaluation.unmatched_finding_ids)
    fingerprint_payload = {
        "false_negative_delta": payload["false_negative_delta"],
        "false_positive_delta": payload["false_positive_delta"],
        "unmatched_label_types": sorted(
            {
                label.label_type
                for label in case.ground_truth
                if label.label_id in unmatched_label_ids
            }
        ),
        "unmatched_finding_recipe_ids": sorted(
            {
                finding.recipe_id
                for finding in result.findings
                if finding.finding_id in unmatched_finding_ids
            }
        ),
    }
    return OracleResult(
        oracle_id="ground_truth_detection",
        verdict="interesting" if interesting else "pass",
        severity="medium" if interesting else "info",
        fingerprint=_fingerprint("ground_truth_detection", target_id, fingerprint_payload),
        evidence=payload,
    )


def detection_latency_oracle(
    case: FuzzCase,
    result: TargetResult,
    target_id: str,
    control_result: TargetResult | None = None,
) -> OracleResult:
    evaluation = _detection_evaluation(case.events, case.ground_truth, result)
    delay = None if evaluation is None else evaluation.metrics.get("mean_time_to_detect_steps")
    if delay is None:
        payload = {"mean_time_to_detect_steps": None, "status": result.status}
        return OracleResult(
            oracle_id="detection_latency",
            verdict="inconclusive",
            severity="low",
            fingerprint=_fingerprint("detection_latency", target_id, payload),
            evidence=payload,
        )
    value = float(delay)
    control_evaluation = (
        _detection_evaluation(case.control_events, case.control_ground_truth, control_result)
        if control_result is not None and case.control_events
        else None
    )
    control_delay = (
        control_evaluation.metrics.get("mean_time_to_detect_steps")
        if control_evaluation is not None
        else None
    )
    delta = value - float(control_delay) if control_delay is not None else None
    payload = {
        "mean_time_to_detect_steps": value,
        "median_time_to_detect_steps": evaluation.metrics.get("median_time_to_detect_steps"),
        "control_mean_time_to_detect_steps": control_delay,
        "mean_time_to_detect_delta": delta,
    }
    interesting = delta > 0.0 if delta is not None else value > 0.0
    return OracleResult(
        oracle_id="detection_latency",
        verdict="interesting" if interesting else "pass",
        severity="low" if interesting else "info",
        fingerprint=_fingerprint("detection_latency", target_id, payload),
        evidence=payload,
    )


def containment_oracle(
    case: FuzzCase,
    closed_result: TargetResult,
    open_result: TargetResult | None,
    target_id: str,
    control_result: TargetResult | None = None,
) -> OracleResult:
    if open_result is None or any(
        result.status != "completed" for result in (open_result, closed_result)
    ):
        payload = {
            "reason": "paired open/closed result unavailable",
            "open_status": open_result.status if open_result is not None else None,
            "closed_status": closed_result.status,
        }
        return OracleResult(
            oracle_id="containment",
            verdict="inconclusive",
            severity="medium",
            fingerprint=_fingerprint("containment", target_id, payload),
            evidence=payload,
        )
    open_state = dict(open_result.state_observations)
    closed_state = dict(closed_result.state_observations)
    open_crossings = int(open_state.get("post_alert_prohibited_boundary_crossing_count", 0))
    closed_crossings = int(closed_state.get("post_alert_prohibited_boundary_crossing_count", 0))
    open_blast = int(open_state.get("post_alert_blast_radius", 0))
    closed_blast = int(closed_state.get("post_alert_blast_radius", 0))
    prevented = int(closed_state.get("prevented_event_count", 0))
    open_feedback = int(open_state.get("feedback_action_count", 0))
    maximum = closed_state.get("max_post_alert_blast_radius")
    blast_limit_exceeded = isinstance(maximum, int) and closed_blast > maximum
    violations: list[str] = []
    if open_feedback != 0:
        violations.append("open_loop_feedback_contamination")
    if prevented < 0:
        violations.append("negative_prevented_event_count")
    if closed_crossings > open_crossings:
        violations.append("prohibited_boundary_crossing_increased")
    if closed_blast > open_blast:
        violations.append("post_alert_blast_radius_increased")
    if blast_limit_exceeded:
        violations.append("post_alert_blast_radius_limit_exceeded")
    gaps: list[str] = []
    if open_crossings > 0 and closed_crossings >= open_crossings:
        gaps.append("prohibited_boundary_crossing_not_reduced")
    control_state = (
        dict(control_result.state_observations)
        if control_result is not None and control_result.status == "completed"
        else None
    )
    control_blast = (
        int(control_state.get("post_alert_blast_radius", 0))
        if control_state is not None
        else None
    )
    control_crossings = (
        int(control_state.get("post_alert_prohibited_boundary_crossing_count", 0))
        if control_state is not None
        else None
    )
    control_prevented = (
        int(control_state.get("prevented_event_count", 0))
        if control_state is not None
        else None
    )
    if control_blast is not None and closed_blast > control_blast:
        gaps.append("post_alert_blast_radius_regressed_vs_control")
    if control_crossings is not None and closed_crossings > control_crossings:
        gaps.append("prohibited_boundary_crossing_regressed_vs_control")
    if control_prevented is not None and prevented < control_prevented:
        gaps.append("prevented_event_count_regressed_vs_control")
    verdict = "fail" if violations else "interesting" if gaps else "pass"
    payload = {
        "case_seed": case.case_seed,
        "open_loop_feedback_action_count": open_feedback,
        "feedback_action_count": closed_state.get("feedback_action_count", 0),
        "effective_feedback_action_count": closed_state.get(
            "effective_feedback_action_count", 0
        ),
        "prevented_event_count": prevented,
        "open_post_alert_prohibited_boundary_crossing_count": open_crossings,
        "closed_post_alert_prohibited_boundary_crossing_count": closed_crossings,
        "open_post_alert_blast_radius": open_blast,
        "closed_post_alert_blast_radius": closed_blast,
        "control_post_alert_blast_radius": control_blast,
        "control_post_alert_prohibited_boundary_crossing_count": control_crossings,
        "control_prevented_event_count": control_prevented,
        "max_post_alert_blast_radius": maximum,
        "failed_defense_domains": closed_state.get("failed_defense_domains", []),
        "violations": violations,
        "containment_gaps": gaps,
        "security_invariant_survived": not violations and closed_crossings == 0,
    }
    fingerprint_payload = {"violations": violations, "containment_gaps": gaps}
    return OracleResult(
        oracle_id="containment",
        verdict=verdict,
        severity="high" if violations else "medium" if gaps else "info",
        fingerprint=_fingerprint("containment", target_id, fingerprint_payload),
        evidence=payload,
    )


def open_closed_metamorphic_oracle(
    case: FuzzCase,
    closed_result: TargetResult,
    open_result: TargetResult | None,
    target_id: str,
) -> OracleResult:
    if open_result is None:
        payload = {"reason": "open-loop pair unavailable"}
        return OracleResult(
            oracle_id="open_closed_metamorphic",
            verdict="inconclusive",
            severity="medium",
            fingerprint=_fingerprint("open_closed_metamorphic", target_id, payload),
            evidence=payload,
        )
    open_state = dict(open_result.state_observations)
    closed_state = dict(closed_result.state_observations)
    invariants = {
        "same_potential_sequence": open_state.get("potential_sequence_hash")
        == closed_state.get("potential_sequence_hash"),
        "same_potential_event_count": open_state.get("potential_event_count")
        == closed_state.get("potential_event_count"),
        "same_mutation_profile": open_state.get("mutation_profile_hash")
        == closed_state.get("mutation_profile_hash"),
        "open_loop_has_no_feedback": open_state.get("feedback_action_count") == 0,
        "closed_observations_not_greater_than_potential": int(
            closed_state.get("observed_event_count", 0)
        )
        <= int(closed_state.get("potential_event_count", 0)),
    }
    failed = sorted(name for name, passed in invariants.items() if not passed)
    payload = {
        "case_seed": case.case_seed,
        "mutation_count": len(case.mutations),
        "invariants": invariants,
        "failed_invariants": failed,
        "potential_sequence_hash": open_state.get("potential_sequence_hash"),
        "mutation_profile_hash": open_state.get("mutation_profile_hash"),
    }
    return OracleResult(
        oracle_id="open_closed_metamorphic",
        verdict="fail" if failed else "pass",
        severity="high" if failed else "info",
        fingerprint=_fingerprint(
            "open_closed_metamorphic", target_id, {"failed_invariants": failed}
        ),
        evidence=payload,
    )
def evaluate_oracles(
    oracle_ids: Sequence[str],
    case: FuzzCase,
    result: TargetResult,
    *,
    replay: TargetResult | None,
    control_result: TargetResult | None = None,
    open_loop_result: TargetResult | None = None,
    control_open_loop_result: TargetResult | None = None,
    target_id: str,
) -> tuple[OracleResult, ...]:
    results: list[OracleResult] = []
    detection_result = open_loop_result or result
    detection_control = control_open_loop_result or control_result
    for oracle_id in oracle_ids:
        if oracle_id == "no_unhandled_exception":
            results.append(no_unhandled_exception_oracle(result, target_id))
        elif oracle_id == "external_execution_health":
            results.append(external_execution_health_oracle(result, target_id))
        elif oracle_id == "deterministic_replay":
            results.append(deterministic_replay_oracle(result, replay, target_id))
        elif oracle_id == "ground_truth_detection":
            results.append(
                ground_truth_detection_oracle(
                    case, detection_result, target_id, detection_control
                )
            )
        elif oracle_id == "detection_latency":
            results.append(
                detection_latency_oracle(case, detection_result, target_id, detection_control)
            )
        elif oracle_id == "containment":
            results.append(
                containment_oracle(
                    case, result, open_loop_result, target_id, control_result
                )
            )
        elif oracle_id == "open_closed_metamorphic":
            results.append(
                open_closed_metamorphic_oracle(case, result, open_loop_result, target_id)
            )
        else:
            raise ValueError(f"unsupported oracle: {oracle_id}")
    return tuple(results)


def is_interesting(results: Sequence[OracleResult]) -> bool:
    return any(result.verdict in {"fail", "interesting"} for result in results)


__all__ = [
    "detection_latency_oracle",
    "containment_oracle",
    "deterministic_replay_oracle",
    "evaluate_oracles",
    "external_execution_health_oracle",
    "ground_truth_detection_oracle",
    "is_interesting",
    "no_unhandled_exception_oracle",
    "open_closed_metamorphic_oracle",
]
