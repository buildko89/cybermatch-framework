import math

import pytest

from cybermatch_core.threat_hunting import (
    AnalystCostProfile,
    Finding,
    GroundTruthLabel,
    HuntEvent,
    ThreatHuntingEvaluator,
)


def _fixtures():
    events = [
        HuntEvent(
            schema_version="1.0",
            event_id=f"event-{index}",
            step=step,
            campaign_id="campaign",
            scenario_id="scenario",
            seed=3,
            actor_id=actor,
            coalition_id=None,
            event_type="signal",
            source_node=None,
            target_node=target,
            source_role=None,
            target_role=None,
            signal_class="telemetry",
        )
        for index, (step, actor, target) in enumerate(
            ((1, "actor-a", 7), (3, "actor-a", 7), (8, "actor-b", 9)),
            start=1,
        )
    ]
    findings = [
        Finding(
            schema_version="1.0",
            finding_id="finding-1",
            recipe_id="recipe",
            recipe_version="1.0",
            severity="high",
            score=0.9,
            campaign_id="campaign",
            actor_id="actor-a",
            start_step=3,
            end_step=3,
            title="matched",
            reason="fixture",
            evidence_event_ids=("event-1", "event-2"),
        ),
        Finding(
            schema_version="1.0",
            finding_id="finding-2",
            recipe_id="recipe",
            recipe_version="1.0",
            severity="low",
            score=0.4,
            campaign_id="campaign",
            actor_id="actor-b",
            start_step=8,
            end_step=8,
            title="false positive",
            reason="fixture",
            evidence_event_ids=("event-3",),
        ),
    ]
    truth = [
        GroundTruthLabel(
            label_id="truth-success",
            campaign_id="campaign",
            label_type="attacker_success",
            start_step=3,
            end_step=3,
            actor_id="actor-a",
            target_node=7,
            severity="high",
        ),
        GroundTruthLabel(
            label_id="truth-compromise",
            campaign_id="campaign",
            label_type="critical_compromise",
            start_step=6,
            end_step=6,
            actor_id="actor-a",
            target_node=7,
            severity="critical",
        ),
    ]
    return events, findings, truth


def _profile():
    return AnalystCostProfile(
        profile_id="soc-standard",
        w_triage=2,
        w_evidence=0.5,
        w_context=3,
        w_escalation=5,
        w_false_positive=7,
        w_false_evidence=1.5,
    )


def test_evaluator_calculates_quality_coverage_and_raw_burden_metrics():
    events, findings, truth = _fixtures()

    result = ThreatHuntingEvaluator().evaluate(
        findings,
        truth,
        events=events,
        total_steps=10,
        duplicate_suppressed_count=4,
    )

    assert result.metrics["precision"] == 0.5
    assert result.metrics["recall"] == 0.5
    assert result.metrics["f1"] == 0.5
    assert result.metrics["false_positives_per_100_steps"] == 10.0
    assert result.metrics["pre_compromise_detection_rate"] == 1.0
    assert result.metrics["campaign_coverage"] == 1.0
    assert result.metrics["target_coverage"] == 1.0
    assert result.metrics["finding_count"] == 2
    assert result.metrics["unique_evidence_event_count"] == 3
    assert result.metrics["total_evidence_references"] == 3
    assert result.metrics["distinct_actor_count"] == 2
    assert result.metrics["distinct_target_count"] == 2
    assert result.metrics["high_severity_finding_count"] == 1
    assert result.metrics["duplicate_suppressed_count"] == 4
    assert result.metrics["findings_per_100_steps"] == 20.0
    assert result.metrics["evidence_events_per_finding"] == 1.5
    assert result.metrics["evidence_completeness"] == 1.0
    assert result.metrics["operational_burden"] is None
    assert result.metrics["wasted_burden"] is None
    assert result.metrics["hunting_value_score"] is None
    assert "hunting_roi" not in result.metrics


def test_cost_profile_enables_weighted_operational_and_wasted_burden():
    events, findings, truth = _fixtures()
    profile = _profile()

    result = ThreatHuntingEvaluator().evaluate(
        findings,
        truth,
        events=events,
        total_steps=10,
        cost_profile=profile,
        protection_delta=0.3,
    )

    # 2*2 findings + .5*3 evidence + 3*1 switch + 5*1 escalation
    assert result.metrics["operational_burden"] == 13.5
    # 7*1 false positive + 1.5*1 false-positive evidence reference
    assert result.metrics["wasted_burden"] == 8.5
    assert result.metrics["operational_burden_per_100_steps"] == 135.0
    assert math.isclose(result.metrics["hunting_value_score"], 0.3 / 136.0)
    assert result.cost_profile.profile_hash == AnalystCostProfile.from_dict(
        profile.to_dict()
    ).profile_hash


def test_evaluation_round_trips_and_verifies_policy_and_profile_hashes():
    events, findings, truth = _fixtures()
    result = ThreatHuntingEvaluator().evaluate(
        findings, truth, events=events, total_steps=10, cost_profile=_profile()
    )

    restored = type(result).from_dict(result.to_dict())

    assert restored.to_dict() == result.to_dict()


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf"), True])
def test_cost_profile_rejects_invalid_weights(value):
    with pytest.raises(ValueError, match="finite non-negative"):
        AnalystCostProfile(
            profile_id="invalid",
            w_triage=value,
            w_evidence=1,
            w_context=1,
            w_escalation=1,
            w_false_positive=1,
            w_false_evidence=1,
        )
