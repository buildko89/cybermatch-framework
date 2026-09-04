from __future__ import annotations

import json
import random

import pytest

from src.cybermatch.fuzzing import (
    ExecutionLimits,
    FuzzConstraintError,
    FuzzSpecError,
    MutatorSpec,
    apply_mutation,
    load_campaign_spec,
    reidentify_events,
    score_analysis_guidance,
    validate_semantic_events,
)
from src.cybermatch.threat_hunting import HuntEvent, SCHEMA_VERSION


def _event(event_id: str, step: int, event_type: str = "critical_path_progress") -> HuntEvent:
    return HuntEvent(
        schema_version=SCHEMA_VERSION,
        event_id=event_id,
        step=step,
        campaign_id="seed-campaign",
        scenario_id="fuzz-test",
        seed=7,
        actor_id="actor-1",
        coalition_id=None,
        event_type=event_type,
        source_node=0,
        target_node=1,
        source_role="workstation",
        target_role="server",
        signal_class="derived_signal" if event_type.startswith("critical_") else "telemetry",
        attributes={"bytes": 256, "ordinal": step},
    )


def test_checked_in_campaign_is_strict_and_round_trips():
    spec = load_campaign_spec("fuzzing/campaigns/threat_hunting_mvp_v1.json")

    assert spec.campaign_id == "threat_hunting_mvp_v1"
    assert spec.limits.max_cases == 20
    assert spec.to_dict()["generation"]["campaign_seed"] == 20260904


def test_campaign_loader_rejects_duplicate_keys(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")

    with pytest.raises(FuzzSpecError, match="duplicate key"):
        load_campaign_spec(path)


def test_campaign_loader_rejects_unknown_mutator_parameter(tmp_path):
    payload = json.loads(
        open("fuzzing/campaigns/threat_hunting_mvp_v1.json", encoding="utf-8").read()
    )
    payload["mutators"][0]["shell_command"] = "not-allowed"
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(FuzzSpecError, match="unknown parameters"):
        load_campaign_spec(path)


def test_campaign_loader_rejects_unimplemented_robustness_lane(tmp_path):
    payload = json.loads(
        open("fuzzing/campaigns/threat_hunting_mvp_v1.json", encoding="utf-8").read()
    )
    payload["mode"] = "robustness"
    path = tmp_path / "robustness.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(FuzzSpecError, match="mode must be one of"):
        load_campaign_spec(path)


@pytest.mark.parametrize(
    ("mutator_id", "parameters"),
    [
        ("shift_step", {"range": [-2, 2]}),
        ("drop_event", {"max_count": 1}),
        ("duplicate_semantic_event", {"max_count": 1}),
        ("insert_benign_noise", {"max_count": 2}),
        ("boundary_numeric_attribute", {"values": [0, 255, 256]}),
    ],
)
def test_mutators_are_deterministic_and_keep_valid_events(mutator_id, parameters):
    events = (_event("event-a", 1), _event("event-b", 2, "lateral_move"))
    spec = MutatorSpec(mutator_id=mutator_id, weight=1.0, parameters=parameters)

    first, first_record = apply_mutation(events, spec, random.Random(19), 0)
    second, second_record = apply_mutation(events, spec, random.Random(19), 0)

    assert [event.to_dict() for event in first] == [event.to_dict() for event in second]
    assert first_record.to_dict() == second_record.to_dict()
    assert len({event.event_id for event in first}) == len(first)
    assert all(event.step >= 0 for event in first)


def test_execution_limits_reject_zero_values():
    with pytest.raises(ValueError, match="max_cases"):
        ExecutionLimits(max_cases=0)


def test_semantic_constraints_reject_truth_leakage():
    event = _event("event-a", 1)
    leaked = HuntEvent.from_dict(
        {**event.to_dict(), "attributes": {"true_mission": "critical_hunter"}}
    )

    with pytest.raises(FuzzConstraintError, match="ground-truth fields leaked"):
        validate_semantic_events((leaked,), max_events=10)


def test_reidentification_preserves_unchanged_ids_when_noise_is_added():
    base = (_event("event-a", 1), _event("event-b", 1, "lateral_move"))
    noise_spec = MutatorSpec(
        "insert_benign_noise",
        1.0,
        {"max_count": 1, "event_types": ["scan"]},
    )
    mutated, _ = apply_mutation(base, noise_spec, random.Random(5), 0)

    control_ids = {event.event_type: event.event_id for event in reidentify_events(base, "case-a")}
    mutant_ids = {
        event.event_type: event.event_id
        for event in reidentify_events(mutated, "case-a")
        if not event.attributes.get("fuzz_generated_benign")
    }

    assert mutant_ids == control_ids


def test_analysis_guidance_uses_documented_fixed_weights():
    result = score_analysis_guidance(
        {
            "inference_uncertainty": 1.0,
            "decision_path_rarity": 0.0,
            "detection_gap": 1.0,
            "detection_latency_norm": 0.0,
            "containment_gap": 0.0,
            "semantic_novelty": 1.0,
        }
    )

    assert result["priority_score"] == pytest.approx(0.5)
    assert result["fallback_equal_weight"] is False
