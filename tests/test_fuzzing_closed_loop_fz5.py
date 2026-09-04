from __future__ import annotations

import inspect
import json
import random
from dataclasses import replace

import pytest

from src.cybermatch.fuzzing import (
    ExecutionLimits,
    FUZZING_SCHEMA_VERSION,
    FuzzCase,
    FuzzSpecError,
    MutationRecord,
    MutatorSpec,
    ThreatHuntingClosedLoopTarget,
    apply_mutation,
    evaluate_oracles,
    load_campaign_spec,
    load_fuzz_campaign,
    replay_case,
    run_campaign,
)
from src.cybermatch.fuzzing.mutators import events_hash
from src.cybermatch.threat_hunting import HuntEvent, SCHEMA_VERSION


def _event(event_id: str, step: int, event_type: str, *, prohibited: bool = False) -> HuntEvent:
    return HuntEvent(
        schema_version=SCHEMA_VERSION,
        event_id=event_id,
        step=step,
        campaign_id="fz5-case",
        scenario_id="fz5-test",
        seed=17,
        actor_id="actor-1",
        coalition_id=None,
        event_type=event_type,
        source_node=1,
        target_node=4,
        source_role="server",
        target_role="critical_server",
        signal_class="derived_signal",
        attributes={
            "fuzz_topology_boundary_id": "server-to-critical",
            "fuzz_prohibited_boundary_crossing": prohibited,
        },
    )


def _events() -> tuple[HuntEvent, ...]:
    return (
        _event("entry", 0, "critical_path_entry"),
        _event("near-target", 1, "critical_path_near_target"),
        _event("crossing", 2, "objective_action", prohibited=True),
    )


def _record(mutator_id: str, parameters: dict[str, object]) -> MutationRecord:
    digest = events_hash(_events())
    return MutationRecord(mutator_id, "1.0", 0, (), parameters, digest, digest)


def _case(mutations: tuple[MutationRecord, ...]) -> FuzzCase:
    return FuzzCase(
        schema_version=FUZZING_SCHEMA_VERSION,
        campaign_id="fz5-campaign",
        case_id="fz5-case",
        campaign_seed=17,
        case_seed=18,
        base_input_id="seed-fz5",
        base_input_hash="a" * 64,
        analysis_guidance={"priority_score": 0.0},
        mutations=mutations,
        events=_events(),
        ground_truth=(),
    )


def _target() -> ThreatHuntingClosedLoopTarget:
    return ThreatHuntingClosedLoopTarget(
        ("recipes/threat_hunting/critical_path_approach_v1.json",),
        repository_root=".",
    )


def test_fz5_campaign_is_strict_and_enables_paired_target():
    spec = load_campaign_spec("fuzzing/campaigns/threat_hunting_fz5_closed_loop_v1.json")

    assert spec.target.adapter == "threat_hunting_closed_loop"
    assert {item.mutator_id for item in spec.mutators} == {
        "feedback_timing",
        "topology_path",
        "defense_failure_domain",
    }
    assert {"containment", "open_closed_metamorphic"}.issubset(spec.oracles)


def test_fz5_nested_topology_schema_rejects_unknown_field(tmp_path):
    payload = json.loads(
        open(
            "fuzzing/campaigns/threat_hunting_fz5_closed_loop_v1.json", encoding="utf-8"
        ).read()
    )
    payload["mutators"][1]["paths"][0]["command"] = "unsafe"
    path = tmp_path / "invalid-fz5.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(FuzzSpecError, match="unknown fields"):
        load_campaign_spec(path)


@pytest.mark.parametrize(
    ("mutator_id", "parameters"),
    [
        ("feedback_timing", {"delays": [0, 1, 3]}),
        (
            "topology_path",
            {
                "paths": [
                    {
                        "source_node": 2,
                        "target_node": 4,
                        "boundary_id": "untrusted-to-critical",
                        "prohibited": True,
                    }
                ],
                "max_post_alert_blast_radius": 1,
            },
        ),
        (
            "defense_failure_domain",
            {"domains": ["edge_blocking", "redirect"], "max_count": 2},
        ),
    ],
)
def test_fz5_mutators_are_deterministic(mutator_id, parameters):
    spec = MutatorSpec(mutator_id, 1.0, parameters)

    first = apply_mutation(_events(), spec, random.Random(29), 0)
    second = apply_mutation(_events(), spec, random.Random(29), 0)

    assert [event.to_dict() for event in first[0]] == [event.to_dict() for event in second[0]]
    assert first[1].to_dict() == second[1].to_dict()


def test_closed_loop_uses_identical_potential_sequence_and_prevents_crossing():
    pair = _target().execute_pair(_events(), ExecutionLimits(), ())

    open_state = pair.open_loop.state_observations
    closed_state = pair.closed_loop.state_observations
    assert open_state["potential_sequence_hash"] == closed_state["potential_sequence_hash"]
    assert open_state["feedback_action_count"] == 0
    assert closed_state["feedback_action_count"] >= 1
    assert closed_state["prevented_event_count"] == 1
    assert open_state["post_alert_prohibited_boundary_crossing_count"] == 1
    assert closed_state["post_alert_prohibited_boundary_crossing_count"] == 0

    case = _case((_record("feedback_timing", {"delay_steps": 0}),))
    results = evaluate_oracles(
        ("containment", "open_closed_metamorphic"),
        case,
        pair.closed_loop,
        replay=None,
        open_loop_result=pair.open_loop,
        target_id=_target().manifest.target_id,
    )
    assert {result.oracle_id: result.verdict for result in results} == {
        "containment": "pass",
        "open_closed_metamorphic": "pass",
    }


def test_feedback_delay_and_failure_domain_expose_containment_gap():
    delay = _record("feedback_timing", {"delay_steps": 3})
    failed = _record("defense_failure_domain", {"failed_domains": ["redirect"]})
    pair = _target().execute_pair(_events(), ExecutionLimits(), (delay, failed))
    case = _case((delay, failed))

    oracle = evaluate_oracles(
        ("containment",),
        case,
        pair.closed_loop,
        replay=None,
        open_loop_result=pair.open_loop,
        target_id=_target().manifest.target_id,
    )[0]

    assert pair.closed_loop.state_observations["prevented_event_count"] == 0
    assert oracle.verdict == "interesting"
    assert "prohibited_boundary_crossing_not_reduced" in oracle.evidence["containment_gaps"]


def test_containment_oracle_enforces_configured_blast_radius_limit():
    delay = _record("feedback_timing", {"delay_steps": 3})
    pair = _target().execute_pair(_events(), ExecutionLimits(), (delay,))
    state = {**dict(pair.closed_loop.state_observations), "max_post_alert_blast_radius": 0}
    closed = replace(pair.closed_loop, state_observations=state)
    case = _case((delay,))

    oracle = evaluate_oracles(
        ("containment",),
        case,
        closed,
        replay=None,
        open_loop_result=pair.open_loop,
        target_id=_target().manifest.target_id,
    )[0]

    assert oracle.verdict == "fail"
    assert "post_alert_blast_radius_limit_exceeded" in oracle.evidence["violations"]


def test_closed_loop_target_pair_interface_has_no_truth_parameter():
    parameters = tuple(inspect.signature(ThreatHuntingClosedLoopTarget.execute_pair).parameters)

    assert parameters == ("self", "events", "limits", "mutations")


def test_fz5_campaign_writes_and_replays_both_loop_results(tmp_path, monkeypatch):
    case = _case((_record("feedback_timing", {"delay_steps": 0}),))
    spec = load_campaign_spec("fuzzing/campaigns/threat_hunting_fz5_closed_loop_v1.json")
    spec = replace(spec, limits=replace(spec.limits, max_cases=1))
    monkeypatch.setattr(
        "src.cybermatch.fuzzing.runner.generate_cases", lambda *args, **kwargs: (case,)
    )
    output = tmp_path / "fz5-artifacts"

    result = run_campaign(spec, output_dir=output)
    corpus = output / "corpus" / case.case_id
    replay = replay_case(corpus)

    assert (corpus / "actual" / "open_loop_target_result.json").is_file()
    assert load_fuzz_campaign(output)["artifact_hash"] == result["artifact_hash"]
    assert replay["saved_result_match"] is True
