from __future__ import annotations

import inspect

from src.cybermatch.fuzzing import (
    ExecutionLimits,
    FUZZING_SCHEMA_VERSION,
    FuzzCampaignSpec,
    FuzzCase,
    FuzzTargetSpec,
    MutationRecord,
    MutatorSpec,
    SeedInput,
    ThreatHuntingEngineTarget,
    evaluate_oracles,
    generate_cases,
)
from src.cybermatch.fuzzing.mutators import events_hash
from src.cybermatch.threat_hunting import GroundTruthLabel, HuntEvent, SCHEMA_VERSION


def _event(event_id: str, step: int, event_type: str) -> HuntEvent:
    return HuntEvent(
        schema_version=SCHEMA_VERSION,
        event_id=event_id,
        step=step,
        campaign_id="seed",
        scenario_id="scenario",
        seed=3,
        actor_id="actor-1",
        coalition_id=None,
        event_type=event_type,
        source_node=0,
        target_node=1,
        source_role="workstation",
        target_role="critical_server",
        signal_class="derived_signal" if event_type.startswith("critical_") else "telemetry",
        attributes={"bytes": 256, "ordinal": step},
    )


def _spec(max_cases: int = 2) -> FuzzCampaignSpec:
    return FuzzCampaignSpec(
        schema_version=FUZZING_SCHEMA_VERSION,
        campaign_id="unit-fuzz",
        mode="semantic",
        base_inputs=("unused.json",),
        target=FuzzTargetSpec(
            adapter="threat_hunting_engine",
            recipes=("recipes/threat_hunting/critical_path_approach_v1.json",),
        ),
        campaign_seed=91,
        limits=ExecutionLimits(max_cases=max_cases, max_mutations_per_case=2),
        mutators=(
            MutatorSpec("shift_step", 1.0, {"range": [-1, 1]}),
            MutatorSpec("insert_benign_noise", 1.0, {"max_count": 1}),
        ),
        oracles=("no_unhandled_exception", "deterministic_replay", "ground_truth_detection"),
        output_dir="output/fuzzing/unit-fuzz",
    )


def _seed() -> SeedInput:
    events = (
        _event("event-a", 1, "critical_path_entry"),
        _event("event-b", 2, "critical_path_progress"),
    )
    truth = (
        GroundTruthLabel(
            label_id="truth-a",
            campaign_id="seed",
            label_type="attacker_success",
            start_step=1,
            end_step=2,
            actor_id="actor-1",
            target_node=1,
            severity="high",
            attributes={"event_id": "event-a"},
        ),
    )
    return SeedInput(
        seed_id="seed-input-a",
        source_path="scenario.json",
        source_hash="a" * 64,
        scenario_id="scenario",
        seed=3,
        events=events,
        ground_truth=truth,
    )


def test_case_generation_is_reproducible_and_retags_truth(monkeypatch):
    monkeypatch.setattr("src.cybermatch.fuzzing.corpus.load_seed_input", lambda *args, **kwargs: _seed())

    first = generate_cases(_spec())
    second = generate_cases(_spec())

    assert [case.manifest_dict() for case in first] == [case.manifest_dict() for case in second]
    assert [[event.to_dict() for event in case.events] for case in first] == [
        [event.to_dict() for event in case.events] for case in second
    ]
    assert all(event.campaign_id == case.case_id for case in first for event in case.events)
    assert all(label.campaign_id == case.case_id for case in first for label in case.ground_truth)


def test_target_interface_cannot_receive_ground_truth():
    parameters = tuple(inspect.signature(ThreatHuntingEngineTarget.execute).parameters)

    assert parameters == ("self", "events", "limits")


def test_target_and_oracles_detect_reproducibly():
    case_id = "fuzz-case-unit"
    source_events = _seed().events
    events = tuple(
        HuntEvent.from_dict({**event.to_dict(), "campaign_id": case_id}) for event in source_events
    )
    truth = tuple(
        GroundTruthLabel.from_dict(
            {
                **label.to_dict(),
                "campaign_id": case_id,
                "attributes": {"event_id": events[0].event_id},
            }
        )
        for label in _seed().ground_truth
    )
    digest = events_hash(events)
    case = FuzzCase(
        schema_version=FUZZING_SCHEMA_VERSION,
        campaign_id="unit-fuzz",
        case_id=case_id,
        campaign_seed=1,
        case_seed=2,
        base_input_id="seed-input-a",
        base_input_hash="a" * 64,
        analysis_guidance={"priority_score": 0.0},
        mutations=(
            MutationRecord("shift_step", "1.0", 0, (), {"delta": 0}, digest, digest),
        ),
        events=events,
        ground_truth=truth,
    )
    target = ThreatHuntingEngineTarget(
        ("recipes/threat_hunting/critical_path_approach_v1.json",),
        repository_root=".",
    )

    result = target.execute(case.events, ExecutionLimits())
    replay = target.execute(case.events, ExecutionLimits())
    oracles = evaluate_oracles(
        _spec().oracles,
        case,
        result,
        replay=replay,
        target_id=target.manifest.target_id,
    )

    assert result.status == "completed"
    assert len(result.findings) == 1
    assert {oracle.oracle_id: oracle.verdict for oracle in oracles} == {
        "no_unhandled_exception": "pass",
        "deterministic_replay": "pass",
        "ground_truth_detection": "pass",
    }


def test_target_reports_case_event_limit():
    target = ThreatHuntingEngineTarget(
        ("recipes/threat_hunting/critical_path_approach_v1.json",), repository_root="."
    )
    result = target.execute(_seed().events, ExecutionLimits(max_events_per_case=1))

    assert result.status == "limit_exceeded"
    assert result.error_type == "max_events_per_case"


def test_detection_oracle_reports_only_mutant_regression_against_control():
    case_id = "fuzz-case-differential"
    control_events = tuple(
        HuntEvent.from_dict({**event.to_dict(), "campaign_id": case_id})
        for event in _seed().events
    )
    truth = (
        GroundTruthLabel(
            label_id="truth-differential",
            campaign_id=case_id,
            label_type="attacker_success",
            start_step=1,
            end_step=2,
            actor_id="actor-1",
            target_node=1,
            severity="high",
            attributes={"event_id": control_events[0].event_id},
        ),
    )
    digest = events_hash(control_events)
    case = FuzzCase(
        schema_version=FUZZING_SCHEMA_VERSION,
        campaign_id="unit-fuzz",
        case_id=case_id,
        campaign_seed=1,
        case_seed=3,
        base_input_id="seed-input-a",
        base_input_hash="a" * 64,
        analysis_guidance={"priority_score": 0.0},
        mutations=(MutationRecord("drop_event", "1.0", 0, ("event-b",), {}, digest, digest),),
        events=(control_events[0],),
        ground_truth=truth,
        control_events=control_events,
        control_ground_truth=truth,
    )
    target = ThreatHuntingEngineTarget(
        ("recipes/threat_hunting/critical_path_approach_v1.json",), repository_root="."
    )
    result = target.execute(case.events, ExecutionLimits())
    control = target.execute(case.control_events, ExecutionLimits())
    oracle = evaluate_oracles(
        ("ground_truth_detection",),
        case,
        result,
        replay=None,
        control_result=control,
        target_id=target.manifest.target_id,
    )[0]

    assert oracle.verdict == "interesting"
    assert oracle.evidence["false_negative_delta"] == 1
