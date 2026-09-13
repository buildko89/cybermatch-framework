from __future__ import annotations

import json

import pytest

from src.cybermatch.fuzzing import (
    ExecutionLimits,
    FUZZING_SCHEMA_VERSION,
    FuzzArtifactError,
    FuzzCampaignSpec,
    FuzzCase,
    FuzzTargetSpec,
    MutationRecord,
    MutatorSpec,
    OracleResult,
    load_fuzz_campaign,
    minimize_events,
    replay_case,
    run_campaign,
)
from src.cybermatch.contracts import EvidenceBundle
from src.cybermatch.fuzzing.mutators import events_hash
from src.cybermatch.threat_hunting import GroundTruthLabel, HuntEvent, SCHEMA_VERSION


def _case() -> FuzzCase:
    case_id = "fuzz-case-artifact"
    events = tuple(
        HuntEvent(
            schema_version=SCHEMA_VERSION,
            event_id=f"event-{index}",
            step=index,
            campaign_id=case_id,
            scenario_id="artifact-test",
            seed=5,
            actor_id="actor-1",
            coalition_id=None,
            event_type=event_type,
            source_node=0,
            target_node=1,
            source_role="workstation",
            target_role="critical_server",
            signal_class="derived_signal",
            attributes={"ordinal": index},
        )
        for index, event_type in enumerate(
            ("critical_path_entry", "critical_path_progress"), start=1
        )
    )
    digest = events_hash(events)
    return FuzzCase(
        schema_version=FUZZING_SCHEMA_VERSION,
        campaign_id="artifact-campaign",
        case_id=case_id,
        campaign_seed=11,
        case_seed=11,
        base_input_id="seed-a",
        base_input_hash="b" * 64,
        analysis_guidance={"priority_score": 0.0, "semantic_signature": "test"},
        mutations=(MutationRecord("shift_step", "1.0", 0, (), {"delta": 0}, digest, digest),),
        events=events,
        ground_truth=(
            GroundTruthLabel(
                label_id="truth-artifact",
                campaign_id=case_id,
                label_type="attacker_success",
                start_step=1,
                end_step=2,
                actor_id="actor-1",
                target_node=1,
                severity="high",
                attributes={"event_id": "event-1"},
            ),
        ),
    )


def _spec() -> FuzzCampaignSpec:
    return FuzzCampaignSpec(
        schema_version=FUZZING_SCHEMA_VERSION,
        campaign_id="artifact-campaign",
        mode="semantic",
        base_inputs=("unused.json",),
        target=FuzzTargetSpec(
            "threat_hunting_engine",
            ("recipes/threat_hunting/critical_path_approach_v1.json",),
        ),
        campaign_seed=11,
        limits=ExecutionLimits(max_cases=1),
        mutators=(MutatorSpec("shift_step", 1.0, {"range": [0, 0]}),),
        oracles=("no_unhandled_exception", "deterministic_replay", "ground_truth_detection"),
        output_dir="output/fuzzing/artifact-campaign",
    )


def test_campaign_writes_hash_verified_artifacts_and_replays(tmp_path, monkeypatch):
    monkeypatch.setattr("src.cybermatch.fuzzing.runner.generate_cases", lambda *args, **kwargs: (_case(),))
    monkeypatch.setattr(
        "src.cybermatch.fuzzing.runner.evaluate_oracles",
        lambda *args, **kwargs: (
            OracleResult("forced_failure", "fail", "high", "forced-fingerprint", {}),
        ),
    )
    output = tmp_path / "campaign"

    result = run_campaign(_spec(), output_dir=output)
    loaded = load_fuzz_campaign(output)
    replay = replay_case(output / "corpus" / _case().case_id)

    assert result["attempted_cases"] == 1
    assert loaded["artifact_hash"] == result["artifact_hash"]
    assert replay["saved_result_match"] is True
    evidence = EvidenceBundle.from_dict(
        json.loads((output / "evidence_bundle.json").read_text(encoding="utf-8"))
    )
    assert evidence.run.metrics.values["minimized_case_count"] == 1
    commands = json.loads((output / "replay_commands.json").read_text(encoding="utf-8"))
    assert commands["commands"][0]["command"].startswith("cybermatch-fuzz --replay ")


def test_campaign_loader_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.setattr("src.cybermatch.fuzzing.runner.generate_cases", lambda *args, **kwargs: (_case(),))
    output = tmp_path / "campaign"
    run_campaign(_spec(), output_dir=output)
    summary = output / "campaign_summary.json"
    payload = json.loads(summary.read_text(encoding="utf-8"))
    payload["attempted_cases"] = 999
    summary.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(FuzzArtifactError, match="hash verification failed"):
        load_fuzz_campaign(output)


def test_identical_campaigns_have_identical_artifact_hashes(tmp_path, monkeypatch):
    monkeypatch.setattr("src.cybermatch.fuzzing.runner.generate_cases", lambda *args, **kwargs: (_case(),))

    first = run_campaign(_spec(), output_dir=tmp_path / "first")
    second = run_campaign(_spec(), output_dir=tmp_path / "second")

    assert first["artifact_hash"] == second["artifact_hash"]


def test_event_minimizer_keeps_only_events_required_by_failure():
    case = _case()

    minimized = minimize_events(
        case,
        lambda candidate: any(event.event_id == "event-2" for event in candidate.events),
    )

    assert [event.event_id for event in minimized] == ["event-2"]
