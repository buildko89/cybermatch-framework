import json

import pytest

from scenario_loader import load_scenario
from src.cybermatch.agentic import (
    COMMON_METRICS,
    DEFENSE_MODES,
    EvaluationIndependenceError,
    audit_detector_inputs,
    distribution,
    evaluate_defense_mode,
    paired_effect,
    run_agentic_resilience_protocol,
)
from src.cybermatch.contracts import EvidenceBundle, load_evidence_bundle
from src.cybermatch.threat_hunting import HuntEvent


pytestmark = pytest.mark.agentic_security


def test_statistical_contract_reports_interval_and_paired_effect() -> None:
    summary = distribution([1.0, 2.0, 3.0])
    effect = paired_effect([3.0, 3.0, 3.0], [1.0, 2.0, 3.0])
    assert summary["mean"] == 2.0
    assert summary["ci95_low"] < summary["mean"] < summary["ci95_high"]
    assert effect["paired_mean_improvement"] == 1.0
    assert effect["rank_biserial_effect_size"] == pytest.approx(2 / 3)


def test_independence_audit_rejects_oracle_and_label_leaks() -> None:
    event = HuntEvent(
        schema_version="1.0",
        event_id="opaque-id",
        step=0,
        campaign_id="campaign",
        scenario_id="scenario",
        seed=0,
        actor_id="agent",
        coalition_id=None,
        event_type="task_blocked",
        source_node=0,
        target_node=1,
        source_role=None,
        target_role=None,
        signal_class="telemetry",
        attributes={"ground_truth": "attack"},
    )
    with pytest.raises(EvaluationIndependenceError, match="forbidden evaluator field"):
        audit_detector_inputs([event])


def test_all_modes_share_metrics_and_are_seed_reproducible() -> None:
    scenario = load_scenario("scenarios/agentic/hugging_face_style_containment.json")
    results = {
        mode: evaluate_defense_mode(scenario, mode=mode, seed=2) for mode in DEFENSE_MODES
    }
    replay = evaluate_defense_mode(scenario, mode="closed_loop", seed=2)
    assert replay == results["closed_loop"]
    assert set(COMMON_METRICS).issubset(results["closed_loop"]["metrics"])
    assert results["static_defense"]["metrics"]["risk_score"] <= results["no_defense"]["metrics"]["risk_score"]
    assert all(result["independence_audit"]["status"] == "passed" for result in results.values())


def test_flagship_protocol_writes_auditable_evidence(tmp_path) -> None:
    output = tmp_path / "flagship"
    result = run_agentic_resilience_protocol(output_dir=str(output))
    summary = json.loads((output / "agentic_resilience_summary.json").read_text(encoding="utf-8"))
    evidence = EvidenceBundle.from_dict(
        json.loads((output / "evidence_bundle.json").read_text(encoding="utf-8"))
    )
    assert result["run_count"] == 155
    assert summary["paired_mode_run_count"] == 150
    assert summary["integrity_run_count"] == 5
    assert len(summary["seed_set"]) == 5
    assert summary["failure_regions"]
    assert summary["closed_loop_decomposition"]["attacker_behavior_risk_reduction_mean"]["mean"] >= 0
    assert evidence.bundle_hash == result["evidence_bundle_hash"]
    assert evidence.run.manifest.code_revision
    assert evidence.run.manifest.dependency_lock_sha256
    assert len(evidence.run.manifest.input_hashes) == 8
    assert load_evidence_bundle(output).bundle_hash == evidence.bundle_hash

    replay_result = run_agentic_resilience_protocol(output_dir=str(tmp_path / "replay"))
    assert replay_result["evidence_bundle_hash"] == result["evidence_bundle_hash"]

    summary_path = output / "agentic_resilience_summary.json"
    summary_path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="artifact (size|hash) mismatch"):
        load_evidence_bundle(output)
