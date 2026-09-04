import json
from pathlib import Path

import pytest

from benchmark_loader import load_benchmark
from scenario_loader import ScenarioValidationError, load_scenario, run_scenario_from_file, validate_scenario


pytestmark = pytest.mark.agentic_security


def test_agentic_scenarios_and_benchmark_validate():
    containment = load_scenario("scenarios/agentic/hugging_face_style_containment.json")
    integrity = load_scenario("scenarios/agentic/fabricated_cve_integrity.json")
    benchmark = load_benchmark("benchmarks/cybermatch_agentic_security_v1.json")

    assert containment["evaluation"]["runner"] == "agentic_security_evaluation"
    assert integrity["threat_intelligence"]["advisories"]
    assert benchmark["metadata"]["type"] == "agentic_security"


def test_agentic_scenario_rejects_unknown_event_type():
    scenario = load_scenario("scenarios/agentic/hugging_face_style_containment.json")
    scenario["agentic"]["events"][0]["event_type"] = "magic_escape"

    with pytest.raises(ScenarioValidationError, match="event_type is unsupported"):
        validate_scenario(scenario)


def test_agentic_containment_scenario_runs_and_prevents_later_chain(tmp_path):
    scenario = load_scenario("scenarios/agentic/hugging_face_style_containment.json")
    scenario["evaluation"]["output_dir"] = str(tmp_path / "agentic")
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(scenario), encoding="utf-8")

    result = run_scenario_from_file(str(path))
    report = json.loads((tmp_path / "agentic" / "agentic_security_report.json").read_text(encoding="utf-8"))
    metrics = report["agentic"]["metrics"]
    open_metrics = report["agentic"]["open_loop"]["metrics"]
    comparison = report["agentic"]["comparison"]

    assert result["success"] is True
    assert metrics["prevented_event_count"] >= 1
    assert metrics["alert_to_halt_steps"] == 1
    assert metrics["security_invariant_survival_rate"] >= 0.5
    assert open_metrics["observed_event_count"] == 11
    assert metrics["observed_event_count"] < open_metrics["observed_event_count"]
    assert comparison["risk_score_reduction"] > 0.0
    assert comparison["unauthorized_path_reduction"] > 0
    assert report["agentic"]["closed_loop"]["trust_boundary_topology"][
        "unknown_node_event_ids"
    ] == []
    assert report["agentic"]["closed_loop"]["defense_failure_model"]["objectives"][
        "network_egress"
    ]["independent_layer_count"] == 2
    assert report["agentic"]["learning"]["comparison"]["final_propensity_reduction"] > 0.0
    assert (tmp_path / "agentic" / "AGENTIC_SECURITY_REPORT.md").is_file()


def test_integrity_scenario_runs_without_exposing_labels_to_gate(tmp_path):
    scenario = load_scenario("scenarios/agentic/fabricated_cve_integrity.json")
    scenario["evaluation"]["output_dir"] = str(tmp_path / "integrity")
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(scenario), encoding="utf-8")

    run_scenario_from_file(str(path))
    report = json.loads((tmp_path / "integrity" / "agentic_security_report.json").read_text(encoding="utf-8"))
    metrics = report["threat_intelligence"]["metrics"]

    assert metrics["fabricated_advisory_acceptance_rate"] == 0.0
    assert metrics["valid_advisory_acceptance_rate"] == 1.0
    assert all("ground_truth" not in item for item in report["threat_intelligence"]["advisories"])
