from __future__ import annotations

import json
from pathlib import Path

import pytest

from scenario_loader import ScenarioValidationError, list_available_scenarios, load_scenario, load_scenario_catalog, run_scenario_from_file, validate_scenario


pytestmark = [pytest.mark.phase8, pytest.mark.scenario]


def _valid_scenario(output_dir: str = "output/phase63_mission_products") -> dict:
    return {
        "metadata": {
            "name": "mission_product_eval_basic",
            "description": "Mission-aware product evaluation using sample product profiles",
            "version": "0.1",
        },
        "evaluation": {
            "runner": "phase63_mission_aware_product",
            "output_dir": output_dir,
        },
        "missions": ["profit", "achievement", "persistence", "critical_hunter"],
        "products": [
            "profiles/products/sample_ids.json",
            "profiles/products/sample_ips.json",
            "profiles/products/sample_honeypot.json",
            "profiles/products/sample_deception.json",
            "profiles/products/sample_xdr.json",
        ],
        "topology": {
            "preset": "default_enterprise",
        },
    }


def test_valid_scenario_load():
    scenario = load_scenario("scenarios/mission_product_eval_basic.json")
    assert scenario["metadata"]["name"] == "mission_product_eval_basic"
    assert scenario["evaluation"]["runner"] == "phase63_mission_aware_product"


def test_hunting_scenario_loads_with_optional_schema_extension():
    scenario = load_scenario("scenarios/threat_hunting/credential_critical_path_smoke.json")

    assert scenario["evaluation"]["runner"] == "hunting_recipe_evaluation"
    assert scenario["hunting"]["baseline_runs"] == 0
    assert scenario["hunting"]["noise_profiles"] == ["none", "moderate", "adversarial"]


def test_hunting_scenario_rejects_truth_oracle_override():
    scenario = _valid_scenario()
    scenario["evaluation"]["runner"] = "hunting_recipe_evaluation"
    scenario["hunting"] = {
        "recipes": ["recipes/threat_hunting/critical_path_approach_v1.json"],
        "noise_profiles": ["none"],
        "simulation_overrides": {"oracle_visibility": True},
    }

    with pytest.raises(ScenarioValidationError, match="unknown SimulationConfig fields: oracle_visibility"):
        validate_scenario(scenario)


def test_hunting_scenario_rejects_recipe_outside_trusted_root():
    scenario = _valid_scenario()
    scenario["evaluation"]["runner"] = "hunting_recipe_evaluation"
    scenario["hunting"] = {
        "recipes": ["profiles/products/sample_ids.json"],
        "noise_profiles": ["none"],
    }

    with pytest.raises(ScenarioValidationError, match="must be below recipes/threat_hunting"):
        validate_scenario(scenario)


def test_invalid_mission_fails():
    scenario = _valid_scenario()
    scenario["missions"] = ["profit", "unsupported_mission"]

    with pytest.raises(ScenarioValidationError, match="Unsupported missions"):
        validate_scenario(scenario)


def test_missing_product_file_fails():
    scenario = _valid_scenario()
    scenario["products"] = ["profiles/products/missing_product.json"]

    with pytest.raises(ScenarioValidationError, match="Product profile not found"):
        validate_scenario(scenario)


def test_run_scenario_from_file_smoke(tmp_path, monkeypatch):
    scenario = _valid_scenario(output_dir=str(tmp_path / "scenario_output"))
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")

    received_kwargs = {}

    def fake_phase63(**kwargs):
        received_kwargs.update(kwargs)
        output_dir = kwargs["output_dir"]
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return [{"ok": True}]

    monkeypatch.setattr("run_scenarios.run_phase63_mission_aware_product_evaluation", fake_phase63)

    result = run_scenario_from_file(str(scenario_path))

    assert result["success"] is True
    assert result["scenario_name"] == "mission_product_eval_basic"
    assert result["runner"] == "phase63_mission_aware_product"
    assert result["rows"] == 1
    assert (tmp_path / "scenario_output").is_dir()
    assert result["success"] is True
    assert received_kwargs["missions"] == scenario["missions"]
    assert received_kwargs["product_profile_paths"] == scenario["products"]
    assert received_kwargs["topology_preset"] == "default_enterprise"


def test_run_hunting_scenario_from_file_smoke(tmp_path, monkeypatch):
    scenario = load_scenario("scenarios/threat_hunting/credential_critical_path_smoke.json")
    scenario["evaluation"]["output_dir"] = str(tmp_path / "hunting")
    scenario["products"] = ["profiles/products/sample_threat_hunting_platform.json"]
    scenario["hunting"]["recipes"] = [
        "recipes/threat_hunting/critical_path_approach_v1.json"
    ]
    scenario["hunting"]["noise_profiles"] = ["none"]
    scenario_path = tmp_path / "hunting_scenario.json"
    scenario_path.write_text(json.dumps(scenario), encoding="utf-8")

    history = {
        "observable_events": [
            "critical_path_entry",
            "critical_path_progress",
            "critical_path_near_target",
        ],
        "critical_path_events": [
            "critical_path_entry",
            "critical_path_progress",
            "critical_path_near_target",
        ],
        "critical_compromise": [False, False, True],
    }
    monkeypatch.setattr(
        "src.cybermatch.threat_hunting.scenario_runner._simulate_history",
        lambda config: history,
    )

    result = run_scenario_from_file(str(scenario_path))

    assert result["runner"] == "hunting_recipe_evaluation"
    assert result["rows"] == 1
    summary = json.loads((tmp_path / "hunting" / "hunting_scenario_summary.json").read_text(encoding="utf-8"))
    assert summary["manifest"]["completeness"] == 1.0
    assert summary["rows"][0]["status"] == "succeeded"
    assert (Path(summary["rows"][0]["artifact_dir"]) / "metrics.json").is_file()


def test_load_scenario_catalog():
    scenarios = load_scenario_catalog()
    names = {scenario["metadata"]["name"] for scenario in scenarios}

    assert len(list_available_scenarios()) == 5
    assert names == {
        "financial_enterprise",
        "hospital_enterprise",
        "cloud_native_startup",
        "ot_factory",
        "small_business",
    }


def test_phase82_scenario_catalog_evaluation_smoke(tmp_path, monkeypatch):
    from run_scenarios import run_phase82_scenario_catalog_evaluation

    monkeypatch.setattr(
        "run_scenarios._phase82_load_phase63_rows",
        lambda: [
            {
                "profile_id": "sample_ids",
                "product_category": "ids",
                "mission_name": "profit",
                "mission_effectiveness": 0.4,
            },
            {
                "profile_id": "sample_deception",
                "product_category": "deception",
                "mission_name": "critical_hunter",
                "mission_effectiveness": 0.6,
            },
        ],
    )

    rows = run_phase82_scenario_catalog_evaluation(output_dir=str(tmp_path / "phase82"))

    assert rows
    assert {row["scenario_name"] for row in rows} == {
        "financial_enterprise",
        "hospital_enterprise",
        "cloud_native_startup",
        "ot_factory",
        "small_business",
    }
    assert (tmp_path / "phase82" / "scenario_catalog_summary.csv").exists()
    assert (tmp_path / "phase82" / "scenario_catalog_summary.json").exists()
    assert (tmp_path / "phase82" / "scenario_comparison_heatmap.png").exists()
    assert (tmp_path / "phase82" / "scenario_mission_matrix.png").exists()
    assert (tmp_path / "phase82" / "scenario_product_matrix.png").exists()
    assert (tmp_path / "phase82" / "PHASE82_SCENARIO_CATALOG_REPORT.md").exists()
