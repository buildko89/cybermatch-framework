from __future__ import annotations

import pytest

from topology_loader import TopologyValidationError, list_available_topologies, load_topology, validate_topology


pytestmark = [pytest.mark.phase84, pytest.mark.topology]


def _valid_topology() -> dict:
    return {
        "metadata": {
            "name": "enterprise",
            "description": "Generic enterprise network",
        },
        "characteristics": {
            "critical_assets": 5,
            "identity_centralization": "high",
            "lateral_movement_complexity": "medium",
            "deception_surface": "medium",
            "operational_sensitivity": "medium",
        },
    }


def test_topology_load():
    topology = load_topology("topologies/enterprise.json")

    assert topology["metadata"]["name"] == "enterprise"
    assert topology["characteristics"]["critical_assets"] == 5


def test_topology_validation_fails_for_invalid_level():
    topology = _valid_topology()
    topology["characteristics"]["identity_centralization"] = "extreme"

    with pytest.raises(TopologyValidationError, match="identity_centralization"):
        validate_topology(topology)


def test_topology_list():
    names = {path.stem for path in list_available_topologies()}

    assert names == {
        "small_business",
        "enterprise",
        "cloud_native",
        "ot_environment",
        "hospital_network",
    }


def test_phase84_topology_evaluation_smoke(tmp_path, monkeypatch):
    from run_scenarios import run_phase84_topology_evaluation

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

    rows = run_phase84_topology_evaluation(output_dir=str(tmp_path / "phase84"))

    assert rows
    assert {row["topology_name"] for row in rows} == {
        "small_business",
        "enterprise",
        "cloud_native",
        "ot_environment",
        "hospital_network",
    }
    assert (tmp_path / "phase84" / "topology_summary.csv").exists()
    assert (tmp_path / "phase84" / "topology_summary.json").exists()
    assert (tmp_path / "phase84" / "topology_comparison_heatmap.png").exists()
    assert (tmp_path / "phase84" / "topology_mission_matrix.png").exists()
    assert (tmp_path / "phase84" / "topology_product_matrix.png").exists()
    assert (tmp_path / "phase84" / "PHASE84_TOPOLOGY_LIBRARY_REPORT.md").exists()
