import json

import numpy as np
import pytest

from cybermatch import CyberDefenseSimulator, SimulationConfig
from intent_inference import MissionInferenceEngine
from run_scenarios import run_phase90_intent_inference_evaluation


pytestmark = [pytest.mark.phase90, pytest.mark.intent]


def test_mission_inference_engine_identifies_critical_hunter():
    engine = MissionInferenceEngine()
    result = engine.evaluate(
        {
            "critical_path_events": ["critical_path_entry|critical_path_progress|critical_asset_reach"],
            "critical_probe_count": 3,
            "critical_node_visit_count": 4,
            "planned_path_is_critical_rate": 1.0,
            "mean_attack_success_prob": 0.7,
        },
        true_mission="critical_hunter",
    )

    assert result["inferred_mission"] == "critical_hunter"
    assert result["mission_confidence"] > 0.25
    assert result["mission_match"] is True


def test_phase90_history_saved(tmp_path):
    config = SimulationConfig(
        T=4,
        H=2,
        attacker_enabled=True,
        attacker_target_selection="adaptive",
        adaptive_attacker_enabled=True,
        adaptive_path_enabled=True,
        adaptive_planning_enabled=True,
        expected_utility_enabled=True,
        trust_enabled=True,
        observable_events_enabled=True,
        critical_path_events_enabled=True,
        attacker_mission="critical_hunter",
        show_plot=False,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    sim.save_outputs(str(tmp_path))

    saved = np.load(tmp_path / "history.npz")
    assert "inferred_mission_history" in saved.files
    assert "mission_confidence_history" in saved.files
    assert len(saved["inferred_mission_history"]) == config.T
    assert len(saved["mission_confidence_history"]) == config.T


def test_phase90_artifacts_generated(tmp_path):
    output_dir = tmp_path / "phase90_intent"
    rows = run_phase90_intent_inference_evaluation(
        seeds=[0],
        output_dir=str(output_dir),
        strategy_profiles=["balanced"],
    )

    assert rows
    assert (output_dir / "intent_inference_summary.csv").exists()
    assert (output_dir / "intent_inference_summary.json").exists()
    assert (output_dir / "mission_confusion_matrix.png").exists()
    assert (output_dir / "mission_accuracy.png").exists()
    assert (output_dir / "mission_confidence_distribution.png").exists()
    assert (output_dir / "PHASE90_INTENT_INFERENCE_REPORT.md").exists()

    summary = json.loads((output_dir / "intent_inference_summary.json").read_text(encoding="utf-8"))
    assert "analysis" in summary
    assert "mission_inference_accuracy" in summary["analysis"]
