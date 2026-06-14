import json

import numpy as np
import pytest

from behavior_profile import BehaviorProfileEngine
from cybermatch import CyberDefenseSimulator, SimulationConfig
from run_scenarios import run_phase91_behavior_profile_evaluation


pytestmark = [pytest.mark.phase91, pytest.mark.behavior]


def test_behavior_profile_engine_identifies_utility_seeking():
    engine = BehaviorProfileEngine()
    result = engine.evaluate(
        {
            "actual_utility_mean": 140.0,
            "expected_utility_mean_mean": 8.0,
            "mean_attack_success_prob_mean": 0.9,
            "critical_node_visit_count_mean": 0.0,
            "lateral_move_count_mean": 2.0,
        },
        expected_profile="utility_seeking",
    )

    assert result["behavior_profile"] == "utility_seeking"
    assert result["profile_confidence"] > 0.15
    assert result["profile_match"] is True


def test_phase91_history_saved(tmp_path):
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
        attacker_mission="profit",
        show_plot=False,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    sim.save_outputs(str(tmp_path))

    saved = np.load(tmp_path / "history.npz")
    assert "behavior_profile_history" in saved.files
    assert "profile_confidence_history" in saved.files
    assert len(saved["behavior_profile_history"]) == config.T
    assert len(saved["profile_confidence_history"]) == config.T


def test_phase91_artifacts_generated(tmp_path):
    output_dir = tmp_path / "phase91_behavior"
    rows = run_phase91_behavior_profile_evaluation(
        seeds=[0],
        output_dir=str(output_dir),
        strategy_profiles=["balanced"],
    )

    assert rows
    assert (output_dir / "behavior_profile_summary.csv").exists()
    assert (output_dir / "behavior_profile_summary.json").exists()
    assert (output_dir / "profile_distribution.png").exists()
    assert (output_dir / "profile_confidence_distribution.png").exists()
    assert (output_dir / "profile_mission_relationship.png").exists()
    assert (output_dir / "PHASE91_BEHAVIOR_PROFILE_REPORT.md").exists()

    summary = json.loads((output_dir / "behavior_profile_summary.json").read_text(encoding="utf-8"))
    assert "analysis" in summary
    assert "profile_distribution" in summary["analysis"]
