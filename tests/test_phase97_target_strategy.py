import json

import numpy as np
import pytest

from cybermatch import CyberDefenseSimulator, SimulationConfig
from run_scenarios import run_phase97_target_strategy_evaluation
from strategy_layer import StrategyInferenceEngine


pytestmark = [pytest.mark.phase97, pytest.mark.target_strategy]


def _sample_rows():
    return [
        {"target": "identity_infrastructure", "trust_collapse_activity": 0.9, "lateral_movement_activity": 0.8},
        {"target": "cloud_control_plane", "adaptation_activity": 0.9, "objective_activity": 0.8},
        {"target": "backup_system", "campaign_disruption_activity": 0.9, "deception_activity": 0.8},
        {"target": "industrial_control_system", "critical_progress": 0.9, "planned_critical_activity": 0.8},
    ]


def test_target_mapping_candidates_switch_by_target():
    engine = StrategyInferenceEngine()

    assert engine.strategy_candidates_for_target("identity_infrastructure") == (
        "credential_hunter",
        "identity_mapper",
        "trust_abuser",
    )
    assert "api_abuser" in engine.strategy_candidates_for_target("cloud_control_plane")


def test_target_specific_strategy_inference_uses_target_candidates():
    engine = StrategyInferenceEngine()
    result = engine.infer(_sample_rows()[1], target="cloud_control_plane")

    assert result.strategy_type in engine.strategy_candidates_for_target("cloud_control_plane")
    assert result.strategy_type in {"permission_escalator", "secret_hunter", "api_abuser"}
    assert 0.0 <= result.strategy_confidence <= 1.0


def test_phase97_history_saved(tmp_path):
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
    assert "target_history" in saved.files
    assert "target_strategy_history" in saved.files
    assert "strategy_alignment_history" in saved.files
    assert len(saved["target_history"]) == config.T


def test_phase97_artifacts_generated(tmp_path):
    output_dir = tmp_path / "phase97_target_strategy"
    result = run_phase97_target_strategy_evaluation(
        output_dir=str(output_dir),
        source_rows=_sample_rows(),
    )

    assert result["rows"]
    assert (output_dir / "target_strategy_matrix.png").exists()
    assert (output_dir / "strategy_distribution.png").exists()
    assert (output_dir / "strategy_diversity.png").exists()
    assert (output_dir / "target_specificity.png").exists()
    assert (output_dir / "strategy_alignment.png").exists()
    assert (output_dir / "PHASE97_TARGET_STRATEGY_REPORT.md").exists()
    assert (output_dir / "target_strategy_summary.json").exists()

    summary = json.loads((output_dir / "target_strategy_summary.json").read_text(encoding="utf-8"))
    assert "strategy_diversity" in summary["analysis"]
    assert "target_specificity_score" in summary["analysis"]
    assert "strategy_target_alignment" in summary["analysis"]
