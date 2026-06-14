import json

import numpy as np
import pytest

from cybermatch import CyberDefenseSimulator, SimulationConfig
from run_scenarios import run_phase95_strategy_layer_evaluation
from strategy_layer import STRATEGY_CLASSES, StrategyInferenceEngine


pytestmark = [pytest.mark.phase95, pytest.mark.strategy]


def _sample_rows():
    return [
        {
            "row_id": "profit_1",
            "true_mission": "profit",
            "behavior_profile": "utility_seeking",
            "archetype": "Archetype-1",
            "trust_collapse_activity": 0.9,
            "lateral_movement_activity": 0.8,
            "stealth_activity": 0.5,
            "utility_activity": 0.7,
            "deception_activity": 0.3,
        },
        {
            "row_id": "critical_1",
            "true_mission": "achievement",
            "behavior_profile": "critical_path_seeking",
            "archetype": "Archetype-2",
            "critical_progress": 0.9,
            "critical_focus": 0.9,
            "planned_critical_activity": 0.8,
            "objective_activity": 0.7,
        },
        {
            "row_id": "persist_1",
            "true_mission": "persistence",
            "behavior_profile": "stealth_seeking",
            "archetype": "Archetype-1",
            "survival_activity": 0.9,
            "stealth_activity": 0.8,
            "adaptation_activity": 0.7,
            "lateral_movement_activity": 0.5,
        },
    ]


def test_strategy_inference_engine_identifies_strategy():
    result = StrategyInferenceEngine().infer(_sample_rows()[0])

    assert result.strategy_type in STRATEGY_CLASSES
    assert result.strategy_type == "credential_hunter"
    assert 0.0 <= result.strategy_confidence <= 1.0
    assert 0.0 <= result.strategy_entropy <= 1.0


def test_phase95_history_saved(tmp_path):
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
    assert "strategy_history" in saved.files
    assert "strategy_confidence_history" in saved.files
    assert len(saved["strategy_history"]) == config.T
    assert len(saved["strategy_confidence_history"]) == config.T


def test_phase95_artifacts_generated_from_existing_rows(tmp_path):
    output_dir = tmp_path / "phase95_strategy_layer"
    result = run_phase95_strategy_layer_evaluation(
        output_dir=str(output_dir),
        source_rows=_sample_rows(),
    )

    assert result["rows"]
    assert (output_dir / "strategy_summary.csv").exists()
    assert (output_dir / "strategy_summary.json").exists()
    assert (output_dir / "strategy_distribution.png").exists()
    assert (output_dir / "mission_strategy_matrix.png").exists()
    assert (output_dir / "strategy_archetype_matrix.png").exists()
    assert (output_dir / "strategy_profile_matrix.png").exists()
    assert (output_dir / "PHASE95_STRATEGY_LAYER_REPORT.md").exists()

    summary = json.loads((output_dir / "strategy_summary.json").read_text(encoding="utf-8"))
    assert "strategy_distribution" in summary["analysis"]
    assert "mission_strategy_overlap" in summary["analysis"]
    assert "strategy_archetype_overlap" in summary["analysis"]
