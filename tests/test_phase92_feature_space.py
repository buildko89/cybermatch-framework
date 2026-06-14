import json

import pytest

from feature_space import FeatureSpaceAnalyzer
from run_scenarios import run_phase92_feature_space_evaluation


pytestmark = [pytest.mark.phase92, pytest.mark.feature]


def test_feature_space_vector_generation():
    analyzer = FeatureSpaceAnalyzer()
    vector = analyzer.build_feature_vector(
        {
            "actual_utility_mean": 120.0,
            "expected_utility_mean_mean": 8.0,
            "mean_attack_success_prob_mean": 0.75,
            "critical_path_progress_count_mean": 3.0,
            "critical_node_visit_count_mean": 5.0,
            "lateral_move_count_mean": 4.0,
        }
    )

    assert "attack_success_rate" in vector
    assert "utility_activity" in vector
    assert "critical_progress" in vector
    assert all(0.0 <= value <= 1.0 for value in vector.values())


def test_critical_path_bias_score_increases_with_critical_features():
    analyzer = FeatureSpaceAnalyzer()
    low = analyzer.analyze_one({"actual_utility_mean": 100.0, "mean_attack_success_prob_mean": 0.8})
    high = analyzer.analyze_one(
        {
            "critical_path_progress_count_mean": 12.0,
            "critical_node_visit_count_mean": 50.0,
            "critical_probe_count_mean": 12.0,
            "planned_path_is_critical_rate": 1.0,
        }
    )

    assert high.critical_path_bias_score > low.critical_path_bias_score
    assert 0.0 <= high.critical_path_bias_score <= 1.0


def test_phase92_artifacts_generated(tmp_path):
    output_dir = tmp_path / "phase92_feature"
    rows = run_phase92_feature_space_evaluation(
        seeds=[0],
        output_dir=str(output_dir),
        strategy_profiles=["balanced"],
    )

    assert rows
    assert (output_dir / "feature_space_summary.csv").exists()
    assert (output_dir / "feature_space_summary.json").exists()
    assert (output_dir / "feature_dominance.png").exists()
    assert (output_dir / "mission_feature_heatmap.png").exists()
    assert (output_dir / "profile_feature_heatmap.png").exists()
    assert (output_dir / "critical_path_bias.png").exists()
    assert (output_dir / "PHASE92_FEATURE_SPACE_REPORT.md").exists()

    summary = json.loads((output_dir / "feature_space_summary.json").read_text(encoding="utf-8"))
    assert "analysis" in summary
    assert "critical_path_bias_score" in summary["analysis"]
