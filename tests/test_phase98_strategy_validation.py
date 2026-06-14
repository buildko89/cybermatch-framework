import json

import pytest

from run_scenarios import run_phase98_strategy_validation
from strategy_validation import StrategyValidationEngine


pytestmark = [pytest.mark.phase98, pytest.mark.strategy_validation]


def _sample_rows():
    return [
        {
            "mission": "credential_theft",
            "target": "identity_infrastructure",
            "strategy_type": "credential_hunter",
            "strategy_confidence": 0.62,
            "trust_collapse_activity": 0.8,
            "lateral_movement_activity": 0.7,
            "stealth_activity": 0.6,
        },
        {
            "mission": "credential_theft",
            "target": "identity_infrastructure",
            "strategy_type": "identity_mapper",
            "strategy_confidence": 0.58,
            "trust_collapse_activity": 0.7,
            "lateral_movement_activity": 0.9,
            "adaptation_activity": 0.4,
        },
        {
            "mission": "data_exfiltration",
            "target": "cloud_control_plane",
            "strategy_type": "secret_hunter",
            "strategy_confidence": 0.64,
            "utility_activity": 0.8,
            "stealth_activity": 0.7,
            "objective_activity": 0.6,
        },
        {
            "mission": "data_exfiltration",
            "target": "research_system",
            "strategy_type": "research_explorer",
            "strategy_confidence": 0.61,
            "stealth_activity": 0.9,
            "objective_activity": 0.8,
            "survival_activity": 0.6,
        },
        {
            "mission": "service_disruption",
            "target": "backup_system",
            "strategy_type": "resource_exhaustion",
            "strategy_confidence": 0.59,
            "utility_activity": 0.7,
            "adaptation_activity": 0.6,
            "campaign_disruption_activity": 0.5,
        },
    ]


def test_strategy_validation_metrics_are_bounded():
    result = StrategyValidationEngine().validate(_sample_rows())

    assert "strategy_validation_pass" in result.metrics
    for key in (
        "strategy_consistency",
        "strategy_stability",
        "target_strategy_confidence",
        "mission_strategy_consistency",
        "strategy_redundancy",
        "strategy_distinctiveness",
        "strategy_explainability",
    ):
        assert 0.0 <= result.metrics[key] <= 1.0


def test_strategy_distance_matrix_contains_pairwise_values():
    result = StrategyValidationEngine().validate(_sample_rows())

    assert result.strategy_distance_matrix["credential_hunter"]["identity_mapper"] >= 0.0
    assert result.strategy_distance_matrix["secret_hunter"]["research_explorer"] >= 0.0
    assert result.strategy_distance_matrix["credential_hunter"]["credential_hunter"] == 0.0
    assert set(result.strategy_distance_matrix) >= {"credential_hunter", "identity_mapper", "secret_hunter"}


def test_target_and_mission_validation_outputs():
    result = StrategyValidationEngine().validate(_sample_rows())

    assert result.target_specificity_validation["identity_infrastructure"] > 0.0
    assert result.mission_strategy_explainability["credential_theft"] >= 0.0
    assert result.strategy_summary


def test_phase98_artifacts_generated(tmp_path):
    output_dir = tmp_path / "phase98_strategy_validation"
    result = run_phase98_strategy_validation(
        output_dir=str(output_dir),
        source_rows=_sample_rows(),
    )

    assert result["analysis"]
    assert (output_dir / "strategy_distance_matrix.png").exists()
    assert (output_dir / "strategy_distinctiveness.png").exists()
    assert (output_dir / "strategy_redundancy.png").exists()
    assert (output_dir / "target_strategy_validation.png").exists()
    assert (output_dir / "mission_strategy_explainability.png").exists()
    assert (output_dir / "strategy_validation_summary.csv").exists()
    assert (output_dir / "strategy_validation_summary.json").exists()
    assert (output_dir / "PHASE98_STRATEGY_VALIDATION_REPORT.md").exists()

    summary = json.loads((output_dir / "strategy_validation_summary.json").read_text(encoding="utf-8"))
    assert "strategy_distinctiveness" in summary["analysis"]
    assert "strategy_distance_matrix" in summary
