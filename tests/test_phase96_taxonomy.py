import json

import pytest

from mission_taxonomy import INTENT_CLASSES, MISSION_LAYER_CLASSES, TARGET_CLASSES, MissionTaxonomyAnalyzer
from run_scenarios import run_phase96_taxonomy_evaluation


pytestmark = [pytest.mark.phase96, pytest.mark.taxonomy]


def _sample_rows():
    return [
        {"true_mission": "profit", "strategy_type": "credential_hunter"},
        {"true_mission": "persistence", "strategy_type": "persistence_builder"},
        {"true_mission": "critical_hunter", "strategy_type": "critical_asset_hunter"},
    ]


def test_taxonomy_validation_counts_and_completeness():
    result = MissionTaxonomyAnalyzer().analyze(_sample_rows())

    assert result.metrics["intent_count"] == len(INTENT_CLASSES)
    assert result.metrics["mission_count"] == len(MISSION_LAYER_CLASSES)
    assert result.metrics["target_count"] == len(TARGET_CLASSES)
    assert 0.0 < result.metrics["taxonomy_completeness"] <= 1.0
    assert result.rows


def test_taxonomy_matrix_generation():
    result = MissionTaxonomyAnalyzer().analyze(_sample_rows())

    assert "financial_gain" in result.intent_mission_matrix
    assert result.mission_target_matrix
    assert result.target_strategy_matrix
    assert 0.0 <= result.metrics["mission_target_overlap"] <= 1.0
    assert 0.0 <= result.metrics["target_strategy_overlap"] <= 1.0


def test_phase96_artifacts_generated(tmp_path):
    output_dir = tmp_path / "phase96_taxonomy"
    result = run_phase96_taxonomy_evaluation(
        output_dir=str(output_dir),
        source_rows=_sample_rows(),
    )

    assert result["rows"]
    assert (output_dir / "taxonomy_summary.csv").exists()
    assert (output_dir / "taxonomy_summary.json").exists()
    assert (output_dir / "intent_mission_matrix.png").exists()
    assert (output_dir / "mission_target_matrix.png").exists()
    assert (output_dir / "target_strategy_matrix.png").exists()
    assert (output_dir / "PHASE96_TAXONOMY_REPORT.md").exists()

    summary = json.loads((output_dir / "taxonomy_summary.json").read_text(encoding="utf-8"))
    assert "intent_mission_matrix" in summary["analysis"]
    assert "mission_target_matrix" in summary["analysis"]
    assert "target_strategy_matrix" in summary["analysis"]
