import json

import pytest

from feature_export import ProfileCorePCAAnalyzer
from run_scenarios import run_phase93_profilecore_analysis


pytestmark = [pytest.mark.phase93, pytest.mark.profilecore]


def test_profilecore_pca_archetype_metrics_from_feature_rows():
    rows = [
        {"mission_scenario": "a", "attack_success_rate": 0.8, "utility_activity": 0.9, "stealth_activity": 0.1},
        {"mission_scenario": "b", "attack_success_rate": 0.7, "utility_activity": 0.8, "stealth_activity": 0.2},
        {"mission_scenario": "c", "attack_success_rate": 0.2, "utility_activity": 0.1, "stealth_activity": 0.9},
        {"mission_scenario": "d", "attack_success_rate": 0.3, "utility_activity": 0.2, "stealth_activity": 0.8},
    ]

    result = ProfileCorePCAAnalyzer(component_count=3, archetype_count=3).analyze(rows)

    assert result.projected_rows
    assert result.explained_variance
    assert result.dominant_component.startswith("PC")
    assert result.archetype_count >= 1
    assert 0.0 <= result.archetype_concentration <= 1.0
    assert 0.0 <= result.archetype_entropy <= 1.0
    assert all(str(row["archetype"]).startswith("Archetype-") for row in result.projected_rows)


def test_phase93_artifacts_generated(tmp_path):
    output_dir = tmp_path / "phase93_profilecore"
    result = run_phase93_profilecore_analysis(
        seeds=[0],
        output_dir=str(output_dir),
        strategy_profiles=["balanced"],
    )

    assert result["rows"]
    assert (output_dir / "pca_variance.png").exists()
    assert (output_dir / "component_loadings.png").exists()
    assert (output_dir / "feature_projection.png").exists()
    assert (output_dir / "archetype_distribution.png").exists()
    assert (output_dir / "PHASE93_PROFILECORE_REPORT.md").exists()
    assert (output_dir / "profilecore_analysis.json").exists()

    summary = json.loads((output_dir / "profilecore_analysis.json").read_text(encoding="utf-8"))
    assert "analysis" in summary
    assert "pca_explained_variance" in summary["analysis"]
    assert "dominant_component" in summary["analysis"]
    assert "archetype_count" in summary["analysis"]
