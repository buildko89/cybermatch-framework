from __future__ import annotations

import json
from pathlib import Path

import pytest


pytestmark = [pytest.mark.phase8]


def _fake_phase63_stats(scenarios, **_kwargs):
    rows = []
    for scenario_name, config in scenarios.items():
        rows.append(
            {
                "scenario": scenario_name,
                "product_profile_name": config["product_profile_name"],
                "product_category": config["product_category"],
                "mission_success_score_mean": 0.4,
                "campaign_disruption_score_mean": 0.3,
                "mean_attack_detection_prob_mean": 0.2,
                "attacker_diversion_score_mean": 0.1,
                "evaluation_score_mean": 0.5,
                "product_effectiveness_mean": 0.6,
            }
        )
    return rows


def test_phase63_selection_limits_rows_and_writes_manifest(tmp_path, monkeypatch):
    from run_scenarios import run_phase63_mission_aware_product_evaluation

    monkeypatch.setattr("run_scenarios.run_scenarios_multi_seed", _fake_phase63_stats)
    output_dir = tmp_path / "phase63"

    rows = run_phase63_mission_aware_product_evaluation(
        seeds=[7],
        output_dir=str(output_dir),
        missions=["profit"],
        product_profile_paths=["profiles/products/sample_ids.json"],
        topology_preset="small_business",
    )

    assert {row["mission_name"] for row in rows} == {"profit"}
    assert {row["profile_id"] for row in rows} == {"baseline", "sample_ids"}
    assert {row["topology_name"] for row in rows} == {"small_business"}
    assert (output_dir / "mission_product_summary.csv").is_file()

    manifest = json.loads((output_dir / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["inputs"]["missions"] == ["profit"]
    assert manifest["inputs"]["topology"] == "small_business"
    assert manifest["inputs"]["seeds"] == [7]
    assert list(manifest["inputs"]["product_profiles"]) == ["sample_ids"]
    report = (output_dir / "PHASE63_MISSION_PRODUCT_REPORT.md").read_text(encoding="utf-8")
    assert "# 防御策の比較評価レポート" in report
    assert "## 結論" in report
    assert "IDS（侵入検知）" in report


def test_phase63_selection_rejects_unknown_mission(tmp_path):
    from run_scenarios import run_phase63_mission_aware_product_evaluation

    with pytest.raises(ValueError, match="Unsupported Phase6.3 missions"):
        run_phase63_mission_aware_product_evaluation(
            output_dir=str(tmp_path),
            missions=["unknown"],
            product_profile_paths=["profiles/products/sample_ids.json"],
        )
