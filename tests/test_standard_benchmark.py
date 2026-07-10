from __future__ import annotations

import pytest

from benchmark_loader import evaluation_matrix_size, load_standard_benchmark


pytestmark = [pytest.mark.phase85, pytest.mark.benchmark]


def test_standard_benchmark_load():
    benchmark = load_standard_benchmark()

    assert benchmark["metadata"]["name"] == "cybermatch_standard_v1"
    assert benchmark["metadata"]["version"] == "0.1"


def test_standard_benchmark_matrix_size():
    benchmark = load_standard_benchmark()

    assert len(benchmark["scenarios"]) == 5
    assert len(benchmark["topologies"]) == 5
    assert len(benchmark["missions"]) == 4
    assert len(benchmark["products"]) == 5
    assert evaluation_matrix_size(benchmark) == 500


def test_phase85_standard_benchmark_runner_smoke(tmp_path, monkeypatch):
    from run_scenarios import run_phase85_standard_benchmark

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

    rows = run_phase85_standard_benchmark(output_dir=str(tmp_path / "phase85"))

    assert rows
    assert rows[0]["benchmark_rank"] == 1
    assert rows[0]["evaluation_matrix_size"] == 500
    assert (tmp_path / "phase85" / "standard_benchmark_summary.csv").exists()
    assert (tmp_path / "phase85" / "standard_benchmark_summary.json").exists()
    assert (tmp_path / "phase85" / "standard_product_ranking.png").exists()
    assert (tmp_path / "phase85" / "standard_scenario_heatmap.png").exists()
    assert (tmp_path / "phase85" / "standard_topology_heatmap.png").exists()
    assert (tmp_path / "phase85" / "standard_mission_heatmap.png").exists()
    assert (tmp_path / "phase85" / "PHASE85_STANDARD_BENCHMARK_REPORT.md").exists()
    report = (tmp_path / "phase85" / "PHASE85_STANDARD_BENCHMARK_REPORT.md").read_text(encoding="utf-8")
    assert "# CyberMatch 標準ベンチマーク比較レポート" in report
    assert "## 結論" in report
