from __future__ import annotations

import json

import pytest

from benchmark_loader import BenchmarkValidationError, load_benchmark, validate_benchmark


pytestmark = [pytest.mark.phase83, pytest.mark.benchmark]


def _valid_benchmark() -> dict:
    return {
        "metadata": {
            "name": "product_evaluation_benchmark",
            "version": "0.1",
        },
        "scenarios": [
            "scenarios/catalog/financial_enterprise.json",
            "scenarios/catalog/hospital_enterprise.json",
            "scenarios/catalog/cloud_native_startup.json",
            "scenarios/catalog/ot_factory.json",
            "scenarios/catalog/small_business.json",
        ],
        "missions": ["profit", "achievement", "persistence", "critical_hunter"],
        "products": [
            "profiles/products/sample_ids.json",
            "profiles/products/sample_ips.json",
            "profiles/products/sample_honeypot.json",
            "profiles/products/sample_deception.json",
            "profiles/products/sample_xdr.json",
        ],
        "seeds": [0],
    }


def test_benchmark_load():
    benchmark = load_benchmark("benchmarks/product_evaluation_benchmark.json")

    assert benchmark["metadata"]["name"] == "product_evaluation_benchmark"
    assert len(benchmark["scenarios"]) == 5
    assert len(benchmark["missions"]) == 4
    assert len(benchmark["products"]) == 5


def test_benchmark_validation_fails_for_invalid_mission():
    benchmark = _valid_benchmark()
    benchmark["missions"] = ["profit", "invalid_mission"]

    with pytest.raises(BenchmarkValidationError, match="Unsupported missions"):
        validate_benchmark(benchmark)


def test_benchmark_validation_fails_for_missing_product():
    benchmark = _valid_benchmark()
    benchmark["products"] = ["profiles/products/missing_product.json"]

    with pytest.raises(BenchmarkValidationError, match="Product profile not found"):
        validate_benchmark(benchmark)


def test_phase83_benchmark_runner_smoke(tmp_path, monkeypatch):
    from run_scenarios import run_phase83_benchmark_suite

    detail_rows = [
        {
            "scenario_name": "financial_enterprise",
            "mission_name": "profit",
            "product_profile": "sample_ids",
            "scenario_adjusted_effectiveness": 0.5,
        },
        {
            "scenario_name": "financial_enterprise",
            "mission_name": "profit",
            "product_profile": "sample_deception",
            "scenario_adjusted_effectiveness": 0.7,
        },
    ]
    monkeypatch.setattr("run_scenarios._phase83_benchmark_rows", lambda config: detail_rows)

    benchmark_path = tmp_path / "benchmark.json"
    benchmark_path.write_text(json.dumps(_valid_benchmark()), encoding="utf-8")

    rows = run_phase83_benchmark_suite(
        benchmark_path=str(benchmark_path),
        output_dir=str(tmp_path / "phase83"),
    )

    assert rows
    assert rows[0]["benchmark_rank"] == 1
    assert (tmp_path / "phase83" / "benchmark_summary.csv").exists()
    assert (tmp_path / "phase83" / "benchmark_summary.json").exists()
    assert (tmp_path / "phase83" / "benchmark_product_ranking.png").exists()
    assert (tmp_path / "phase83" / "benchmark_scenario_heatmap.png").exists()
    assert (tmp_path / "phase83" / "benchmark_mission_heatmap.png").exists()
    assert (tmp_path / "phase83" / "benchmark_consistency.png").exists()
    assert (tmp_path / "phase83" / "PHASE83_BENCHMARK_SUITE_REPORT.md").exists()
