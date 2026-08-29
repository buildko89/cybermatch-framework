from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from benchmark_loader import hunting_evaluation_matrix_size, load_hunting_benchmark
from src.cybermatch.threat_hunting.benchmark_runner import run_hunting_benchmark


pytestmark = [pytest.mark.threat_hunting, pytest.mark.benchmark]


def test_hunting_smoke_benchmark_loads_and_has_full_h3_axes():
    benchmark = load_hunting_benchmark()

    assert benchmark["metadata"]["name"] == "cybermatch_hunting_v1"
    assert benchmark["metadata"]["profile"] == "smoke"
    assert hunting_evaluation_matrix_size(benchmark) == 18


def test_standard_v1_definition_is_unchanged():
    payload = json.loads(
        Path("benchmarks/cybermatch_standard_v1.json").read_text(encoding="utf-8")
    )
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert hashlib.sha256(canonical).hexdigest() == (
        "e236ac3c76282ebae34b22f16e482492d70d849e76053c246fcafbd446f92bd8"
    )


def test_hunting_benchmark_smoke_completeness_is_one(tmp_path, monkeypatch):
    def fake_runner(
        scenario,
        *,
        output_dir,
        topology_preset,
        missions,
        product_paths,
        recipe_paths,
        noise_profiles,
        seeds,
    ):
        rows = []
        for mission in missions:
            for product in product_paths:
                for recipe in recipe_paths:
                    for noise in noise_profiles:
                        for seed in seeds:
                            rows.append(
                                {
                                    "status": "succeeded",
                                    "scenario_name": scenario["metadata"]["name"],
                                    "topology_name": topology_preset,
                                    "mission_name": mission,
                                    "product_profile": product.rsplit("/", 1)[-1].removesuffix(".json"),
                                    "recipe_id": recipe.rsplit("/", 1)[-1].removesuffix(".json"),
                                    "noise_profile": noise,
                                    "seed": seed,
                                    "finding_count": 1,
                                    "f1": 0.5,
                                }
                            )
        return rows

    monkeypatch.setattr(
        "src.cybermatch.threat_hunting.benchmark_runner.run_hunting_recipe_evaluation",
        fake_runner,
    )
    output = tmp_path / "benchmark"

    rows = run_hunting_benchmark(output_dir=str(output))

    assert len(rows) == 3
    assert all(row["completeness"] == 1.0 for row in rows)
    payload = json.loads((output / "hunting_benchmark_summary.json").read_text(encoding="utf-8"))
    assert payload["manifest"]["evaluation_matrix_size"] == 18
    assert payload["manifest"]["benchmark_completeness"] == 1.0
    assert len(payload["detail_rows"]) == 18
