"""Reproducible smoke benchmark orchestration for threat hunting."""

from __future__ import annotations

import csv
import json
import shutil
from collections import defaultdict
from pathlib import Path
from statistics import fmean

from benchmark_loader import hunting_evaluation_matrix_size, load_benchmark
from scenario_loader import load_scenario

from .models import canonical_json
from .scenario_runner import run_hunting_recipe_evaluation


def _write_json(path: Path, value: object) -> None:
    path.write_text(canonical_json(value) + "\n", encoding="utf-8", newline="\n")


def _summary_rows(detail_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_product: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in detail_rows:
        by_product[str(row.get("product_profile", ""))].append(row)
    result: list[dict[str, object]] = []
    for product, rows in sorted(by_product.items()):
        succeeded = [row for row in rows if row.get("status") == "succeeded"]
        f1_values = [float(row["f1"]) for row in succeeded if row.get("f1") is not None]
        result.append(
            {
                "product_profile": product,
                "case_count": len(rows),
                "succeeded_case_count": len(succeeded),
                "completeness": len(succeeded) / len(rows) if rows else 0.0,
                "mean_f1": fmean(f1_values) if f1_values else 0.0,
                "finding_count": sum(int(row.get("finding_count", 0)) for row in succeeded),
            }
        )
    return result


def run_hunting_benchmark(
    benchmark_path: str = "benchmarks/cybermatch_hunting_v1.json",
    output_dir: str = "output/threat_hunting/cybermatch_hunting_v1",
) -> list[dict[str, object]]:
    config = load_benchmark(benchmark_path)
    metadata = config["metadata"]
    if metadata.get("type") != "threat_hunting":
        raise ValueError("benchmark metadata.type must be threat_hunting")
    root = Path(output_dir).resolve()
    if root.exists():
        raise FileExistsError(f"output path already exists: {root}")
    root.mkdir(parents=True, exist_ok=False)
    detail_rows: list[dict[str, object]] = []
    try:
        for scenario_path in config["scenarios"]:
            scenario = load_scenario(scenario_path)
            scenario_name = str(scenario["metadata"]["name"])
            for topology_path in config.get("topologies", []):
                topology_name = Path(topology_path).stem
                child = root / "runs" / scenario_name / topology_name
                rows = run_hunting_recipe_evaluation(
                    scenario,
                    output_dir=str(child),
                    topology_preset=topology_name,
                    missions=config["missions"],
                    product_paths=config["products"],
                    recipe_paths=config["recipes"],
                    noise_profiles=config["noise_profiles"],
                    seeds=config.get("seeds", [0]),
                )
                detail_rows.extend(rows)

        expected = hunting_evaluation_matrix_size(config)
        succeeded = sum(row.get("status") == "succeeded" for row in detail_rows)
        completeness = succeeded / expected if expected else 0.0
        summary_rows = _summary_rows(detail_rows)
        manifest = {
            "schema_version": "1.0",
            "runner": "hunting_recipe_evaluation",
            "benchmark_name": metadata["name"],
            "benchmark_version": metadata.get("version"),
            "profile": metadata.get("profile", "smoke"),
            "evaluation_matrix_size": expected,
            "succeeded_cases": succeeded,
            "benchmark_completeness": completeness,
        }
        _write_json(
            root / "hunting_benchmark_summary.json",
            {"manifest": manifest, "summary_rows": summary_rows, "detail_rows": detail_rows},
        )
        with (root / "hunting_benchmark_summary.csv").open(
            "w", encoding="utf-8", newline=""
        ) as handle:
            fields = [
                "product_profile",
                "case_count",
                "succeeded_case_count",
                "completeness",
                "mean_f1",
                "finding_count",
            ]
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(summary_rows)
        _write_json(root / "hunting_benchmark_manifest.json", manifest)
        return summary_rows
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


__all__ = ["run_hunting_benchmark"]
