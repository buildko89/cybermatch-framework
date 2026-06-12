"""Benchmark suite loader for CyberMatch Phase8.3."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scenario_loader import ALLOWED_MISSIONS, ScenarioValidationError, _resolve_repo_path, load_scenario
from topology_loader import TopologyValidationError, load_topology


BENCHMARK_DIR = _resolve_repo_path("benchmarks")
STANDARD_BENCHMARK_PATH = "benchmarks/cybermatch_standard_v1.json"


class BenchmarkValidationError(ValueError):
    """Raised when a CyberMatch benchmark configuration is invalid."""


def load_benchmark(path: str) -> Dict[str, Any]:
    benchmark_path = _resolve_repo_path(path)
    try:
        benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BenchmarkValidationError(f"Benchmark file not found: {benchmark_path}") from exc
    except json.JSONDecodeError as exc:
        raise BenchmarkValidationError(f"Benchmark JSON is invalid: {benchmark_path}: {exc}") from exc

    if not isinstance(benchmark, dict):
        raise BenchmarkValidationError("Benchmark root must be a JSON object.")
    validate_benchmark(benchmark)
    return benchmark


def validate_benchmark(config: Dict[str, Any]) -> None:
    metadata = config.get("metadata")
    if not isinstance(metadata, dict) or not metadata.get("name"):
        raise BenchmarkValidationError("Benchmark requires metadata.name.")

    scenarios = config.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise BenchmarkValidationError("Benchmark requires a non-empty scenarios list.")
    for scenario_path in scenarios:
        if not isinstance(scenario_path, str) or not scenario_path:
            raise BenchmarkValidationError("Scenario paths must be non-empty strings.")
        try:
            load_scenario(scenario_path)
        except ScenarioValidationError as exc:
            raise BenchmarkValidationError(f"Invalid benchmark scenario {scenario_path}: {exc}") from exc

    topologies = config.get("topologies", [])
    if topologies is not None:
        if not isinstance(topologies, list):
            raise BenchmarkValidationError("Benchmark topologies must be a list when provided.")
        for topology_path in topologies:
            if not isinstance(topology_path, str) or not topology_path:
                raise BenchmarkValidationError("Topology paths must be non-empty strings.")
            try:
                load_topology(topology_path)
            except TopologyValidationError as exc:
                raise BenchmarkValidationError(f"Invalid benchmark topology {topology_path}: {exc}") from exc

    missions = config.get("missions")
    if not isinstance(missions, list) or not missions:
        raise BenchmarkValidationError("Benchmark requires a non-empty missions list.")
    invalid_missions = [mission for mission in missions if mission not in ALLOWED_MISSIONS]
    if invalid_missions:
        raise BenchmarkValidationError(f"Unsupported missions: {invalid_missions}")

    products = config.get("products")
    if not isinstance(products, list) or not products:
        raise BenchmarkValidationError("Benchmark requires a non-empty products list.")
    for product_path_value in products:
        if not isinstance(product_path_value, str) or not product_path_value:
            raise BenchmarkValidationError("Product paths must be non-empty strings.")
        product_path = _resolve_repo_path(product_path_value)
        if not product_path.is_file():
            raise BenchmarkValidationError(f"Product profile not found: {product_path_value}")
        try:
            json.loads(product_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BenchmarkValidationError(f"Product profile JSON is invalid: {product_path_value}: {exc}") from exc

    seeds = config.get("seeds", [0])
    if not isinstance(seeds, list) or not all(isinstance(seed, int) for seed in seeds):
        raise BenchmarkValidationError("Benchmark seeds must be a list of integers.")


def benchmark_counts(config: Dict[str, Any]) -> Dict[str, int]:
    return {
        "scenario_count": len(config.get("scenarios", [])),
        "topology_count": len(config.get("topologies", [])),
        "mission_count": len(config.get("missions", [])),
        "product_count": len(config.get("products", [])),
    }


def evaluation_matrix_size(config: Dict[str, Any]) -> int:
    counts = benchmark_counts(config)
    topology_count = counts["topology_count"] or 1
    return counts["scenario_count"] * topology_count * counts["mission_count"] * counts["product_count"]


def list_available_benchmarks(benchmark_dir: str | None = None) -> List[Path]:
    base_dir = _resolve_repo_path(benchmark_dir) if benchmark_dir else BENCHMARK_DIR
    if not base_dir.exists():
        return []
    return sorted(base_dir.glob("*.json"))


def load_standard_benchmark() -> Dict[str, Any]:
    return load_benchmark(STANDARD_BENCHMARK_PATH)
