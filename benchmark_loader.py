"""Benchmark suite loader for CyberMatch Phase8.3."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scenario_loader import (
    ALLOWED_HUNTING_NOISE_PROFILES,
    ALLOWED_MISSIONS,
    ScenarioValidationError,
    _resolve_repo_path,
    load_scenario,
)
from topology_loader import TopologyValidationError, load_topology


BENCHMARK_DIR = _resolve_repo_path("benchmarks")
STANDARD_BENCHMARK_PATH = "benchmarks/cybermatch_standard_v1.json"
HUNTING_BENCHMARK_PATH = "benchmarks/cybermatch_hunting_v1.json"
AGENTIC_SECURITY_BENCHMARK_PATH = "benchmarks/cybermatch_agentic_security_v1.json"


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
            scenario = load_scenario(scenario_path)
        except ScenarioValidationError as exc:
            raise BenchmarkValidationError(f"Invalid benchmark scenario {scenario_path}: {exc}") from exc
        if metadata.get("type") in {"agentic_security", "agentic_resilience"} and scenario["evaluation"]["runner"] != "agentic_security_evaluation":
            raise BenchmarkValidationError(
                f"Agentic-security benchmark scenario has incompatible runner: {scenario_path}"
            )
        if metadata.get("type") == "threat_hunting" and scenario["evaluation"]["runner"] != "hunting_recipe_evaluation":
            raise BenchmarkValidationError(
                f"Threat-hunting benchmark scenario has incompatible runner: {scenario_path}"
            )

    if metadata.get("type") in {"agentic_security", "agentic_resilience"}:
        seeds = config.get("seeds", [0])
        if not isinstance(seeds, list) or not all(isinstance(seed, int) and not isinstance(seed, bool) for seed in seeds):
            raise BenchmarkValidationError("Benchmark seeds must be a list of integers.")
        if len(seeds) != len(set(seeds)):
            raise BenchmarkValidationError("Benchmark seeds must not contain duplicates.")
        if metadata.get("type") == "agentic_resilience":
            modes = config.get("defense_modes")
            from src.cybermatch.agentic.mode_runner import DEFENSE_MODES

            if modes != list(DEFENSE_MODES):
                raise BenchmarkValidationError(
                    "Agentic-resilience benchmark must declare all standard defense modes."
                )
            for name in ("protocol_catalog", "parameters", "sensitivity_axes"):
                if name not in config:
                    raise BenchmarkValidationError(f"Agentic-resilience benchmark requires {name}.")
        return

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
            from src.cybermatch.models.product import load_product_profile

            load_product_profile(str(product_path))
        except (json.JSONDecodeError, ValueError) as exc:
            raise BenchmarkValidationError(f"Product profile is invalid: {product_path_value}: {exc}") from exc

    seeds = config.get("seeds", [0])
    if not isinstance(seeds, list) or not all(isinstance(seed, int) for seed in seeds):
        raise BenchmarkValidationError("Benchmark seeds must be a list of integers.")

    if metadata.get("type") == "threat_hunting":
        _validate_hunting_benchmark_dimensions(config)


def _validate_hunting_benchmark_dimensions(config: Dict[str, Any]) -> None:
    recipes = config.get("recipes")
    if not isinstance(recipes, list) or not recipes:
        raise BenchmarkValidationError("Threat-hunting benchmark requires a non-empty recipes list.")
    recipe_root = (_resolve_repo_path("recipes/threat_hunting")).resolve()
    from src.cybermatch.threat_hunting import ThreatHuntingRecipeLoader

    loader = ThreatHuntingRecipeLoader(recipe_root)
    for recipe_path_value in recipes:
        if not isinstance(recipe_path_value, str) or not recipe_path_value:
            raise BenchmarkValidationError("Hunting recipe paths must be non-empty strings.")
        recipe_path = _resolve_repo_path(recipe_path_value).resolve()
        if not recipe_path.is_relative_to(recipe_root):
            raise BenchmarkValidationError(
                f"Hunting recipe must be below recipes/threat_hunting: {recipe_path_value}"
            )
        try:
            loader.load(recipe_path.relative_to(recipe_root))
        except ValueError as exc:
            raise BenchmarkValidationError(f"Invalid hunting recipe {recipe_path_value}: {exc}") from exc

    noise_profiles = config.get("noise_profiles")
    if not isinstance(noise_profiles, list) or not noise_profiles:
        raise BenchmarkValidationError(
            "Threat-hunting benchmark requires a non-empty noise_profiles list."
        )
    if any(not isinstance(value, str) for value in noise_profiles):
        raise BenchmarkValidationError("Hunting noise profiles must be strings.")
    if len(set(noise_profiles)) != len(noise_profiles):
        raise BenchmarkValidationError("Hunting noise profiles must not contain duplicates.")
    invalid = sorted(set(noise_profiles) - ALLOWED_HUNTING_NOISE_PROFILES)
    if invalid:
        raise BenchmarkValidationError(f"Unsupported hunting noise profiles: {invalid}")
    if not config.get("topologies"):
        raise BenchmarkValidationError("Threat-hunting benchmark requires at least one topology.")


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


def hunting_evaluation_matrix_size(config: Dict[str, Any]) -> int:
    """Return the complete H3 axis product without changing Standard v1 semantics."""

    return (
        evaluation_matrix_size(config)
        * len(config.get("recipes", []))
        * len(config.get("noise_profiles", []))
        * len(config.get("seeds", [0]))
    )


def list_available_benchmarks(benchmark_dir: str | None = None) -> List[Path]:
    base_dir = _resolve_repo_path(benchmark_dir) if benchmark_dir else BENCHMARK_DIR
    if not base_dir.exists():
        return []
    return sorted(base_dir.glob("*.json"))


def load_standard_benchmark() -> Dict[str, Any]:
    return load_benchmark(STANDARD_BENCHMARK_PATH)


def load_hunting_benchmark() -> Dict[str, Any]:
    return load_benchmark(HUNTING_BENCHMARK_PATH)


def load_agentic_security_benchmark() -> Dict[str, Any]:
    return load_benchmark(AGENTIC_SECURITY_BENCHMARK_PATH)
