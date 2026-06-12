"""Scenario import foundation for CyberMatch Phase8.1.

The loader validates lightweight JSON scenarios and dispatches to existing
product evaluation runners. It does not add simulation logic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parent

ALLOWED_RUNNERS = {
    "phase62_product_profile",
    "phase63_mission_aware_product",
}

ALLOWED_MISSIONS = {
    "profit",
    "achievement",
    "persistence",
    "critical_hunter",
}

ALLOWED_TOPOLOGY_PRESETS = {
    "default_enterprise",
    "small_business",
    "enterprise",
    "cloud_native",
    "ot_environment",
    "hospital_network",
}

ALLOWED_CHARACTERISTIC_LEVELS = {
    "low",
    "medium",
    "high",
}

CATALOG_DIR = ROOT / "scenarios" / "catalog"


class ScenarioValidationError(ValueError):
    """Raised when an imported CyberMatch scenario is invalid."""


def _resolve_repo_path(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return ROOT / path


def load_scenario(path: str) -> Dict[str, Any]:
    """Load and validate a scenario JSON file."""

    scenario_path = _resolve_repo_path(path)
    try:
        scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ScenarioValidationError(f"Scenario file not found: {scenario_path}") from exc
    except json.JSONDecodeError as exc:
        raise ScenarioValidationError(f"Scenario JSON is invalid: {scenario_path}: {exc}") from exc

    if not isinstance(scenario, dict):
        raise ScenarioValidationError("Scenario root must be a JSON object.")
    validate_scenario(scenario)
    return scenario


def validate_scenario(scenario: Dict[str, Any]) -> None:
    """Validate the minimal Phase8.1 scenario schema."""

    metadata = scenario.get("metadata")
    if not isinstance(metadata, dict) or not metadata.get("name"):
        raise ScenarioValidationError("Scenario requires metadata.name.")

    evaluation = scenario.get("evaluation")
    if not isinstance(evaluation, dict) or not evaluation.get("runner"):
        raise ScenarioValidationError("Scenario requires evaluation.runner.")

    runner = evaluation["runner"]
    if runner not in ALLOWED_RUNNERS:
        raise ScenarioValidationError(f"Unsupported runner: {runner}")
    seeds = evaluation.get("seeds")
    if seeds is not None:
        if not isinstance(seeds, list) or not all(isinstance(seed, int) for seed in seeds):
            raise ScenarioValidationError("evaluation.seeds must be a list of integers when provided.")

    missions = scenario.get("missions")
    if not isinstance(missions, list) or not missions:
        raise ScenarioValidationError("Scenario requires a non-empty missions list.")
    invalid_missions = [mission for mission in missions if mission not in ALLOWED_MISSIONS]
    if invalid_missions:
        raise ScenarioValidationError(f"Unsupported missions: {invalid_missions}")

    products = scenario.get("products")
    if not isinstance(products, list) or not products:
        raise ScenarioValidationError("Scenario requires a non-empty products list.")
    for product_path_value in products:
        if not isinstance(product_path_value, str) or not product_path_value:
            raise ScenarioValidationError("Product paths must be non-empty strings.")
        product_path = _resolve_repo_path(product_path_value)
        if not product_path.is_file():
            raise ScenarioValidationError(f"Product profile not found: {product_path_value}")
        try:
            json.loads(product_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ScenarioValidationError(f"Product profile JSON is invalid: {product_path_value}: {exc}") from exc

    topology = scenario.get("topology", {})
    if not isinstance(topology, dict):
        raise ScenarioValidationError("topology must be an object when provided.")
    topology_preset = topology.get("preset", "default_enterprise")
    if topology_preset not in ALLOWED_TOPOLOGY_PRESETS:
        raise ScenarioValidationError(f"Unsupported topology preset: {topology_preset}")
    try:
        from topology_loader import TopologyValidationError, resolve_topology_preset

        resolve_topology_preset(str(topology_preset))
    except TopologyValidationError as exc:
        raise ScenarioValidationError(f"Invalid topology preset {topology_preset}: {exc}") from exc

    characteristics = scenario.get("characteristics")
    if characteristics is not None:
        if not isinstance(characteristics, dict):
            raise ScenarioValidationError("characteristics must be an object when provided.")
        critical_asset_count = characteristics.get("critical_asset_count")
        if not isinstance(critical_asset_count, int) or not 1 <= critical_asset_count <= 5:
            raise ScenarioValidationError("characteristics.critical_asset_count must be an integer from 1 to 5.")
        for key in ("identity_dependency", "operational_sensitivity", "deception_effectiveness"):
            value = characteristics.get(key)
            if value not in ALLOWED_CHARACTERISTIC_LEVELS:
                raise ScenarioValidationError(f"characteristics.{key} must be low, medium, or high.")


def list_available_scenarios(catalog_dir: str | None = None) -> List[Path]:
    """List JSON scenarios from the reusable scenario catalog."""

    base_dir = _resolve_repo_path(catalog_dir) if catalog_dir else CATALOG_DIR
    if not base_dir.exists():
        return []
    return sorted(base_dir.glob("*.json"))


def load_scenario_catalog(catalog_dir: str | None = None) -> List[Dict[str, Any]]:
    """Load and validate all scenarios from the reusable scenario catalog."""

    scenarios: List[Dict[str, Any]] = []
    for scenario_path in list_available_scenarios(catalog_dir):
        scenarios.append(load_scenario(str(scenario_path)))
    return scenarios


def run_scenario_from_file(path: str) -> Dict[str, Any]:
    """Run a validated scenario with an existing Phase6 product evaluation runner."""

    scenario = load_scenario(path)
    metadata = scenario["metadata"]
    evaluation = scenario["evaluation"]
    runner = evaluation["runner"]
    output_dir = evaluation.get("output_dir")
    seeds = evaluation.get("seeds")
    runner_kwargs: Dict[str, Any] = {}
    if output_dir:
        runner_kwargs["output_dir"] = output_dir
    if seeds is not None:
        runner_kwargs["seeds"] = seeds

    from run_scenarios import run_phase62_product_profile_evaluation, run_phase63_mission_aware_product_evaluation

    if runner == "phase62_product_profile":
        rows = run_phase62_product_profile_evaluation(**runner_kwargs)
    elif runner == "phase63_mission_aware_product":
        rows = run_phase63_mission_aware_product_evaluation(**runner_kwargs)
    else:
        raise ScenarioValidationError(f"Unsupported runner: {runner}")

    return {
        "scenario_name": metadata["name"],
        "runner": runner,
        "output_dir": output_dir,
        "rows": len(rows) if rows is not None else 0,
        "success": True,
    }
