"""Enterprise topology preset loader for CyberMatch Phase8.4."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parent
TOPOLOGY_DIR = ROOT / "topologies"

ALLOWED_TOPOLOGY_LEVELS = {
    "low",
    "medium",
    "high",
}

TOPOLOGY_ALIASES = {
    "default_enterprise": "enterprise",
}


class TopologyValidationError(ValueError):
    """Raised when a topology preset is invalid."""


def _resolve_repo_path(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return ROOT / path


def _topology_path_from_preset(preset: str) -> Path:
    name = TOPOLOGY_ALIASES.get(preset, preset)
    return TOPOLOGY_DIR / f"{name}.json"


def load_topology(path: str) -> Dict[str, Any]:
    topology_path = _topology_path_from_preset(path) if "/" not in path and "\\" not in path and not path.endswith(".json") else _resolve_repo_path(path)
    try:
        topology = json.loads(topology_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TopologyValidationError(f"Topology file not found: {topology_path}") from exc
    except json.JSONDecodeError as exc:
        raise TopologyValidationError(f"Topology JSON is invalid: {topology_path}: {exc}") from exc

    if not isinstance(topology, dict):
        raise TopologyValidationError("Topology root must be a JSON object.")
    validate_topology(topology)
    return topology


def validate_topology(topology: Dict[str, Any]) -> None:
    metadata = topology.get("metadata")
    if not isinstance(metadata, dict) or not metadata.get("name"):
        raise TopologyValidationError("Topology requires metadata.name.")

    characteristics = topology.get("characteristics")
    if not isinstance(characteristics, dict):
        raise TopologyValidationError("Topology requires characteristics.")

    critical_assets = characteristics.get("critical_assets")
    if not isinstance(critical_assets, int) or not 1 <= critical_assets <= 10:
        raise TopologyValidationError("characteristics.critical_assets must be an integer from 1 to 10.")

    for key in (
        "identity_centralization",
        "lateral_movement_complexity",
        "deception_surface",
        "operational_sensitivity",
    ):
        value = characteristics.get(key)
        if value not in ALLOWED_TOPOLOGY_LEVELS:
            raise TopologyValidationError(f"characteristics.{key} must be low, medium, or high.")


def list_available_topologies(topology_dir: str | None = None) -> List[Path]:
    base_dir = _resolve_repo_path(topology_dir) if topology_dir else TOPOLOGY_DIR
    if not base_dir.exists():
        return []
    return sorted(base_dir.glob("*.json"))


def resolve_topology_preset(preset: str) -> Dict[str, Any]:
    return load_topology(preset)
