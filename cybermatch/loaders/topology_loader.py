"""Enterprise topology preset loader for CyberMatch Phase8.4."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


# Repository root: cybermatch/loaders/<module>.py -> parents[2].
ROOT = Path(__file__).resolve().parents[2]
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
    if "schema_version" in topology and "topology_id" in topology:
        # Phase 9 CPS network topology (schema.json alternative branch)
        if not isinstance(topology.get("topology_id"), str) or not topology["topology_id"]:
            raise TopologyValidationError("Topology requires topology_id.")
        zones = topology.get("zones")
        if not isinstance(zones, list) or len(zones) == 0:
            raise TopologyValidationError("Topology requires at least one zone.")
        if not all(isinstance(z, dict) and "node_id" in z for z in zones):
            raise TopologyValidationError("Each zone in topology must be a dict with node_id.")
        controls = topology.get("controls")
        if not isinstance(controls, list) or len(controls) == 0:
            raise TopologyValidationError("Topology requires at least one control.")
        if not all(isinstance(c, dict) and "control_id" in c for c in controls):
            raise TopologyValidationError("Each control in topology must be a dict with control_id.")
        return

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
