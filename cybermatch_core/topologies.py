"""Topology library compatibility exports."""

from __future__ import annotations

from src.cybermatch.loaders.topology_loader import (
    TopologyValidationError,
    list_available_topologies,
    load_topology,
    resolve_topology_preset,
    validate_topology,
)


__all__ = [
    "TopologyValidationError",
    "list_available_topologies",
    "load_topology",
    "resolve_topology_preset",
    "validate_topology",
]
