"""CyberMatch implementation package.

``cybermatch_core`` is the stable facade for integrations. The names below keep
1.x code such as ``from cybermatch import CyberDefenseSimulator`` working; they
are resolved lazily (PEP 562) so importing a subpackage stays lightweight.
"""

from __future__ import annotations

from importlib import import_module

_LEGACY_EXPORTS = {
    "CyberDefenseSimulator": "cybermatch.simulation.simulator",
    "HuntingCapabilities": "cybermatch.models.product",
    "ProductProfile": "cybermatch.models.product",
    "load_product_profile": "cybermatch.models.product",
    "SimulationConfig": "cybermatch.config.simulation_config",
    "Visualizer": "cybermatch.visualization.visualizer",
    "AttackerModel": "cybermatch.attacker.attacker_model",
    "OptimizationEngine": "cybermatch.defense.ilp_mpc_strategy",
}

__all__ = sorted(_LEGACY_EXPORTS)


def __getattr__(name: str):
    module = _LEGACY_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(import_module(module), name)
