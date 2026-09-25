"""Fuzz target adapters. Targets receive observations, never ground truth."""

from .external import ExternalSUTTarget
from .threat_hunting import (
    FuzzTarget,
    PairedTargetResult,
    TargetManifest,
    ThreatHuntingClosedLoopTarget,
    ThreatHuntingEngineTarget,
)

__all__ = [
    "FuzzTarget",
    "ExternalSUTTarget",
    "PairedTargetResult",
    "TargetManifest",
    "ThreatHuntingClosedLoopTarget",
    "ThreatHuntingEngineTarget",
]
