"""Transparent scoring used to prioritize CyberMatch fuzz cases."""

from __future__ import annotations

import math
from typing import Mapping


GUIDANCE_WEIGHTS = {
    "inference_uncertainty": 0.20,
    "decision_path_rarity": 0.20,
    "detection_gap": 0.20,
    "detection_latency_norm": 0.15,
    "containment_gap": 0.15,
    "semantic_novelty": 0.10,
}


def _score(value: object, name: str) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"analysis guidance {name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError(f"analysis guidance {name} must be between 0 and 1")
    return result


def score_analysis_guidance(values: Mapping[str, object] | None) -> dict[str, object]:
    """Return the auditable fixed-weight F3 priority score."""

    supplied = dict(values or {})
    unknown = sorted(set(supplied) - set(GUIDANCE_WEIGHTS))
    if unknown:
        raise ValueError(f"unknown analysis guidance fields: {', '.join(unknown)}")
    components = {name: _score(supplied.get(name), name) for name in GUIDANCE_WEIGHTS}
    priority = sum(GUIDANCE_WEIGHTS[name] * components[name] for name in GUIDANCE_WEIGHTS)
    return {
        "components": components,
        "weights": dict(GUIDANCE_WEIGHTS),
        "priority_score": float(priority),
        "fallback_equal_weight": not bool(values),
    }


__all__ = ["GUIDANCE_WEIGHTS", "score_analysis_guidance"]
