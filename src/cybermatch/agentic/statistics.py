"""Dependency-light statistical summaries for paired Agentic benchmarks."""

from __future__ import annotations

import math
from collections.abc import Sequence


def distribution(values: Sequence[float]) -> dict[str, float | int]:
    if not values:
        raise ValueError("distribution requires at least one value")
    numeric = [float(value) for value in values]
    count = len(numeric)
    mean = sum(numeric) / count
    variance = sum((value - mean) ** 2 for value in numeric) / (count - 1) if count > 1 else 0.0
    std = math.sqrt(variance)
    margin = 1.96 * std / math.sqrt(count)
    return {
        "count": count,
        "mean": mean,
        "std": std,
        "ci95_low": mean - margin,
        "ci95_high": mean + margin,
        "min": min(numeric),
        "max": max(numeric),
    }


def paired_effect(
    baseline: Sequence[float], treatment: Sequence[float], *, lower_is_better: bool = True
) -> dict[str, float | int]:
    if len(baseline) != len(treatment) or not baseline:
        raise ValueError("paired effect requires equally sized, non-empty samples")
    improvements = [
        (float(left) - float(right)) if lower_is_better else (float(right) - float(left))
        for left, right in zip(baseline, treatment, strict=True)
    ]
    wins = sum(value > 0 for value in improvements)
    losses = sum(value < 0 for value in improvements)
    ties = len(improvements) - wins - losses
    return {
        "paired_mean_improvement": sum(improvements) / len(improvements),
        "paired_win_rate": wins / len(improvements),
        "rank_biserial_effect_size": (wins - losses) / len(improvements),
        "wins": wins,
        "losses": losses,
        "ties": ties,
    }


__all__ = ["distribution", "paired_effect"]
