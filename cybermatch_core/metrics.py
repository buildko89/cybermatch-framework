"""Small shared metric helpers for reporting code."""

from __future__ import annotations

from typing import Iterable


def safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def mean(values: Iterable[object]) -> float:
    numeric_values = [safe_float(value) for value in values]
    if not numeric_values:
        return 0.0
    return sum(numeric_values) / len(numeric_values)


__all__ = [
    "mean",
    "safe_float",
]
