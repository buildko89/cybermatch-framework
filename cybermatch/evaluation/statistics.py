"""Small, deterministic statistics helpers shared by evaluation workflows."""

from collections.abc import Sequence

import numpy as np


def to_float(value: object) -> float:
    """Convert an evaluation value to float, treating missing cells as zero."""
    if value is None or value == "":
        return 0.0
    return float(value)


def mean_or_none(values: Sequence[float]) -> float | None:
    """Return the population mean, or ``None`` for an empty sequence."""
    if not values:
        return None
    return float(np.mean(values))


def std_or_none(values: Sequence[float]) -> float | None:
    """Return the population standard deviation, or ``None`` when empty."""
    if not values:
        return None
    return float(np.std(values))
