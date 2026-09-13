"""Pure probability-vector operations used by simulation state updates."""

import numpy as np


def normalize_probability_vector(values: np.ndarray, *, size: int) -> np.ndarray:
    """Clip negative values and normalize, using a uniform zero-mass fallback."""
    vector = np.asarray(values, dtype=float)
    if vector.shape != (size,):
        raise ValueError(f"expected probability vector of shape ({size},), got {vector.shape}")
    clipped = np.clip(vector, 0.0, None)
    total = float(np.sum(clipped))
    if total <= 0.0:
        return np.full(size, 1.0 / size, dtype=float)
    return clipped / total
