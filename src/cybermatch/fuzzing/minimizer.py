"""Deterministic event-deletion minimizer for reproducible fuzz failures."""

from __future__ import annotations

from dataclasses import replace
from typing import Callable, Sequence

from src.cybermatch.threat_hunting import HuntEvent

from .models import FuzzCase


def minimize_events(
    case: FuzzCase,
    preserves_failure: Callable[[FuzzCase], bool],
) -> tuple[HuntEvent, ...]:
    """Delete events one at a time while the original failure remains.

    The implementation intentionally starts with a simple, deterministic
    reducer. Attribute and mutation-trace shrinking can be layered on without
    changing the artifact contract.
    """

    current = tuple(case.events)
    index = 0
    while len(current) > 1 and index < len(current):
        candidate_events = current[:index] + current[index + 1 :]
        candidate = replace(case, events=candidate_events)
        if preserves_failure(candidate):
            current = candidate_events
        else:
            index += 1
    return current


__all__ = ["minimize_events"]
