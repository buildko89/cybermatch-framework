"""Deterministic case scheduling and semantic novelty signatures."""

from __future__ import annotations

import hashlib
from typing import Iterable

from src.cybermatch.threat_hunting import canonical_json

from .models import FuzzCase


def semantic_signature(case: FuzzCase) -> str:
    payload = [
        {
            "step": event.step,
            "event_type": event.event_type,
            "source_role": event.source_role,
            "target_role": event.target_role,
            "attributes": dict(event.attributes),
        }
        for event in case.events
    ]
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def schedule_cases(cases: Iterable[FuzzCase]) -> tuple[FuzzCase, ...]:
    return tuple(
        sorted(
            cases,
            key=lambda case: (
                -float(case.analysis_guidance.get("priority_score", 0.0)),
                case.case_id,
            ),
        )
    )


__all__ = ["schedule_cases", "semantic_signature"]
