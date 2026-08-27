"""Execution limits for the threat hunting engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping

from .models import SCHEMA_VERSION


@dataclass(frozen=True)
class ThreatHuntingRunConfig:
    """Explicit resource bounds for deterministic recipe execution."""

    schema_version: str = SCHEMA_VERSION
    max_events: int = 100_000
    max_window_steps: int = 10_000
    max_groups: int = 10_000
    max_sequence_length: int = 20
    max_regex_length: int = 512
    max_findings: int = 10_000

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, str) or not self.schema_version.strip():
            raise ValueError("schema_version must be a non-empty string")
        for field_name in (
            "max_events",
            "max_window_steps",
            "max_groups",
            "max_sequence_length",
            "max_regex_length",
            "max_findings",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ThreatHuntingRunConfig":
        if not isinstance(payload, Mapping):
            raise ValueError("ThreatHuntingRunConfig payload must be a mapping")
        return cls(**dict(payload))


__all__ = ["ThreatHuntingRunConfig"]
