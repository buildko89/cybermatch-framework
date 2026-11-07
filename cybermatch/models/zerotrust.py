"""Zero trust assessment value objects."""

from dataclasses import dataclass
from collections.abc import Mapping
from enum import IntEnum, StrEnum
from math import isfinite
from types import MappingProxyType


class MaturityLevel(IntEnum):
    TRADITIONAL = 1
    INITIAL = 2
    ADVANCED = 3
    OPTIMAL = 4


class ZTPillar(StrEnum):
    IDENTITY = "identity"
    DEVICE = "device"
    NETWORK = "network"
    APPLICATION = "application"
    DATA = "data"


class MFABypassVector(StrEnum):
    SIM_SWAP = "sim_swap"
    PUSH_BOMBING = "push_bombing"
    AITM_TOKEN_THEFT = "aitm_token_theft"


@dataclass(frozen=True)
class MFAMitigation:
    fido2_passkey: bool = False
    number_matching: bool = False
    token_binding_cae: bool = False
    device_compliance_required: bool = False


def _unit_interval(value: float) -> None:
    if not isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError("score and containment_factor must be finite and within [0, 1]")


@dataclass(frozen=True)
class PillarAssessment:
    pillar: ZTPillar
    level: MaturityLevel
    score: float
    unmet_requirements: tuple[str, ...]

    def __post_init__(self) -> None:
        _unit_interval(self.score)
        object.__setattr__(self, "unmet_requirements", tuple(self.unmet_requirements))


@dataclass(frozen=True)
class ZeroTrustAssessmentResult:
    overall_score: float
    pillars: Mapping[ZTPillar, PillarAssessment]
    containment_factor: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "pillars", MappingProxyType(dict(self.pillars)))
        _unit_interval(self.overall_score)
        _unit_interval(self.containment_factor)
        if set(self.pillars) != set(ZTPillar):
            raise ValueError("all five pillars are required")
        if any(key != value.pillar for key, value in self.pillars.items()):
            raise ValueError("pillar keys must match their assessments")
