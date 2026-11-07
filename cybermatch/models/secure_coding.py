"""Immutable values for the local secure coding heuristic audit."""

from dataclasses import dataclass
from enum import StrEnum
from math import isfinite


class VulnerabilityCategory(StrEnum):
    SQLI = "sqli"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    IDOR_BOLA = "idor_bola"
    COMMAND_INJECTION = "command_injection"


class KillChainPhase(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "c2"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class VulnerabilityFinding:
    category: VulnerabilityCategory
    severity: Severity
    line_number: int
    matched_text: str
    description: str
    remediation_guide: str
    asvs_requirement: str


@dataclass(frozen=True)
class SecureCodingAuditResult:
    findings: tuple[VulnerabilityFinding, ...]
    asvs_score: float
    mitigated_killchain_phases: tuple[KillChainPhase, ...]

    def __post_init__(self) -> None:
        if (isinstance(self.asvs_score, bool)
                or not isinstance(self.asvs_score, (int, float))
                or not isfinite(self.asvs_score) or not 0 <= self.asvs_score <= 1):
            raise ValueError("asvs_score must be finite and within [0, 1]")
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "mitigated_killchain_phases",
                           tuple(self.mitigated_killchain_phases))
