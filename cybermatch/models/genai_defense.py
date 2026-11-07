"""Immutable results for heuristic GenAI input screening."""

from dataclasses import dataclass
from enum import StrEnum
from math import isfinite


class GenAIRiskCategory(StrEnum):
    PROMPT_INJECTION_DIRECT = "prompt_injection_direct"
    PROMPT_INJECTION_INDIRECT = "prompt_injection_indirect"
    SENSITIVE_DATA_LEAKAGE = "sensitive_data_leakage"
    DEEPFAKE_BEC_ATTEMPT = "deepfake_bec_attempt"
    # Out of scope and unevaluated by input screening; reserved for future output validation.
    INSECURE_OUTPUT_HANDLING = "insecure_output_handling"


class GenAISeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class GenAIRiskFinding:
    category: GenAIRiskCategory
    severity: GenAISeverity
    matched_pattern: str
    description: str
    owasp_llm_id: str
    business_impact: str
    mitigation_guidance: str


@dataclass(frozen=True)
class GenAIEvaluationResult:
    findings: tuple[GenAIRiskFinding, ...]
    safety_score: float
    business_summary: str
    is_safe_to_process: bool

    def __post_init__(self) -> None:
        """Recompute is_safe_to_process from finding severities, overriding the supplied value."""
        if (isinstance(self.safety_score, bool)
                or not isinstance(self.safety_score, (int, float))
                or not isfinite(self.safety_score)
                or not 0 <= self.safety_score <= 1):
            raise ValueError("safety_score must be finite and within [0, 1]")
        findings = tuple(self.findings)
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "is_safe_to_process", not any(
            f.severity in (GenAISeverity.CRITICAL, GenAISeverity.HIGH) for f in findings))
