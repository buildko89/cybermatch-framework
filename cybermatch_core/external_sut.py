"""Stable facade for the external SUT contract and replay evaluation."""

from src.cybermatch.external_sut import (
    EVIDENCE_CLASSES,
    EXTERNAL_SUT_CONTRACT_VERSION,
    SUT_STATUSES,
    ExternalSUTAdapter,
    ExternalSUTRequest,
    ExternalSUTResponse,
    InProcessHuntingSUTAdapter,
    validate_sut_response,
)
from src.cybermatch.threat_hunting.replay import run_external_replay_evaluation

__all__ = [
    "EVIDENCE_CLASSES",
    "EXTERNAL_SUT_CONTRACT_VERSION",
    "SUT_STATUSES",
    "ExternalSUTAdapter",
    "ExternalSUTRequest",
    "ExternalSUTResponse",
    "InProcessHuntingSUTAdapter",
    "run_external_replay_evaluation",
    "validate_sut_response",
]
