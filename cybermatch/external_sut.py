"""Stable, transport-neutral contract for external systems under test.

The contract deliberately contains observable ``HuntEvent`` values only. Ground
truth remains evaluator-side and cannot be passed to an SUT implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence, runtime_checkable

from .threat_hunting.config import ThreatHuntingRunConfig
from .threat_hunting.engine import ThreatHuntingEngine
from .threat_hunting.models import Finding, HuntEvent
from .threat_hunting.recipes import ThreatHuntingRecipe


EXTERNAL_SUT_CONTRACT_VERSION = "1.0"
EVIDENCE_CLASSES = frozenset({"synthetic-only", "replay-backed", "external-sut-backed"})
SUT_STATUSES = frozenset({"succeeded", "infrastructure_error", "inconclusive"})


@dataclass(frozen=True)
class ExternalSUTRequest:
    run_id: str
    events: tuple[HuntEvent, ...]
    evidence_class: str
    detector_id: str
    detector_version: str
    contract_version: str = EXTERNAL_SUT_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.contract_version != EXTERNAL_SUT_CONTRACT_VERSION:
            raise ValueError("unsupported external SUT contract version")
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        if self.evidence_class not in EVIDENCE_CLASSES:
            raise ValueError("unsupported evidence_class")
        for value, name in ((self.detector_id, "detector_id"), (self.detector_version, "detector_version")):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        values = tuple(self.events)
        if any(not isinstance(event, HuntEvent) for event in values):
            raise ValueError("events must contain HuntEvent observations only")
        object.__setattr__(self, "events", values)

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "run_id": self.run_id,
            "evidence_class": self.evidence_class,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "events": [event.to_dict() for event in self.events],
        }


@dataclass(frozen=True)
class ExternalSUTResponse:
    adapter_id: str
    adapter_version: str
    status: str
    findings: tuple[Finding, ...] = ()
    detail: str | None = None
    contract_version: str = EXTERNAL_SUT_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.contract_version != EXTERNAL_SUT_CONTRACT_VERSION:
            raise ValueError("unsupported external SUT contract version")
        for value, name in ((self.adapter_id, "adapter_id"), (self.adapter_version, "adapter_version")):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if self.status not in SUT_STATUSES:
            raise ValueError("unsupported external SUT status")
        findings = tuple(self.findings)
        if any(not isinstance(finding, Finding) for finding in findings):
            raise ValueError("findings must contain Finding values only")
        if self.status != "succeeded" and findings:
            raise ValueError("non-successful responses must not contain findings")
        object.__setattr__(self, "findings", findings)


@runtime_checkable
class ExternalSUTAdapter(Protocol):
    """Replaceable SUT boundary; implementations may be local or externally backed."""

    adapter_id: str
    adapter_version: str

    def evaluate(self, request: ExternalSUTRequest) -> ExternalSUTResponse: ...


class InProcessHuntingSUTAdapter:
    """Reference adapter using the built-in engine through the public SUT boundary."""

    adapter_id = "cybermatch-in-process-hunting"
    adapter_version = "1.0.0"

    def __init__(self, recipe: ThreatHuntingRecipe, config: ThreatHuntingRunConfig | None = None):
        self.recipe = recipe
        self.config = config or ThreatHuntingRunConfig()

    def evaluate(self, request: ExternalSUTRequest) -> ExternalSUTResponse:
        findings = ThreatHuntingEngine(self.config).run(self.recipe, request.events)
        return ExternalSUTResponse(
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            status="succeeded",
            findings=tuple(findings),
        )


def validate_sut_response(request: ExternalSUTRequest, response: ExternalSUTResponse) -> None:
    """Reject findings that reference hidden or unrelated observations."""

    known = {event.event_id for event in request.events}
    for finding in response.findings:
        if not set(finding.evidence_event_ids).issubset(known):
            raise ValueError("SUT finding references an event absent from the request")
        if finding.campaign_id not in {event.campaign_id for event in request.events}:
            raise ValueError("SUT finding campaign does not match the request")
        if (finding.recipe_id, finding.recipe_version) != (
            request.detector_id,
            request.detector_version,
        ):
            raise ValueError("SUT finding detector metadata does not match the request")


__all__ = [
    "EVIDENCE_CLASSES",
    "EXTERNAL_SUT_CONTRACT_VERSION",
    "SUT_STATUSES",
    "ExternalSUTAdapter",
    "ExternalSUTRequest",
    "ExternalSUTResponse",
    "InProcessHuntingSUTAdapter",
    "validate_sut_response",
]
