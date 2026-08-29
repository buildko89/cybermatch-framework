"""Typed feedback contract shared by offline and opt-in closed-loop hunting."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .models import stable_identifier


FEEDBACK_ACTION_TYPES = frozenset(
    {
        "observe_only",
        "increase_monitoring",
        "block_edge",
        "redirect_to_decoy",
        "require_additional_auth",
    }
)


@dataclass(frozen=True)
class ThreatHuntingFeedback:
    """A defender action request derived from a Finding."""

    feedback_id: str
    finding_id: str
    action_type: str
    effective_step: int
    duration_steps: int
    target_nodes: tuple[int, ...] = ()
    target_edges: tuple[tuple[int, int], ...] = ()
    confidence: float = 0.0
    reason: str = ""

    def __post_init__(self) -> None:
        for field_name in ("feedback_id", "finding_id", "reason"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
        if self.action_type not in FEEDBACK_ACTION_TYPES:
            allowed = ", ".join(sorted(FEEDBACK_ACTION_TYPES))
            raise ValueError(f"action_type must be one of: {allowed}")
        if isinstance(self.effective_step, bool) or not isinstance(self.effective_step, int) or self.effective_step < 0:
            raise ValueError("effective_step must be a non-negative integer")
        if isinstance(self.duration_steps, bool) or not isinstance(self.duration_steps, int) or self.duration_steps <= 0:
            raise ValueError("duration_steps must be a positive integer")

        nodes = tuple(self.target_nodes)
        if any(isinstance(node, bool) or not isinstance(node, int) or node < 0 for node in nodes):
            raise ValueError("target_nodes must contain non-negative integers")
        if len(set(nodes)) != len(nodes):
            raise ValueError("target_nodes must not contain duplicates")
        object.__setattr__(self, "target_nodes", nodes)

        edges = tuple(tuple(edge) for edge in self.target_edges)
        for edge in edges:
            if len(edge) != 2 or any(isinstance(node, bool) or not isinstance(node, int) or node < 0 for node in edge):
                raise ValueError("target_edges must contain pairs of non-negative integers")
        if len(set(edges)) != len(edges):
            raise ValueError("target_edges must not contain duplicates")
        object.__setattr__(self, "target_edges", edges)

        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise ValueError("confidence must be a finite number between 0 and 1")
        confidence = float(self.confidence)
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be a finite number between 0 and 1")
        object.__setattr__(self, "confidence", confidence)

    @classmethod
    def create(
        cls,
        *,
        finding_id: str,
        action_type: str,
        effective_step: int,
        duration_steps: int,
        target_nodes: tuple[int, ...] = (),
        target_edges: tuple[tuple[int, int], ...] = (),
        confidence: float = 0.0,
        reason: str,
    ) -> "ThreatHuntingFeedback":
        feedback_id = stable_identifier(
            "feedback",
            {
                "finding_id": finding_id,
                "action_type": action_type,
                "effective_step": effective_step,
                "duration_steps": duration_steps,
                "target_nodes": list(target_nodes),
                "target_edges": [list(edge) for edge in target_edges],
            },
        )
        return cls(
            feedback_id=feedback_id,
            finding_id=finding_id,
            action_type=action_type,
            effective_step=effective_step,
            duration_steps=duration_steps,
            target_nodes=target_nodes,
            target_edges=target_edges,
            confidence=confidence,
            reason=reason,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "feedback_id": self.feedback_id,
            "finding_id": self.finding_id,
            "action_type": self.action_type,
            "effective_step": self.effective_step,
            "duration_steps": self.duration_steps,
            "target_nodes": list(self.target_nodes),
            "target_edges": [list(edge) for edge in self.target_edges],
            "confidence": self.confidence,
            "reason": self.reason,
        }


@runtime_checkable
class ThreatHuntingFeedbackSink(Protocol):
    """Receiver for future defender-side feedback actions."""

    def submit(self, feedback: ThreatHuntingFeedback) -> None:
        """Accept a feedback request."""


class NullThreatHuntingFeedbackSink:
    """No-op sink used while threat hunting remains offline-only."""

    def submit(self, feedback: ThreatHuntingFeedback) -> None:
        if not isinstance(feedback, ThreatHuntingFeedback):
            raise TypeError("feedback must be a ThreatHuntingFeedback instance")


__all__ = [
    "FEEDBACK_ACTION_TYPES",
    "NullThreatHuntingFeedbackSink",
    "ThreatHuntingFeedback",
    "ThreatHuntingFeedbackSink",
]
