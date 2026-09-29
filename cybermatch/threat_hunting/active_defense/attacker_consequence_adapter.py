"""T4b: 攻撃者へ観測可能な防御結果だけを通知する境界adapter。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .stateful_mock_world import OperationOutcome


class ConsequenceObserver(Protocol):
    def observe_defender_consequence(self, *, blocked: bool, delayed: bool, detected: bool,
                                     redirected: bool, confidence_decay: float,
                                     frustration_increase: float) -> None: ...


@dataclass(frozen=True)
class ObservableDefenderConsequence:
    """Finding、CTI、score、truthを含まない攻撃者観測。"""

    blocked: bool
    delayed: bool
    detected: bool
    redirected: bool

    def to_dict(self) -> dict[str, bool]:
        return dict(self.__dict__)


class AttackerConsequenceAdapter:
    def __init__(self, *, confidence_decay: float = 0.9, frustration_increase: float = 1.0):
        if not 0.0 <= confidence_decay <= 1.0 or frustration_increase < 0.0:
            raise ValueError("attacker consequence係数が範囲外です")
        self.confidence_decay = float(confidence_decay)
        self.frustration_increase = float(frustration_increase)

    @staticmethod
    def from_operation_outcome(outcome: OperationOutcome) -> ObservableDefenderConsequence:
        if not isinstance(outcome, OperationOutcome):
            raise TypeError("OperationOutcomeだけを変換できます")
        return ObservableDefenderConsequence(
            blocked=outcome.status == "blocked", delayed=False, detected=False, redirected=False)

    def notify(self, observer: ConsequenceObserver, consequence: ObservableDefenderConsequence) -> None:
        if not isinstance(consequence, ObservableDefenderConsequence):
            raise TypeError("ObservableDefenderConsequenceだけを通知できます")
        observer.observe_defender_consequence(
            blocked=consequence.blocked, delayed=consequence.delayed, detected=consequence.detected,
            redirected=consequence.redirected, confidence_decay=self.confidence_decay,
            frustration_increase=self.frustration_increase)


__all__ = ["AttackerConsequenceAdapter", "ConsequenceObserver", "ObservableDefenderConsequence"]
