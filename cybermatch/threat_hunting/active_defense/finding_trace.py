"""Findingと、それを生んだ仮説・内部観測・外部予兆の対応を記録するsidecar。

Findingの`evidence_event_ids`は実際にengineへ渡した内部観測だけを参照する。CTI/ASM/binding
との対応はFinding本体ではなく、本traceの`context_observation_refs`へ分けて記録する。
検知時刻は初めてFindingを生成したstep（detected_step）であり、観測の発生stepではない。
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from ..models import Finding, HuntEvent
from . import contract_validation as cv
from .contract_validation import ActiveDefenseContractError


@dataclass(frozen=True)
class FindingTrace:
    finding_id: str
    recipe_id: str
    recipe_hash: str
    detected_step: int
    finding_start_step: int
    finding_end_step: int
    hypothesis_ids: tuple[str, ...]
    observation_refs: tuple[str, ...]
    context_observation_refs: tuple[str, ...]
    evaluation_status: str = "evaluated"

    @property
    def response_eligible(self) -> bool:
        """内部観測の証拠を持つFindingだけが、後続（T3）の対処判断へ進める。"""
        return self.evaluation_status == "evaluated" and bool(self.observation_refs)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION, "finding_id": self.finding_id,
            "recipe_id": self.recipe_id, "recipe_hash": self.recipe_hash,
            "detected_step": self.detected_step, "finding_start_step": self.finding_start_step,
            "finding_end_step": self.finding_end_step, "hypothesis_ids": list(self.hypothesis_ids),
            "observation_refs": list(self.observation_refs),
            "context_observation_refs": list(self.context_observation_refs),
            "evaluation_status": self.evaluation_status, "response_eligible": self.response_eligible,
        }


@dataclass
class _Entry:
    finding: Finding
    recipe_hash: str
    detected_step: int
    hypothesis_ids: set[str] = field(default_factory=set)
    context_refs: set[str] = field(default_factory=set)


class FindingTraceLedger:
    """finding_id単位で最初の検知stepを固定し、後続の重複検知は仮説の対応だけを追加する。"""

    def __init__(self) -> None:
        self._entries: dict[str, _Entry] = {}

    def record(self, *, step: int, hypothesis_id: str, recipe_hash: str, finding: Finding,
               input_events: Sequence[HuntEvent], context_refs: Iterable[str]) -> bool:
        """新規FindingならTrueを返す。未入力eventや未到着eventを引用するFindingは拒否する。"""
        cv.step(step, "step")
        by_id = {event.event_id: event for event in input_events}
        if not finding.evidence_event_ids or any(ref not in by_id for ref in finding.evidence_event_ids):
            raise ActiveDefenseContractError("Findingがengineへ渡していない観測を引用しています")
        if any(int(by_id[ref].attributes["available_step"]) > step for ref in finding.evidence_event_ids):
            raise ActiveDefenseContractError("Findingが検知時点で未到着の観測を引用しています")
        entry = self._entries.get(finding.finding_id)
        is_new = entry is None
        if entry is None:
            entry = _Entry(finding=finding, recipe_hash=recipe_hash, detected_step=step)
            self._entries[finding.finding_id] = entry
        elif entry.recipe_hash != recipe_hash:
            raise ActiveDefenseContractError("同一finding_idが異なるrecipe hashから生成されました")
        entry.hypothesis_ids.add(hypothesis_id)
        entry.context_refs.update(context_refs)
        return is_new

    def findings(self) -> tuple[Finding, ...]:
        return tuple(entry.finding for _, entry in sorted(self._entries.items()))

    def traces(self) -> tuple[FindingTrace, ...]:
        return tuple(
            FindingTrace(
                finding_id=finding_id, recipe_id=entry.finding.recipe_id, recipe_hash=entry.recipe_hash,
                detected_step=entry.detected_step, finding_start_step=entry.finding.start_step,
                finding_end_step=entry.finding.end_step, hypothesis_ids=tuple(sorted(entry.hypothesis_ids)),
                observation_refs=tuple(entry.finding.evidence_event_ids),
                context_observation_refs=tuple(sorted(entry.context_refs)),
            )
            for finding_id, entry in sorted(self._entries.items(), key=lambda item: (item[1].detected_step, item[0]))
        )


__all__ = ["FindingTrace", "FindingTraceLedger"]
