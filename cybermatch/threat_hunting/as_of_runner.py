"""到着済み観測snapshotだけを既存hunting engineへ渡すT2接続点。"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .engine import ThreatHuntingEngine
from .models import Finding, HuntEvent
from .recipes import ThreatHuntingRecipe
from .t0_observation_adapter import T0ObservationAdapter


class AsOfThreatHuntingRunnerError(ValueError):
    """as-of runnerの構成または入力が不正。"""


@dataclass(frozen=True)
class AsOfFindingTrace:
    """as-of実行で実際に使った観測・recipe・Findingの最小証跡。"""

    current_step: int
    recipe_id: str
    recipe_hash: str
    event_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "current_step": self.current_step,
            "recipe_id": self.recipe_id,
            "recipe_hash": self.recipe_hash,
            "event_ids": list(self.event_ids),
            "finding_ids": list(self.finding_ids),
        }


@dataclass(frozen=True)
class AsOfThreatHuntingResult:
    """as-of step、実際に検知器へ渡した観測、生成Findingを結び付ける。"""

    current_step: int
    events: tuple[HuntEvent, ...]
    findings: tuple[Finding, ...]
    trace: AsOfFindingTrace

    def to_dict(self) -> dict[str, object]:
        """Evidence Bundleの入力にできる、到着済み結果だけのwire形式。"""
        return {
            "current_step": self.current_step,
            "events": [event.to_dict() for event in self.events],
            "findings": [finding.to_dict() for finding in self.findings],
            "trace": self.trace.to_dict(),
        }


class AsOfThreatHuntingRunner:
    """truthを引数に持たない、決定論的な観測→recipe実行接続点。"""

    def __init__(self, *, adapter: T0ObservationAdapter, engine: ThreatHuntingEngine | None = None):
        if not isinstance(adapter, T0ObservationAdapter):
            raise AsOfThreatHuntingRunnerError("adapterはT0ObservationAdapterで指定してください")
        if engine is not None and not isinstance(engine, ThreatHuntingEngine):
            raise AsOfThreatHuntingRunnerError("engineはThreatHuntingEngineで指定してください")
        self._adapter = adapter
        self._engine = engine or ThreatHuntingEngine()

    def run(
        self, *, recipe: ThreatHuntingRecipe, payloads: Iterable[Mapping[str, object]], current_step: int,
    ) -> AsOfThreatHuntingResult:
        if not isinstance(recipe, ThreatHuntingRecipe):
            raise AsOfThreatHuntingRunnerError("recipeは検証済みThreatHuntingRecipeで指定してください")
        events = self._adapter.adapt_snapshot(payloads, current_step=current_step)
        findings = tuple(self._engine.run(recipe, events))
        trace = AsOfFindingTrace(
            current_step=current_step,
            recipe_id=recipe.recipe_id,
            recipe_hash=recipe.recipe_hash,
            event_ids=tuple(event.event_id for event in events),
            finding_ids=tuple(finding.finding_id for finding in findings),
        )
        return AsOfThreatHuntingResult(current_step=current_step, events=events, findings=findings, trace=trace)


__all__ = ["AsOfFindingTrace", "AsOfThreatHuntingResult", "AsOfThreatHuntingRunner", "AsOfThreatHuntingRunnerError"]
