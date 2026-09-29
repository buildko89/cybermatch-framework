"""T2: CTI/ASM相関→仮説→scheduler→既存engineを、step順に決定論的に実行するrunner。

1 stepの処理順（計画§4.1のうちT2が担う部分）:
  1. このstepで到着した内部telemetryだけをbufferへ追加する（未到着は渡さない）
  2. 到着済みCTI/ASM/bindingで相関し、matchedの予兆からtemplateで仮説を作る
  3. schedulerが予算内のbindingを選び、scope内の到着済み観測でrecipeを実行する
  4. 生成Findingを`detected_step=t`としてtraceへ記録する
truth・evaluator専用labelは入力に持たない。対処要求（T3）は生成しない。
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cybermatch.contracts import (
    AssetSchemaError, SchemaRegistry, SensitiveDataHygieneError, assert_hygienic_payload, canonical_sha256,
)

from ..engine import ThreatHuntingEngine
from ..models import Finding, HuntEvent
from ..recipes import ThreatHuntingRecipeLoader
from ..t0_observation_adapter import T0ObservationAdapter, T0ObservationAdapterError
from . import contract_validation as cv
from .as_of_selection import validate_supersession
from .contract_validation import ActiveDefenseContractError
from .exposure_correlation import ExposureCorrelator, ExposureMatch
from .exposure_observations import ASMAssetObservation, CTIObservation, ObservedAssetBinding
from .finding_trace import FindingTrace, FindingTraceLedger
from .hypothesis_scheduler import (
    NOT_EVALUABLE_MISSING_FIELDS, HypothesisScheduler, SchedulerDecision, SchedulerPolicy, SelectedBinding,
)
from .hypothesis_templates import HypothesisGenerator, HypothesisSpec, HypothesisTemplateCatalog
from .priority_policy import PriorityPolicy

INTERNAL_TELEMETRY_KINDS = ("synthetic_internal_telemetry", "replay_internal_telemetry")
_SPEC_FIELDS = {"schema_version", "run_id", "scenario_id", "tenant_id", "seed", "horizon_steps",
                "observation_fixture", "priority_policy", "scheduler_policy", "hypothesis_templates",
                "recipe_root"}
_FIXTURE_FIELDS = {"schema_version", "fixture_id", "run_id", "tenant_id", "evidence_class", "description",
                   "cti_observations", "asm_observations", "asset_bindings", "internal_telemetry"}
_MAX_HORIZON = 10_000
_DOCUMENT_SCHEMAS = {
    "observation_fixture": "active_defense_observation_fixture",
    "priority_policy": "active_defense_priority_policy",
    "scheduler_policy": "active_defense_scheduler_policy",
    "hypothesis_templates": "active_defense_hypothesis_templates",
}


@dataclass(frozen=True)
class ContextHuntingRunSpec:
    """T2 runの入力path・horizon・seedを固定する仕様。pathはrepository相対のみ。"""

    run_id: str
    scenario_id: str
    tenant_id: str
    seed: int
    horizon_steps: int
    observation_fixture: str
    priority_policy: str
    scheduler_policy: str
    hypothesis_templates: str
    recipe_root: str

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ContextHuntingRunSpec":
        data = cv.exact_fields(payload, _SPEC_FIELDS, "ContextHuntingRunSpec")
        cv.version(data["schema_version"], "ContextHuntingRunSpec.schema_version")
        horizon = cv.positive_int(data["horizon_steps"], "horizon_steps")
        if horizon > _MAX_HORIZON:
            raise ActiveDefenseContractError(f"horizon_stepsは{_MAX_HORIZON}以下にしてください")
        paths = {}
        for name in ("observation_fixture", "priority_policy", "scheduler_policy", "hypothesis_templates",
                     "recipe_root"):
            value = data[name]
            if not isinstance(value, str) or not value or Path(value).is_absolute() or ".." in Path(value).parts:
                raise ActiveDefenseContractError(f"{name}: repository相対pathが必要です")
            paths[name] = value
        return cls(run_id=cv.ref(data["run_id"], "run_id"), scenario_id=cv.ref(data["scenario_id"], "scenario_id"),
                   tenant_id=cv.ref(data["tenant_id"], "tenant_id"), seed=cv.step(data["seed"], "seed"),
                   horizon_steps=horizon, **paths)

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION, **self.__dict__}


@dataclass(frozen=True)
class ContextHuntingInputs:
    """読込・検証済みの入力一式。各payloadはEvidence Bundleの入力hashに使う。"""

    spec: ContextHuntingRunSpec
    cti_observations: tuple[CTIObservation, ...]
    asm_observations: tuple[ASMAssetObservation, ...]
    bindings: tuple[ObservedAssetBinding, ...]
    internal_telemetry: tuple[Mapping[str, object], ...]
    priority_policy: PriorityPolicy
    scheduler_policy: SchedulerPolicy
    catalog: HypothesisTemplateCatalog
    payloads: Mapping[str, Mapping[str, object]]

    def provenance(self) -> dict[str, object]:
        return {
            "spec_hash": canonical_sha256(self.payloads["run_spec"]),
            "observation_fixture_hash": canonical_sha256(self.payloads["observation_fixture"]),
            "priority_policy_hash": self.priority_policy.policy_hash,
            "scheduler_policy_hash": self.scheduler_policy.policy_hash,
            "template_catalog_hash": self.catalog.catalog_hash,
            "recipe_hashes": dict(sorted(self.catalog.recipe_hashes.items())),
            "identity_normalization_version": self.priority_policy.identity_normalization_version,
        }


def _reject_non_finite(token: str) -> object:
    raise ActiveDefenseContractError(f"JSONに{token}は使えません")


def _read_json(root: Path, relative: str) -> dict[str, object]:
    path = _inside(root, relative)
    if path.suffix.lower() != ".json" or not path.is_file():
        raise ActiveDefenseContractError(f"repository内のJSON fileが必要です: {relative}")
    payload = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_non_finite)
    if not isinstance(payload, dict):
        raise ActiveDefenseContractError(f"JSONオブジェクトが必要です: {relative}")
    return payload


def load_context_hunting_inputs(repository_root: Path, spec_path: str) -> ContextHuntingInputs:
    """run specと参照先fileを読み、`build_context_hunting_inputs`で検証する。"""
    root = Path(repository_root).resolve()
    spec_payload = _read_json(root, spec_path)
    spec = ContextHuntingRunSpec.from_dict(spec_payload)
    documents = {name: _read_json(root, getattr(spec, name)) for name in _DOCUMENT_SCHEMAS}
    return build_context_hunting_inputs(spec_payload=spec_payload, documents=documents,
                                        recipe_root=_inside(root, spec.recipe_root))


def build_context_hunting_inputs(
    *, spec_payload: Mapping[str, object], documents: Mapping[str, Mapping[str, object]], recipe_root: Path,
) -> ContextHuntingInputs:
    """JSON Schema → 保存禁止形式の検査 → Python契約の順に検証し、実行入力を組み立てる。"""
    registry = SchemaRegistry()
    try:
        registry.validate("active_defense_t2_run_spec", spec_payload, source="run_spec")
    except AssetSchemaError as exc:
        raise ActiveDefenseContractError(str(exc)) from exc
    spec = ContextHuntingRunSpec.from_dict(spec_payload)
    if set(documents) != set(_DOCUMENT_SCHEMAS):
        raise ActiveDefenseContractError("入力documentの組が不正です")
    for name, schema_name in _DOCUMENT_SCHEMAS.items():
        try:
            registry.validate(schema_name, documents[name], source=name)
            assert_hygienic_payload(documents[name])
        except AssetSchemaError as exc:
            raise ActiveDefenseContractError(str(exc)) from exc
        except SensitiveDataHygieneError as exc:
            raise ActiveDefenseContractError(f"{name}に保存禁止のfieldまたは値があります") from exc
    priority = PriorityPolicy.from_dict(documents["priority_policy"])
    scheduler = SchedulerPolicy.from_dict(documents["scheduler_policy"])
    catalog = HypothesisTemplateCatalog.from_dict(
        documents["hypothesis_templates"], recipe_loader=ThreatHuntingRecipeLoader(recipe_root),
        max_window_steps=scheduler.max_lookback_steps)
    ctis, asms, bindings, telemetry = parse_observation_fixture(documents["observation_fixture"], spec)
    return ContextHuntingInputs(
        spec=spec, cti_observations=ctis, asm_observations=asms, bindings=bindings,
        internal_telemetry=telemetry, priority_policy=priority, scheduler_policy=scheduler, catalog=catalog,
        payloads={"run_spec": dict(spec_payload), **{name: dict(doc) for name, doc in documents.items()}},
    )


def _inside(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ActiveDefenseContractError(f"repository外のpathは使えません: {relative}")
    return path


def parse_observation_fixture(payload: Mapping[str, object], spec: ContextHuntingRunSpec) -> tuple[
        tuple[CTIObservation, ...], tuple[ASMAssetObservation, ...], tuple[ObservedAssetBinding, ...],
        tuple[Mapping[str, object], ...]]:
    data = cv.exact_fields(payload, _FIXTURE_FIELDS, "ObservationFixture")
    cv.version(data["schema_version"], "ObservationFixture.schema_version")
    if data["run_id"] != spec.run_id or data["tenant_id"] != spec.tenant_id:
        raise ActiveDefenseContractError("fixtureのrun_id/tenant_idがrun specと一致しません")
    if data["evidence_class"] != "synthetic-only":
        raise ActiveDefenseContractError("T2 CLIは合成データ（synthetic-only）だけを受け付けます")
    lists = {}
    for name in ("cti_observations", "asm_observations", "asset_bindings", "internal_telemetry"):
        if not isinstance(data[name], list):
            raise ActiveDefenseContractError(f"{name}: 配列が必要です")
        lists[name] = data[name]
    ctis = tuple(CTIObservation.from_dict(item) for item in lists["cti_observations"])
    asms = tuple(ASMAssetObservation.from_dict(item) for item in lists["asm_observations"])
    bindings = tuple(ObservedAssetBinding.from_dict(item) for item in lists["asset_bindings"])
    for record in (*ctis, *asms, *bindings):
        if record.tenant_id != spec.tenant_id:
            raise ActiveDefenseContractError("fixtureに別tenantの観測が含まれています")
    validate_supersession(ctis, name="cti_observations",
                          subject_key=lambda r: (r.identity_ref, r.endpoint_ref, r.domain_ref))
    validate_supersession(asms, name="asm_observations", subject_key=lambda r: r.asset_ref)
    validate_supersession(bindings, name="asset_bindings", subject_key=lambda r: r.asset_ref)
    telemetry = tuple(lists["internal_telemetry"])
    registry = SchemaRegistry()
    for item in telemetry:
        try:
            registry.validate("cti_observation_envelope", item, source="internal_telemetry")
        except AssetSchemaError as exc:
            raise ActiveDefenseContractError(str(exc)) from exc
        if item["source_kind"] not in INTERNAL_TELEMETRY_KINDS:
            # CTI/ASMを内部ログとしてengineへ流すと、CTIだけで検知・対処が起き得る。
            raise ActiveDefenseContractError("internal_telemetryには内部telemetryのenvelopeだけを置けます")
        if item["run_id"] != spec.run_id or item["tenant_id"] != spec.tenant_id:
            raise ActiveDefenseContractError("internal_telemetryのrun_id/tenant_idがrun specと一致しません")
    return ctis, asms, bindings, telemetry


@dataclass(frozen=True)
class BindingExecution:
    step: int
    binding_id: str
    hypothesis_id: str
    recipe_id: str
    recipe_hash: str
    evaluation_status: str
    missing_fields: tuple[str, ...]
    input_event_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]
    new_finding_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {key: list(value) if isinstance(value, tuple) else value for key, value in self.__dict__.items()}


@dataclass(frozen=True)
class ContextHuntingResult:
    spec: ContextHuntingRunSpec
    provenance: Mapping[str, object]
    matches: tuple[ExposureMatch, ...]
    final_matches: tuple[ExposureMatch, ...]
    cti_record_count: int
    first_matched_step_by_cti: Mapping[str, int]
    hypotheses: tuple[HypothesisSpec, ...]
    decisions: tuple[SchedulerDecision, ...]
    executions: tuple[BindingExecution, ...]
    traces: tuple[FindingTrace, ...]
    findings: tuple[Finding, ...]
    arrived_event_ids: tuple[str, ...]
    not_arrived_event_ids: tuple[str, ...]
    pending_binding_ids_at_horizon: tuple[str, ...]

    def metrics(self) -> dict[str, int]:
        """Evidence Bundleへ登録するscalar指標。分布・case別結果は別JSONに置く。"""
        status_count = {status: sum(m.status == status for m in self.final_matches)
                        for status in ("matched", "ambiguous", "unmatched", "stale")}
        return {
            "cti_record_count": self.cti_record_count,
            "cti_current_at_horizon_count": len(self.final_matches),
            "cti_ever_matched_count": len(self.first_matched_step_by_cti),
            **{f"final_{status}_count": count for status, count in status_count.items()},
            "hypothesis_count": len(self.hypotheses),
            "binding_execution_count": len(self.executions),
            "not_evaluable_execution_count": sum(e.evaluation_status != "evaluated" for e in self.executions),
            "deferred_decision_count": sum(d.decision == "deferred_budget" for d in self.decisions),
            "expired_unexecuted_count": sum(d.decision == "expired_unexecuted" for d in self.decisions),
            "pending_at_horizon_count": len(self.pending_binding_ids_at_horizon),
            "max_wait_steps_observed": max((d.wait_steps for d in self.decisions), default=0),
            "finding_count": len(self.traces),
            "response_eligible_finding_count": sum(t.response_eligible for t in self.traces),
            "internal_event_arrived_count": len(self.arrived_event_ids),
            "internal_event_not_arrived_count": len(self.not_arrived_event_ids),
        }

    def to_dict(self) -> dict[str, object]:
        """wall-clockを含まない決定論的payload。同入力・同codeならhashが一致する。"""
        return {
            "schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION,
            "evidence_class": "synthetic-only",
            "run": self.spec.to_dict(),
            "provenance": dict(self.provenance),
            "matches": [match.to_dict() for match in self.matches],
            "final_match_ids": [match.match_id for match in self.final_matches],
            "first_matched_step_by_cti": dict(sorted(self.first_matched_step_by_cti.items())),
            "hypotheses": [spec.to_dict() for spec in self.hypotheses],
            "scheduler_decisions": [decision.to_dict() for decision in self.decisions],
            "binding_executions": [execution.to_dict() for execution in self.executions],
            "finding_traces": [trace.to_dict() for trace in self.traces],
            "findings": [finding.to_dict() for finding in self.findings],
            "arrived_event_ids": list(self.arrived_event_ids),
            "not_arrived_event_ids": list(self.not_arrived_event_ids),
            "pending_binding_ids_at_horizon": list(self.pending_binding_ids_at_horizon),
            "metrics": self.metrics(),
        }

    @property
    def result_hash(self) -> str:
        return canonical_sha256(self.to_dict())


class ContextHuntingRunner:
    """一tenant・一runのT2実行。同じ入力なら入力順序に依らず同じ結果を返す。"""

    def __init__(self, inputs: ContextHuntingInputs, *, engine: ThreatHuntingEngine | None = None):
        self._inputs = inputs
        spec = inputs.spec
        self._adapter = T0ObservationAdapter(run_id=spec.run_id, tenant_id=spec.tenant_id,
                                             scenario_id=spec.scenario_id, seed=spec.seed)
        self._engine = engine or ThreatHuntingEngine()
        self._correlator = ExposureCorrelator(tenant_id=spec.tenant_id, policy=inputs.priority_policy)
        self._generator = HypothesisGenerator(tenant_id=spec.tenant_id, catalog=inputs.catalog)
        self._scheduler = HypothesisScheduler(inputs.scheduler_policy)

    def run(self) -> ContextHuntingResult:
        inputs, spec = self._inputs, self._inputs.spec
        telemetry = sorted(inputs.internal_telemetry, key=lambda item: (item["available_step"], item["event_id"]))
        cursor = 0
        buffer: list[HuntEvent] = []
        matches: dict[str, ExposureMatch] = {}
        first_matched: dict[str, int] = {}
        hypotheses: list[HypothesisSpec] = []
        decisions: list[SchedulerDecision] = []
        executions: list[BindingExecution] = []
        ledger = FindingTraceLedger()
        step_matches: tuple[ExposureMatch, ...] = ()
        for step in range(spec.horizon_steps):
            arrived = []
            while cursor < len(telemetry) and int(telemetry[cursor]["available_step"]) <= step:  # type: ignore[call-overload]
                arrived.append(telemetry[cursor])
                cursor += 1
            if arrived:
                try:
                    buffer.extend(self._adapter.adapt_snapshot(arrived, current_step=step))
                except T0ObservationAdapterError as exc:
                    raise ActiveDefenseContractError(f"内部telemetryを取り込めません: {exc}") from exc
                if len({event.event_id for event in buffer}) != len(buffer):
                    raise ActiveDefenseContractError("内部telemetryのevent_idが重複しています")
            step_matches = self._correlator.correlate(
                step=step, cti_observations=inputs.cti_observations,
                asm_observations=inputs.asm_observations, bindings=inputs.bindings)
            for match in step_matches:
                matches.setdefault(match.match_id, match)
                if match.status == "matched":
                    first_matched.setdefault(match.cti_ref, step)
            hypotheses.extend(self._generator.generate(step=step, matches=step_matches, existing=hypotheses))
            step_decisions, selected = self._scheduler.select(step=step, hypotheses=hypotheses, events=buffer)
            decisions.extend(step_decisions)
            for item in selected:
                executions.append(self._execute(step, item, matches, ledger))
        traces = ledger.traces()
        return ContextHuntingResult(
            spec=spec, provenance=inputs.provenance(),
            matches=tuple(sorted(matches.values(), key=lambda m: (m.computed_step, m.cti_ref, m.match_id))),
            final_matches=step_matches, cti_record_count=len(inputs.cti_observations),
            first_matched_step_by_cti=first_matched, hypotheses=tuple(hypotheses), decisions=tuple(decisions),
            executions=tuple(executions), traces=traces, findings=ledger.findings(),
            arrived_event_ids=tuple(sorted(event.event_id for event in buffer)),
            not_arrived_event_ids=tuple(sorted(str(item["event_id"]) for item in telemetry[cursor:])),
            pending_binding_ids_at_horizon=self._scheduler.pending_binding_ids(),
        )

    def _execute(self, step: int, item: SelectedBinding, matches: Mapping[str, ExposureMatch],
                 ledger: FindingTraceLedger) -> BindingExecution:
        binding, hypothesis = item.binding, item.hypothesis
        recipe = self._generator.recipe_for(binding.recipe_id)
        if recipe.recipe_hash != binding.recipe_hash:
            raise ActiveDefenseContractError("bindingのrecipe hashと実行recipeが一致しません")
        input_ids = tuple(event.event_id for event in item.events)
        if item.missing_fields:
            return BindingExecution(step, binding.binding_id, hypothesis.hypothesis_id, recipe.recipe_id,
                                    recipe.recipe_hash, NOT_EVALUABLE_MISSING_FIELDS, item.missing_fields,
                                    input_ids, (), ())
        findings = self._engine.run(recipe, item.events)
        context_refs = _context_refs(hypothesis.match_refs, matches)
        new_ids = [finding.finding_id for finding in findings
                   if ledger.record(step=step, hypothesis_id=hypothesis.hypothesis_id,
                                    recipe_hash=recipe.recipe_hash, finding=finding,
                                    input_events=item.events, context_refs=context_refs)]
        return BindingExecution(step, binding.binding_id, hypothesis.hypothesis_id, recipe.recipe_id,
                                recipe.recipe_hash, "evaluated", (), input_ids,
                                tuple(finding.finding_id for finding in findings), tuple(new_ids))


def _context_refs(match_refs: Sequence[str], matches: Mapping[str, ExposureMatch]) -> tuple[str, ...]:
    refs: set[str] = set()
    for match_id in match_refs:
        match = matches[match_id]
        refs.add(match.cti_ref)
        refs.update(match.binding_refs)
        if match.asm_ref is not None:
            refs.add(match.asm_ref)
    return tuple(sorted(refs))


__all__ = [
    "BindingExecution", "ContextHuntingInputs", "ContextHuntingResult", "ContextHuntingRunSpec",
    "ContextHuntingRunner", "INTERNAL_TELEMETRY_KINDS", "build_context_hunting_inputs",
    "load_context_hunting_inputs",
    "parse_observation_fixture",
]
