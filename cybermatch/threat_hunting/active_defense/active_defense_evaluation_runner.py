"""T3: 状態付き合成世界でB0〜B3とログ健全性profileを比較するrunner。"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cybermatch.contracts import (
    AssetSchemaError, SchemaRegistry, ScopedResponseAction, SensitiveDataHygieneError,
    assert_hygienic_payload, canonical_sha256,
)

from ..engine import ThreatHuntingEngine, ThreatHuntingInputError
from ..models import Finding, HuntEvent
from ..t0_observation_adapter import T0ObservationAdapter
from . import contract_validation as cv
from .closed_loop_evaluation import (
    build_critical_prevention_summary, build_logging_hygiene_summary, build_paired_comparisons,
)
from .context_hunting_runner import ContextHuntingInputs, load_context_hunting_inputs
from .contract_validation import ActiveDefenseContractError
from .exposure_correlation import ExposureCorrelator, ExposureMatch
from .logging_hygiene import LoggingHygieneConfig, LoggingHygieneTransform
from .response_action_sink import FindingAuthorization, StatefulResponseActionSink
from .stateful_mock_world import OperationOutcome, PotentialOperation, StatefulMockWorld

MODES = (
    "B0_internal_open", "B1_context_open", "B2_internal_closed", "B3_context_closed",
)


@dataclass(frozen=True)
class ActiveDefenseEvaluationSpec:
    run_id: str
    scenario_id: str
    tenant_id: str
    seeds: tuple[int, ...]
    horizon_steps: int
    t2_context_spec: str
    potential_graph: str
    logging_hygiene_profiles: str
    response_duration_steps: int
    response_policy_hash: str
    cost_profile: Mapping[str, int]
    modes: tuple[str, ...]

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ActiveDefenseEvaluationSpec":
        fields = {"schema_version", "run_id", "scenario_id", "tenant_id", "seeds", "horizon_steps",
                  "t2_context_spec", "potential_graph", "logging_hygiene_profiles",
                  "response_duration_steps", "response_policy_hash", "modes"}
        fields.add("cost_profile")
        data = cv.exact_fields(payload, fields, "ActiveDefenseEvaluationSpec")
        cv.version(data["schema_version"], "schema_version")
        seeds = tuple(data["seeds"])
        if not seeds or any(isinstance(seed, bool) or not isinstance(seed, int) or seed < 0 for seed in seeds):
            raise ActiveDefenseContractError("seedsは重複のない非負整数配列が必要です")
        if tuple(sorted(set(seeds))) != seeds:
            raise ActiveDefenseContractError("seedsは重複なしの昇順が必要です")
        modes = tuple(data["modes"])
        if modes != MODES:
            raise ActiveDefenseContractError("modesはB0〜B3を規定順で全て指定してください")
        raw_cost = data["cost_profile"]
        cost_names = {"job_cost_units", "triage_cost_units", "false_response_cost_units", "cti_asm_cost_units"}
        if not isinstance(raw_cost, Mapping) or set(raw_cost) != cost_names or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in raw_cost.values()):
            raise ActiveDefenseContractError("cost_profileは4種類の非負整数cost unitが必要です")
        paths = {}
        for name in ("t2_context_spec", "potential_graph", "logging_hygiene_profiles"):
            value = data[name]
            if not isinstance(value, str) or Path(value).is_absolute() or ".." in Path(value).parts:
                raise ActiveDefenseContractError(f"{name}はrepository相対pathが必要です")
            paths[name] = value
        return cls(run_id=cv.ref(data["run_id"], "run_id"), scenario_id=cv.ref(data["scenario_id"], "scenario_id"),
                   tenant_id=cv.ref(data["tenant_id"], "tenant_id"), seeds=seeds,
                   horizon_steps=cv.positive_int(data["horizon_steps"], "horizon_steps"),
                   response_duration_steps=cv.positive_int(data["response_duration_steps"], "response_duration_steps"),
                   response_policy_hash=data["response_policy_hash"], cost_profile=dict(sorted(raw_cost.items())),
                   modes=modes, **paths)

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION, **{
            key: list(value) if isinstance(value, tuple) else value for key, value in self.__dict__.items()}}


@dataclass(frozen=True)
class ActiveDefenseEvaluationInputs:
    spec: ActiveDefenseEvaluationSpec
    context: ContextHuntingInputs
    operations: tuple[PotentialOperation, ...]
    exposure_truth: tuple["ExposureTruth", ...]
    hygiene_profiles: tuple[LoggingHygieneConfig, ...]
    payloads: Mapping[str, Mapping[str, object]]


@dataclass(frozen=True)
class ExposureTruth:
    """evaluatorだけが読む公開資産露出のgold interval。"""

    asset_ref: str
    exposure_kind: str
    start_step: int
    end_step: int

    def __post_init__(self) -> None:
        cv.ref(self.asset_ref, "ExposureTruth.asset_ref")
        cv.ref(self.exposure_kind, "ExposureTruth.exposure_kind")
        cv.step(self.start_step, "ExposureTruth.start_step")
        cv.step(self.end_step, "ExposureTruth.end_step")
        if self.end_step <= self.start_step:
            raise ActiveDefenseContractError("ExposureTruth.end_stepはstart_stepより後が必要です")

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ExposureTruth":
        return cls(**cv.exact_fields(payload, {"asset_ref", "exposure_kind", "start_step", "end_step"},
                                     "ExposureTruth"))


@dataclass(frozen=True)
class ModeEvaluationResult:
    mode_id: str
    profile_id: str
    seed: int
    potential_graph_hash: str
    matches: tuple[ExposureMatch, ...]
    findings: tuple[Finding, ...]
    actions: tuple[ScopedResponseAction, ...]
    receipts: tuple[object, ...]
    outcomes: tuple[OperationOutcome, ...]
    dropped_event_ids: tuple[str, ...]
    expired_event_ids: tuple[str, ...]
    job_count: int
    not_evaluable_job_count: int
    first_detection_step: int | None
    metrics: Mapping[str, int | float | bool | None]

    def to_summary(self) -> dict[str, object]:
        return {"mode_id": self.mode_id, "profile_id": self.profile_id, "seed": self.seed,
                "potential_graph_hash": self.potential_graph_hash, **dict(self.metrics)}

    def to_dict(self) -> dict[str, object]:
        return {**self.to_summary(), "matches": [item.to_dict() for item in self.matches],
                "findings": [item.to_dict() for item in self.findings],
                "actions": [item.to_dict() for item in self.actions],
                "receipts": [item.to_dict() for item in self.receipts],
                "outcomes": [item.to_dict() for item in self.outcomes],
                "dropped_event_ids": list(self.dropped_event_ids),
                "expired_event_ids": list(self.expired_event_ids)}


@dataclass(frozen=True)
class ActiveDefenseEvaluationResult:
    spec: ActiveDefenseEvaluationSpec
    runs: tuple[ModeEvaluationResult, ...]
    comparisons: Mapping[str, object]

    @property
    def result_hash(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION, "evidence_class": "synthetic-only",
                "run": self.spec.to_dict(), "mode_profile_results": [item.to_dict() for item in self.runs],
                "paired_comparisons": dict(self.comparisons)}


def _read_object(root: Path, relative: str) -> dict[str, object]:
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ActiveDefenseContractError(f"repository内のJSON fileが必要です: {relative}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ActiveDefenseContractError(f"JSON objectが必要です: {relative}")
    return payload


def load_active_defense_evaluation_inputs(root: Path, spec_path: str) -> ActiveDefenseEvaluationInputs:
    repository = root.resolve()
    spec_payload = _read_object(repository, spec_path)
    spec = ActiveDefenseEvaluationSpec.from_dict(spec_payload)
    context = load_context_hunting_inputs(repository, spec.t2_context_spec)
    if context.spec.tenant_id != spec.tenant_id:
        raise ActiveDefenseContractError("T2 context specとT3 specのtenantが一致しません")
    graph_payload = _read_object(repository, spec.potential_graph)
    hygiene_payload = _read_object(repository, spec.logging_hygiene_profiles)
    registry = SchemaRegistry()
    try:
        registry.validate("active_defense_t3_run_spec", spec_payload, source="T3 run spec")
        registry.validate("active_defense_potential_graph", graph_payload, source="potential graph")
        registry.validate("active_defense_logging_hygiene_profiles", hygiene_payload,
                          source="logging hygiene profiles")
        assert_hygienic_payload(spec_payload)
        assert_hygienic_payload(hygiene_payload)
        assert_hygienic_payload(graph_payload)
    except (AssetSchemaError, SensitiveDataHygieneError) as exc:
        raise ActiveDefenseContractError(f"T3入力を検証できません: {exc}") from exc
    graph = cv.exact_fields(graph_payload, {"schema_version", "graph_id", "tenant_id", "exposure_truth", "operations"},
                            "PotentialOperationGraph")
    cv.version(graph["schema_version"], "PotentialOperationGraph.schema_version")
    if (graph["tenant_id"] != spec.tenant_id or not isinstance(graph["operations"], list)
            or not isinstance(graph["exposure_truth"], list)):
        raise ActiveDefenseContractError("potential graphのtenantまたはoperationsが不正です")
    operations = tuple(PotentialOperation.from_dict(item) for item in graph["operations"])
    exposure_truth = tuple(ExposureTruth.from_dict(item) for item in graph["exposure_truth"])
    hp = cv.exact_fields(hygiene_payload, {"schema_version", "profiles"}, "LoggingHygieneProfiles")
    cv.version(hp["schema_version"], "LoggingHygieneProfiles.schema_version")
    if not isinstance(hp["profiles"], list) or not hp["profiles"]:
        raise ActiveDefenseContractError("logging hygiene profilesが必要です")
    profiles = tuple(LoggingHygieneConfig.from_dict(item) for item in hp["profiles"])
    if len({item.profile_id for item in profiles}) != len(profiles):
        raise ActiveDefenseContractError("profile_idが重複しています")
    return ActiveDefenseEvaluationInputs(spec, context, operations, exposure_truth, profiles, {
        "run_spec": spec_payload, "potential_graph": graph_payload, "logging_hygiene_profiles": hygiene_payload,
        **{f"t2_{key}": value for key, value in context.payloads.items()},
    })


class ActiveDefenseEvaluationRunner:
    """全mode/profile/seedを、同じ潜在graphから独立した世界状態で実行する。"""

    def __init__(self, inputs: ActiveDefenseEvaluationInputs):
        self.inputs = inputs

    def run(self) -> ActiveDefenseEvaluationResult:
        runs = tuple(self._run_one(mode, profile, seed) for profile in self.inputs.hygiene_profiles
                     for seed in self.inputs.spec.seeds for mode in self.inputs.spec.modes)
        summaries = [item.to_summary() for item in runs]
        comparisons = {
            "critical_reach_rate": build_paired_comparisons(summaries, metric="critical_reach_rate"),
            "finding_count": build_paired_comparisons(summaries, metric="finding_count"),
            "false_response_count": build_paired_comparisons(summaries, metric="false_response_count"),
            "logging_hygiene": build_logging_hygiene_summary(summaries),
            "critical_reach_prevention": build_critical_prevention_summary(summaries),
        }
        return ActiveDefenseEvaluationResult(self.inputs.spec, runs, comparisons)

    def _run_one(self, mode: str, profile: LoggingHygieneConfig, seed: int) -> ModeEvaluationResult:
        spec, context = self.inputs.spec, self.inputs.context
        run_id = f"{spec.run_id}-{mode.lower()}-{profile.profile_id}-seed-{seed}"
        known = tuple(sorted({item.identity_ref for item in self.inputs.operations}))
        sink = StatefulResponseActionSink(run_id=run_id, tenant_id=spec.tenant_id, known_identities=known)
        world = StatefulMockWorld(run_id=run_id, tenant_id=spec.tenant_id, scenario_id=spec.scenario_id,
                                  seed=seed, operations=self.inputs.operations)
        adapter = T0ObservationAdapter(run_id=run_id, tenant_id=spec.tenant_id,
                                       scenario_id=spec.scenario_id, seed=seed)
        transform = LoggingHygieneTransform(profile)
        correlator = ExposureCorrelator(tenant_id=spec.tenant_id, policy=context.priority_policy)
        recipe = next((template.recipe for template in context.catalog.templates
                       if template.recipe.recipe_id == "identity_process_chain_v1"), None)
        if recipe is None:
            raise ActiveDefenseContractError("T3にはidentity_process_chain_v1 recipeが必要です")
        engine = ThreatHuntingEngine()
        pending: list[dict[str, object]] = []
        buffer: list[HuntEvent] = []
        findings: dict[str, Finding] = {}
        last_fingerprint: dict[str, str] = {}
        all_matches: dict[str, ExposureMatch] = {}
        dropped: set[str] = set()
        expired: set[str] = set()
        job_count = not_evaluable = 0
        executed_subjects: set[str] = set()
        first_detection: int | None = None
        closed = mode.endswith("closed")
        contextual = "context" in mode
        for step in range(spec.horizon_steps):
            sink.advance(step)
            produced = world.execute_step(step, sink)
            transformed = transform.apply(produced, seed=seed)
            pending.extend(transformed.observations)
            dropped.update(transformed.dropped_event_ids)
            expired.update(transformed.expired_event_ids)
            arrived = [item for item in pending if int(item["available_step"]) <= step]
            pending = [item for item in pending if int(item["available_step"]) > step]
            if arrived:
                buffer.extend(adapter.adapt_snapshot(arrived, current_step=step))
            matches = correlator.correlate(step=step, cti_observations=context.cti_observations,
                                           asm_observations=context.asm_observations, bindings=context.bindings)
            for match in matches:
                all_matches.setdefault(match.match_id, match)
            if contextual:
                ranked = sorted(((match.identity_ref, match.priority_bp or 0) for match in matches
                                 if match.status == "matched" and match.identity_ref is not None),
                                key=lambda item: (-item[1], item[0]))
                candidates = [identity for identity, _ in ranked]
            else:
                candidates = list(known)
            changed = []
            for identity in candidates:
                scoped = tuple(event for event in buffer if event.attributes.get("identity_ref") == identity)
                fingerprint = canonical_sha256([event.event_id for event in scoped])
                if scoped and last_fingerprint.get(identity) != fingerprint:
                    changed.append((identity, scoped, fingerprint))
            for identity, scoped, fingerprint in changed[:context.scheduler_policy.max_bindings_per_step]:
                job_count += 1
                executed_subjects.add(identity)
                last_fingerprint[identity] = fingerprint
                try:
                    detected = engine.run(recipe, scoped)
                except ThreatHuntingInputError:
                    not_evaluable += 1
                    continue
                for finding in detected:
                    is_new = finding.finding_id not in findings
                    findings.setdefault(finding.finding_id, finding)
                    if not is_new:
                        continue
                    first_detection = step if first_detection is None else min(first_detection, step)
                    if closed:
                        sink.authorize(FindingAuthorization(finding.finding_id, spec.tenant_id, (identity,)))
                        action = ScopedResponseAction.create(
                            run_id=run_id, tenant_id=spec.tenant_id, finding_ids=(finding.finding_id,),
                            action_type="revoke_identity", scope_kind="identity", subject_refs=(identity,),
                            requested_step=step, effective_step=step + 1,
                            expires_step=step + 1 + spec.response_duration_steps,
                            policy_hash=spec.response_policy_hash, reason_code="verified_identity_chain",
                        )
                        sink.submit(action)
        sink.advance(spec.horizon_steps)
        metrics = self._metrics(world.outcomes, findings, sink, job_count, not_evaluable, executed_subjects,
                                first_detection, len(dropped), len(expired), spec.horizon_steps,
                                tuple(all_matches.values()), context, self.inputs.exposure_truth,
                                spec.cost_profile, contextual)
        return ModeEvaluationResult(mode, profile.profile_id, seed, world.potential_graph_hash,
                                    tuple(all_matches.values()), tuple(findings.values()), sink.actions, sink.receipts,
                                    world.outcomes, tuple(sorted(dropped)), tuple(sorted(expired)), job_count,
                                    not_evaluable, first_detection, metrics)

    @staticmethod
    def _metrics(outcomes: Sequence[OperationOutcome], findings: Mapping[str, Finding],
                 sink: StatefulResponseActionSink, jobs: int, not_evaluable: int,
                 executed_subjects: set[str], first_detection: int | None, dropped: int, expired: int,
                 horizon: int, matches: Sequence[ExposureMatch], context: ContextHuntingInputs,
                 exposure_truth: Sequence[ExposureTruth], cost_profile: Mapping[str, int],
                 contextual: bool) -> dict[str, int | float | bool | None]:
        malicious = [item for item in outcomes if not item.legitimate]
        initial = [item for item in malicious if item.operation_kind == "authenticate"]
        first_attempt = min((item.step for item in initial), default=None)
        started = any(item.status == "succeeded" for item in initial)
        critical = any(item.operation_kind == "critical_reach" and item.status == "succeeded" for item in malicious)
        false_responses = sum(item.legitimate and item.status == "blocked" and
                              item.reason_code == "identity_revoked" for item in outcomes)
        applied = sum(item.status == "applied" for item in sink.receipts)
        ttd = None if first_attempt is None or first_detection is None else first_detection - first_attempt
        first_match = min((item.computed_step for item in matches if item.status == "matched"), default=None)
        lead_time = None if first_attempt is None or first_match is None else first_attempt - first_match
        # 現行Findingはidentityをattributesへ複写しないため、Findingがあれば単一scopeのhitとして扱う。
        hit_count = min(len(findings), len(executed_subjects))
        hit_rate = None if not executed_subjects else hit_count / len(executed_subjects)
        predicted_assets = set()
        asm_by_id = {item.observation_id: item for item in context.asm_observations}
        for match in matches:
            if match.status == "matched" and match.asm_ref in asm_by_id:
                predicted_assets.add(asm_by_id[match.asm_ref].asset_ref)
        gold_assets = {item.asset_ref for item in exposure_truth
                       if item.start_step < horizon and item.end_step > 0}
        exposure_tp = len(predicted_assets & gold_assets)
        exposure_precision = None if not predicted_assets else exposure_tp / len(predicted_assets)
        exposure_recall = None if not gold_assets else exposure_tp / len(gold_assets)
        successful_steps = [item.step for item in malicious if item.status == "succeeded"]
        blocked_reauth = [item.step for item in malicious if item.operation_kind == "authenticate"
                          and item.status == "blocked"]
        terminal_step = min((step for step in blocked_reauth
                             if not any(later >= step for later in successful_steps)), default=None)
        dwell = None if first_attempt is None or terminal_step is None else terminal_step - first_attempt
        analyst_cost = (jobs * cost_profile["job_cost_units"] + len(findings) * cost_profile["triage_cost_units"]
                        + false_responses * cost_profile["false_response_cost_units"]
                        + (cost_profile["cti_asm_cost_units"] if contextual else 0))
        return {"campaign_started": started, "critical_reach_rate": 1.0 if critical else 0.0,
                "critical_reach_count": int(critical), "finding_count": len(findings),
                "applied_action_count": applied, "false_response_count": false_responses,
                "blocked_operation_count": sum(item.status == "blocked" for item in outcomes),
                "job_count": jobs, "not_evaluable_job_count": not_evaluable,
                "dropped_event_count": dropped, "expired_event_count": expired,
                "first_detection_step": first_detection, "time_to_detection_steps": ttd,
                "lead_time_steps": lead_time, "late_signal": lead_time is not None and lead_time < 0,
                "executed_unique_hypothesis_count": len(executed_subjects),
                "hypothesis_hit_count": hit_count, "hypothesis_hit_rate": hit_rate,
                "exposure_true_positive_count": exposure_tp, "exposure_predicted_count": len(predicted_assets),
                "exposure_gold_count": len(gold_assets), "exposure_precision": exposure_precision,
                "exposure_recall": exposure_recall, "dwell_duration_steps": dwell,
                "dwell_right_censored": started and terminal_step is None,
                "analyst_cost_units": analyst_cost,
                "detection_right_censored": started and first_detection is None,
                "restricted_mean_detection_steps": (horizon - first_attempt) if started and first_detection is None
                else ttd}


__all__ = [
    "MODES", "ActiveDefenseEvaluationInputs", "ActiveDefenseEvaluationResult",
    "ActiveDefenseEvaluationRunner", "ActiveDefenseEvaluationSpec", "ExposureTruth", "ModeEvaluationResult",
    "load_active_defense_evaluation_inputs",
]
