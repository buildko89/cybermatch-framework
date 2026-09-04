"""End-to-end orchestration for CyberMatch analysis-guided fuzzing."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping, Sequence

from src.cybermatch.threat_hunting import GroundTruthLabel, HuntEvent

from .artifacts import FuzzArtifactWriter, load_fuzz_campaign
from .corpus import REPOSITORY_ROOT, generate_cases
from .minimizer import minimize_events
from .models import FuzzCase, MutationRecord, OracleResult, TargetResult
from .oracles import evaluate_oracles, is_interesting
from .scheduler import semantic_signature
from .specs import FuzzCampaignSpec, load_campaign_spec, validate_campaign_spec
from .targets import ExternalSUTTarget, ThreatHuntingClosedLoopTarget, ThreatHuntingEngineTarget


@dataclass(frozen=True)
class _ExecutionBundle:
    result: TargetResult
    control_result: TargetResult | None
    oracle_results: tuple[OracleResult, ...]
    open_loop_result: TargetResult | None = None
    control_open_loop_result: TargetResult | None = None


def _build_target(spec: FuzzCampaignSpec, root: Path):
    if spec.target.adapter == "external_sut":
        return ExternalSUTTarget(
            spec.target.recipes,
            repository_root=root,
            configuration=spec.target.external,
        )
    target_type = (
        ThreatHuntingClosedLoopTarget
        if spec.target.adapter == "threat_hunting_closed_loop"
        else ThreatHuntingEngineTarget
    )
    return target_type(spec.target.recipes, repository_root=root)


def _safe_output_path(value: str | Path, repository_root: Path, *, explicit: bool) -> Path:
    requested = Path(value)
    if requested.is_absolute():
        if explicit:
            return requested.resolve()
        raise ValueError("campaign output_dir must be repository-relative")
    resolved = (repository_root / requested).resolve()
    if not resolved.is_relative_to(repository_root) or resolved == repository_root:
        raise ValueError("campaign output_dir escapes repository root")
    return resolved


def _execute_with_oracles(
    case: FuzzCase,
    spec: FuzzCampaignSpec,
    target: ThreatHuntingEngineTarget,
) -> _ExecutionBundle:
    open_loop_result = None
    control_open_loop_result = None
    if isinstance(target, ThreatHuntingClosedLoopTarget):
        pair = target.execute_pair(case.events, spec.limits, case.mutations)
        result = pair.closed_loop
        open_loop_result = pair.open_loop
        if case.control_events:
            control_pair = target.execute_pair(case.control_events, spec.limits)
            control_result = control_pair.closed_loop
            control_open_loop_result = control_pair.open_loop
        else:
            control_result = None
        replay = (
            target.execute_pair(case.events, spec.limits, case.mutations).closed_loop
            if "deterministic_replay" in spec.oracles
            else None
        )
    else:
        result = target.execute(case.events, spec.limits)
        control_result = (
            target.execute(case.control_events, spec.limits) if case.control_events else None
        )
        replay = (
            target.execute(case.events, spec.limits)
            if "deterministic_replay" in spec.oracles
            else None
        )
    oracle_results = evaluate_oracles(
        spec.oracles,
        case,
        result,
        replay=replay,
        control_result=control_result,
        open_loop_result=open_loop_result,
        control_open_loop_result=control_open_loop_result,
        target_id=target.manifest.target_id,
    )
    return _ExecutionBundle(
        result=result,
        control_result=control_result,
        oracle_results=oracle_results,
        open_loop_result=open_loop_result,
        control_open_loop_result=control_open_loop_result,
    )


def run_campaign(
    campaign: str | Path | FuzzCampaignSpec,
    *,
    repository_root: str | Path = REPOSITORY_ROOT,
    output_dir: str | Path | None = None,
    max_cases: int | None = None,
    minimize: bool = True,
) -> dict[str, object]:
    root = Path(repository_root).resolve()
    spec = campaign if isinstance(campaign, FuzzCampaignSpec) else load_campaign_spec(campaign)
    if max_cases is not None:
        if isinstance(max_cases, bool) or not isinstance(max_cases, int) or max_cases <= 0:
            raise ValueError("max_cases override must be a positive integer")
        spec = replace(spec, limits=replace(spec.limits, max_cases=max_cases))
    selected_output = _safe_output_path(
        output_dir if output_dir is not None else spec.output_dir,
        root,
        explicit=output_dir is not None,
    )
    target = _build_target(spec, root)
    cases = generate_cases(spec, repository_root=root)
    rows: list[dict[str, object]] = []
    corpus: list[
        tuple[
            FuzzCase,
            TargetResult,
            TargetResult | None,
            Sequence[OracleResult],
            Sequence[HuntEvent] | None,
            TargetResult | None,
            TargetResult | None,
        ]
    ] = []
    seen_fingerprints: set[str] = set()
    seen_semantics: set[str] = set()
    for case in cases:
        execution = _execute_with_oracles(case, spec, target)
        result = execution.result
        control_result = execution.control_result
        oracle_results = execution.oracle_results
        interesting = is_interesting(oracle_results)
        signature = semantic_signature(case)
        failure_fingerprints = {
            oracle.fingerprint
            for oracle in oracle_results
            if oracle.verdict in {"fail", "interesting"}
        }
        novel_failure = bool(failure_fingerprints - seen_fingerprints)
        novel_semantics = signature not in seen_semantics
        seen_fingerprints.update(failure_fingerprints)
        seen_semantics.add(signature)
        minimized_events: Sequence[HuntEvent] | None = None
        tracked_findings = {
            oracle.fingerprint
            for oracle in oracle_results
            if oracle.verdict in {"fail", "interesting"}
        }
        if minimize and tracked_findings:
            def preserves_failure(candidate: FuzzCase) -> bool:
                candidate_execution = _execute_with_oracles(candidate, spec, target)
                candidate_oracles = candidate_execution.oracle_results
                return tracked_findings.issubset(
                    {
                        oracle.fingerprint
                        for oracle in candidate_oracles
                        if oracle.verdict in {"fail", "interesting"}
                    }
                )

            minimized_events = minimize_events(case, preserves_failure)
        if interesting or novel_failure or novel_semantics:
            corpus.append(
                (
                    case,
                    result,
                    control_result,
                    oracle_results,
                    minimized_events,
                    execution.open_loop_result,
                    execution.control_open_loop_result,
                )
            )
        rows.append(
            {
                "case_id": case.case_id,
                "case_seed": case.case_seed,
                "base_input_id": case.base_input_id,
                "status": result.status,
                "event_count": len(case.events),
                "finding_count": len(result.findings),
                "control_finding_count": (
                    len(control_result.findings) if control_result is not None else None
                ),
                "interesting": interesting,
                "oracle_failures": sum(value.verdict == "fail" for value in oracle_results),
                "oracle_interesting": sum(
                    value.verdict == "interesting" for value in oracle_results
                ),
                "semantic_signature": signature,
                "loop_mode": result.state_observations.get("loop_mode", "open_loop"),
                "prevented_event_count": result.state_observations.get(
                    "prevented_event_count", 0
                ),
                "post_alert_blast_radius": result.state_observations.get(
                    "post_alert_blast_radius"
                ),
            }
        )
    return FuzzArtifactWriter(selected_output).write(
        spec=spec,
        target_manifest=target.manifest,
        rows=rows,
        corpus=corpus,
    )


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_saved_case(case_dir: Path, campaign_id: str) -> FuzzCase:
    manifest = _read_json(case_dir / "case_manifest.json")
    mutation_payload = _read_json(case_dir / "mutation_trace.json")
    truth_payload = _read_json(case_dir / "expected" / "ground_truth_labels.json")
    if not isinstance(manifest, Mapping) or not isinstance(mutation_payload, list) or not isinstance(truth_payload, list):
        raise ValueError("saved case artifacts have invalid structure")
    def read_events(path: Path) -> tuple[HuntEvent, ...]:
        values: list[HuntEvent] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, Mapping):
                raise ValueError(f"saved event line {line_number} must be an object")
            values.append(HuntEvent.from_dict(value))
        return tuple(values)

    events = read_events(case_dir / "hunt_events.jsonl")
    control_events_path = case_dir / "control" / "hunt_events.jsonl"
    control_truth_path = case_dir / "control" / "ground_truth_labels.json"
    control_events = read_events(control_events_path) if control_events_path.is_file() else ()
    control_truth_payload = _read_json(control_truth_path) if control_truth_path.is_file() else []
    if not isinstance(control_truth_payload, list):
        raise ValueError("saved control ground truth must be an array")
    mutations = tuple(
        MutationRecord(
            mutator_id=value["mutator_id"],
            mutator_version=value["mutator_version"],
            operation_index=value["operation_index"],
            target_event_ids=tuple(value["target_event_ids"]),
            parameters=value["parameters"],
            before_hash=value["before_hash"],
            after_hash=value["after_hash"],
        )
        for value in mutation_payload
    )
    return FuzzCase(
        schema_version=manifest["schema_version"],
        campaign_id=campaign_id,
        case_id=manifest["case_id"],
        campaign_seed=manifest["campaign_seed"],
        case_seed=manifest["case_seed"],
        base_input_id=manifest["base_input_id"],
        base_input_hash=manifest["base_input_hash"],
        analysis_guidance=manifest["analysis_guidance"],
        mutations=mutations,
        events=events,
        ground_truth=tuple(GroundTruthLabel.from_dict(value) for value in truth_payload),
        control_events=control_events,
        control_ground_truth=tuple(
            GroundTruthLabel.from_dict(value) for value in control_truth_payload
        ),
    )


def replay_case(
    case_dir: str | Path,
    *,
    repository_root: str | Path = REPOSITORY_ROOT,
) -> dict[str, object]:
    case_path = Path(case_dir).resolve()
    if case_path.parent.name != "corpus":
        raise ValueError("case directory must be directly below a campaign corpus directory")
    campaign_root = case_path.parent.parent
    manifest = load_fuzz_campaign(campaign_root)
    spec_payload = manifest.get("spec")
    if not isinstance(spec_payload, Mapping):
        raise ValueError("campaign manifest does not contain a valid spec")
    spec = validate_campaign_spec(spec_payload)
    case = _load_saved_case(case_path, spec.campaign_id)
    target = _build_target(spec, Path(repository_root).resolve())
    execution = _execute_with_oracles(case, spec, target)
    result = execution.result
    oracle_results = execution.oracle_results
    saved_result = _read_json(case_path / "actual" / "target_result.json")
    if not isinstance(saved_result, Mapping):
        raise ValueError("saved target result must be an object")
    saved_comparable = dict(saved_result)
    saved_comparable.pop("duration_ms", None)
    return {
        "case_id": case.case_id,
        "status": result.status,
        "saved_result_match": saved_comparable == result.comparable_dict(),
        "findings": len(result.findings),
        "oracle_results": [oracle.to_dict() for oracle in oracle_results],
        "result": result.to_dict(),
    }


__all__ = ["replay_case", "run_campaign"]
