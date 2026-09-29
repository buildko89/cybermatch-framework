"""T4a: token化済みsnapshotをT2の決定論的探索へ接続するread-only runner。"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from collections.abc import Mapping

from cybermatch.contracts import AssetSchemaError, SchemaRegistry, canonical_sha256

from . import contract_validation as cv
from .as_of_selection import validate_supersession
from .context_hunting_runner import ContextHuntingInputs, ContextHuntingResult, ContextHuntingRunner, load_context_hunting_inputs
from .contract_validation import ActiveDefenseContractError
from .tokenized_replay_adapter import ReplayDataQualityReport, TokenizedReplayAdapter


@dataclass(frozen=True)
class TokenizedReplayRunSpec:
    run_id: str
    scenario_id: str
    tenant_id: str
    seed: int
    horizon_steps: int
    base_context_spec: str
    source_manifest: str

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "TokenizedReplayRunSpec":
        data = cv.exact_fields(payload, {"schema_version", "run_id", "scenario_id", "tenant_id", "seed",
                                                 "horizon_steps", "base_context_spec", "source_manifest"},
                               "TokenizedReplayRunSpec")
        cv.version(data["schema_version"], "schema_version")
        paths = {}
        for name in ("base_context_spec", "source_manifest"):
            value = data[name]
            if not isinstance(value, str) or Path(value).is_absolute() or ".." in Path(value).parts:
                raise ActiveDefenseContractError(f"{name}はrepository相対pathが必要です")
            paths[name] = value
        return cls(run_id=cv.ref(data["run_id"], "run_id"), scenario_id=cv.ref(data["scenario_id"], "scenario_id"),
                   tenant_id=cv.ref(data["tenant_id"], "tenant_id"), seed=cv.step(data["seed"], "seed"),
                   horizon_steps=cv.positive_int(data["horizon_steps"], "horizon_steps"), **paths)

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION, **self.__dict__}


@dataclass(frozen=True)
class TokenizedReplayInputs:
    spec: TokenizedReplayRunSpec
    context: ContextHuntingInputs
    quality: ReplayDataQualityReport
    payloads: Mapping[str, Mapping[str, object]]


@dataclass(frozen=True)
class TokenizedReplayResult:
    spec: TokenizedReplayRunSpec
    hunting: ContextHuntingResult
    quality: ReplayDataQualityReport

    @property
    def result_hash(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        source = self.hunting.to_dict()
        source["evidence_class"] = "replay-backed"
        source["run"] = self.spec.to_dict()
        return {"schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION, "evidence_class": "replay-backed",
                "claim_scope": "detection_compatibility_only", "data_quality": self.quality.to_dict(),
                "hunting_result": source}


def _read(root: Path, relative: str) -> dict[str, object]:
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ActiveDefenseContractError(f"repository内のJSON fileが必要です: {relative}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ActiveDefenseContractError(f"JSON objectが必要です: {relative}")
    return value


def load_tokenized_replay_inputs(root: Path, spec_path: str) -> TokenizedReplayInputs:
    repository = root.resolve()
    spec_payload = _read(repository, spec_path)
    spec = TokenizedReplayRunSpec.from_dict(spec_payload)
    base = load_context_hunting_inputs(repository, spec.base_context_spec)
    manifest = _read(repository, spec.source_manifest)
    registry = SchemaRegistry()
    try:
        registry.validate("active_defense_t4a_run_spec", spec_payload, source="T4a run spec")
        registry.validate("active_defense_tokenized_replay_manifest", manifest, source="T4a source manifest")
    except AssetSchemaError as exc:
        raise ActiveDefenseContractError(f"T4a入力schemaが不正です: {exc}") from exc
    expected = {"schema_version", "manifest_id", "evidence_class", "tenant_id", "input_file", "input_format",
                "normalization_version", "identity_key_version", "retention_days", "source_refs", "limitations"}
    data = cv.exact_fields(manifest, expected, "TokenizedReplaySourceManifest")
    cv.version(data["schema_version"], "manifest.schema_version")
    if data["evidence_class"] != "replay-backed" or data["tenant_id"] != spec.tenant_id:
        raise ActiveDefenseContractError("source manifestのevidence_classまたはtenantが不正です")
    input_file = data["input_file"]
    if not isinstance(input_file, str) or Path(input_file).is_absolute() or ".." in Path(input_file).parts:
        raise ActiveDefenseContractError("input_fileはrepository相対pathが必要です")
    adapter = TokenizedReplayAdapter(
        tenant_id=spec.tenant_id, run_id=spec.run_id,
        normalization_version=str(data["normalization_version"]),
        identity_key_version=str(data["identity_key_version"]), retention_days=data["retention_days"],
        source_refs=tuple(data["source_refs"]),
    )
    snapshot = adapter.load(repository / input_file, input_format=str(data["input_format"]))
    if not snapshot.quality.passed:
        raise ActiveDefenseContractError("data quality検査に不合格です: unsupported/rejected recordを確認してください")
    validate_supersession(snapshot.cti_observations, name="cti_observations",
                          subject_key=lambda item: (item.identity_ref, item.endpoint_ref, item.domain_ref))
    validate_supersession(snapshot.asm_observations, name="asm_observations", subject_key=lambda item: item.asset_ref)
    validate_supersession(snapshot.bindings, name="asset_bindings", subject_key=lambda item: item.asset_ref)
    run = replace(base.spec, run_id=spec.run_id, scenario_id=spec.scenario_id, tenant_id=spec.tenant_id,
                  seed=spec.seed, horizon_steps=spec.horizon_steps)
    context = replace(base, spec=run, cti_observations=snapshot.cti_observations,
                      asm_observations=snapshot.asm_observations, bindings=snapshot.bindings,
                      internal_telemetry=snapshot.internal_telemetry,
                      payloads={"run_spec": spec_payload, "source_manifest": manifest,
                                "observation_fixture": {"sha256": snapshot.quality.input_sha256,
                                                        "record_count": snapshot.quality.total_record_count,
                                                        "evidence_class": "replay-backed"},
                                **{f"base_{key}": value for key, value in base.payloads.items()
                                   if key != "run_spec"}})
    return TokenizedReplayInputs(spec, context, snapshot.quality, context.payloads)


class TokenizedReplayRunner:
    def __init__(self, inputs: TokenizedReplayInputs):
        self.inputs = inputs

    def run(self) -> TokenizedReplayResult:
        return TokenizedReplayResult(self.inputs.spec, ContextHuntingRunner(self.inputs.context).run(),
                                     self.inputs.quality)


__all__ = [
    "TokenizedReplayInputs", "TokenizedReplayResult", "TokenizedReplayRunSpec", "TokenizedReplayRunner",
    "load_tokenized_replay_inputs",
]
