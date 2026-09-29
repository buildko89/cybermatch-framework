"""T4b: 観測済み仮説のallowlist選択だけを行うshadow Pilot。"""

from __future__ import annotations

import json
from importlib.resources import files
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from jsonschema import Draft202012Validator

from cybermatch.contracts import canonical_json, canonical_sha256, load_evidence_bundle


class HypothesisSelectionGateway(Protocol):
    provider_id: str
    model_id: str
    def select(self, view: Mapping[str, object]) -> Mapping[str, object]: ...


class DeterministicHypothesisSelectionGateway:
    provider_id = "deterministic-template"
    model_id = "hypothesis-shadow-v1"

    def select(self, view: Mapping[str, object]) -> Mapping[str, object]:
        candidates = view["candidates"]
        assert isinstance(candidates, list)
        if not candidates:
            return _abstention(view, "candidateなし")
        selected = sorted(candidates, key=lambda item: (-int(item["priority_bp"]), str(item["hypothesis_id"])))[0]
        recipes = selected["recipes"]
        return {"schema_version": "1.0", "bundle_hash": view["bundle_hash"], "abstain": False,
                "abstain_reason": None, "selected_hypothesis_ids": [selected["hypothesis_id"]],
                "selected_recipes": recipes, "observation_refs": selected["observation_refs"],
                "scope": selected["scope"], "rationale": "priority最大のallowlist候補をshadow提案"}


def _abstention(view: Mapping[str, object], reason: str) -> dict[str, object]:
    return {"schema_version": "1.0", "bundle_hash": view["bundle_hash"], "abstain": True,
            "abstain_reason": reason, "selected_hypothesis_ids": [], "selected_recipes": [],
            "observation_refs": [], "scope": None, "rationale": "実行提案を生成しません"}


def build_hypothesis_pilot_view(output_dir: Path) -> dict[str, object]:
    """T2/T4a成果物から、truth・Finding本文を含まない候補viewを作る。"""
    root = output_dir.resolve()
    bundle = load_evidence_bundle(root)
    path = root / "hypotheses.jsonl"
    candidates = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            recipes = [{"recipe_id": item["recipe_id"], "recipe_hash": item["recipe_hash"]}
                       for item in row["recipe_bindings"]]
            candidates.append({"hypothesis_id": row["hypothesis_id"], "template_id": row["template_id"],
                               "priority_bp": row["priority_bp"], "scope": row["scope"],
                               "observation_refs": row["match_refs"], "recipes": recipes})
    artifacts = [{"path": item.path} for item in bundle.run.artifacts
                 if "evaluator_only" not in PurePosixPath(item.path).parts]
    evidence_class = "replay-backed" if (root / "data_quality_report.json").is_file() else "synthetic-only"
    view = {"schema_version": "1.0", "run_id": bundle.run.manifest.run_id,
            "evidence_class": evidence_class, "bundle_hash": bundle.bundle_hash,
            "candidates": sorted(candidates, key=lambda item: item["hypothesis_id"]),
            "artifacts": artifacts,
            "limitations": ["shadow提案であり自動実行しない", "allowlist外recipe・自由predicate・閾値変更を禁止"]}
    _validate_view(view)
    return view


def run_hypothesis_pilot_shadow(view: Mapping[str, object],
                                gateway: HypothesisSelectionGateway | None = None) -> dict[str, object]:
    _validate_view(view)
    selected = gateway or DeterministicHypothesisSelectionGateway()
    failure: str | None = None
    try:
        proposal = dict(selected.select(view))
        _validate_proposal(proposal, view)
        status = "accepted_shadow"
    except Exception as exc:
        proposal = _abstention(view, "gateway失敗またはgrounding不一致")
        failure, status = type(exc).__name__, "abstained"
    return {"schema_version": "1.0", "mode": "shadow", "execution_authorized": False,
            "view_hash": canonical_sha256(view), "provider_id": selected.provider_id,
            "model_id": selected.model_id, "status": status, "failure_class": failure,
            "proposal": proposal}


def write_hypothesis_pilot_shadow(view: Mapping[str, object], result: Mapping[str, object],
                                  output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=False)
    view_path, result_path = output_dir / "hypothesis_pilot_view.json", output_dir / "hypothesis_pilot_shadow.json"
    view_path.write_text(canonical_json(view) + "\n", encoding="utf-8")
    result_path.write_text(canonical_json(result) + "\n", encoding="utf-8")
    return view_path, result_path


def _validate_view(view: Mapping[str, object]) -> None:
    _validate_schema("active-defense-hypothesis-pilot-view.schema.json", view)
    if set(view) != {"schema_version", "run_id", "evidence_class", "bundle_hash", "candidates", "artifacts", "limitations"}:
        raise ValueError("hypothesis Pilot viewのfieldが不正です")
    if view["schema_version"] != "1.0" or view["evidence_class"] not in {"synthetic-only", "replay-backed"}:
        raise ValueError("hypothesis Pilot viewのversion/evidence classが不正です")
    if not isinstance(view["candidates"], list):
        raise ValueError("candidatesは配列が必要です")


def _validate_proposal(proposal: Mapping[str, object], view: Mapping[str, object]) -> None:
    _validate_schema("active-defense-hypothesis-pilot-proposal.schema.json", proposal)
    expected = {"schema_version", "bundle_hash", "abstain", "abstain_reason", "selected_hypothesis_ids",
                "selected_recipes", "observation_refs", "scope", "rationale"}
    if set(proposal) != expected or proposal["schema_version"] != "1.0" or proposal["bundle_hash"] != view["bundle_hash"]:
        raise ValueError("proposal契約またはBundle groundingが不正です")
    candidates = {item["hypothesis_id"]: item for item in view["candidates"]}
    selected_ids = proposal["selected_hypothesis_ids"]
    if not isinstance(selected_ids, list) or any(item not in candidates for item in selected_ids):
        raise ValueError("allowlist外のhypothesis IDです")
    if proposal["abstain"]:
        if selected_ids or proposal["selected_recipes"] or proposal["scope"] is not None:
            raise ValueError("abstain時に実行候補を返せません")
        return
    if len(selected_ids) != 1:
        raise ValueError("v1は仮説を1件だけ提案できます")
    candidate = candidates[selected_ids[0]]
    if proposal["selected_recipes"] != candidate["recipes"]:
        raise ValueError("recipe ID/hashがallowlist候補と一致しません")
    if proposal["observation_refs"] != candidate["observation_refs"] or proposal["scope"] != candidate["scope"]:
        raise ValueError("観測参照またはscope groundingが一致しません")


def _validate_schema(name: str, payload: Mapping[str, object]) -> None:
    schema = json.loads(files("cybermatch.schemas").joinpath(name).read_text("utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda item: list(item.path))
    if errors:
        location = ".".join(str(item) for item in errors[0].path) or "<root>"
        raise ValueError(f"{name}:{location}: {errors[0].message}")


__all__ = [
    "DeterministicHypothesisSelectionGateway", "HypothesisSelectionGateway", "build_hypothesis_pilot_view",
    "run_hypothesis_pilot_shadow", "write_hypothesis_pilot_shadow",
]
