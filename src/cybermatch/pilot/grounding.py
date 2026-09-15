"""Build sanitized result views and validate evidence-grounded AI answers."""

from __future__ import annotations

import json
from pathlib import Path
from pathlib import PurePosixPath, PureWindowsPath
from typing import Mapping

from src.cybermatch.contracts import canonical_sha256, load_evidence_bundle

from .contracts import validate_contract
from .policy import LLMPolicyError


FORBIDDEN_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "credentials",
        "ground_truth",
        "labels",
        "password",
        "secret",
        "token",
    }
)
MAX_RESULT_VIEW_BYTES = 256 * 1024


class AIAnswerSchemaError(ValueError):
    """Raised when a provider answer does not satisfy the versioned schema."""


class GroundingValidationError(ValueError):
    """Raised when a schema-valid answer is not grounded in the Result View."""


def build_result_view(output_dir: str | Path) -> dict[str, object]:
    root = Path(output_dir).resolve()
    bundle = load_evidence_bundle(root)
    summary = json.loads((root / "phase3_external_validity_summary.json").read_text("utf-8"))
    manifest = json.loads((root / "replay_manifest.json").read_text("utf-8"))
    view = {
        "schema_version": "1.0",
        "run_id": bundle.run.manifest.run_id,
        "status": summary["status"],
        "evidence_class": summary["evidence_class"],
        "protocol_id": summary["protocol_id"],
        "scenario_id": bundle.run.manifest.scenario_id,
        "metrics": summary["metrics"],
        "domain_gap": summary["domain_gap"],
        "provenance": {
            "source_id": manifest["source"]["path"],
            "source_sha256": manifest["source"]["sha256"],
            "mapping_id": manifest["mapping"]["id"],
            "mapping_sha256": manifest["mapping"]["sha256"],
        },
        # The explainer needs only citeable repository-relative paths. Roles,
        # media types, sizes, and hashes remain in the verified Evidence Bundle.
        "artifacts": [
            {"path": item.path}
            for item in bundle.run.artifacts
            if _is_public_artifact_path(item.path)
        ],
        "bundle_hash": bundle.bundle_hash,
        "limitations": [
            "This result is replay-backed and does not establish live production effectiveness."
        ],
    }
    validate_contract("result_view", view)
    validate_result_view_safety(view)
    return view


def validate_result_view_safety(view: Mapping[str, object]) -> None:
    """Reject secret-bearing, path-escaping, or unbounded views before explanation."""

    serialized = json.dumps(view, ensure_ascii=False, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > MAX_RESULT_VIEW_BYTES:
        raise LLMPolicyError("result view exceeds the explanation size limit")
    _validate_safe_value(view)


def _validate_safe_value(value: object, key: str | None = None) -> None:
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            normalized = str(child_key).strip().lower().replace("-", "_")
            if normalized in FORBIDDEN_KEYS:
                raise LLMPolicyError(
                    "result view contains evaluator-only or secret material"
                )
            _validate_safe_value(child, normalized)
    elif isinstance(value, list):
        for child in value:
            _validate_safe_value(child, key)
    elif isinstance(value, str) and key in {"path", "source_id"}:
        posix = PurePosixPath(value.replace("\\", "/"))
        normalized_parts = {part.strip().lower().replace("-", "_") for part in posix.parts}
        if (
            PureWindowsPath(value).is_absolute()
            or posix.is_absolute()
            or ".." in posix.parts
            or normalized_parts.intersection({"ground_truth", "labels"})
        ):
            raise LLMPolicyError("result view contains an unsafe path")


def _is_public_artifact_path(path: str) -> bool:
    parts = {
        part.strip().lower().replace("-", "_")
        for part in PurePosixPath(path.replace("\\", "/")).parts
    }
    return not parts.intersection({"ground_truth", "labels"})


def validate_ai_answer(answer: Mapping[str, object], view: Mapping[str, object]) -> str:
    try:
        validate_contract("ai_answer", answer)
    except ValueError as exc:
        raise AIAnswerSchemaError(str(exc)) from exc
    if answer["bundle_hash"] != view["bundle_hash"]:
        raise GroundingValidationError("AI answer bundle hash does not match the result view")
    view_limitations = view["limitations"]
    answer_limitations = answer["limitations"]
    assert isinstance(view_limitations, list)
    assert isinstance(answer_limitations, list)
    missing_limitations = [item for item in view_limitations if item not in answer_limitations]
    if missing_limitations:
        raise GroundingValidationError("AI answer removed a required result-view limitation")
    artifacts = {item["path"] for item in view["artifacts"] if isinstance(item, Mapping)}
    metrics = view["metrics"]
    assert isinstance(metrics, Mapping)
    for claim in answer["claims"]:
        if claim["metric"] not in metrics:
            raise GroundingValidationError(
                f"AI claim references unknown metric: {claim['metric']}"
            )
        if claim["evidence_path"] not in artifacts:
            raise GroundingValidationError(
                f"AI claim references unknown artifact: {claim['evidence_path']}"
            )
    return canonical_sha256(answer)


__all__ = [
    "AIAnswerSchemaError",
    "GroundingValidationError",
    "MAX_RESULT_VIEW_BYTES",
    "build_result_view",
    "validate_ai_answer",
    "validate_result_view_safety",
]
