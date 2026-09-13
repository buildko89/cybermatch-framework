"""Repository-aware writer for the common, hash-verified evidence contract."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Mapping, Sequence

from .canonical import canonical_json, canonical_sha256
from .evidence import EvaluationRun, EvidenceArtifact, EvidenceBundle, MetricScalar, MetricSet, RunManifest


EVIDENCE_BUNDLE_FILENAME = "evidence_bundle.json"


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_revision(repository_root: str | Path) -> str:
    override = os.environ.get("CYBERMATCH_CODE_REVISION")
    if override:
        return override
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(repository_root),
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return completed.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def reproducible_timestamp() -> str:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def _framework_version() -> str:
    try:
        return version("cybermatch-framework")
    except PackageNotFoundError:
        return "1.0.1"


def write_evidence_bundle(
    output_root: str | Path,
    *,
    repository_root: str | Path,
    run_id: str,
    runner: str,
    scenario_id: str,
    seed: int,
    input_payloads: Mapping[str, Mapping[str, object]],
    metrics: Mapping[str, MetricScalar],
    artifact_paths: Sequence[str | Path],
) -> EvidenceBundle:
    root = Path(output_root).resolve()
    repository = Path(repository_root).resolve()
    lock_path = repository / "requirements.lock"
    artifacts: list[EvidenceArtifact] = []
    for value in artifact_paths:
        path = Path(value).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(f"evidence artifact must be a file below output root: {path}")
        relative = path.relative_to(root).as_posix()
        media_type = {
            ".json": "application/json",
            ".jsonl": "application/x-ndjson",
            ".csv": "text/csv",
            ".md": "text/markdown",
        }.get(path.suffix.lower(), "application/octet-stream")
        artifacts.append(
            EvidenceArtifact(
                path=relative,
                sha256=sha256_file(path),
                size_bytes=path.stat().st_size,
                role="evaluation_evidence",
                media_type=media_type,
            )
        )
    manifest = RunManifest(
        run_id=run_id,
        runner=runner,
        scenario_id=scenario_id,
        seed=seed,
        framework_version=_framework_version(),
        code_revision=source_revision(repository),
        dependency_lock_sha256=sha256_file(lock_path),
        input_hashes={name: canonical_sha256(payload) for name, payload in input_payloads.items()},
        created_at=reproducible_timestamp(),
    )
    bundle = EvidenceBundle(
        EvaluationRun(manifest=manifest, metrics=MetricSet(metrics), artifacts=tuple(artifacts))
    )
    (root / EVIDENCE_BUNDLE_FILENAME).write_text(
        canonical_json(bundle.to_dict()) + "\n", encoding="utf-8", newline="\n"
    )
    return bundle


def load_evidence_bundle(output_root: str | Path) -> EvidenceBundle:
    """Load a bundle and verify every referenced artifact's size and digest."""
    root = Path(output_root).resolve()
    payload = json.loads((root / EVIDENCE_BUNDLE_FILENAME).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("evidence bundle must be a JSON object")
    bundle = EvidenceBundle.from_dict(payload)
    for artifact in bundle.run.artifacts:
        path = (root / artifact.path).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(f"evidence artifact is missing: {artifact.path}")
        if path.stat().st_size != artifact.size_bytes:
            raise ValueError(f"evidence artifact size mismatch: {artifact.path}")
        if sha256_file(path) != artifact.sha256:
            raise ValueError(f"evidence artifact hash mismatch: {artifact.path}")
    return bundle


__all__ = [
    "EVIDENCE_BUNDLE_FILENAME",
    "reproducible_timestamp",
    "load_evidence_bundle",
    "sha256_file",
    "source_revision",
    "write_evidence_bundle",
]
