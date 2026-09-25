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
        return "2.0.0"


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


def collect_input_payloads(
    input_paths: Sequence[str | Path],
    *,
    repository_root: str | Path,
) -> dict[str, Mapping[str, object]]:
    """Load JSON inputs and every repository JSON asset they reference.

    References are string values naming an existing ``.json`` file relative to
    the repository root, plus ``{"preset": <name>}`` topology presets. Keys are
    repository-relative POSIX paths (or the file name for external inputs).
    """
    repository = Path(repository_root).resolve()
    payloads: dict[str, Mapping[str, object]] = {}
    pending = [Path(value) for value in input_paths]
    while pending:
        path = pending.pop()
        resolved = path if path.is_absolute() else (repository / path)
        resolved = resolved.resolve()
        key = resolved.relative_to(repository).as_posix() if resolved.is_relative_to(repository) else resolved.name
        if key in payloads or not resolved.is_file():
            continue
        payload = json.loads(resolved.read_text(encoding="utf-8"))
        payloads[key] = payload if isinstance(payload, Mapping) else {"items": payload}
        stack: list[object] = [payload]
        while stack:
            value = stack.pop()
            if isinstance(value, Mapping):
                preset = value.get("preset")
                if isinstance(preset, str) and (repository / "topologies" / f"{preset}.json").is_file():
                    pending.append(Path("topologies") / f"{preset}.json")
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
            elif isinstance(value, str) and value.endswith(".json") and not Path(value).is_absolute():
                if (repository / value).is_file():
                    pending.append(Path(value))
    return payloads


def write_directory_evidence_bundle(
    output_root: str | Path,
    *,
    repository_root: str | Path,
    runner: str,
    scenario_id: str,
    seeds: Sequence[int],
    input_paths: Sequence[str | Path],
    metrics: Mapping[str, MetricScalar],
) -> EvidenceBundle:
    """Bundle every file already written below ``output_root``.

    Used for workflows whose runners predate the common contract. Multi-seed
    runs record ``seed=-1`` (as the Agentic Resilience protocol does) and list
    the seeds in the metrics.
    """
    root = Path(output_root).resolve()
    artifact_paths = sorted(
        path for path in root.rglob("*") if path.is_file() and path.name != EVIDENCE_BUNDLE_FILENAME
    )
    seed_values = [int(seed) for seed in seeds]
    return write_evidence_bundle(
        root,
        repository_root=repository_root,
        run_id=root.name,
        runner=runner,
        scenario_id=scenario_id,
        seed=seed_values[0] if len(seed_values) == 1 else -1,
        input_payloads=collect_input_payloads(input_paths, repository_root=repository_root),
        metrics={
            **dict(metrics),
            "seed_count": len(seed_values),
            "seeds": ",".join(str(seed) for seed in seed_values),
            "artifact_count": len(artifact_paths),
        },
        artifact_paths=artifact_paths,
    )


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
    "collect_input_payloads",
    "reproducible_timestamp",
    "load_evidence_bundle",
    "sha256_file",
    "source_revision",
    "write_directory_evidence_bundle",
    "write_evidence_bundle",
]
