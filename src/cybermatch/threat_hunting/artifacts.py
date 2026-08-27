"""Deterministic, reloadable artifacts for offline threat-hunting runs."""

from __future__ import annotations

import hashlib
import json
import math
import shutil
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .adapters import HistorySource
from .config import ThreatHuntingRunConfig
from .models import Finding, HuntEvent, SCHEMA_VERSION, canonical_json
from .recipes import ThreatHuntingRecipe


ARTIFACT_FORMAT_VERSION = "1.0"
MANIFEST_FILENAME = "threat_hunting_manifest.json"
EVENTS_FILENAME = "hunt_events.jsonl"
FINDINGS_FILENAME = "findings.json"
SUMMARY_FILENAME = "execution_summary.json"
_HASHED_ARTIFACT_FILENAMES = (
    EVENTS_FILENAME,
    FINDINGS_FILENAME,
    SUMMARY_FILENAME,
)


class ThreatHuntingArtifactError(ValueError):
    """Raised when an artifact bundle cannot be written or verified."""


class ThreatHuntingArtifactExistsError(ThreatHuntingArtifactError):
    """Raised when an output target already exists."""


@dataclass(frozen=True)
class ThreatHuntingArtifactPaths:
    output_dir: Path
    manifest: Path
    events: Path
    findings: Path
    summary: Path
    artifact_hash: str


@dataclass(frozen=True)
class LoadedThreatHuntingArtifacts:
    events: tuple[HuntEvent, ...]
    findings: tuple[Finding, ...]
    summary: Mapping[str, object]
    manifest: Mapping[str, object]
    artifact_hash: str


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ThreatHuntingArtifactError(f"unable to hash {path}: {exc}") from exc
    return digest.hexdigest()


def _normalize_history_value(value: object) -> object:
    if isinstance(value, np.ndarray):
        return {
            "dtype": str(value.dtype),
            "shape": list(value.shape),
            "values": _normalize_history_value(value.tolist()),
        }
    if isinstance(value, np.generic):
        return _normalize_history_value(value.item())
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ThreatHuntingArtifactError("history mapping keys must be strings")
        return {
            key: _normalize_history_value(item)
            for key, item in sorted(value.items())
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize_history_value(item) for item in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ThreatHuntingArtifactError("history values must be finite")
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ThreatHuntingArtifactError("history bytes must contain UTF-8") from exc
    raise ThreatHuntingArtifactError(
        f"history contains unsupported value type: {type(value).__name__}"
    )


def hash_history_source(source: HistorySource) -> str:
    """Hash exact file bytes or a canonicalized in-memory history mapping."""

    if isinstance(source, Mapping):
        normalized = _normalize_history_value(source)
        assert isinstance(normalized, dict)
        return _sha256_bytes(canonical_json(normalized).encode("utf-8"))
    path = Path(source)
    if not path.is_file():
        raise ThreatHuntingArtifactError(f"history file not found: {path}")
    return _sha256_file(path)


def _write_text(path: Path, content: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(path)


def _write_json(path: Path, payload: Mapping[str, object] | list[object]) -> None:
    content = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    _write_text(path, content + "\n")


def _require_metadata_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ThreatHuntingArtifactError(f"{field_name} must be a non-empty string")
    return value


def _require_seed(seed: object) -> int | None:
    if seed is None:
        return None
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ThreatHuntingArtifactError("seed must be a non-negative integer or None")
    return seed


def _validate_bundle_inputs(
    events: tuple[HuntEvent, ...],
    findings: tuple[Finding, ...],
    recipe: ThreatHuntingRecipe,
    campaign_id: str,
    scenario_id: str,
    seed: int | None,
) -> None:
    if any(not isinstance(event, HuntEvent) for event in events):
        raise ThreatHuntingArtifactError("events must contain HuntEvent observations only")
    if any(not isinstance(finding, Finding) for finding in findings):
        raise ThreatHuntingArtifactError("findings must contain Finding values only")
    event_ids = [event.event_id for event in events]
    finding_ids = [finding.finding_id for finding in findings]
    if len(set(event_ids)) != len(event_ids):
        raise ThreatHuntingArtifactError("event_id values must be unique")
    if len(set(finding_ids)) != len(finding_ids):
        raise ThreatHuntingArtifactError("finding_id values must be unique")
    if any(
        event.campaign_id != campaign_id
        or event.scenario_id != scenario_id
        or event.seed != seed
        for event in events
    ):
        raise ThreatHuntingArtifactError("event metadata does not match artifact metadata")
    if any(
        finding.campaign_id != campaign_id
        or finding.recipe_id != recipe.recipe_id
        or finding.recipe_version != recipe.version
        for finding in findings
    ):
        raise ThreatHuntingArtifactError("finding metadata does not match artifact metadata")
    known_events = set(event_ids)
    missing_evidence = sorted(
        {
            event_id
            for finding in findings
            for event_id in finding.evidence_event_ids
            if event_id not in known_events
        }
    )
    if missing_evidence:
        raise ThreatHuntingArtifactError(
            "finding evidence is absent from hunt events: " + ", ".join(missing_evidence)
        )


class ThreatHuntingArtifactWriter:
    """Create one immutable-on-write artifact directory."""

    def __init__(self, output_dir: str | Path):
        self._output_dir = Path(output_dir).resolve()

    @property
    def output_dir(self) -> Path:
        return self._output_dir

    def write(
        self,
        *,
        events: Iterable[HuntEvent],
        findings: Iterable[Finding],
        recipe: ThreatHuntingRecipe,
        config: ThreatHuntingRunConfig,
        source_history: HistorySource,
        campaign_id: str,
        scenario_id: str,
        seed: int | None,
    ) -> ThreatHuntingArtifactPaths:
        if not isinstance(recipe, ThreatHuntingRecipe):
            raise ThreatHuntingArtifactError("recipe must be a ThreatHuntingRecipe")
        if not isinstance(config, ThreatHuntingRunConfig):
            raise ThreatHuntingArtifactError("config must be a ThreatHuntingRunConfig")
        campaign_id = _require_metadata_string(campaign_id, "campaign_id")
        scenario_id = _require_metadata_string(scenario_id, "scenario_id")
        seed = _require_seed(seed)
        supplied_events = tuple(events)
        supplied_findings = tuple(findings)
        if any(not isinstance(event, HuntEvent) for event in supplied_events):
            raise ThreatHuntingArtifactError("events must contain HuntEvent observations only")
        if any(not isinstance(finding, Finding) for finding in supplied_findings):
            raise ThreatHuntingArtifactError("findings must contain Finding values only")
        ordered_events = tuple(
            sorted(supplied_events, key=lambda event: (event.step, event.event_id))
        )
        ordered_findings = tuple(
            sorted(
                supplied_findings,
                key=lambda finding: (
                    finding.start_step,
                    finding.end_step,
                    finding.recipe_id,
                    finding.finding_id,
                ),
            )
        )
        _validate_bundle_inputs(
            ordered_events,
            ordered_findings,
            recipe,
            campaign_id,
            scenario_id,
            seed,
        )
        source_history_hash = hash_history_source(source_history)

        if self._output_dir.exists():
            raise ThreatHuntingArtifactExistsError(
                f"output path already exists: {self._output_dir}"
            )
        self._output_dir.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._output_dir.mkdir(exist_ok=False)
        except FileExistsError as exc:
            raise ThreatHuntingArtifactExistsError(
                f"output path already exists: {self._output_dir}"
            ) from exc

        manifest_path = self._output_dir / MANIFEST_FILENAME
        events_path = self._output_dir / EVENTS_FILENAME
        findings_path = self._output_dir / FINDINGS_FILENAME
        summary_path = self._output_dir / SUMMARY_FILENAME
        try:
            events_content = "".join(
                canonical_json(event.to_dict()) + "\n" for event in ordered_events
            )
            _write_text(events_path, events_content)
            _write_json(findings_path, [finding.to_dict() for finding in ordered_findings])

            steps = [event.step for event in ordered_events]
            summary: dict[str, object] = {
                "schema_version": SCHEMA_VERSION,
                "status": "succeeded",
                "recipe_id": recipe.recipe_id,
                "recipe_version": recipe.version,
                "campaign_id": campaign_id,
                "scenario_id": scenario_id,
                "seed": seed,
                "event_count": len(ordered_events),
                "finding_count": len(ordered_findings),
                "first_step": min(steps) if steps else None,
                "last_step": max(steps) if steps else None,
            }
            _write_json(summary_path, summary)

            artifact_descriptors = {
                filename: {
                    "sha256": _sha256_file(self._output_dir / filename),
                    "size_bytes": (self._output_dir / filename).stat().st_size,
                }
                for filename in _HASHED_ARTIFACT_FILENAMES
            }
            manifest: dict[str, object] = {
                "schema_version": SCHEMA_VERSION,
                "artifact_format_version": ARTIFACT_FORMAT_VERSION,
                "campaign_id": campaign_id,
                "scenario_id": scenario_id,
                "seed": seed,
                "source_history_hash": source_history_hash,
                "recipe": {
                    "id": recipe.recipe_id,
                    "version": recipe.version,
                    "sha256": recipe.recipe_hash,
                },
                "config": config.to_dict(),
                "event_count": len(ordered_events),
                "finding_count": len(ordered_findings),
                "artifacts": artifact_descriptors,
            }
            artifact_hash = _sha256_bytes(canonical_json(manifest).encode("utf-8"))
            manifest["artifact_hash"] = artifact_hash
            _write_json(manifest_path, manifest)
        except Exception:
            shutil.rmtree(self._output_dir)
            raise

        return ThreatHuntingArtifactPaths(
            output_dir=self._output_dir,
            manifest=manifest_path,
            events=events_path,
            findings=findings_path,
            summary=summary_path,
            artifact_hash=artifact_hash,
        )


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ThreatHuntingArtifactError(f"unable to read artifact {path.name}: {exc}") from exc


def load_threat_hunting_artifacts(
    output_dir: str | Path,
) -> LoadedThreatHuntingArtifacts:
    """Reload an artifact directory and verify every recorded content hash."""

    root = Path(output_dir).resolve()
    if not root.is_dir():
        raise ThreatHuntingArtifactError(f"artifact directory not found: {root}")
    manifest_value = _load_json(root / MANIFEST_FILENAME)
    if not isinstance(manifest_value, dict):
        raise ThreatHuntingArtifactError("manifest must contain a JSON object")
    manifest = manifest_value
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ThreatHuntingArtifactError("manifest schema_version is unsupported")
    if manifest.get("artifact_format_version") != ARTIFACT_FORMAT_VERSION:
        raise ThreatHuntingArtifactError("artifact_format_version is unsupported")
    recorded_hash = manifest.get("artifact_hash")
    if not isinstance(recorded_hash, str):
        raise ThreatHuntingArtifactError("manifest artifact_hash is missing")
    hash_payload = dict(manifest)
    hash_payload.pop("artifact_hash")
    expected_bundle_hash = _sha256_bytes(canonical_json(hash_payload).encode("utf-8"))
    if recorded_hash != expected_bundle_hash:
        raise ThreatHuntingArtifactError("manifest artifact_hash verification failed")

    descriptors = manifest.get("artifacts")
    if not isinstance(descriptors, dict):
        raise ThreatHuntingArtifactError("manifest artifacts descriptor is missing")
    for filename in _HASHED_ARTIFACT_FILENAMES:
        descriptor = descriptors.get(filename)
        if not isinstance(descriptor, dict) or not isinstance(descriptor.get("sha256"), str):
            raise ThreatHuntingArtifactError(f"manifest descriptor is missing for {filename}")
        path = root / filename
        if not path.is_file() or _sha256_file(path) != descriptor["sha256"]:
            raise ThreatHuntingArtifactError(f"artifact hash verification failed: {filename}")
        if path.stat().st_size != descriptor.get("size_bytes"):
            raise ThreatHuntingArtifactError(f"artifact size verification failed: {filename}")

    events: list[HuntEvent] = []
    try:
        for line_number, line in enumerate(
            (root / EVENTS_FILENAME).read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                events.append(HuntEvent.from_dict(value))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ThreatHuntingArtifactError(
                    f"invalid hunt event at line {line_number}: {exc}"
                ) from exc
    except (OSError, UnicodeError) as exc:
        raise ThreatHuntingArtifactError(f"unable to read {EVENTS_FILENAME}: {exc}") from exc

    findings_value = _load_json(root / FINDINGS_FILENAME)
    if not isinstance(findings_value, list):
        raise ThreatHuntingArtifactError("findings artifact must contain a JSON array")
    try:
        findings = tuple(Finding.from_dict(value) for value in findings_value)
    except (TypeError, ValueError) as exc:
        raise ThreatHuntingArtifactError(f"invalid finding artifact: {exc}") from exc
    summary_value = _load_json(root / SUMMARY_FILENAME)
    if not isinstance(summary_value, dict):
        raise ThreatHuntingArtifactError("execution summary must contain a JSON object")
    if manifest.get("event_count") != len(events) or summary_value.get("event_count") != len(events):
        raise ThreatHuntingArtifactError("event count verification failed")
    if manifest.get("finding_count") != len(findings) or summary_value.get("finding_count") != len(findings):
        raise ThreatHuntingArtifactError("finding count verification failed")
    try:
        ThreatHuntingRunConfig.from_dict(manifest["config"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ThreatHuntingArtifactError(f"manifest config is invalid: {exc}") from exc

    return LoadedThreatHuntingArtifacts(
        events=tuple(events),
        findings=findings,
        summary=summary_value,
        manifest=manifest,
        artifact_hash=recorded_hash,
    )


__all__ = [
    "ARTIFACT_FORMAT_VERSION",
    "EVENTS_FILENAME",
    "FINDINGS_FILENAME",
    "MANIFEST_FILENAME",
    "SUMMARY_FILENAME",
    "LoadedThreatHuntingArtifacts",
    "ThreatHuntingArtifactError",
    "ThreatHuntingArtifactExistsError",
    "ThreatHuntingArtifactPaths",
    "ThreatHuntingArtifactWriter",
    "hash_history_source",
    "load_threat_hunting_artifacts",
]
