"""Hash-verified artifacts for CyberMatch fuzzing campaigns."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import shutil
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from src.cybermatch.threat_hunting import HuntEvent, canonical_json
from src.cybermatch.contracts import EVIDENCE_BUNDLE_FILENAME, write_evidence_bundle

from .models import FuzzCase, OracleResult, TargetResult
from .specs import FuzzCampaignSpec
from .targets import TargetManifest


FUZZING_ARTIFACT_FORMAT_VERSION = "1.0"
CAMPAIGN_MANIFEST_FILENAME = "fuzz_campaign_manifest.json"
CAMPAIGN_SUMMARY_FILENAME = "campaign_summary.json"
CAMPAIGN_CSV_FILENAME = "campaign_summary.csv"
CAMPAIGN_REPORT_FILENAME = "FUZZING_REPORT.md"
REPLAY_COMMANDS_FILENAME = "replay_commands.json"


class FuzzArtifactError(ValueError):
    """Raised when campaign artifacts cannot be written or verified."""


class FuzzArtifactExistsError(FuzzArtifactError):
    """Raised when an artifact write would overwrite an existing path."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(payload) + "\n", encoding="utf-8", newline="\n")


def _write_events(path: Path, events: Iterable[HuntEvent]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(canonical_json(event.to_dict()) + "\n" for event in events)
    path.write_text(content, encoding="utf-8", newline="\n")


def _csv_text(rows: Sequence[Mapping[str, object]]) -> str:
    fieldnames = [
        "case_id",
        "case_seed",
        "base_input_id",
        "status",
        "event_count",
        "finding_count",
        "control_finding_count",
        "interesting",
        "oracle_failures",
        "oracle_interesting",
        "semantic_signature",
        "loop_mode",
        "prevented_event_count",
        "post_alert_blast_radius",
    ]
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows({name: row.get(name) for name in fieldnames} for row in rows)
    return handle.getvalue()


def _report(summary: Mapping[str, object]) -> str:
    counts = summary["status_counts"]
    assert isinstance(counts, Mapping)
    lines = [
        "# CyberMatch Analysis-Guided Fuzzing Report",
        "",
        f"- Campaign: `{summary['campaign_id']}`",
        f"- Attempted cases: `{summary['attempted_cases']}`",
        f"- Interesting cases: `{summary['interesting_cases']}`",
        f"- Unique failure fingerprints: `{summary['unique_failure_fingerprints']}`",
        f"- Semantic signatures: `{summary['semantic_signature_count']}`",
        "",
        "## Target status",
        "",
        "| status | cases |",
        "|---|---:|",
    ]
    for status in (
        "completed",
        "rejected",
        "limit_exceeded",
        "infrastructure_error",
        "timeout",
        "crashed",
    ):
        lines.append(f"| {status} | {counts.get(status, 0)} |")
    lines.extend(
        [
            "",
            "## Cases",
            "",
            "| case | status | events | findings | interesting | oracle failures |",
            "|---|---|---:|---:|---|---:|",
        ]
    )
    rows = summary["rows"]
    assert isinstance(rows, list)
    for row in rows:
        assert isinstance(row, Mapping)
        lines.append(
            f"| `{row['case_id']}` | {row['status']} | {row['event_count']} | "
            f"{row['finding_count']} | {str(row['interesting']).lower()} | {row['oracle_failures']} |"
        )
    return "\n".join(lines) + "\n"


class FuzzArtifactWriter:
    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir).resolve()

    def write(
        self,
        *,
        spec: FuzzCampaignSpec,
        target_manifest: TargetManifest,
        rows: Sequence[Mapping[str, object]],
        corpus: Sequence[
            tuple[
                FuzzCase,
                TargetResult,
                TargetResult | None,
                Sequence[OracleResult],
                Sequence[HuntEvent] | None,
                TargetResult | None,
                TargetResult | None,
            ]
        ],
    ) -> dict[str, object]:
        if self.output_dir.exists():
            raise FuzzArtifactExistsError(f"output path already exists: {self.output_dir}")
        self.output_dir.mkdir(parents=True, exist_ok=False)
        try:
            for (
                case,
                target_result,
                control_result,
                oracle_results,
                minimized,
                open_loop_result,
                control_open_loop_result,
            ) in corpus:
                self._write_case(
                    case,
                    target_result,
                    control_result,
                    oracle_results,
                    minimized,
                    open_loop_result,
                    control_open_loop_result,
                )
            status_counts = {
                status: sum(row.get("status") == status for row in rows)
                for status in (
                    "completed",
                    "rejected",
                    "limit_exceeded",
                    "infrastructure_error",
                    "timeout",
                    "crashed",
                )
            }
            failure_fingerprints = {
                result.fingerprint
                for _, _, _, results, _, _, _ in corpus
                for result in results
                if result.verdict == "fail"
            }
            interesting_fingerprints = {
                result.fingerprint
                for _, _, _, results, _, _, _ in corpus
                for result in results
                if result.verdict == "interesting"
            }
            summary: dict[str, object] = {
                "schema_version": spec.schema_version,
                "campaign_id": spec.campaign_id,
                "attempted_cases": len(rows),
                "interesting_cases": sum(bool(row.get("interesting")) for row in rows),
                "corpus_case_count": len(corpus),
                "unique_failure_fingerprints": len(failure_fingerprints),
                "unique_interesting_fingerprints": len(interesting_fingerprints),
                "semantic_signature_count": len(
                    {str(row.get("semantic_signature")) for row in rows}
                ),
                "status_counts": status_counts,
                "rows": [dict(row) for row in rows],
            }
            _write_json(self.output_dir / CAMPAIGN_SUMMARY_FILENAME, summary)
            (self.output_dir / CAMPAIGN_CSV_FILENAME).write_text(
                _csv_text(rows), encoding="utf-8", newline="\n"
            )
            (self.output_dir / CAMPAIGN_REPORT_FILENAME).write_text(
                _report(summary), encoding="utf-8", newline="\n"
            )
            spec_payload = spec.to_dict()
            replay_commands = [
                {
                    "case_id": case.case_id,
                    "minimized_input": f"corpus/{case.case_id}/minimized/hunt_events.jsonl",
                    "command": f"cybermatch-fuzz --replay corpus/{case.case_id}",
                    "working_directory": ".",
                }
                for case, _, _, _, minimized, _, _ in corpus
                if minimized is not None
            ]
            _write_json(self.output_dir / REPLAY_COMMANDS_FILENAME, {"commands": replay_commands})
            evidence_paths = [
                path
                for path in sorted(self.output_dir.rglob("*"))
                if path.is_file()
                and path.name not in {CAMPAIGN_MANIFEST_FILENAME, EVIDENCE_BUNDLE_FILENAME}
            ]
            write_evidence_bundle(
                self.output_dir,
                repository_root=Path(__file__).resolve().parents[3],
                run_id=f"fuzz-{spec.campaign_id}-{spec.campaign_seed}",
                runner="analysis_guided_fuzzing",
                scenario_id=spec.campaign_id,
                seed=spec.campaign_seed,
                input_payloads={"campaign_spec": spec_payload},
                metrics={
                    "attempted_cases": len(rows),
                    "interesting_cases": summary["interesting_cases"],
                    "unique_failure_fingerprints": len(failure_fingerprints),
                    "minimized_case_count": len(replay_commands),
                    "replay_command_index": REPLAY_COMMANDS_FILENAME,
                },
                artifact_paths=evidence_paths,
            )
            descriptors: dict[str, dict[str, object]] = {}
            for path in sorted(self.output_dir.rglob("*")):
                if not path.is_file() or path.name == CAMPAIGN_MANIFEST_FILENAME:
                    continue
                relative = path.relative_to(self.output_dir).as_posix()
                descriptors[relative] = {
                    "sha256": _sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            manifest: dict[str, object] = {
                "schema_version": spec.schema_version,
                "artifact_format_version": FUZZING_ARTIFACT_FORMAT_VERSION,
                "campaign_id": spec.campaign_id,
                "campaign_seed": spec.campaign_seed,
                "spec": spec_payload,
                "spec_hash": _sha256_bytes(canonical_json(spec_payload).encode("utf-8")),
                "target": target_manifest.to_dict(),
                "limits": spec.limits.to_dict(),
                "artifacts": descriptors,
            }
            artifact_hash = _sha256_bytes(canonical_json(manifest).encode("utf-8"))
            manifest["artifact_hash"] = artifact_hash
            _write_json(self.output_dir / CAMPAIGN_MANIFEST_FILENAME, manifest)
            return {"output_dir": str(self.output_dir), "artifact_hash": artifact_hash, **summary}
        except Exception:
            shutil.rmtree(self.output_dir, ignore_errors=True)
            raise

    def _write_case(
        self,
        case: FuzzCase,
        target_result: TargetResult,
        control_result: TargetResult | None,
        oracle_results: Sequence[OracleResult],
        minimized: Sequence[HuntEvent] | None,
        open_loop_result: TargetResult | None,
        control_open_loop_result: TargetResult | None,
    ) -> None:
        root = self.output_dir / "corpus" / case.case_id
        _write_json(root / "case_manifest.json", case.manifest_dict())
        _write_events(root / "hunt_events.jsonl", case.events)
        _write_json(root / "mutation_trace.json", [value.to_dict() for value in case.mutations])
        _write_json(
            root / "expected" / "ground_truth_labels.json",
            [label.to_dict() for label in case.ground_truth],
        )
        _write_json(root / "actual" / "findings.json", [value.to_dict() for value in target_result.findings])
        # Runtime duration is operational telemetry and intentionally excluded
        # from canonical artifacts so identical inputs have identical hashes.
        _write_json(root / "actual" / "target_result.json", target_result.comparable_dict())
        if open_loop_result is not None:
            _write_json(
                root / "actual" / "open_loop_target_result.json",
                open_loop_result.comparable_dict(),
            )
        _write_json(root / "actual" / "oracle_results.json", [value.to_dict() for value in oracle_results])
        if case.control_events:
            _write_events(root / "control" / "hunt_events.jsonl", case.control_events)
            _write_json(
                root / "control" / "ground_truth_labels.json",
                [label.to_dict() for label in case.control_ground_truth],
            )
        if control_result is not None:
            _write_json(root / "control" / "target_result.json", control_result.comparable_dict())
        if control_open_loop_result is not None:
            _write_json(
                root / "control" / "open_loop_target_result.json",
                control_open_loop_result.comparable_dict(),
            )
        if minimized is not None:
            _write_events(root / "minimized" / "hunt_events.jsonl", minimized)
            _write_json(
                root / "minimized" / "reduction.json",
                {
                    "parent_case_id": case.case_id,
                    "original_event_count": len(case.events),
                    "minimized_event_count": len(minimized),
                    "removed_event_count": len(case.events) - len(minimized),
                    "preserved_fingerprints": sorted(
                        result.fingerprint
                        for result in oracle_results
                        if result.verdict in {"fail", "interesting"}
                    ),
                },
            )


def load_fuzz_campaign(output_dir: str | Path) -> dict[str, object]:
    root = Path(output_dir).resolve()
    manifest_path = root / CAMPAIGN_MANIFEST_FILENAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FuzzArtifactError(f"unable to read campaign manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise FuzzArtifactError("campaign manifest must be an object")
    if manifest.get("artifact_format_version") != FUZZING_ARTIFACT_FORMAT_VERSION:
        raise FuzzArtifactError("unsupported fuzzing artifact format")
    recorded_hash = manifest.get("artifact_hash")
    hash_payload = dict(manifest)
    hash_payload.pop("artifact_hash", None)
    if recorded_hash != _sha256_bytes(canonical_json(hash_payload).encode("utf-8")):
        raise FuzzArtifactError("campaign manifest hash verification failed")
    descriptors = manifest.get("artifacts")
    if not isinstance(descriptors, Mapping):
        raise FuzzArtifactError("campaign artifact descriptors are missing")
    for relative, descriptor in descriptors.items():
        if not isinstance(relative, str) or not isinstance(descriptor, Mapping):
            raise FuzzArtifactError("campaign artifact descriptor is invalid")
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise FuzzArtifactError(f"campaign artifact is missing: {relative}")
        if descriptor.get("sha256") != _sha256_file(path):
            raise FuzzArtifactError(f"campaign artifact hash verification failed: {relative}")
        if descriptor.get("size_bytes") != path.stat().st_size:
            raise FuzzArtifactError(f"campaign artifact size verification failed: {relative}")
    return manifest


__all__ = [
    "CAMPAIGN_CSV_FILENAME",
    "CAMPAIGN_MANIFEST_FILENAME",
    "CAMPAIGN_REPORT_FILENAME",
    "CAMPAIGN_SUMMARY_FILENAME",
    "FUZZING_ARTIFACT_FORMAT_VERSION",
    "REPLAY_COMMANDS_FILENAME",
    "FuzzArtifactError",
    "FuzzArtifactExistsError",
    "FuzzArtifactWriter",
    "load_fuzz_campaign",
]
