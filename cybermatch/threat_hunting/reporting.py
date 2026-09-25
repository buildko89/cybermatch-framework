"""Deterministic CSV, JSON, and Markdown reporting for H2 evaluation runs."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .artifacts import MANIFEST_FILENAME, ThreatHuntingArtifactError, load_threat_hunting_artifacts
from .evaluation import ThreatHuntingEvaluation
from .models import Finding, GroundTruthLabel, canonical_json


METRICS_FILENAME = "metrics.json"
FINDINGS_CSV_FILENAME = "findings.csv"
REPORT_FILENAME = "THREAT_HUNTING_REPORT.md"
GROUND_TRUTH_DIRNAME = "ground_truth"
GROUND_TRUTH_LABELS_FILENAME = "ground_truth/labels.json"
GROUND_TRUTH_MATCHING_FILENAME = "ground_truth/matching.json"
EVALUATION_ARTIFACT_FILENAMES = (
    METRICS_FILENAME,
    FINDINGS_CSV_FILENAME,
    REPORT_FILENAME,
    GROUND_TRUTH_LABELS_FILENAME,
    GROUND_TRUTH_MATCHING_FILENAME,
)


class ThreatHuntingReportError(ThreatHuntingArtifactError):
    """Raised when evaluation artifacts cannot be written or verified."""


class ThreatHuntingReportExistsError(ThreatHuntingReportError):
    """Raised when a report would overwrite an existing evaluation artifact."""


@dataclass(frozen=True)
class ThreatHuntingReportPaths:
    output_dir: Path
    metrics: Path
    findings_csv: Path
    report: Path
    ground_truth_labels: Path
    ground_truth_matching: Path
    manifest: Path
    artifact_hash: str


@dataclass(frozen=True)
class LoadedThreatHuntingReport:
    evaluation: ThreatHuntingEvaluation
    ground_truth: tuple[GroundTruthLabel, ...]
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
        raise ThreatHuntingReportError(f"unable to hash {path}: {exc}") from exc
    return digest.hexdigest()


def _json_content(payload: Mapping[str, object] | list[object]) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"


def _write_text(path: Path, content: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(path)


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ThreatHuntingReportError(f"unable to read {path.name}: {exc}") from exc


def _csv_content(
    findings: tuple[Finding, ...],
    evaluation: ThreatHuntingEvaluation,
) -> str:
    match_by_finding = {match.finding_id: match for match in evaluation.matches}
    output = io.StringIO(newline="")
    fieldnames = (
        "finding_id",
        "recipe_id",
        "recipe_version",
        "severity",
        "score",
        "campaign_id",
        "actor_id",
        "start_step",
        "end_step",
        "title",
        "reason",
        "evidence_event_ids",
        "truth_status",
        "matched_label_id",
        "detection_delay_steps",
        "matched_on",
    )
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for finding in findings:
        match = match_by_finding.get(finding.finding_id)
        writer.writerow(
            {
                "finding_id": finding.finding_id,
                "recipe_id": finding.recipe_id,
                "recipe_version": finding.recipe_version,
                "severity": finding.severity,
                "score": finding.score,
                "campaign_id": finding.campaign_id,
                "actor_id": finding.actor_id or "",
                "start_step": finding.start_step,
                "end_step": finding.end_step,
                "title": finding.title,
                "reason": finding.reason,
                "evidence_event_ids": "|".join(finding.evidence_event_ids),
                "truth_status": "true_positive" if match else "false_positive",
                "matched_label_id": match.label_id if match else "",
                "detection_delay_steps": match.detection_delay_steps if match else "",
                "matched_on": "|".join(match.matched_on) if match else "",
            }
        )
    return output.getvalue()


def _markdown_content(evaluation: ThreatHuntingEvaluation) -> str:
    metrics = evaluation.metrics
    lines = [
        "# Threat Hunting Evaluation Report",
        "",
        f"Schema version: `{evaluation.schema_version}`  ",
        f"Total steps: `{evaluation.total_steps}`  ",
        f"Matching policy: `{evaluation.matching_policy.policy_id}` ",
        f"(`{evaluation.matching_policy.policy_hash}`)",
        "",
        "## Detection quality",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    primary_metrics = (
        "precision",
        "recall",
        "f1",
        "false_positives_per_100_steps",
        "mean_time_to_detect_steps",
        "median_time_to_detect_steps",
        "pre_compromise_detection_rate",
        "campaign_coverage",
        "actor_coverage",
        "target_coverage",
        "window_coverage",
        "evidence_completeness",
    )
    for name in primary_metrics:
        lines.append(f"| `{name}` | {_format_metric(metrics.get(name))} |")
    lines.extend(
        [
            "",
            "## Analyst burden",
            "",
            "| Metric | Value |",
            "|---|---:|",
        ]
    )
    burden_metrics = (
        "finding_count",
        "unique_evidence_event_count",
        "total_evidence_references",
        "distinct_actor_count",
        "distinct_target_count",
        "high_severity_finding_count",
        "duplicate_suppressed_count",
        "findings_per_100_steps",
        "evidence_events_per_finding",
        "context_switch_count",
        "operational_burden",
        "wasted_burden",
        "hunting_value_score",
    )
    for name in burden_metrics:
        lines.append(f"| `{name}` | {_format_metric(metrics.get(name))} |")
    if evaluation.cost_profile is None:
        lines.extend(
            [
                "",
                "Weighted burden is not calculated because no AnalystCostProfile was supplied.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                f"Cost profile: `{evaluation.cost_profile.profile_id}` ",
                f"(`{evaluation.cost_profile.profile_hash}`)",
            ]
        )
    lines.extend(
        [
            "",
            "## Matching summary",
            "",
            f"- Matched pairs: {len(evaluation.matches)}",
            f"- Unmatched findings: {len(evaluation.unmatched_finding_ids)}",
            f"- Unmatched truth labels: {len(evaluation.unmatched_label_ids)}",
            "",
        ]
    )
    return "\n".join(lines)


def _format_metric(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, float):
        return format(value, ".12g")
    return str(value)


class ThreatHuntingReportWriter:
    """Add immutable evaluation-mode artifacts to an existing H1 bundle."""

    def __init__(self, output_dir: str | Path):
        self._output_dir = Path(output_dir).resolve()

    @property
    def output_dir(self) -> Path:
        return self._output_dir

    def write(
        self,
        *,
        evaluation: ThreatHuntingEvaluation,
        findings: Iterable[Finding],
        ground_truth: Iterable[GroundTruthLabel],
    ) -> ThreatHuntingReportPaths:
        if not isinstance(evaluation, ThreatHuntingEvaluation):
            raise ThreatHuntingReportError(
                "evaluation must be a ThreatHuntingEvaluation"
            )
        finding_values = tuple(
            sorted(
                findings,
                key=lambda finding: (
                    finding.start_step,
                    finding.end_step,
                    finding.recipe_id,
                    finding.finding_id,
                ),
            )
        )
        truth_values = tuple(
            sorted(
                ground_truth,
                key=lambda label: (label.start_step, label.label_type, label.label_id),
            )
        )
        if any(not isinstance(value, Finding) for value in finding_values):
            raise ThreatHuntingReportError("findings must contain Finding values only")
        if any(not isinstance(value, GroundTruthLabel) for value in truth_values):
            raise ThreatHuntingReportError(
                "ground_truth must contain GroundTruthLabel values only"
            )

        loaded = load_threat_hunting_artifacts(self._output_dir)
        if {finding.finding_id for finding in finding_values} != {
            finding.finding_id for finding in loaded.findings
        }:
            raise ThreatHuntingReportError(
                "reported findings do not match the existing artifact bundle"
            )
        finding_ids = {finding.finding_id for finding in finding_values}
        label_ids = {label.label_id for label in truth_values}
        if not {match.finding_id for match in evaluation.matches}.issubset(finding_ids):
            raise ThreatHuntingReportError("evaluation references an unknown finding")
        if not {match.label_id for match in evaluation.matches}.issubset(label_ids):
            raise ThreatHuntingReportError("evaluation references an unknown truth label")
        evaluated_label_ids = {
            label.label_id
            for label in truth_values
            if label.label_type in evaluation.matching_policy.evaluated_label_types
        }
        reported_finding_ids = {
            match.finding_id for match in evaluation.matches
        }.union(evaluation.unmatched_finding_ids)
        reported_label_ids = {
            match.label_id for match in evaluation.matches
        }.union(evaluation.unmatched_label_ids)
        if reported_finding_ids != finding_ids:
            raise ThreatHuntingReportError(
                "evaluation finding IDs do not cover the reported findings"
            )
        if reported_label_ids != evaluated_label_ids:
            raise ThreatHuntingReportError(
                "evaluation label IDs do not cover the evaluated truth labels"
            )

        paths = {name: self._output_dir / Path(name) for name in EVALUATION_ARTIFACT_FILENAMES}
        existing = [name for name, path in paths.items() if path.exists()]
        if existing:
            raise ThreatHuntingReportExistsError(
                "evaluation artifact already exists: " + ", ".join(existing)
            )
        ground_truth_dir = self._output_dir / GROUND_TRUTH_DIRNAME
        if ground_truth_dir.exists():
            raise ThreatHuntingReportExistsError(
                f"evaluation artifact already exists: {GROUND_TRUTH_DIRNAME}"
            )

        matching_payload: dict[str, object] = {
            "schema_version": evaluation.schema_version,
            "matching_policy": evaluation.matching_policy.to_dict(),
            "matching_policy_hash": evaluation.matching_policy.policy_hash,
            "matches": [match.to_dict() for match in evaluation.matches],
            "unmatched_finding_ids": list(evaluation.unmatched_finding_ids),
            "unmatched_label_ids": list(evaluation.unmatched_label_ids),
        }
        contents = {
            METRICS_FILENAME: _json_content(evaluation.to_dict()),
            FINDINGS_CSV_FILENAME: _csv_content(finding_values, evaluation),
            REPORT_FILENAME: _markdown_content(evaluation),
            GROUND_TRUTH_LABELS_FILENAME: _json_content(
                [label.to_dict() for label in truth_values]
            ),
            GROUND_TRUTH_MATCHING_FILENAME: _json_content(matching_payload),
        }
        manifest_path = self._output_dir / MANIFEST_FILENAME
        manifest_value = _read_json(manifest_path)
        if not isinstance(manifest_value, dict):
            raise ThreatHuntingReportError("manifest must contain a JSON object")
        manifest = dict(manifest_value)
        created: list[Path] = []
        try:
            ground_truth_dir.mkdir(exist_ok=False)
            created.append(ground_truth_dir)
            for name in EVALUATION_ARTIFACT_FILENAMES:
                path = paths[name]
                _write_text(path, contents[name])
                created.append(path)
            descriptors = manifest.get("artifacts")
            if not isinstance(descriptors, dict):
                raise ThreatHuntingReportError("manifest artifacts descriptor is missing")
            descriptors = dict(descriptors)
            for name in EVALUATION_ARTIFACT_FILENAMES:
                path = paths[name]
                descriptors[name] = {
                    "sha256": _sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            manifest["artifacts"] = descriptors
            manifest["evaluation_mode"] = True
            manifest["truth_matching_policy"] = {
                **evaluation.matching_policy.to_dict(),
                "sha256": evaluation.matching_policy.policy_hash,
            }
            manifest["cost_profile"] = (
                {
                    **evaluation.cost_profile.to_dict(),
                    "sha256": evaluation.cost_profile.profile_hash,
                }
                if evaluation.cost_profile is not None
                else None
            )
            manifest.pop("artifact_hash", None)
            artifact_hash = _sha256_bytes(canonical_json(manifest).encode("utf-8"))
            manifest["artifact_hash"] = artifact_hash
            _write_text(manifest_path, _json_content(manifest))
        except Exception:
            for path in reversed(created):
                try:
                    if path.is_file():
                        path.unlink()
                    elif path.is_dir():
                        path.rmdir()
                except OSError:
                    pass
            raise

        return ThreatHuntingReportPaths(
            output_dir=self._output_dir,
            metrics=paths[METRICS_FILENAME],
            findings_csv=paths[FINDINGS_CSV_FILENAME],
            report=paths[REPORT_FILENAME],
            ground_truth_labels=paths[GROUND_TRUTH_LABELS_FILENAME],
            ground_truth_matching=paths[GROUND_TRUTH_MATCHING_FILENAME],
            manifest=manifest_path,
            artifact_hash=artifact_hash,
        )


def load_threat_hunting_report(output_dir: str | Path) -> LoadedThreatHuntingReport:
    """Load and hash-verify evaluation artifacts from an H2 bundle."""

    root = Path(output_dir).resolve()
    loaded = load_threat_hunting_artifacts(root)
    manifest = loaded.manifest
    if manifest.get("evaluation_mode") is not True:
        raise ThreatHuntingReportError("artifact bundle is not an evaluation-mode run")
    descriptors = manifest.get("artifacts")
    if not isinstance(descriptors, Mapping):
        raise ThreatHuntingReportError("manifest artifacts descriptor is missing")
    for name in EVALUATION_ARTIFACT_FILENAMES:
        descriptor = descriptors.get(name)
        path = root / Path(name)
        if not isinstance(descriptor, Mapping):
            raise ThreatHuntingReportError(f"manifest descriptor is missing for {name}")
        if not path.is_file() or descriptor.get("sha256") != _sha256_file(path):
            raise ThreatHuntingReportError(f"artifact hash verification failed: {name}")
        if descriptor.get("size_bytes") != path.stat().st_size:
            raise ThreatHuntingReportError(f"artifact size verification failed: {name}")
    metrics_value = _read_json(root / METRICS_FILENAME)
    labels_value = _read_json(root / Path(GROUND_TRUTH_LABELS_FILENAME))
    matching_value = _read_json(root / Path(GROUND_TRUTH_MATCHING_FILENAME))
    if not isinstance(metrics_value, Mapping):
        raise ThreatHuntingReportError("metrics artifact must contain a JSON object")
    if not isinstance(labels_value, list):
        raise ThreatHuntingReportError("ground truth labels must contain a JSON array")
    if not isinstance(matching_value, Mapping):
        raise ThreatHuntingReportError("ground truth matching must contain a JSON object")
    try:
        evaluation = ThreatHuntingEvaluation.from_dict(metrics_value)
        labels = tuple(GroundTruthLabel.from_dict(value) for value in labels_value)
    except (TypeError, ValueError) as exc:
        raise ThreatHuntingReportError(f"invalid evaluation artifact: {exc}") from exc
    expected_matching = {
        "schema_version": evaluation.schema_version,
        "matching_policy": evaluation.matching_policy.to_dict(),
        "matching_policy_hash": evaluation.matching_policy.policy_hash,
        "matches": [match.to_dict() for match in evaluation.matches],
        "unmatched_finding_ids": list(evaluation.unmatched_finding_ids),
        "unmatched_label_ids": list(evaluation.unmatched_label_ids),
    }
    if dict(matching_value) != expected_matching:
        raise ThreatHuntingReportError("ground truth matching disagrees with metrics")
    manifest_policy = manifest.get("truth_matching_policy")
    expected_manifest_policy = {
        **evaluation.matching_policy.to_dict(),
        "sha256": evaluation.matching_policy.policy_hash,
    }
    if manifest_policy != expected_manifest_policy:
        raise ThreatHuntingReportError("manifest truth matching policy disagrees with metrics")
    expected_manifest_cost = (
        {
            **evaluation.cost_profile.to_dict(),
            "sha256": evaluation.cost_profile.profile_hash,
        }
        if evaluation.cost_profile is not None
        else None
    )
    if manifest.get("cost_profile") != expected_manifest_cost:
        raise ThreatHuntingReportError("manifest cost profile disagrees with metrics")
    return LoadedThreatHuntingReport(
        evaluation=evaluation,
        ground_truth=labels,
        manifest=manifest,
        artifact_hash=loaded.artifact_hash,
    )


__all__ = [
    "EVALUATION_ARTIFACT_FILENAMES",
    "FINDINGS_CSV_FILENAME",
    "GROUND_TRUTH_DIRNAME",
    "GROUND_TRUTH_LABELS_FILENAME",
    "GROUND_TRUTH_MATCHING_FILENAME",
    "METRICS_FILENAME",
    "REPORT_FILENAME",
    "LoadedThreatHuntingReport",
    "ThreatHuntingReportError",
    "ThreatHuntingReportExistsError",
    "ThreatHuntingReportPaths",
    "ThreatHuntingReportWriter",
    "load_threat_hunting_report",
]
