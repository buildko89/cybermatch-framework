"""Auditable external telemetry replay and domain-gap evaluation."""

from __future__ import annotations

import json
import math
import shutil
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from src.cybermatch.contracts import canonical_json, sha256_file, write_evidence_bundle
from src.cybermatch.external_sut import (
    EVIDENCE_CLASSES,
    ExternalSUTAdapter,
    ExternalSUTRequest,
    InProcessHuntingSUTAdapter,
    validate_sut_response,
)

from .artifacts import ThreatHuntingArtifactWriter
from .config import ThreatHuntingRunConfig
from .evaluation import ThreatHuntingEvaluator
from .external import ExternalTelemetryAdapter
from .mappings import ExternalFieldMapping
from .models import GroundTruthLabel
from .recipes import ThreatHuntingRecipeLoader, default_recipe_root
from .reporting import ThreatHuntingReportWriter


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
REPLAY_PROTOCOL_ID = "cybermatch_external_replay_v1"


def _read_object(path: Path, name: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return value


def _portable_path(path: Path, repository: Path) -> str:
    resolved = path.resolve()
    return (
        resolved.relative_to(repository).as_posix()
        if resolved.is_relative_to(repository)
        else resolved.name
    )


def _distribution(events: tuple[object, ...]) -> dict[str, float]:
    counts = Counter(getattr(event, "event_type") for event in events)
    total = sum(counts.values())
    return {name: count / total for name, count in sorted(counts.items())} if total else {}


def _jensen_shannon(left: Mapping[str, object], right: Mapping[str, object]) -> float:
    keys = set(left) | set(right)
    p = {key: float(left.get(key, 0.0)) for key in keys}
    q = {key: float(right.get(key, 0.0)) for key in keys}
    if any(value < 0 or not math.isfinite(value) for value in (*p.values(), *q.values())):
        raise ValueError("event distributions must contain finite non-negative values")
    p_total, q_total = sum(p.values()), sum(q.values())
    if p_total <= 0 or q_total <= 0:
        return 0.0 if p_total == q_total else 1.0
    p = {key: value / p_total for key, value in p.items()}
    q = {key: value / q_total for key, value in q.items()}
    midpoint = {key: (p[key] + q[key]) / 2.0 for key in keys}

    def divergence(values: Mapping[str, float]) -> float:
        return sum(
            value * math.log2(value / midpoint[key])
            for key, value in values.items()
            if value > 0
        )

    return (divergence(p) + divergence(q)) / 2.0


def _domain_gap(
    *,
    events: tuple[object, ...],
    metrics: Mapping[str, object],
    reference: Mapping[str, object],
) -> dict[str, object]:
    reference_metrics = reference.get("metrics")
    reference_distribution = reference.get("event_type_distribution")
    if not isinstance(reference_metrics, Mapping) or not isinstance(reference_distribution, Mapping):
        raise ValueError("synthetic reference requires metrics and event_type_distribution objects")
    current_distribution = _distribution(events)
    selected = ("precision", "recall", "f1", "false_positives_per_100_steps")
    metric_delta: dict[str, float | None] = {}
    for name in selected:
        current, baseline = metrics.get(name), reference_metrics.get(name)
        metric_delta[name] = (
            float(current) - float(baseline)
            if isinstance(current, (int, float)) and isinstance(baseline, (int, float))
            else None
        )
    reference_count = int(reference_metrics.get("event_count", 0))
    event_count_delta = (len(events) - reference_count) / reference_count if reference_count else None
    return {
        "schema_version": "1.0",
        "reference_id": reference.get("reference_id"),
        "reference_evidence_class": reference.get("evidence_class"),
        "event_type_distribution": current_distribution,
        "reference_event_type_distribution": dict(reference_distribution),
        "event_type_js_divergence": _jensen_shannon(current_distribution, reference_distribution),
        "relative_event_count_delta": event_count_delta,
        "metric_delta_replay_minus_synthetic": metric_delta,
    }


def _report(summary: Mapping[str, object], gap: Mapping[str, object]) -> str:
    metrics = summary["metrics"]
    assert isinstance(metrics, Mapping)
    deltas = gap["metric_delta_replay_minus_synthetic"]
    assert isinstance(deltas, Mapping)
    lines = [
        "# CyberMatch Phase 3 External Validity Report",
        "",
        f"Evidence class: `{summary['evidence_class']}`  ",
        f"Protocol: `{summary['protocol_id']}`  ",
        f"Mapping: `{summary['mapping_id']}` (`{summary['mapping_standard']}`)  ",
        "",
        "## Replay result",
        "",
        "| Metric | Value | Delta vs synthetic |",
        "|---|---:|---:|",
    ]
    for name in ("precision", "recall", "f1", "false_positives_per_100_steps"):
        lines.append(f"| `{name}` | {metrics.get(name)} | {deltas.get(name)} |")
    lines.extend(
        [
            "",
            "## Domain gap",
            "",
            f"- Event-type Jensen-Shannon divergence: `{gap['event_type_js_divergence']}`",
            f"- Relative event-count delta: `{gap['relative_event_count_delta']}`",
            "",
            "## Generalization boundary",
            "",
            "This replay demonstrates the adapter, mapping, evaluation, and evidence path for the recorded dataset only. ",
            "It does not establish effectiveness for live production traffic, other organizations, unobserved event families, or an external product unless the evidence class is `external-sut-backed`.",
            "",
        ]
    )
    return "\n".join(lines)


def run_external_replay_evaluation(
    *,
    source_path: str | Path,
    mapping_path: str | Path,
    recipe_path: str | Path,
    ground_truth_path: str | Path,
    synthetic_reference_path: str | Path,
    output_dir: str | Path,
    campaign_id: str,
    scenario_id: str,
    evidence_class: str = "replay-backed",
    seed: int = 0,
    sut_adapter: ExternalSUTAdapter | None = None,
    repository_root: str | Path = REPOSITORY_ROOT,
) -> dict[str, object]:
    """Run the same hunting protocol over external file telemetry and record its gap."""

    if evidence_class not in EVIDENCE_CLASSES or evidence_class == "synthetic-only":
        raise ValueError("external replay evidence_class must be replay-backed or external-sut-backed")
    repository = Path(repository_root).resolve()
    source = Path(source_path).resolve()
    mapping_file = Path(mapping_path).resolve()
    truth_file = Path(ground_truth_path).resolve()
    reference_file = Path(synthetic_reference_path).resolve()
    output = Path(output_dir).resolve()
    if output.exists():
        raise FileExistsError(f"output path already exists: {output}")

    mapping = ExternalFieldMapping.from_dict(_read_object(mapping_file, "mapping"))
    recipe_root = default_recipe_root().resolve()
    recipe_file = Path(recipe_path).resolve()
    if not recipe_file.is_relative_to(recipe_root):
        raise ValueError(f"recipe must be below {recipe_root}")
    recipe = ThreatHuntingRecipeLoader(recipe_root).load(recipe_file.relative_to(recipe_root))
    telemetry = ExternalTelemetryAdapter(
        mapping, campaign_id=campaign_id, scenario_id=scenario_id, seed=seed
    )
    if source.suffix.lower() == ".jsonl":
        events = telemetry.from_jsonl(source)
    elif source.suffix.lower() == ".csv":
        events = telemetry.from_csv(source)
    else:
        raise ValueError("external replay source must be .jsonl or .csv")

    adapter = sut_adapter or InProcessHuntingSUTAdapter(recipe)
    if evidence_class == "external-sut-backed" and isinstance(adapter, InProcessHuntingSUTAdapter):
        raise ValueError("external-sut-backed evidence requires a non-reference SUT adapter")
    request = ExternalSUTRequest(
        run_id=f"{scenario_id}-seed-{seed}",
        events=events,
        evidence_class=evidence_class,
        detector_id=recipe.recipe_id,
        detector_version=recipe.version,
    )
    response = adapter.evaluate(request)
    validate_sut_response(request, response)
    if response.status != "succeeded":
        raise RuntimeError(f"external SUT result is {response.status}: {response.detail or ''}")

    # Ground truth is intentionally loaded only after the SUT has returned.
    truth_payload = json.loads(truth_file.read_text(encoding="utf-8"))
    if not isinstance(truth_payload, list):
        raise ValueError("ground truth must contain a JSON array")
    truth = tuple(GroundTruthLabel.from_dict(value) for value in truth_payload)
    total_steps = max((event.step + 1 for event in events), default=0)
    evaluation = ThreatHuntingEvaluator().evaluate(
        response.findings, truth, events=events, total_steps=total_steps
    )
    reference = _read_object(reference_file, "synthetic reference")
    gap = _domain_gap(events=events, metrics=evaluation.metrics, reference=reference)

    output.mkdir(parents=True, exist_ok=False)
    try:
        hunting_dir = output / "hunting"
        run_config = getattr(adapter, "config", ThreatHuntingRunConfig())
        artifact = ThreatHuntingArtifactWriter(hunting_dir).write(
            events=events,
            findings=response.findings,
            recipe=recipe,
            config=run_config,
            source_history=source,
            campaign_id=campaign_id,
            scenario_id=scenario_id,
            seed=seed,
        )
        report = ThreatHuntingReportWriter(hunting_dir).write(
            evaluation=evaluation, findings=response.findings, ground_truth=truth
        )
        replay_manifest = {
            "schema_version": "1.0",
            "protocol_id": REPLAY_PROTOCOL_ID,
            "evidence_class": evidence_class,
            "campaign_id": campaign_id,
            "scenario_id": scenario_id,
            "seed": seed,
            "source": {
                "path": _portable_path(source, repository),
                "sha256": sha256_file(source),
                "size_bytes": source.stat().st_size,
                "record_count": len(events),
            },
            "mapping": {
                "path": _portable_path(mapping_file, repository),
                "id": mapping.mapping_id,
                "version": mapping.mapping_version,
                "standard": mapping.standard,
                "sha256": mapping.mapping_hash,
            },
            "ground_truth": {
                "path": _portable_path(truth_file, repository),
                "sha256": sha256_file(truth_file),
                "label_count": len(truth),
                "evaluator_only": True,
            },
            "recipe": {"id": recipe.recipe_id, "version": recipe.version, "sha256": recipe.recipe_hash},
            "sut": {"adapter_id": response.adapter_id, "adapter_version": response.adapter_version},
        }
        summary: dict[str, object] = {
            "schema_version": "1.0",
            "protocol_id": REPLAY_PROTOCOL_ID,
            "evidence_class": evidence_class,
            "status": response.status,
            "mapping_id": mapping.mapping_id,
            "mapping_standard": mapping.standard,
            "event_count": len(events),
            "finding_count": len(response.findings),
            "metrics": dict(evaluation.metrics),
            "domain_gap": gap,
        }
        manifest_path = output / "replay_manifest.json"
        gap_path = output / "domain_gap.json"
        summary_path = output / "phase3_external_validity_summary.json"
        phase_report_path = output / "PHASE3_EXTERNAL_VALIDITY_REPORT.md"
        manifest_path.write_text(canonical_json(replay_manifest) + "\n", encoding="utf-8", newline="\n")
        gap_path.write_text(canonical_json(gap) + "\n", encoding="utf-8", newline="\n")
        summary_path.write_text(canonical_json(summary) + "\n", encoding="utf-8", newline="\n")
        phase_report_path.write_text(_report(summary, gap), encoding="utf-8", newline="\n")
        scalar_metrics = {
            "event_count": len(events),
            "finding_count": len(response.findings),
            "f1": evaluation.metrics.get("f1"),
            "event_type_js_divergence": gap["event_type_js_divergence"],
        }
        bundle = write_evidence_bundle(
            output,
            repository_root=repository,
            run_id=f"external-replay-{scenario_id}-{seed}",
            runner=REPLAY_PROTOCOL_ID,
            scenario_id=scenario_id,
            seed=seed,
            input_payloads={"replay_manifest": replay_manifest, "synthetic_reference": reference},
            metrics=scalar_metrics,
            artifact_paths=[
                manifest_path,
                gap_path,
                summary_path,
                phase_report_path,
                artifact.manifest,
                artifact.events,
                artifact.findings,
                report.metrics,
                report.findings_csv,
                report.report,
                report.ground_truth_labels,
                report.ground_truth_matching,
            ],
        )
        summary["evidence_bundle_hash"] = bundle.bundle_hash
        return summary
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


__all__ = ["REPLAY_PROTOCOL_ID", "run_external_replay_evaluation"]
