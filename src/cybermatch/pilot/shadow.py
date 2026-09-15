"""Internal-only shadow comparison for approved explanation gateways."""

from __future__ import annotations

from pathlib import Path
import statistics
from typing import Mapping

from src.cybermatch.contracts import canonical_json, canonical_sha256

from .ai import LLMGateway, grounded_explanation
from .grounding import validate_result_view_safety


SHADOW_REPORT_VERSION = "1.0"


def run_shadow_evaluation(
    result_view: Mapping[str, object],
    gateways: Mapping[str, LLMGateway],
    *,
    runs: int = 3,
    unavailable: Mapping[str, str] | None = None,
) -> dict[str, object]:
    if not 3 <= runs <= 5:
        raise ValueError("shadow evaluation requires 3 to 5 runs")
    validate_result_view_safety(result_view)
    view_hash = canonical_sha256(result_view)
    rows: list[dict[str, object]] = []
    for candidate_id, gateway in gateways.items():
        for run_index in range(runs):
            explanation = grounded_explanation(result_view, gateway)
            audit = explanation["audit"]
            rows.append(
                {
                    "candidate_id": candidate_id,
                    "run_index": run_index,
                    "provider_id": audit["provider_id"],
                    "requested_model": audit["requested_model"],
                    "resolved_model": audit["resolved_model"],
                    "validation_status": audit["validation_status"],
                    "failure_class": audit["failure_class"],
                    "failure_detail": audit["failure_detail"],
                    "schema_grounding_passed": audit["failure_class"] is None,
                    "fallback_used": (
                        audit["failure_class"] is not None
                        and audit["validation_status"] == "fallback"
                    ),
                    "latency_ms": audit["latency_ms"],
                    "prompt_tokens": audit["prompt_tokens"],
                    "completion_tokens": audit["completion_tokens"],
                    "total_tokens": audit["total_tokens"],
                    "cost_usd": audit["cost_usd"],
                    "output_hash": audit["output_hash"],
                    "answer": explanation["answer"],
                    "automated_review_flags": _review_flags(explanation["answer"]),
                    "review_status": "pending_blind_review",
                }
            )
    summaries = [_summarize(candidate_id, rows) for candidate_id in gateways]
    unavailable_rows = [
        {"candidate_id": key, "status": "not_run", "reason": value}
        for key, value in sorted((unavailable or {}).items())
    ]
    return {
        "schema_version": SHADOW_REPORT_VERSION,
        "result_view_hash": view_hash,
        "bundle_hash": result_view["bundle_hash"],
        "runs_per_candidate": runs,
        "candidate_summaries": summaries,
        "unavailable_candidates": unavailable_rows,
        "runs": rows,
        "blind_review_status": "pending",
    }


def write_shadow_report(report: Mapping[str, object], output_dir: str | Path) -> tuple[Path, Path]:
    target = Path(output_dir).resolve()
    target.mkdir(parents=True, exist_ok=True)
    json_path = target / "shadow_evaluation.json"
    markdown_path = target / "shadow_evaluation.md"
    blind_path = target / "shadow_blind_review.json"
    blind_key_path = target / "shadow_blind_review_key.json"
    json_path.write_text(canonical_json(report) + "\n", encoding="utf-8", newline="\n")
    markdown_path.write_text(_markdown(report), encoding="utf-8", newline="\n")
    packet, key = _blind_review_packet(report)
    blind_path.write_text(canonical_json(packet) + "\n", encoding="utf-8", newline="\n")
    blind_key_path.write_text(canonical_json(key) + "\n", encoding="utf-8", newline="\n")
    return json_path, markdown_path


def _summarize(candidate_id: str, rows: list[Mapping[str, object]]) -> dict[str, object]:
    selected = [row for row in rows if row["candidate_id"] == candidate_id]
    passed = sum(bool(row["schema_grounding_passed"]) for row in selected)
    fallbacks = sum(bool(row["fallback_used"]) for row in selected)
    latencies = [float(row["latency_ms"]) for row in selected if row["latency_ms"] is not None]
    costs = [float(row["cost_usd"]) for row in selected if row["cost_usd"] is not None]
    return {
        "candidate_id": candidate_id,
        "run_count": len(selected),
        "accepted_count": passed,
        "schema_grounding_pass_rate": passed / len(selected),
        "fallback_count": fallbacks,
        "mean_latency_ms": statistics.fmean(latencies) if latencies else None,
        "total_cost_usd": sum(costs) if costs else None,
        "unique_output_count": len({row["output_hash"] for row in selected}),
        "automated_flag_count": sum(
            bool(row["automated_review_flags"]) for row in selected
        ),
    }


def _review_flags(answer: object) -> list[str]:
    text = canonical_json(answer).lower()
    flags: list[str] = []
    if any(
        phrase in text
        for phrase in (
            "perfect performance",
            "trust the findings",
            "verified and reliable",
            "guaranteed",
        )
    ):
        flags.append("potential_overclaim")
    return flags


def _blind_review_packet(
    report: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    candidates = sorted(
        {str(row["candidate_id"]) for row in report["runs"]}
    )
    labels = {
        candidate: f"candidate-{chr(ord('A') + index)}"
        for index, candidate in enumerate(candidates)
    }
    items = [
        {
            "candidate_label": labels[str(row["candidate_id"])],
            "run_index": row["run_index"],
            "answer": row["answer"],
            "review": {
                "clarity_score_1_to_5": None,
                "evidence_traceability_score_1_to_5": None,
                "material_overclaim": None,
                "notes": None,
            },
        }
        for row in report["runs"]
    ]
    packet = {
        "schema_version": "1.0",
        "bundle_hash": report["bundle_hash"],
        "review_status": "pending",
        "items": items,
    }
    key = {
        "schema_version": "1.0",
        "candidate_mapping": {
            label: candidate for candidate, label in labels.items()
        },
        "instruction": "Keep this mapping separate until blind review is complete.",
    }
    return packet, key


def _markdown(report: Mapping[str, object]) -> str:
    lines = [
        "# CyberMatch OR-4 Shadow Evaluation",
        "",
        f"- Result View hash: `{report['result_view_hash']}`",
        f"- Bundle hash: `{report['bundle_hash']}`",
        f"- Runs per candidate: `{report['runs_per_candidate']}`",
        f"- Blind review: `{report['blind_review_status']}`",
        "",
        "| Candidate | Pass rate | Fallbacks | Mean latency ms | Cost USD | Unique outputs |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for item in report["candidate_summaries"]:
        latency = "n/a" if item["mean_latency_ms"] is None else f"{item['mean_latency_ms']:.2f}"
        cost = "n/a" if item["total_cost_usd"] is None else f"{item['total_cost_usd']:.6f}"
        lines.append(
            f"| {item['candidate_id']} | {item['schema_grounding_pass_rate']:.1%} | "
            f"{item['fallback_count']} | {latency} | {cost} | {item['unique_output_count']} |"
        )
    for item in report["unavailable_candidates"]:
        lines.append("")
        lines.append(f"- `{item['candidate_id']}`: not run ({item['reason']})")
    lines.extend(["", "Generated answers require pending blind human review.", ""])
    return "\n".join(lines)


__all__ = ["SHADOW_REPORT_VERSION", "run_shadow_evaluation", "write_shadow_report"]
