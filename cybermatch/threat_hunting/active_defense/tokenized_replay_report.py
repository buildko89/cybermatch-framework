"""T4a replayのdata quality・検知適合性を日本語成果物へ保存する。"""

from __future__ import annotations

from pathlib import Path

from cybermatch.contracts import canonical_json, write_evidence_bundle

from .tokenized_replay_runner import TokenizedReplayInputs, TokenizedReplayResult

RUNNER_NAME = "tokenized_cti_asm_replay"


def _jsonl(path: Path, rows: list[dict[str, object]]) -> Path:
    path.write_text("".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8")
    return path


def write_tokenized_replay_outputs(*, result: TokenizedReplayResult, inputs: TokenizedReplayInputs,
                                   output_dir: Path, repository_root: Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=False)
    hunting = result.hunting
    paths = [
        _jsonl(output_dir / "cti_observations.jsonl", [item.to_dict() for item in inputs.context.cti_observations]),
        _jsonl(output_dir / "asm_observations.jsonl", [item.to_dict() for item in inputs.context.asm_observations]),
        _jsonl(output_dir / "asset_bindings.jsonl", [item.to_dict() for item in inputs.context.bindings]),
        _jsonl(output_dir / "matches.jsonl", [item.to_dict() for item in hunting.matches]),
        _jsonl(output_dir / "hypotheses.jsonl", [item.to_dict() for item in hunting.hypotheses]),
        _jsonl(output_dir / "finding_trace.jsonl", [item.to_dict() for item in hunting.traces]),
    ]
    quality_path = output_dir / "data_quality_report.json"
    quality_path.write_text(canonical_json(result.quality.to_dict()) + "\n", encoding="utf-8")
    result_path = output_dir / "tokenized_replay_result.json"
    result_path.write_text(canonical_json(result.to_dict()) + "\n", encoding="utf-8")
    report_path = output_dir / "report.md"
    report_path.write_text(render_tokenized_replay_report(result), encoding="utf-8")
    paths.extend((quality_path, result_path, report_path))
    metrics = {**hunting.metrics(), "data_quality_passed": result.quality.passed,
               "rejected_record_count": result.quality.rejected_record_count,
               "unsupported_field_count": len(result.quality.unsupported_fields),
               "result_hash": result.result_hash}
    bundle = write_evidence_bundle(
        output_dir, repository_root=repository_root, run_id=result.spec.run_id, runner=RUNNER_NAME,
        scenario_id=result.spec.scenario_id, seed=result.spec.seed, input_payloads=inputs.payloads,
        metrics=metrics, artifact_paths=paths)
    return {"result_hash": result.result_hash, "bundle_hash": bundle.bundle_hash,
            "report": str(report_path), "evidence_class": "replay-backed", "metrics": metrics}


def render_tokenized_replay_report(result: TokenizedReplayResult) -> str:
    quality, metrics = result.quality, result.hunting.metrics()
    lines = ["# Token化済みCTI・ASM replay評価（T4a）", "",
             f"- run ID: `{result.spec.run_id}`",
             "- evidence class: `replay-backed`",
             "- 結論の範囲: **実ログへの検知適合性のみ**。反実仮想の対処効果は評価しません。", "",
             "## データ品質", "", "| 項目 | 値 |", "|---|---:|",
             f"| 入力record | {quality.total_record_count} |",
             f"| 受理 | {quality.accepted_record_count} |",
             f"| 拒否 | {quality.rejected_record_count} |",
             f"| 未対応field | {len(quality.unsupported_fields)} |",
             f"| 正規化version | `{quality.normalization_version}` |",
             f"| identity key version | `{quality.identity_key_version}` |",
             f"| 保持日数 | {quality.retention_days} |", "", "## 検知適合性", "",
             "| 指標 | 値 |", "|---|---:|",
             *(f"| `{name}` | {value} |" for name, value in metrics.items()), "",
             "## 制約", "",
             "- 入力は事前token化snapshotであり、取得元サービスの網羅性や即時性を保証しません。",
             "- 招待制forumやstealer logの網羅性は商用CTIより低い可能性があります。",
             "- source・normalization・retentionを固定したread-only replayです。",
             "- 本結果から本番identity失効や対処の因果効果を主張しません。", ""]
    return "\n".join(lines)


__all__ = ["RUNNER_NAME", "render_tokenized_replay_report", "write_tokenized_replay_outputs"]
