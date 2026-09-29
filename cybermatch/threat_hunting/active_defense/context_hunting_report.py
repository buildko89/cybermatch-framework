"""T2 runの結果をJSONL・日本語レポート・Evidence Bundleとして新規directoryへ保存する。"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from cybermatch.contracts import (
    SensitiveDataHygieneError, assert_hygienic_payload, canonical_json, write_evidence_bundle,
)

from .context_hunting_runner import ContextHuntingInputs, ContextHuntingResult
from .contract_validation import ActiveDefenseContractError

RUNNER_NAME = "cti_asm_hypothesis_hunt"
_STATUS_JA = {"matched": "確定match", "ambiguous": "曖昧（保留）", "unmatched": "対応なし", "stale": "期限切れ"}
_DECISION_JA = {"executed": "実行", "deferred_budget": "予算待ち", "expired_unexecuted": "未実行で失効"}
LIMITATIONS = (
    "合成CTI/ASM/内部telemetryによる決定論的な再生であり、実環境での検知性能を示すものではない",
    "priorityは調査順の人工的な重み付きscoreであり、侵害確率ではない",
    "CTIのmatchは侵害の証拠ではない。本runは対処要求（ScopedResponseAction）を生成しない",
    "ログ欠損・遅延の比較、4mode比較、対処効果の評価はT3で行う",
)


def _jsonl(path: Path, rows: list[dict[str, object]]) -> Path:
    path.write_text("".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8")
    return path


def write_context_hunting_outputs(
    *, result: ContextHuntingResult, inputs: ContextHuntingInputs, output_dir: Path, repository_root: Path,
) -> dict[str, object]:
    """既存directoryは上書きしない。保存前に全payloadの保存禁止形式を検査する。"""
    payload = result.to_dict()
    try:
        assert_hygienic_payload(payload)
    except SensitiveDataHygieneError as exc:
        raise ActiveDefenseContractError("結果に保存禁止のfieldまたは値があるため保存しません") from exc
    output_dir.mkdir(parents=True, exist_ok=False)
    paths = [
        _jsonl(output_dir / "cti_observations.jsonl", [r.to_dict() for r in inputs.cti_observations]),
        _jsonl(output_dir / "asm_observations.jsonl", [r.to_dict() for r in inputs.asm_observations]),
        _jsonl(output_dir / "asset_bindings.jsonl", [r.to_dict() for r in inputs.bindings]),
        _jsonl(output_dir / "matches.jsonl", payload["matches"]),  # type: ignore[arg-type]
        _jsonl(output_dir / "hypotheses.jsonl", payload["hypotheses"]),  # type: ignore[arg-type]
        _jsonl(output_dir / "scheduler_decisions.jsonl", payload["scheduler_decisions"]),  # type: ignore[arg-type]
        _jsonl(output_dir / "binding_executions.jsonl", payload["binding_executions"]),  # type: ignore[arg-type]
        _jsonl(output_dir / "finding_trace.jsonl", payload["finding_traces"]),  # type: ignore[arg-type]
        _jsonl(output_dir / "findings.jsonl", payload["findings"]),  # type: ignore[arg-type]
    ]
    result_hash = result.result_hash
    metrics = result.metrics()
    metrics_path = output_dir / "metrics.json"
    metrics_path.write_text(canonical_json({**metrics, "result_hash": result_hash}) + "\n", encoding="utf-8")
    result_path = output_dir / "context_hunting_result.json"
    result_path.write_text(canonical_json(payload) + "\n", encoding="utf-8")
    report_path = output_dir / "report.md"
    report_path.write_text(render_report(result, result_hash), encoding="utf-8")
    spec = result.spec
    bundle = write_evidence_bundle(
        output_dir, repository_root=repository_root, run_id=spec.run_id, runner=RUNNER_NAME,
        scenario_id=spec.scenario_id, seed=spec.seed, input_payloads=dict(inputs.payloads),
        metrics={**metrics, "result_hash": result_hash},
        artifact_paths=(*paths, metrics_path, result_path, report_path),
    )
    return {"result_hash": result_hash, "bundle_hash": bundle.bundle_hash, "report": str(report_path),
            "evidence_class": "synthetic-only", "metrics": metrics}


def render_report(result: ContextHuntingResult, result_hash: str) -> str:
    spec, metrics = result.spec, result.metrics()
    latest = {match.cti_ref: match for match in result.final_matches}
    fence = chr(96) * 3
    lines = [
        "# CTI・ASM文脈ハンティング（T2）実行結果", "",
        f"- run ID: `{spec.run_id}` / tenant: `{spec.tenant_id}` / horizon: {spec.horizon_steps} step",
        "- evidence class: `synthetic-only`（合成データのみ。実ログ・実credentialは含まない）",
        f"- 決定論的結果hash: `{result_hash}`", "",
        "## 処理の流れ", "",
        f"{fence}mermaid", "flowchart LR",
        '    C["CTI予兆"] --> X["相関規則v1"]', '    A["ASM資産"] --> X', '    B["観測済みbinding"] --> X',
        '    X -->|matchedのみ| H["仮説template"]', '    H --> S["scheduler（予算・待機）"]',
        '    L["到着済み内部telemetry"] --> S', '    S --> E["既存engine / recipe"]',
        '    E --> F["Finding + detected_step"]', f"{fence}", "",
        "## 主要指標", "", "| 指標 | 値 |", "|---|---|",
        *(f"| `{name}` | {value} |" for name, value in metrics.items()), "",
        "## 相関結果（horizon最終stepの状態）", "",
        "置換（supersedes）された旧版CTIは表に含めません。全履歴は`matches.jsonl`にあります。", "",
        "| CTI | 状態 | 相関種別 | priority_bp | 欠損成分 | 初回matched step | 理由コード |",
        "|---|---|---|---|---|---|---|",
    ]
    for cti_ref, match in sorted(latest.items()):
        lines.append(
            f"| `{cti_ref}` | {_STATUS_JA[match.status]} | {match.match_kind} | "
            f"{'-' if match.priority_bp is None else match.priority_bp} | "
            f"{', '.join(match.missing_components) or '-'} | "
            f"{result.first_matched_step_by_cti.get(cti_ref, '-')} | {', '.join(match.reason_codes)} |")
    lines += ["", "## 仮説", "", "| 作成step | template | subject | priority_bp | 失効step | recipe |",
              "|---|---|---|---|---|---|"]
    for spec_item in result.hypotheses:
        lines.append(
            f"| {spec_item.created_step} | {spec_item.template_id} | {spec_item.subject_kind}:`{spec_item.subject_ref}` | "
            f"{spec_item.priority_bp} | {spec_item.expires_step} | "
            f"{', '.join(b.recipe_id for b in spec_item.recipe_bindings)} |")
    per_step = Counter((d.step, d.decision) for d in result.decisions)
    steps = sorted({d.step for d in result.decisions})
    lines += ["", "## schedulerの判断（stepごとの件数）", "",
              "| step | " + " | ".join(_DECISION_JA.values()) + " |", "|---" * (len(_DECISION_JA) + 1) + "|"]
    for step in steps:
        lines.append(f"| {step} | " + " | ".join(str(per_step[(step, key)]) for key in _DECISION_JA) + " |")
    lines += ["", "## recipe実行", "", "| step | recipe | 評価状態 | 入力観測数 | 欠損field | 新規Finding |",
              "|---|---|---|---|---|---|"]
    for execution in result.executions:
        lines.append(
            f"| {execution.step} | {execution.recipe_id} | {execution.evaluation_status} | "
            f"{len(execution.input_event_ids)} | {', '.join(execution.missing_fields) or '-'} | "
            f"{len(execution.new_finding_ids)} |")
    lines += ["", "## Finding trace", "",
              "| Finding | recipe | 証拠の発生step | 検知step | 内部観測数 | 外部予兆ref | T3対処判断の入力可 |",
              "|---|---|---|---|---|---|---|"]
    for trace in result.traces:
        lines.append(
            f"| `{trace.finding_id}` | {trace.recipe_id} | {trace.finding_start_step}–{trace.finding_end_step} | "
            f"{trace.detected_step} | {len(trace.observation_refs)} | {', '.join(trace.context_observation_refs)} | "
            f"{'はい' if trace.response_eligible else 'いいえ'} |")
    if not result.traces:
        lines.append("| - | - | - | - | - | - | - |")
    lines += ["", "## 解釈上の制約", "", *(f"- {item}" for item in LIMITATIONS), ""]
    return "\n".join(lines)


__all__ = ["LIMITATIONS", "RUNNER_NAME", "render_report", "write_context_hunting_outputs"]
