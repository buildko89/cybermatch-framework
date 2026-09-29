"""T3評価結果を日本語reportと共通Evidence Bundleへ保存する。"""

from __future__ import annotations

from pathlib import Path

from cybermatch.contracts import canonical_json, write_evidence_bundle

from .active_defense_evaluation_runner import ActiveDefenseEvaluationInputs, ActiveDefenseEvaluationResult

RUNNER_NAME = "active_defense_closed_loop_evaluation"


def _jsonl(path: Path, rows: list[dict[str, object]]) -> Path:
    path.write_text("".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8")
    return path


def write_active_defense_evaluation_outputs(
    *, result: ActiveDefenseEvaluationResult, inputs: ActiveDefenseEvaluationInputs,
    output_dir: Path, repository_root: Path,
) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=False)
    mode_rows = [run.to_summary() for run in result.runs]
    actions = [{"mode_id": run.mode_id, "profile_id": run.profile_id, "seed": run.seed, **item.to_dict()}
               for run in result.runs for item in run.actions]
    receipts = [{"mode_id": run.mode_id, "profile_id": run.profile_id, "seed": run.seed, **item.to_dict()}
                for run in result.runs for item in run.receipts]
    outcomes = [{"mode_id": run.mode_id, "profile_id": run.profile_id, "seed": run.seed, **item.to_dict()}
                for run in result.runs for item in run.outcomes]
    paths = [
        _jsonl(output_dir / "mode_profile_results.jsonl", mode_rows),
        _jsonl(output_dir / "actions.jsonl", actions),
        _jsonl(output_dir / "receipts.jsonl", receipts),
        _jsonl(output_dir / "evaluator_only_world_outcomes.jsonl", outcomes),
    ]
    comparison_path = output_dir / "paired_comparisons.json"
    comparison_path.write_text(canonical_json(result.comparisons) + "\n", encoding="utf-8")
    result_path = output_dir / "active_defense_evaluation_result.json"
    result_path.write_text(canonical_json(result.to_dict()) + "\n", encoding="utf-8")
    report_path = output_dir / "report.md"
    report_path.write_text(render_active_defense_evaluation_report(result), encoding="utf-8")
    paths.extend((comparison_path, result_path, report_path))
    scalar = {
        "mode_profile_seed_run_count": len(result.runs), "seed_count": len(result.spec.seeds),
        "profile_count": len(inputs.hygiene_profiles), "result_hash": result.result_hash,
        "applied_action_count": sum(int(run.metrics["applied_action_count"]) for run in result.runs),
        "false_response_count": sum(int(run.metrics["false_response_count"]) for run in result.runs),
    }
    bundle = write_evidence_bundle(
        output_dir, repository_root=repository_root, run_id=result.spec.run_id, runner=RUNNER_NAME,
        scenario_id=result.spec.scenario_id, seed=-1, input_payloads=inputs.payloads, metrics=scalar,
        artifact_paths=paths,
    )
    return {"result_hash": result.result_hash, "bundle_hash": bundle.bundle_hash,
            "report": str(report_path), "metrics": scalar, "evidence_class": "synthetic-only"}


def render_active_defense_evaluation_report(result: ActiveDefenseEvaluationResult) -> str:
    complete = [run for run in result.runs if run.profile_id == "complete"]
    modes = {run.mode_id: run for run in complete if run.seed == result.spec.seeds[0]}
    lines = [
        "# 能動防御・閉ループ評価（T3）", "",
        f"- run ID: `{result.spec.run_id}`",
        f"- seed: {result.spec.seeds[0]}〜{result.spec.seeds[-1]}（{len(result.spec.seeds)}件）",
        "- evidence class: `synthetic-only`（実ログ・実credentialは含まない）", "",
        "## 比較モード", "", "| モード | 調査順 | 対処 |", "|---|---|---|",
        "| B0 internal_open | 内部identityの固定順 | なし |",
        "| B1 context_open | CTI/ASM priority順 | なし |",
        "| B2 internal_closed | 内部identityの固定順 | identity限定失効 |",
        "| B3 context_closed | CTI/ASM priority順 | identity限定失効 |", "",
        "## 完全ログprofileの固定fixture結果（先頭seed）", "",
        "| モード | Finding | applied | critical到達 | 阻止操作 | TTD |", "|---|---:|---:|---:|---:|---:|",
    ]
    for mode in result.spec.modes:
        run = modes[mode]
        m = run.metrics
        lines.append(f"| {mode} | {m['finding_count']} | {m['applied_action_count']} | "
                     f"{m['critical_reach_count']} | {m['blocked_operation_count']} | "
                     f"{m['time_to_detection_steps'] if m['time_to_detection_steps'] is not None else '-'} |")
    lines += ["", "## paired比較", "",
              "区間は同じcase/seedを組にした2,000回bootstrapの95%区間です。詳細は`paired_comparisons.json`にあります。", ""]
    for metric in ("critical_reach_rate", "finding_count", "false_response_count"):
        comparisons = result.comparisons[metric]
        lines += [f"### `{metric}`", "", "| 比較 | 平均差 | 95%区間 | pair数 |", "|---|---:|---:|---:|"]
        for name, values in comparisons.items():
            mean = values["mean_difference"]
            interval = "-" if mean is None else f"{values['ci_low']:.3f}〜{values['ci_high']:.3f}"
            lines.append(f"| {name} | {'-' if mean is None else f'{mean:.3f}'} | {interval} | {values['pair_count']} |")
        lines.append("")
    hygiene = result.comparisons["logging_hygiene"]
    lines += ["### ログ健全性（LHR）", "",
              "| mode:profile | end-to-end recall | 完全profile比（LHR） | recall差 |",
              "|---|---:|---:|---:|"]
    for name, values in hygiene.items():
        def shown(value):
            return "-" if value is None else f"{value:.3f}"
        lines.append(f"| {name} | {shown(values['end_to_end_recall'])} | "
                     f"{shown(values['logging_hygiene_ratio'])} | "
                     f"{shown(values['recall_difference_from_complete'])} |")
    prevention = result.comparisons["critical_reach_prevention"]
    lines += ["", "### critical到達の防止", "",
              "| profile:mode | B0固定分母 | 防止件数 | 防止率 |", "|---|---:|---:|---:|"]
    for name, values in prevention.items():
        rate = values["critical_reach_prevention_rate"]
        lines.append(f"| {name} | {values['reference_critical_count']} | {values['prevented_count']} | "
                     f"{'-' if rate is None else f'{rate:.3f}'} |")
    lines.append("")
    lines += ["## 解釈上の制約", "",
              "- 合成世界と宣言済み対処モデル内の比較であり、実環境での因果効果を保証しません。",
              "- 20% dropは評価用の設定値であり、実環境の欠損率推定ではありません。",
              "- seed間で同じtemplateを使うため、区間はシナリオ多様性を表しません。",
              "- identity失効は新規認証を拒否しますが、既存sessionを直ちに終了しません。",
              "- evaluator-only成果物は検知器入力へ渡していません。", ""]
    return "\n".join(lines)


__all__ = ["RUNNER_NAME", "render_active_defense_evaluation_report", "write_active_defense_evaluation_outputs"]
