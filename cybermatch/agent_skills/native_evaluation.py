"""native Agent SkillsのS-B01/S-B03/S-B04を再生するS3評価runner。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from cybermatch.contracts import AssetSchemaError, SchemaRegistry, canonical_sha256, write_evidence_bundle

from .mock_tool_boundary import MockToolBoundary, MockToolRequest
from .skill_selection import DeterministicSkillSelector, load_approved_bindings
from .summary_inspection import inspect_summary


class NativeSkillsEvaluationError(ValueError):
    """評価設定、fixture、または出力先が不正。"""


@dataclass(frozen=True)
class NativeSkillsEvaluationResult:
    result_hash: str
    selections: tuple[dict[str, object], ...]
    binding_traces: tuple[dict[str, object], ...]
    summary_inspections: tuple[dict[str, object], ...]
    mock_receipts: tuple[dict[str, object], ...]
    metrics: dict[str, object]


def _read_json(root: Path, relative_path: str) -> dict[str, object]:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise NativeSkillsEvaluationError("fixture pathはrepository内の相対pathに限ります")
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or path.is_symlink():
        raise NativeSkillsEvaluationError("fixtureがrepository外またはsymlinkです")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NativeSkillsEvaluationError("fixtureをJSONとして読み取れません") from exc
    if not isinstance(value, dict):
        raise NativeSkillsEvaluationError("fixture rootはobjectでなければなりません")
    return value


def evaluate_native_skills(
    *, repository_root: str | Path, manifest_path: str, fixture_path: str, max_selected: int = 3,
) -> NativeSkillsEvaluationResult:
    root = Path(repository_root).resolve(strict=True)
    fixture = _read_json(root, fixture_path)
    bindings = load_approved_bindings(repository_root=root, manifest_path=manifest_path)
    selector = DeterministicSkillSelector(bindings, max_selected=max_selected)
    by_skill = {binding.skill_id: binding for binding in bindings}

    selections: list[dict[str, object]] = []
    traces: list[dict[str, object]] = []
    correct_selection = 0
    selection_cases = 0
    correct_abstain = 0
    abstain_cases = 0
    for raw in fixture.get("tasks", []):
        if not isinstance(raw, dict):
            raise NativeSkillsEvaluationError("tasksはobject配列です")
        selection = selector.select(
            task_id=str(raw["task_id"]), task_kind=str(raw["task_kind"]),
            available_fields=raw["available_fields"],
        )
        item = selection.to_dict()
        selections.append(item)
        expected = raw.get("expected_skill_ids")
        if isinstance(expected, list):
            selection_cases += 1
            correct_selection += int(bool(set(expected) & set(selection.selected_ids)))
        else:
            abstain_cases += 1
            correct_abstain += int(selection.abstain_reason == raw.get("expected_abstain_reason"))
        for skill_id in selection.selected_ids:
            binding = by_skill[skill_id]
            traces.append({
                "schema_version": "1.0", "selection_id": selection.selection_id,
                "binding_id": binding.binding_id, "skill_id": binding.skill_id,
                "recipe_id": binding.recipe_id, "recipe_hash": binding.recipe_hash,
                "evaluation_status": "selected_recipe_only",
            })

    inspections: list[dict[str, object]] = []
    summary_correct = 0
    summaries = fixture.get("summaries", [])
    for raw in summaries:
        inspection = inspect_summary(
            summary_id=str(raw["summary_id"]), summary_text=str(raw["text"]),
            visible_record_refs=tuple(str(value) for value in raw["visible_record_refs"]),
        )
        inspections.append(inspection.to_dict())
        summary_correct += int(inspection.verdict == raw["label"])

    mock = fixture.get("mock_tool", {})
    allowlist = {
        (str(item["tenant_id"]), str(item["operation"]), str(item["resource_ref"]))
        for item in mock.get("allowlist", [])
    }
    boundary = MockToolBoundary(allowlist)
    receipts: list[dict[str, object]] = []
    mock_correct = 0
    requests = mock.get("requests", [])
    for raw in requests:
        receipt = boundary.evaluate(MockToolRequest(**{key: str(raw[key]) for key in (
            "request_id", "tenant_id", "agent_ref", "operation", "resource_ref", "purpose_ref"
        )}))
        receipts.append(receipt.to_dict())
        mock_correct += int(receipt.status == raw["label"])

    metrics: dict[str, object] = {
        "selection_case_count": selection_cases,
        "selection_hit_at_3": correct_selection / selection_cases if selection_cases else None,
        "abstain_case_count": abstain_cases,
        "correct_abstain_rate": correct_abstain / abstain_cases if abstain_cases else None,
        "summary_case_count": len(summaries),
        "summary_accuracy": summary_correct / len(summaries) if summaries else None,
        "mock_request_count": len(requests),
        "mock_boundary_accuracy": mock_correct / len(requests) if requests else None,
        "external_package_execution_count": 0,
    }
    semantic = {
        "selections": selections, "binding_traces": traces,
        "summary_inspections": inspections, "mock_receipts": receipts, "metrics": metrics,
    }
    return NativeSkillsEvaluationResult(
        result_hash=canonical_sha256(semantic), selections=tuple(selections),
        binding_traces=tuple(traces), summary_inspections=tuple(inspections),
        mock_receipts=tuple(receipts), metrics=metrics,
    )


def evaluate_native_skills_spec(
    *, repository_root: str | Path, spec_path: str | Path,
) -> NativeSkillsEvaluationResult:
    """登録済み評価specから、truthをselectorへ渡さず評価を開始する。"""
    root = Path(repository_root).resolve(strict=True)
    spec = _read_json(root, str(spec_path))
    try:
        SchemaRegistry().validate("skills_evaluation_spec", spec, source=str(spec_path))
    except AssetSchemaError as exc:
        raise NativeSkillsEvaluationError("Skills評価specが不正です") from exc
    policy = spec["selector_policy"]
    if not isinstance(policy, dict):
        raise NativeSkillsEvaluationError("selector_policyが不正です")
    # evaluator_truth_pathは評価器用の存在証明だけを行い、selectorへは渡さない。
    _read_json(root, str(spec["evaluator_truth_path"]))
    return evaluate_native_skills(
        repository_root=root,
        manifest_path=str(spec["manifest_path"]),
        fixture_path=str(spec["task_fixture_path"]),
        max_selected=int(policy["max_selected"]),
    )


def write_native_skills_evaluation(
    result: NativeSkillsEvaluationResult, output_dir: str | Path,
    *, repository_root: str | Path | None = None,
) -> None:
    output = Path(output_dir)
    if output.exists():
        raise NativeSkillsEvaluationError("既存の出力directoryは上書きしません")
    output.mkdir(parents=True)

    def write_jsonl(name: str, rows: tuple[dict[str, object], ...]) -> None:
        (output / name).write_text(
            "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )

    write_jsonl("skill_selections.jsonl", result.selections)
    write_jsonl("skill_binding_traces.jsonl", result.binding_traces)
    write_jsonl("summary_inspections.jsonl", result.summary_inspections)
    write_jsonl("mock_tool_receipts.jsonl", result.mock_receipts)
    (output / "metrics.json").write_text(
        json.dumps({"result_hash": result.result_hash, **result.metrics}, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report = f"""# Agent Skills native評価レポート

## 結果

- 結果hash: `{result.result_hash}`
- 選択hit@3: {result.metrics['selection_hit_at_3']}
- 正しい棄権率: {result.metrics['correct_abstain_rate']}
- 要約検査の正解率: {result.metrics['summary_accuracy']}
- 模擬tool境界の正解率: {result.metrics['mock_boundary_accuracy']}

## 適用範囲

この結果は固定済みnative SOP、承認manifest、合成fixtureに対する再生結果です。外部Skillの安全性、自然言語理解、実OSのネットワーク遮断、実環境での対処成功を示すものではありません。Skill本文やscriptsは実行していません。
"""
    (output / "report.md").write_text(report, encoding="utf-8")
    repository = Path(repository_root).resolve() if repository_root else Path(__file__).resolve().parents[2]
    artifacts = sorted(path for path in output.iterdir() if path.is_file())
    write_evidence_bundle(
        output,
        repository_root=repository,
        run_id=output.name,
        runner="native_agent_skills_evaluation",
        scenario_id="synthetic-skills-evaluation-v1",
        seed=0,
        input_payloads={"result": {"result_hash": result.result_hash}},
        metrics={**result.metrics, "result_hash": result.result_hash},
        artifact_paths=artifacts,
    )


__all__ = [
    "NativeSkillsEvaluationError", "NativeSkillsEvaluationResult",
    "evaluate_native_skills", "write_native_skills_evaluation",
    "evaluate_native_skills_spec",
]
