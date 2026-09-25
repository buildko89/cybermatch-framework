"""Run CyberMatch evaluations from a single, named menu.

Each selected lane writes to ``output/evaluations/<run-id>/<lane>/`` so runs
never collide with earlier results. After all lanes finish, an
``EVALUATION_SUMMARY.md`` lists the status, elapsed time, the report to read
first, and the verified Evidence Bundle hashes for every lane.

Examples::

    python scripts/evaluate.py --list
    python scripts/evaluate.py quickstart
    python scripts/evaluate.py product hunting
    python scripts/evaluate.py all --run-id review-20260925
    python scripts/evaluate.py product --seeds 0      # fastest, no confidence intervals
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_OUTPUT_ROOT = "output/evaluations"
DEFAULT_SEEDS = "0,1,2,3,4"
QUICKSTART_SEEDS = "0"
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
SEEDS_PATTERN = re.compile(r"^\d+(,\d+)*$")
DEMOS = ("demo_vendor_comparison", "demo_deception_value", "demo_ot_factory_defense")


@dataclass(frozen=True)
class Lane:
    """One named evaluation that can be selected from the command line."""

    lane_id: str
    title: str
    question: str
    minutes: str
    build_commands: Callable[[str, str], List[List[str]]]
    reports: Sequence[str]
    evidence_bundles: Sequence[str] = ()
    uses_output_dir: bool = True
    uses_seeds: bool = False


@dataclass
class LaneResult:
    lane: Lane
    status: str
    seconds: float
    output_dir: str | None
    commands: List[str] = field(default_factory=list)
    evidence_bundle_hashes: Dict[str, str] = field(default_factory=dict)
    message: str = ""


def _py(*args: str) -> List[str]:
    return [sys.executable, *args]


def _check_commands(_: str, __: str) -> List[List[str]]:
    return [
        _py("scripts/run_tests.py", "--smoke"),
        _py("scripts/validate_assets.py", "--root", "."),
    ]


def _product_commands(out: str, seeds: str) -> List[List[str]]:
    return [
        _py("scripts/run_scenario.py", f"scenarios/demos/{demo}.json", "--output-dir", f"{out}/{demo}", "--seeds", seeds)
        for demo in DEMOS
    ]


def _standard_commands(out: str, seeds: str) -> List[List[str]]:
    # run_scenario.py generates a fresh Phase6.3 baseline inside the output
    # directory, so the result never depends on output/phase63_mission_products.
    return [_py("scripts/run_scenario.py", "benchmarks/cybermatch_standard_v1.json", "--output-dir", out, "--seeds", seeds)]


def _hunting_commands(out: str, _: str) -> List[List[str]]:
    return [
        _py("scripts/run_scenario.py", "benchmarks/cybermatch_hunting_v1.json", "--output-dir", f"{out}/benchmark"),
        _py(
            "scripts/run_scenario.py",
            "scenarios/threat_hunting/threat_hunt_c2_jitter.json",
            "--output-dir",
            f"{out}/closed_loop_c2_jitter",
        ),
    ]


def _agentic_commands(out: str, _: str) -> List[List[str]]:
    return [_py("scripts/run_scenario.py", "benchmarks/cybermatch_agentic_security_v1.json", "--output-dir", out)]


def _resilience_commands(out: str, _: str) -> List[List[str]]:
    return [_py("scripts/run_agentic_resilience.py", "--output-dir", out)]


def _fuzzing_commands(out: str, _: str) -> List[List[str]]:
    return [_py("scripts/run_fuzzing.py", "fuzzing/campaigns/threat_hunting_mvp_v1.json", "--output-dir", out)]


def _replay_commands(out: str, _: str) -> List[List[str]]:
    return [
        _py(
            "scripts/run_external_replay.py",
            "--source", "replays/anonymized/ocsf_boundary_escape_v1.jsonl",
            "--mapping", "mappings/telemetry/ocsf_security_finding_v1.json",
            "--recipe", "recipes/threat_hunting/agentic_boundary_pressure_v1.json",
            "--ground-truth", "replays/anonymized/ocsf_boundary_escape_v1.ground_truth.json",
            "--synthetic-reference", "replays/synthetic_reference/agentic_boundary_pressure_v1.json",
            "--output", out,
            "--campaign-id", "phase3-anonymized-replay",
            "--scenario-id", "agentic-boundary-pressure-external",
            "--evidence-class", "replay-backed",
            "--seed", "0",
        )
    ]


LANES: Dict[str, Lane] = {
    lane.lane_id: lane
    for lane in (
        Lane(
            "check",
            "環境確認",
            "インストールは正しいか、同梱JSON資産はスキーマに適合しているか",
            "~0.5",
            _check_commands,
            reports=("output/test-results/smoke-*.xml",),
            uses_output_dir=False,
        ),
        Lane(
            "replay",
            "外部妥当性リプレイ",
            "記録済みテレメトリ(OCSF)に対して検知レシピは正解ラベルをどこまで再現するか",
            "<0.5",
            _replay_commands,
            reports=("PHASE3_EXTERNAL_VALIDITY_REPORT.md", "phase3_external_validity_summary.json"),
            evidence_bundles=(".",),
        ),
        Lane(
            "product",
            "製品×攻撃目的の比較デモ",
            "攻撃者のmissionが変わると、有効な製品プロファイルはどう変わるか。seedを変えても結論は変わらないか",
            "~3 (5 seed) / ~0.7 (1 seed)",
            _product_commands,
            reports=tuple(
                f"{demo}/{name}" for demo in DEMOS for name in ("PHASE63_MISSION_PRODUCT_REPORT.md", "SEED_ROBUSTNESS_REPORT.md")
            ),
            uses_seeds=True,
        ),
        Lane(
            "standard",
            "標準ベンチマーク",
            "業種シナリオ×トポロジ×mission×製品の総当たりで、どの防御が安定して効くか",
            "~3 (5 seed) / ~1 (1 seed)",
            _standard_commands,
            reports=(
                "PHASE85_STANDARD_BENCHMARK_REPORT.md",
                "SEED_ROBUSTNESS_REPORT.md",
                "baseline_provenance.json",
            ),
            uses_seeds=True,
        ),
        Lane(
            "hunting",
            "脅威ハンティング",
            "ハンティングレシピは攻撃をどれだけ早く・少ない誤検知で捉え、閉ループ対処は攻撃を止めるか",
            "<0.5",
            _hunting_commands,
            reports=(
                "benchmark/hunting_benchmark_summary.csv",
                "closed_loop_c2_jitter/THREAT_HUNTING_CLOSED_LOOP_REPORT.md",
            ),
        ),
        Lane(
            "agentic",
            "Agentic Security",
            "自律エージェントの境界逸脱・脅威情報汚染・共通原因故障・報酬ハックを封じ込められるか",
            "<0.5",
            _agentic_commands,
            reports=(
                "agentic_security_benchmark_summary.json",
                "runs/hugging_face_style_agentic_containment/AGENTIC_SECURITY_REPORT.md",
            ),
        ),
        Lane(
            "resilience",
            "Agentic Resilience v2 (統計付き)",
            "6種の防御モードの差は、5 seed の信頼区間・効果量で見ても有意か",
            "<0.5",
            _resilience_commands,
            reports=("agentic_resilience_summary.json", "AGENTIC_RESILIENCE_REPORT.md"),
            evidence_bundles=(".",),
        ),
        Lane(
            "fuzzing",
            "分析駆動ファジング",
            "意味的に変異させたイベント列で、検知ロジックに回帰(見逃し・誤検知)が生じるか",
            "<0.5",
            _fuzzing_commands,
            reports=("FUZZING_REPORT.md", "campaign_summary.csv"),
            evidence_bundles=(".",),
        ),
    )
}

PRESETS: Dict[str, Sequence[str]] = {
    "quickstart": ("check", "replay", "product"),
    "all": tuple(LANES),
}


def _print_menu() -> None:
    print("CyberMatch 評価メニュー")
    print("=" * 72)
    for lane in LANES.values():
        print(f"  {lane.lane_id:<11} {lane.title}  (目安 {lane.minutes} 分)")
        print(f"              問い: {lane.question}")
    print()
    print("プリセット:")
    for name, lanes in PRESETS.items():
        print(f"  {name:<11} = {' + '.join(lanes)}")
    print()
    print(f"seed: product / standard は既定で {DEFAULT_SEEDS}(95%信頼区間付き)。quickstart のみ既定 {QUICKSTART_SEEDS}。")
    print("      --seeds 0 で高速化、--seeds 0,1,2,3,4 で信頼区間付き。")
    print()
    print("例: python scripts/evaluate.py quickstart")
    print("    python scripts/evaluate.py product hunting --run-id my-review-001")


def _resolve_lanes(names: Sequence[str]) -> List[Lane]:
    selected: List[str] = []
    for name in names:
        expanded = PRESETS.get(name, (name,))
        for lane_id in expanded:
            if lane_id not in LANES:
                known = ", ".join([*LANES, *PRESETS])
                raise SystemExit(f"unknown lane or preset: {lane_id} (choose from: {known})")
            if lane_id not in selected:
                selected.append(lane_id)
    return [LANES[lane_id] for lane_id in selected]


def _display(command: Sequence[str]) -> str:
    parts = ["python" if index == 0 else part for index, part in enumerate(command)]
    return " ".join(f'"{part}"' if " " in part else part for part in parts)


def _verify_bundle(directory: Path) -> str:
    from cybermatch_core.contracts import load_evidence_bundle

    return load_evidence_bundle(directory).bundle_hash


def _run_lane(lane: Lane, run_root: Path, env: Dict[str, str], seeds: str, dry_run: bool) -> LaneResult:
    lane_dir = run_root / lane.lane_id
    out_arg = lane_dir.relative_to(ROOT).as_posix()
    commands = lane.build_commands(out_arg, seeds)
    result = LaneResult(
        lane=lane,
        status="planned" if dry_run else "succeeded",
        seconds=0.0,
        output_dir=out_arg if lane.uses_output_dir else None,
        commands=[_display(command) for command in commands],
    )
    if dry_run:
        return result

    log_dir = run_root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    for index, command in enumerate(commands, start=1):
        print(f"  [{index}/{len(commands)}] {_display(command)}", flush=True)
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        log_path = log_dir / f"{lane.lane_id}-{index}.log"
        log_path.write_text(completed.stdout or "", encoding="utf-8")
        if completed.returncode != 0:
            tail = "\n".join((completed.stdout or "").strip().splitlines()[-8:])
            result.status = "failed"
            result.message = f"exit code {completed.returncode}; log: {log_path.relative_to(ROOT).as_posix()}\n{tail}"
            break
    result.seconds = time.monotonic() - started

    if result.status == "succeeded":
        for relative in lane.evidence_bundles:
            try:
                result.evidence_bundle_hashes[relative] = _verify_bundle(lane_dir / relative)
            except Exception as exc:  # verification failure must be visible, not fatal to other lanes
                result.status = "failed"
                result.message = f"Evidence Bundle verification failed ({relative}): {exc}"
                break
    return result


def _report_paths(result: LaneResult) -> List[str]:
    if result.output_dir is None:
        return list(result.lane.reports)
    return [f"{result.output_dir}/{report}" for report in result.lane.reports]


def _write_summary(run_root: Path, run_id: str, results: List[LaneResult], seeds: str = DEFAULT_SEEDS) -> Path:
    rows = []
    for result in results:
        rows.append(
            {
                "lane": result.lane.lane_id,
                "title": result.lane.title,
                "question": result.lane.question,
                "status": result.status,
                "seconds": round(result.seconds, 1),
                "output_dir": result.output_dir,
                "read_first": _report_paths(result),
                "evidence_bundle_hashes": result.evidence_bundle_hashes,
                "commands": result.commands,
                "message": result.message,
            }
        )
    (run_root / "evaluation_summary.json").write_text(
        json.dumps({"run_id": run_id, "seeds": seeds, "lanes": rows}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        f"# CyberMatch 評価サマリー: `{run_id}`",
        "",
        f"- 実行日時: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"- Python: {sys.version.split()[0]}",
        f"- seed(product / standard): `{seeds}`",
        "",
        "| レーン | 評価内容 | 結果 | 所要(秒) | まず読むファイル | Evidence Bundle |",
        "|---|---|---|---:|---|---|",
    ]
    for row in rows:
        reads = "<br>".join(f"`{path}`" for path in row["read_first"])
        hashes = row["evidence_bundle_hashes"]
        bundle = "<br>".join(
            f"`{digest[:12]}…`" if name == "." else f"{name}: `{digest[:12]}…`" for name, digest in hashes.items()
        ) or "-"
        status = {"succeeded": "OK", "failed": "**NG**"}.get(row["status"], row["status"])
        lines.append(f"| `{row['lane']}` | {row['title']} | {status} | {row['seconds']} | {reads} | {bundle} |")
    lines += ["", "## 各レーンが答える問い", ""]
    for row in rows:
        lines.append(f"- **{row['title']}** (`{row['lane']}`): {row['question']}")
    failures = [row for row in rows if row["status"] == "failed"]
    if failures:
        lines += ["", "## 失敗したレーン", ""]
        for row in failures:
            lines += [f"### `{row['lane']}`", "", "```text", row["message"], "```", ""]
    lines += [
        "",
        "## 実行コマンド (再現用)",
        "",
    ]
    for row in rows:
        lines += [f"### `{row['lane']}`", "", "```text", *row["commands"], "```", ""]
    lines += [
        "## 解釈上の注意",
        "",
        "- 結果は同梱の合成シナリオ・記録済みデータ・固定seedに対する比較評価であり、実製品の認証や本番環境での有効性を示すものではない。",
        "- Evidence Bundle は各出力フォルダーの `evidence_bundle.json`。`load_evidence_bundle()` で改ざん・欠落を再検証できる。",
        "- 読み方は `docs/02_evaluation_menu.md` を参照。",
        "",
    ]
    summary_path = run_root / "EVALUATION_SUMMARY.md"
    summary_path.write_text("\n".join(lines), encoding="utf-8")
    return summary_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run CyberMatch evaluations by name. Use --list to show the evaluation menu."
    )
    parser.add_argument("lanes", nargs="*", help="Lane IDs or presets (quickstart, all).")
    parser.add_argument("--list", action="store_true", help="Show the evaluation menu and exit.")
    parser.add_argument("--run-id", help="Unique run ID (default: timestamp).")
    parser.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT, help="Repository-relative output root.")
    parser.add_argument(
        "--seeds",
        help=(
            f"Comma-separated seeds for the product and standard lanes (default: {DEFAULT_SEEDS}; "
            f"{QUICKSTART_SEEDS} when only the quickstart preset is selected)."
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Print the commands without running them.")
    args = parser.parse_args(argv)

    if args.list or not args.lanes:
        _print_menu()
        return 0

    lanes = _resolve_lanes(args.lanes)
    if args.seeds is None:
        args.seeds = QUICKSTART_SEEDS if list(args.lanes) == ["quickstart"] else DEFAULT_SEEDS
    if not SEEDS_PATTERN.fullmatch(args.seeds):
        parser.error("--seeds must be comma-separated non-negative integers, e.g. 0,1,2,3,4")
    run_id = args.run_id or datetime.now().strftime("%Y%m%d-%H%M%S")
    if not RUN_ID_PATTERN.fullmatch(run_id):
        parser.error("--run-id must be 3-64 characters of letters, digits, '_' or '-'")
    output_root = (ROOT / args.output_root).resolve()
    if ROOT not in output_root.parents:
        parser.error("--output-root must be inside the repository")
    run_root = output_root / run_id
    if run_root.exists():
        parser.error(f"run directory already exists: {run_root.relative_to(ROOT).as_posix()} (use a new --run-id)")

    env = os.environ.copy()
    env.setdefault("MPLBACKEND", "Agg")
    env["PYTHONIOENCODING"] = "utf-8"

    if not args.dry_run:
        run_root.mkdir(parents=True)
    results: List[LaneResult] = []
    for lane in lanes:
        print(f"=== {lane.lane_id}: {lane.title}", flush=True)
        result = _run_lane(lane, run_root, env, args.seeds, args.dry_run)
        results.append(result)
        if args.dry_run:
            for command in result.commands:
                print(f"  {command}")
        else:
            print(f"  -> {result.status} ({result.seconds:.1f}s)", flush=True)
            if result.message:
                print("  " + result.message.replace("\n", "\n  "), flush=True)

    if args.dry_run:
        return 0
    summary_path = _write_summary(run_root, run_id, results, args.seeds)
    print()
    print(f"summary: {summary_path.relative_to(ROOT).as_posix()}")
    return 0 if all(result.status == "succeeded" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
