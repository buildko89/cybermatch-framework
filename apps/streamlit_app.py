"""Streamlit MVP for CyberMatch product evaluation artifacts.

This app is intentionally thin: it calls existing Phase6 runners and reads
existing artifact files. It does not add simulation logic.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import streamlit as st


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PRODUCT_PROFILE_DIR = ROOT / "profiles" / "products"
SCENARIO_DIR = ROOT / "scenarios"
SCENARIO_CATALOG_DIR = SCENARIO_DIR / "catalog"
BENCHMARK_DIR = ROOT / "benchmarks"
TOPOLOGY_DIR = ROOT / "topologies"
PHASE63_OUTPUT_DIR = ROOT / "output" / "phase63_mission_products"
PHASE62_OUTPUT_DIR = ROOT / "output" / "phase62_product_profiles"
PHASE83_OUTPUT_DIR = ROOT / "output" / "phase83_benchmark_suite"
PHASE85_OUTPUT_DIR = ROOT / "output" / "phase85_standard_benchmark"
PHASE63_LOG_PATH = PHASE63_OUTPUT_DIR / "streamlit_phase63_run.log"
PHASE62_LOG_PATH = PHASE62_OUTPUT_DIR / "streamlit_phase62_run.log"
PHASE83_LOG_PATH = PHASE83_OUTPUT_DIR / "streamlit_phase83_run.log"
PHASE85_LOG_PATH = PHASE85_OUTPUT_DIR / "streamlit_phase85_run.log"

PHASE63_ARTIFACTS = {
    "summary_csv": PHASE63_OUTPUT_DIR / "mission_product_summary.csv",
    "summary_json": PHASE63_OUTPUT_DIR / "mission_product_summary.json",
    "heatmap": PHASE63_OUTPUT_DIR / "mission_product_heatmap.png",
    "variance": PHASE63_OUTPUT_DIR / "mission_variance.png",
    "phase62_comparison": PHASE63_OUTPUT_DIR / "phase63_vs_phase62.png",
    "report": PHASE63_OUTPUT_DIR / "PHASE63_MISSION_PRODUCT_REPORT.md",
}

PHASE83_ARTIFACTS = {
    "summary_csv": PHASE83_OUTPUT_DIR / "benchmark_summary.csv",
    "summary_json": PHASE83_OUTPUT_DIR / "benchmark_summary.json",
    "ranking": PHASE83_OUTPUT_DIR / "benchmark_product_ranking.png",
    "scenario_heatmap": PHASE83_OUTPUT_DIR / "benchmark_scenario_heatmap.png",
    "mission_heatmap": PHASE83_OUTPUT_DIR / "benchmark_mission_heatmap.png",
    "consistency": PHASE83_OUTPUT_DIR / "benchmark_consistency.png",
    "report": PHASE83_OUTPUT_DIR / "PHASE83_BENCHMARK_SUITE_REPORT.md",
}

PHASE85_ARTIFACTS = {
    "summary_csv": PHASE85_OUTPUT_DIR / "standard_benchmark_summary.csv",
    "summary_json": PHASE85_OUTPUT_DIR / "standard_benchmark_summary.json",
    "ranking": PHASE85_OUTPUT_DIR / "standard_product_ranking.png",
    "scenario_heatmap": PHASE85_OUTPUT_DIR / "standard_scenario_heatmap.png",
    "topology_heatmap": PHASE85_OUTPUT_DIR / "standard_topology_heatmap.png",
    "mission_heatmap": PHASE85_OUTPUT_DIR / "standard_mission_heatmap.png",
    "report": PHASE85_OUTPUT_DIR / "PHASE85_STANDARD_BENCHMARK_REPORT.md",
}

PROFILE_COLUMNS = [
    "name",
    "category",
    "detection_boost",
    "interruption_boost",
    "diversion_boost",
    "confidence_boost",
    "false_positive_penalty",
    "latency_penalty",
    "maintenance_penalty",
]

MISSION_OPTIONS = ["all", "profit", "achievement", "persistence", "critical_hunter"]

TEXT = {
    "日本語": {
        "nav": ["ホーム", "シナリオ", "製品", "実行", "結果", "ベンチマーク"],
        "nav_to_key": {
            "ホーム": "home",
            "シナリオ": "scenario",
            "製品": "products",
            "実行": "run",
            "結果": "results",
            "ベンチマーク": "benchmark",
        },
        "language": "表示言語",
        "scope": "Product Evaluation のみ",
        "home_subtitle": "製品評価ダッシュボード MVP",
        "definition": (
            "CyberMatch は、攻撃者の意思決定を再現し、防御戦略やセキュリティ製品を"
            "比較評価できるサイバー意思決定シミュレータです。"
        ),
        "mvp_scope": (
            "MVP範囲: Product Evaluation のみ。既存の Phase6.2 / Phase6.3 runner と"
            "生成済み artifact を利用します。"
        ),
        "cert_warning": (
            "CyberMatch は実製品認証ではありません。制御された product profile を比較する"
            "再現可能なシナリオ評価フレームワークです。"
        ),
        "current_focus": """
        **現在のMVP対象**

        - Product profile の確認
        - Phase6.3 mission-aware product evaluation
        - 既存 artifact の表示
        - CSV、JSON、PNG、Markdown report へのアクセス
        """,
        "scenario_title": "シナリオ",
        "scenario_import": "Scenario import",
        "scenario_catalog": "Scenario catalog",
        "scenario_name": "Scenario Name",
        "scenario_industry": "Industry",
        "scenario_description": "Description",
        "benchmark_suite": "Benchmark suite",
        "benchmark_name": "Benchmark name",
        "scenario_count": "Scenario count",
        "mission_count": "Mission count",
        "product_count": "Product count",
        "topology_count": "Topology count",
        "matrix_size": "Matrix size",
        "benchmark_json": "Benchmark JSON",
        "no_benchmarks": "benchmarks/ 配下にbenchmark JSONが見つかりません。",
        "topology_library": "Topology library",
        "topology_name": "Topology name",
        "topology_description": "Topology description",
        "topology_characteristics": "Topology characteristics",
        "topology_json": "Topology JSON",
        "no_topologies": "topologies/ 配下にtopology JSONが見つかりません。",
        "scenario_json": "Scenario JSON",
        "selected_scenario_path": "Selected scenario path",
        "no_scenarios": "scenarios/ 配下にscenario JSONが見つかりません。",
        "scenario_selector": "Built-in scenario",
        "mission_selection": "Mission selection",
        "mission_caption": (
            "MVPでは mission selection をUI表示しています。Phase6.3 runner は既存の"
            " all-mission evaluation を実行します。"
        ),
        "products_title": "製品",
        "no_profiles": "profiles/products/ 配下に product profile が見つかりません。",
        "comparison_targets": "比較対象",
        "product_caption": (
            "MVPでは選択内容を表示します。既存runnerは現在の sample product profile set を使用します。"
        ),
        "run_title": "実行",
        "scenario_import_hook": "Scenario import hook",
        "primary_runner": "Primary runner:",
        "output": "出力先:",
        "run_phase63": "Phase6.3 Mission-Aware Product Evaluation を実行",
        "run_phase83": "Phase8.3 Benchmark Suite を実行",
        "run_standard_benchmark": "Run CyberMatch Standard Benchmark",
        "stop_run": "実行を停止",
        "running_phase63": "Phase6.3 evaluation を実行中...",
        "runner_failed": "Runner が失敗しました",
        "runner_running": "Evaluation is running.",
        "runner_stopped": "Evaluation を停止しました。",
        "runner_exit_code": "終了コード",
        "runner_not_running": "実行中のrunnerはありません。",
        "phase63_done": "Phase6.3 evaluation が完了しました。",
        "phase83_done": "Phase8.3 benchmark suite が完了しました。",
        "phase85_done": "Phase8.5 standard benchmark が完了しました。",
        "phase62_done": "Phase6.2 evaluation が完了しました。",
        "artifacts_written": "Artifacts written to",
        "optional_phase62": "Optional Phase6.2 runner",
        "run_phase62": "Phase6.2 Product Profile Evaluation を実行",
        "running_phase62": "Phase6.2 evaluation を実行中...",
        "results_title": "結果",
        "results_missing": "Results not found. Run the evaluation first.",
        "go_to_run": "Run PageでPhase6.3 evaluationを実行してください。",
        "expected_output_path": "Expected output path",
        "missing_files": "Missing files",
        "results_intro": (
            "この画面は Phase6.3 の生成済みartifactを表示します。画像内の軸や列名は"
            "runnerが生成した英語表記のままですが、下の説明で読み方を確認できます。"
        ),
        "interpretation_notice": (
            "CyberMatchは単一最強製品を認定するものではありません。攻撃者Missionごとの"
            "有効性差を比較する評価ダッシュボードです。"
        ),
        "summary_cards": "Summary cards",
        "best_product_overall": "Best product overall",
        "best_product_per_mission": "Best product per mission",
        "worst_mission_coverage": "Worst mission coverage",
        "highest_mission_variance": "Highest mission variance",
        "single_winner_exists": "Single winner exists",
        "product_mission_table": "Product x Mission table",
        "product_mission_chart": "Product x Mission table heatmap",
        "winner_explanation": "Mission winner explanation",
        "product_detail": "Product detail",
        "product_selector": "Product profile",
        "detail_metric": "Metric",
        "detail_value": "Value",
        "per_mission_detail": "Per-mission detail",
        "summary_table": "Summary table",
        "heatmap": "Product x Mission heatmap",
        "heatmap_help": (
            "Heatmap は product profile と attacker mission の組み合わせごとの "
            "mission_effectiveness を示します。縦方向が製品/profile、横方向が mission です。"
            "色が強いほど、そのmissionに対して効果が大きいことを意味します。"
        ),
        "variance": "Mission variance",
        "variance_help": (
            "Mission variance は、同じ製品profileがmissionごとにどれだけ異なる効果を"
            "示したかを表します。値が大きいほど、製品効果がmission依存であることを示します。"
        ),
        "phase62_comparison": "Phase6.2 comparison",
        "phase62_help": (
            "Phase6.2 comparison は、製品profile単位の評価と Phase6.3 のmission-aware評価を"
            "比較するための図です。Phase6.3では単一ランキングではなく、mission別の適性を確認します。"
        ),
        "markdown_report": "Markdown report",
        "json_summary": "JSON summary",
        "downloads": "Downloads",
        "benchmark_artifacts": "Benchmark artifacts",
        "benchmark_results_missing": "Benchmark results not found. Run the benchmark suite first.",
        "metric_guide": "Metric guide",
        "metric_guide_text": """
        - `mission_effectiveness`: mission別に見た製品profileの効果。
        - `mission_success_delta`: baselineと比べてmission successをどれだけ下げたか。
        - `mission_disruption_delta`: campaign disruptionをどれだけ増やしたか。
        - `mission_detection_delta`: detection probabilityをどれだけ増やしたか。
        - `diversion_delta`: attacker diversionをどれだけ増やしたか。
        - `best_mission` / `worst_mission`: profileごとに最も効果が出たmission / 出にくかったmission。
        """,
        "mission_interpretation": "Mission別の読み方",
        "mission_interpretation_help": (
            "Summary CSVから、missionごとに mission_effectiveness が最も高いprofileを抽出しています。"
            "これは最強製品の認定ではなく、missionごとの効果差を見るための補助表示です。"
        ),
        "download_csv": "CSVをダウンロード",
        "download_json": "JSONをダウンロード",
        "download_md": "Markdownをダウンロード",
        "missing": "Missing",
        "not_found": "not found.",
    },
    "English": {
        "nav": ["Home", "Scenario", "Products", "Run", "Results", "Benchmark"],
        "nav_to_key": {
            "Home": "home",
            "Scenario": "scenario",
            "Products": "products",
            "Run": "run",
            "Results": "results",
            "Benchmark": "benchmark",
        },
        "language": "Display language",
        "scope": "Product Evaluation only",
        "home_subtitle": "Product Evaluation Dashboard MVP",
        "definition": (
            "CyberMatch is a cyber decision-making simulator that reproduces attacker "
            "decision processes and enables comparative evaluation of defense strategies "
            "and security products."
        ),
        "mvp_scope": (
            "MVP scope: Product Evaluation only. The app uses existing Phase6.2 and "
            "Phase6.3 runners and generated artifacts."
        ),
        "cert_warning": (
            "CyberMatch is not real product certification. It is a reproducible scenario "
            "evaluation framework for comparing controlled product profiles."
        ),
        "current_focus": """
        **Current MVP focus**

        - Product profile inspection
        - Phase6.3 mission-aware product evaluation
        - Existing artifact viewing
        - CSV, JSON, PNG, and Markdown report access
        """,
        "scenario_title": "Scenario",
        "scenario_import": "Scenario import",
        "scenario_catalog": "Scenario catalog",
        "scenario_name": "Scenario Name",
        "scenario_industry": "Industry",
        "scenario_description": "Description",
        "benchmark_suite": "Benchmark suite",
        "benchmark_name": "Benchmark name",
        "scenario_count": "Scenario count",
        "mission_count": "Mission count",
        "product_count": "Product count",
        "topology_count": "Topology count",
        "matrix_size": "Matrix size",
        "benchmark_json": "Benchmark JSON",
        "no_benchmarks": "No benchmark JSON files found under benchmarks/.",
        "topology_library": "Topology library",
        "topology_name": "Topology name",
        "topology_description": "Topology description",
        "topology_characteristics": "Topology characteristics",
        "topology_json": "Topology JSON",
        "no_topologies": "No topology JSON files found under topologies/.",
        "scenario_json": "Scenario JSON",
        "selected_scenario_path": "Selected scenario path",
        "no_scenarios": "No scenario JSON files found under scenarios/.",
        "scenario_selector": "Built-in scenario",
        "mission_selection": "Mission selection",
        "mission_caption": (
            "Mission selection is visible in the MVP UI. The Phase6.3 runner currently "
            "executes the existing all-mission evaluation."
        ),
        "products_title": "Products",
        "no_profiles": "No product profiles found under profiles/products/.",
        "comparison_targets": "Comparison targets",
        "product_caption": (
            "Selection is displayed for MVP usability. Existing runners use the current "
            "sample product profile set."
        ),
        "run_title": "Run",
        "scenario_import_hook": "Scenario import hook",
        "primary_runner": "Primary runner:",
        "output": "Output:",
        "run_phase63": "Run Phase6.3 Mission-Aware Product Evaluation",
        "run_phase83": "Run Phase8.3 Benchmark Suite",
        "run_standard_benchmark": "Run CyberMatch Standard Benchmark",
        "stop_run": "Stop run",
        "running_phase63": "Running Phase6.3 evaluation...",
        "runner_failed": "Runner failed",
        "runner_running": "Evaluation is running.",
        "runner_stopped": "Evaluation stopped.",
        "runner_exit_code": "Exit code",
        "runner_not_running": "No runner is currently active.",
        "phase63_done": "Phase6.3 evaluation completed.",
        "phase83_done": "Phase8.3 benchmark suite completed.",
        "phase85_done": "Phase8.5 standard benchmark completed.",
        "artifacts_written": "Artifacts written to",
        "optional_phase62": "Optional Phase6.2 runner",
        "run_phase62": "Run Phase6.2 Product Profile Evaluation",
        "running_phase62": "Running Phase6.2 evaluation...",
        "phase62_done": "Phase6.2 evaluation completed.",
        "results_title": "Results",
        "results_missing": "Results not found. Run the evaluation first.",
        "go_to_run": "Open the Run page and execute the Phase6.3 evaluation.",
        "expected_output_path": "Expected output path",
        "missing_files": "Missing files",
        "results_intro": (
            "This page displays generated Phase6.3 artifacts. Chart labels come from "
            "the existing runner output; use the explanations below to interpret each view."
        ),
        "interpretation_notice": (
            "CyberMatch does not certify one universally strongest product. It is an "
            "evaluation dashboard for comparing effectiveness differences by attacker mission."
        ),
        "summary_cards": "Summary cards",
        "best_product_overall": "Best product overall",
        "best_product_per_mission": "Best product per mission",
        "worst_mission_coverage": "Worst mission coverage",
        "highest_mission_variance": "Highest mission variance",
        "single_winner_exists": "Single winner exists",
        "product_mission_table": "Product x Mission table",
        "product_mission_chart": "Product x Mission table heatmap",
        "winner_explanation": "Mission winner explanation",
        "product_detail": "Product detail",
        "product_selector": "Product profile",
        "detail_metric": "Metric",
        "detail_value": "Value",
        "per_mission_detail": "Per-mission detail",
        "summary_table": "Summary table",
        "heatmap": "Product x Mission heatmap",
        "heatmap_help": (
            "The heatmap shows mission_effectiveness for each product profile and attacker mission. "
            "Rows are products/profiles, columns are missions, and stronger color means stronger "
            "mission-specific effectiveness."
        ),
        "variance": "Mission variance",
        "variance_help": (
            "Mission variance shows how differently the same product profile performs across missions. "
            "A larger value means the effect is more mission-dependent."
        ),
        "phase62_comparison": "Phase6.2 comparison",
        "phase62_help": (
            "The Phase6.2 comparison view contrasts profile-level evaluation with Phase6.3 "
            "mission-aware evaluation. Phase6.3 should be read as mission suitability, not a single ranking."
        ),
        "markdown_report": "Markdown report",
        "json_summary": "JSON summary",
        "downloads": "Downloads",
        "benchmark_artifacts": "Benchmark artifacts",
        "benchmark_results_missing": "Benchmark results not found. Run the benchmark suite first.",
        "metric_guide": "Metric guide",
        "metric_guide_text": """
        - `mission_effectiveness`: product profile effect for a specific mission.
        - `mission_success_delta`: reduction in mission success compared with baseline.
        - `mission_disruption_delta`: increase in campaign disruption.
        - `mission_detection_delta`: increase in detection probability.
        - `diversion_delta`: increase in attacker diversion.
        - `best_mission` / `worst_mission`: mission where a profile is strongest / weakest.
        """,
        "mission_interpretation": "Mission interpretation",
        "mission_interpretation_help": (
            "This table extracts the profile with the highest mission_effectiveness for each mission "
            "from the summary CSV. It is a reading aid, not product certification or a universal ranking."
        ),
        "download_csv": "Download CSV",
        "download_json": "Download JSON",
        "download_md": "Download Markdown",
        "missing": "Missing",
        "not_found": "not found.",
    },
}


def load_product_profiles() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path in sorted(PRODUCT_PROFILE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            rows.append({"name": path.stem, "category": "invalid", "error": str(exc), "file": str(path)})
            continue
        row = {column: data.get(column, 0.0) for column in PROFILE_COLUMNS}
        row["file"] = str(path.relative_to(ROOT))
        rows.append(row)
    return rows


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def list_scenario_files() -> List[Path]:
    if not SCENARIO_DIR.exists():
        return []
    return sorted(SCENARIO_DIR.glob("*.json"))


def list_catalog_scenario_files() -> List[Path]:
    if not SCENARIO_CATALOG_DIR.exists():
        return []
    return sorted(SCENARIO_CATALOG_DIR.glob("*.json"))


def list_benchmark_files() -> List[Path]:
    if not BENCHMARK_DIR.exists():
        return []
    return sorted(BENCHMARK_DIR.glob("*.json"))


def list_topology_files() -> List[Path]:
    if not TOPOLOGY_DIR.exists():
        return []
    return sorted(TOPOLOGY_DIR.glob("*.json"))


def render_scenario_metadata(path: Path, text: Dict[str, Any]) -> None:
    scenario_data = read_json(path)
    if not isinstance(scenario_data, dict):
        return
    metadata = scenario_data.get("metadata", {})
    if not isinstance(metadata, dict):
        return
    col1, col2 = st.columns(2)
    with col1:
        st.write(text["scenario_name"])
        st.code(str(metadata.get("name", "")), language="text")
    with col2:
        st.write(text["scenario_industry"])
        st.code(str(metadata.get("industry", "")), language="text")
    st.write(text["scenario_description"])
    st.write(str(metadata.get("description", "")))


def render_benchmark_metadata(path: Path, text: Dict[str, Any]) -> None:
    benchmark_data = read_json(path)
    if not isinstance(benchmark_data, dict):
        return
    metadata = benchmark_data.get("metadata", {})
    if not isinstance(metadata, dict):
        return
    scenario_count = len(benchmark_data.get("scenarios", []))
    topology_count = len(benchmark_data.get("topologies", []))
    mission_count = len(benchmark_data.get("missions", []))
    product_count = len(benchmark_data.get("products", []))
    matrix_size = scenario_count * (topology_count or 1) * mission_count * product_count
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1:
        st.metric(text["benchmark_name"], str(metadata.get("name", "")))
    with col2:
        st.metric("Version", str(metadata.get("version", "")))
    with col3:
        st.metric(text["scenario_count"], scenario_count)
    with col4:
        st.metric(text["topology_count"], topology_count)
    with col5:
        st.metric(text["mission_count"], mission_count)
    with col6:
        st.metric(text["product_count"], product_count)
    st.metric(text["matrix_size"], matrix_size)


def render_topology_metadata(path: Path, text: Dict[str, Any]) -> None:
    topology_data = read_json(path)
    if not isinstance(topology_data, dict):
        return
    metadata = topology_data.get("metadata", {})
    characteristics = topology_data.get("characteristics", {})
    if not isinstance(metadata, dict):
        return
    col1, col2 = st.columns(2)
    with col1:
        st.write(text["topology_name"])
        st.code(str(metadata.get("name", "")), language="text")
    with col2:
        st.write(text["topology_description"])
        st.write(str(metadata.get("description", "")))
    st.write(text["topology_characteristics"])
    if isinstance(characteristics, dict):
        st.dataframe(
            [{"characteristic": key, "value": value} for key, value in characteristics.items()],
            use_container_width=True,
            hide_index=True,
        )


def to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def non_baseline_rows(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    return [row for row in rows if row.get("profile_id") != "baseline"]


def product_label(row: Dict[str, str]) -> str:
    return row.get("product_profile_name") or row.get("profile_id") or ""


def mean(values: List[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def round_metric(value: Any) -> float:
    return round(to_float(value), 4)


def build_product_mission_pivot(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    products: Dict[str, Dict[str, Any]] = {}
    missions: Set[str] = set()
    for row in non_baseline_rows(rows):
        profile_id = row.get("profile_id", "")
        if not profile_id:
            continue
        mission = row.get("mission_name", "")
        if not mission:
            continue
        missions.add(mission)
        product_row = products.setdefault(
            profile_id,
            {
                "profile_id": profile_id,
                "product_profile_name": product_label(row),
                "category": row.get("product_category", ""),
            },
        )
        product_row[mission] = round_metric(row.get("mission_effectiveness"))
    ordered_missions = sorted(missions)
    return [
        {**product_row, **{mission: product_row.get(mission, 0.0) for mission in ordered_missions}}
        for _, product_row in sorted(products.items())
    ]


def build_summary_cards(rows: List[Dict[str, str]], summary_json: Any) -> Dict[str, Any]:
    active_rows = non_baseline_rows(rows)
    by_product: Dict[str, List[Dict[str, str]]] = {}
    by_mission: Dict[str, List[Dict[str, str]]] = {}
    for row in active_rows:
        by_product.setdefault(row.get("profile_id", ""), []).append(row)
        by_mission.setdefault(row.get("mission_name", ""), []).append(row)

    product_scores = {
        product_id: mean([to_float(row.get("mission_effectiveness")) for row in product_rows])
        for product_id, product_rows in by_product.items()
    }
    best_product_id = max(product_scores, key=product_scores.get) if product_scores else ""
    best_product_row = by_product.get(best_product_id, [{}])[0]

    best_by_mission: Dict[str, str] = {}
    best_by_mission_scores: Dict[str, float] = {}
    for mission, mission_rows in by_mission.items():
        best_row = max(mission_rows, key=lambda row: to_float(row.get("mission_effectiveness")))
        best_by_mission[mission] = best_row.get("profile_id", "")
        best_by_mission_scores[mission] = to_float(best_row.get("mission_effectiveness"))

    mission_coverage = {
        mission: mean([to_float(row.get("mission_effectiveness")) for row in mission_rows])
        for mission, mission_rows in by_mission.items()
    }
    worst_mission = min(mission_coverage, key=mission_coverage.get) if mission_coverage else ""

    variance_by_product = {
        product_id: to_float(product_rows[0].get("mission_variance_score"))
        for product_id, product_rows in by_product.items()
    }
    highest_variance_product = max(variance_by_product, key=variance_by_product.get) if variance_by_product else ""
    highest_variance_row = by_product.get(highest_variance_product, [{}])[0]

    analysis = summary_json.get("analysis", {}) if isinstance(summary_json, dict) else {}
    single_winner = analysis.get("single_strongest_product_exists")
    if single_winner is None and best_by_mission:
        single_winner = len(set(best_by_mission.values())) == 1

    return {
        "best_product_overall": {
            "profile_id": best_product_id,
            "name": product_label(best_product_row),
            "score": product_scores.get(best_product_id, 0.0),
        },
        "best_product_per_mission": best_by_mission,
        "best_product_per_mission_scores": best_by_mission_scores,
        "worst_mission_coverage": {
            "mission": worst_mission,
            "score": mission_coverage.get(worst_mission, 0.0),
        },
        "highest_mission_variance": {
            "profile_id": highest_variance_product,
            "name": product_label(highest_variance_row),
            "score": variance_by_product.get(highest_variance_product, 0.0),
        },
        "single_winner_exists": bool(single_winner),
    }


def build_mission_interpretation(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    best_by_mission: Dict[str, Dict[str, str]] = {}
    for row in rows:
        if row.get("profile_id") == "baseline":
            continue
        mission = str(row.get("mission_name") or "")
        if not mission:
            continue
        current = best_by_mission.get(mission)
        if current is None or to_float(row.get("mission_effectiveness")) > to_float(current.get("mission_effectiveness")):
            best_by_mission[mission] = row
    return [
        {
            "mission_name": mission,
            "profile_id": row.get("profile_id", ""),
            "product_profile_name": row.get("product_profile_name", ""),
            "product_category": row.get("product_category", ""),
            "mission_effectiveness": round(to_float(row.get("mission_effectiveness")), 4),
            "best_mission_for_profile": row.get("best_mission", ""),
            "worst_mission_for_profile": row.get("worst_mission", ""),
        }
        for mission, row in sorted(best_by_mission.items())
    ]


def build_winner_explanations(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    winners = build_mission_interpretation(rows)
    return [
        {
            "mission": row["mission_name"],
            "winner": row["profile_id"],
            "explanation": (
                f"{row['mission_name']} winner is {row['profile_id']} "
                f"({row['product_category']}) with mission_effectiveness "
                f"{row['mission_effectiveness']}."
            ),
        }
        for row in winners
    ]


def build_product_detail(rows: List[Dict[str, str]], profile_id: str) -> Dict[str, Any]:
    product_rows = [row for row in non_baseline_rows(rows) if row.get("profile_id") == profile_id]
    if not product_rows:
        return {}
    first = product_rows[0]
    return {
        "category": first.get("product_category", ""),
        "evaluation_score": round_metric(first.get("evaluation_score")),
        "best_mission": first.get("best_mission", ""),
        "worst_mission": first.get("worst_mission", ""),
        "mission_variance_score": round_metric(first.get("mission_variance_score")),
        "mission_success_delta": round(mean([to_float(row.get("mission_success_delta")) for row in product_rows]), 4),
        "mission_disruption_delta": round(mean([to_float(row.get("mission_disruption_delta")) for row in product_rows]), 4),
        "mission_detection_delta": round(mean([to_float(row.get("mission_detection_delta")) for row in product_rows]), 4),
    }


def build_product_mission_detail(rows: List[Dict[str, str]], profile_id: str) -> List[Dict[str, Any]]:
    product_rows = [row for row in non_baseline_rows(rows) if row.get("profile_id") == profile_id]
    return [
        {
            "mission_name": row.get("mission_name", ""),
            "mission_effectiveness": round_metric(row.get("mission_effectiveness")),
            "mission_success_delta": round_metric(row.get("mission_success_delta")),
            "mission_disruption_delta": round_metric(row.get("mission_disruption_delta")),
            "mission_detection_delta": round_metric(row.get("mission_detection_delta")),
        }
        for row in sorted(product_rows, key=lambda row: row.get("mission_name", ""))
    ]


def get_runner_process() -> Optional[subprocess.Popen[Any]]:
    process = st.session_state.get("runner_process")
    if isinstance(process, subprocess.Popen):
        return process
    return None


def runner_is_active() -> bool:
    process = get_runner_process()
    return process is not None and process.poll() is None


def start_runner(command: List[str], log_path: Path, success_key: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            command,
            cwd=str(ROOT),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
    st.session_state["runner_process"] = process
    st.session_state["runner_log_path"] = str(log_path)
    st.session_state["runner_success_key"] = success_key
    st.session_state["runner_stopped"] = False


def stop_runner() -> bool:
    process = get_runner_process()
    if process is None or process.poll() is not None:
        return False
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    st.session_state["runner_stopped"] = True
    return True


def render_runner_status(text: Dict[str, Any]) -> None:
    process = get_runner_process()
    log_path_value = st.session_state.get("runner_log_path")
    log_path = Path(str(log_path_value)) if log_path_value else None
    if process is None:
        st.caption(text["runner_not_running"])
    elif process.poll() is None:
        st.info(text["runner_running"])
    elif st.session_state.get("runner_stopped"):
        st.warning(text["runner_stopped"])
    elif process.returncode == 0:
        st.success(text.get(str(st.session_state.get("runner_success_key")), text["phase63_done"]))
    else:
        st.error(f"{text['runner_failed']}. {text['runner_exit_code']}: {process.returncode}")

    if log_path is not None and log_path.is_file():
        log_text = read_text(log_path)
        if log_text.strip():
            with st.expander("Run log"):
                st.code(log_text[-6000:], language="text")


def render_download(path: Path, label: str, mime: str, text: Dict[str, Any]) -> None:
    if not path.exists():
        st.caption(f"{text['missing']}: {path.relative_to(ROOT)}")
        return
    st.download_button(
        label=label,
        data=path.read_bytes(),
        file_name=path.name,
        mime=mime,
        use_container_width=True,
    )


def render_home(text: Dict[str, Any]) -> None:
    st.title("CyberMatch")
    st.subheader(text["home_subtitle"])
    st.write(text["definition"])
    st.info(text["mvp_scope"])
    st.warning(text["cert_warning"])
    st.markdown(text["current_focus"])


def render_scenario(text: Dict[str, Any]) -> None:
    st.title(text["scenario_title"])
    topology_files = list_topology_files()
    st.subheader(text["topology_library"])
    if topology_files:
        selected_topology = st.selectbox(text["topology_json"], topology_files, format_func=lambda path: path.stem)
        st.session_state["selected_topology_path"] = str(selected_topology.relative_to(ROOT))
        render_topology_metadata(selected_topology, text)
        st.code(str(selected_topology.relative_to(ROOT)), language="text")
    else:
        st.warning(text["no_topologies"])

    benchmark_files = list_benchmark_files()
    st.subheader(text["benchmark_suite"])
    if benchmark_files:
        selected_benchmark = st.selectbox(text["benchmark_json"], benchmark_files, format_func=lambda path: path.name)
        st.session_state["selected_benchmark_path"] = str(selected_benchmark.relative_to(ROOT))
        render_benchmark_metadata(selected_benchmark, text)
        st.write(text["selected_scenario_path"])
        st.code(str(selected_benchmark.relative_to(ROOT)), language="text")
    else:
        st.warning(text["no_benchmarks"])

    catalog_files = list_catalog_scenario_files()
    st.subheader(text["scenario_catalog"])
    if catalog_files:
        selected_catalog = st.selectbox(text["scenario_catalog"], catalog_files, format_func=lambda path: path.stem)
        st.session_state["selected_catalog_scenario_path"] = str(selected_catalog.relative_to(ROOT))
        render_scenario_metadata(selected_catalog, text)
        st.write(text["selected_scenario_path"])
        st.code(str(selected_catalog.relative_to(ROOT)), language="text")
    else:
        st.warning(text["no_scenarios"])

    scenario_files = list_scenario_files()
    st.subheader(text["scenario_import"])
    if scenario_files:
        selected = st.selectbox(text["scenario_json"], scenario_files, format_func=lambda path: path.name)
        st.session_state["selected_scenario_path"] = str(selected.relative_to(ROOT))
        st.write(text["selected_scenario_path"])
        st.code(str(selected.relative_to(ROOT)), language="text")
        scenario_data = read_json(selected)
        if scenario_data is not None:
            st.json(scenario_data)
    else:
        st.warning(text["no_scenarios"])

    st.selectbox(
        text["scenario_selector"],
        ["Phase6.3 Mission-Aware Product Evaluation", "Phase6.2 Product Profile Evaluation"],
        index=0,
    )
    st.selectbox(text["mission_selection"], MISSION_OPTIONS, index=0)
    st.caption(text["mission_caption"])
    st.code(str(PHASE63_OUTPUT_DIR.relative_to(ROOT)), language="text")


def render_products(text: Dict[str, Any]) -> None:
    st.title(text["products_title"])
    profiles = load_product_profiles()
    if not profiles:
        st.warning(text["no_profiles"])
        return

    names = [str(row.get("name", "")) for row in profiles]
    st.multiselect(text["comparison_targets"], names, default=names)
    st.caption(text["product_caption"])
    st.dataframe(profiles, use_container_width=True, hide_index=True)


def render_run(text: Dict[str, Any]) -> None:
    st.title(text["run_title"])
    topology_files = list_topology_files()
    with st.expander(text["topology_library"], expanded=True):
        if topology_files:
            default_topology_path = st.session_state.get("selected_topology_path")
            default_topology_index = 0
            if default_topology_path:
                for index, path in enumerate(topology_files):
                    if str(path.relative_to(ROOT)) == default_topology_path:
                        default_topology_index = index
                        break
            selected_topology = st.selectbox(
                text["topology_json"],
                topology_files,
                index=default_topology_index,
                format_func=lambda path: path.stem,
            )
            st.session_state["selected_topology_path"] = str(selected_topology.relative_to(ROOT))
            render_topology_metadata(selected_topology, text)
            st.code(str(selected_topology.relative_to(ROOT)), language="text")
        else:
            st.warning(text["no_topologies"])

    benchmark_files = list_benchmark_files()
    with st.expander(text["benchmark_suite"], expanded=True):
        if benchmark_files:
            default_benchmark_path = st.session_state.get("selected_benchmark_path")
            default_benchmark_index = 0
            if default_benchmark_path:
                for index, path in enumerate(benchmark_files):
                    if str(path.relative_to(ROOT)) == default_benchmark_path:
                        default_benchmark_index = index
                        break
            selected_benchmark = st.selectbox(
                text["benchmark_json"],
                benchmark_files,
                index=default_benchmark_index,
                format_func=lambda path: path.name,
            )
            st.session_state["selected_benchmark_path"] = str(selected_benchmark.relative_to(ROOT))
            render_benchmark_metadata(selected_benchmark, text)
            st.code(str(selected_benchmark.relative_to(ROOT)), language="text")
            if st.button(text["run_phase83"], disabled=runner_is_active()):
                start_runner(
                    [
                        sys.executable,
                        "-c",
                        "from run_scenarios import run_phase83_benchmark_suite; run_phase83_benchmark_suite()",
                    ],
                    PHASE83_LOG_PATH,
                    "phase83_done",
                )
                st.rerun()
        else:
            st.warning(text["no_benchmarks"])

    catalog_files = list_catalog_scenario_files()
    with st.expander(text["scenario_catalog"], expanded=True):
        if catalog_files:
            default_catalog_path = st.session_state.get("selected_catalog_scenario_path")
            default_catalog_index = 0
            if default_catalog_path:
                for index, path in enumerate(catalog_files):
                    if str(path.relative_to(ROOT)) == default_catalog_path:
                        default_catalog_index = index
                        break
            selected_catalog = st.selectbox(
                text["scenario_catalog"],
                catalog_files,
                index=default_catalog_index,
                format_func=lambda path: path.stem,
            )
            st.session_state["selected_catalog_scenario_path"] = str(selected_catalog.relative_to(ROOT))
            render_scenario_metadata(selected_catalog, text)
            st.write(text["selected_scenario_path"])
            st.code(str(selected_catalog.relative_to(ROOT)), language="text")
        else:
            st.warning(text["no_scenarios"])

    scenario_files = list_scenario_files()
    with st.expander(text["scenario_import_hook"], expanded=True):
        if scenario_files:
            default_path = st.session_state.get("selected_scenario_path")
            default_index = 0
            if default_path:
                for index, path in enumerate(scenario_files):
                    if str(path.relative_to(ROOT)) == default_path:
                        default_index = index
                        break
            selected = st.selectbox(text["scenario_json"], scenario_files, index=default_index, format_func=lambda path: path.name)
            st.session_state["selected_scenario_path"] = str(selected.relative_to(ROOT))
            st.write(text["selected_scenario_path"])
            st.code(str(selected.relative_to(ROOT)), language="text")
        else:
            st.warning(text["no_scenarios"])

    st.write(text["primary_runner"])
    st.code("run_phase63_mission_aware_product_evaluation()", language="python")
    st.write(text["output"])
    st.code(str(PHASE63_OUTPUT_DIR.relative_to(ROOT)), language="text")

    run_col, stop_col = st.columns(2)
    with run_col:
        if st.button(text["run_phase63"], type="primary", disabled=runner_is_active()):
            start_runner(
                [
                    sys.executable,
                    "-c",
                    "from run_scenarios import run_phase63_mission_aware_product_evaluation; run_phase63_mission_aware_product_evaluation()",
                ],
                PHASE63_LOG_PATH,
                "phase63_done",
            )
            st.rerun()
    with stop_col:
        if st.button(text["stop_run"], disabled=not runner_is_active()):
            stop_runner()
            st.rerun()

    render_runner_status(text)
    if get_runner_process() is not None and not runner_is_active() and not st.session_state.get("runner_stopped"):
        st.write(f"{text['artifacts_written']} `{PHASE63_OUTPUT_DIR.relative_to(ROOT)}`.")

    with st.expander(text["optional_phase62"]):
        st.code("run_phase62_product_profile_evaluation()", language="python")
        st.write(f"{text['output']} `{PHASE62_OUTPUT_DIR.relative_to(ROOT)}`")
        if st.button(text["run_phase62"], disabled=runner_is_active()):
            start_runner(
                [
                    sys.executable,
                    "-c",
                    "from run_scenarios import run_phase62_product_profile_evaluation; run_phase62_product_profile_evaluation()",
                ],
                PHASE62_LOG_PATH,
                "phase62_done",
            )
            st.rerun()


def render_results(text: Dict[str, Any]) -> None:
    st.title(text["results_title"])
    st.info(text["results_intro"])
    st.warning(text["interpretation_notice"])
    missing_artifacts = [path for path in PHASE63_ARTIFACTS.values() if not path.exists()]
    if not PHASE63_ARTIFACTS["summary_csv"].exists():
        st.warning(text["results_missing"])
        st.info(text["go_to_run"])
        st.write(text["expected_output_path"])
        st.code(str(PHASE63_OUTPUT_DIR.relative_to(ROOT)), language="text")
        st.write(text["missing_files"])
        st.dataframe(
            [{"missing_file": str(path.relative_to(ROOT))} for path in missing_artifacts],
            use_container_width=True,
            hide_index=True,
        )
        return
    if missing_artifacts:
        with st.expander(text["missing_files"]):
            st.dataframe(
                [{"missing_file": str(path.relative_to(ROOT))} for path in missing_artifacts],
                use_container_width=True,
                hide_index=True,
            )

    rows = read_csv_rows(PHASE63_ARTIFACTS["summary_csv"])
    summary_json = read_json(PHASE63_ARTIFACTS["summary_json"])
    summary_cards = build_summary_cards(rows, summary_json)

    st.subheader(text["summary_cards"])
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        best = summary_cards["best_product_overall"]
        st.metric(text["best_product_overall"], best["profile_id"], f"{best['score']:.4f}")
        st.caption(best["name"])
    with col2:
        best_by_mission = summary_cards["best_product_per_mission"]
        st.metric(text["best_product_per_mission"], str(len(set(best_by_mission.values()))))
        st.caption(", ".join(f"{mission}: {product}" for mission, product in sorted(best_by_mission.items())))
    with col3:
        worst = summary_cards["worst_mission_coverage"]
        st.metric(text["worst_mission_coverage"], worst["mission"], f"{worst['score']:.4f}")
    with col4:
        variance = summary_cards["highest_mission_variance"]
        st.metric(text["highest_mission_variance"], variance["profile_id"], f"{variance['score']:.4f}")
        st.caption(variance["name"])
    with col5:
        st.metric(text["single_winner_exists"], str(summary_cards["single_winner_exists"]).lower())
    st.dataframe(
        [
            {
                "mission": mission,
                "winner": product,
                "mission_effectiveness": round_metric(
                    summary_cards["best_product_per_mission_scores"].get(mission, 0.0)
                ),
            }
            for mission, product in sorted(summary_cards["best_product_per_mission"].items())
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.subheader(text["product_mission_table"])
    pivot_rows = build_product_mission_pivot(rows)
    st.dataframe(pivot_rows, use_container_width=True, hide_index=True)

    st.subheader(text["product_mission_chart"])
    st.caption(text["heatmap_help"])
    st.dataframe(pivot_rows, use_container_width=True, hide_index=True)

    st.subheader(text["winner_explanation"])
    for winner in build_winner_explanations(rows):
        st.write(winner["explanation"])

    st.subheader(text["product_detail"])
    product_ids = sorted({row.get("profile_id", "") for row in non_baseline_rows(rows) if row.get("profile_id")})
    if product_ids:
        labels_by_product = {
            profile_id: product_label(next(row for row in non_baseline_rows(rows) if row.get("profile_id") == profile_id))
            for profile_id in product_ids
        }
        selected_product_label = st.selectbox(
            text["product_selector"],
            [f"{profile_id} - {labels_by_product[profile_id]}" for profile_id in product_ids],
        )
        selected_product = selected_product_label.split(" - ", 1)[0]
        detail = build_product_detail(rows, selected_product)
        st.dataframe(
            [{text["detail_metric"]: key, text["detail_value"]: value} for key, value in detail.items()],
            use_container_width=True,
            hide_index=True,
        )
        st.caption(text["per_mission_detail"])
        st.dataframe(build_product_mission_detail(rows, selected_product), use_container_width=True, hide_index=True)

    st.subheader(text["summary_table"])
    st.dataframe(rows, use_container_width=True, hide_index=True)

    with st.expander(text["metric_guide"], expanded=True):
        st.markdown(text["metric_guide_text"])

    st.subheader(text["mission_interpretation"])
    st.caption(text["mission_interpretation_help"])
    st.dataframe(build_mission_interpretation(rows), use_container_width=True, hide_index=True)

    st.subheader(text["heatmap"])
    st.caption(text["heatmap_help"])
    if PHASE63_ARTIFACTS["heatmap"].exists():
        st.image(str(PHASE63_ARTIFACTS["heatmap"]))
    else:
        st.warning(f"mission_product_heatmap.png {text['not_found']}")

    st.subheader(text["variance"])
    st.caption(text["variance_help"])
    if PHASE63_ARTIFACTS["variance"].exists():
        st.image(str(PHASE63_ARTIFACTS["variance"]))
    else:
        st.warning(f"mission_variance.png {text['not_found']}")

    st.subheader(text["phase62_comparison"])
    st.caption(text["phase62_help"])
    if PHASE63_ARTIFACTS["phase62_comparison"].exists():
        st.image(str(PHASE63_ARTIFACTS["phase62_comparison"]))
    else:
        st.warning(f"phase63_vs_phase62.png {text['not_found']}")

    st.subheader(text["markdown_report"])
    report = read_text(PHASE63_ARTIFACTS["report"])
    if report:
        st.markdown(report)
    else:
        st.warning(f"PHASE63_MISSION_PRODUCT_REPORT.md {text['not_found']}")

    with st.expander(text["json_summary"]):
        if summary_json is None:
            st.warning(f"mission_product_summary.json {text['not_found']}")
        else:
            st.json(summary_json)

    st.subheader(text["downloads"])
    col1, col2, col3 = st.columns(3)
    with col1:
        render_download(PHASE63_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
    with col2:
        render_download(PHASE63_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
    with col3:
        render_download(PHASE63_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["benchmark_artifacts"])
    if not PHASE83_ARTIFACTS["summary_csv"].exists():
        st.warning(text["benchmark_results_missing"])
        st.code(str(PHASE83_OUTPUT_DIR.relative_to(ROOT)), language="text")
        return
    benchmark_rows = read_csv_rows(PHASE83_ARTIFACTS["summary_csv"])
    st.dataframe(benchmark_rows, use_container_width=True, hide_index=True)
    for key in ("ranking", "scenario_heatmap", "mission_heatmap", "consistency"):
        if PHASE83_ARTIFACTS[key].exists():
            st.image(str(PHASE83_ARTIFACTS[key]))
    benchmark_report = read_text(PHASE83_ARTIFACTS["report"])
    if benchmark_report:
        st.markdown(benchmark_report)
    col1, col2, col3 = st.columns(3)
    with col1:
        render_download(PHASE83_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
    with col2:
        render_download(PHASE83_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
    with col3:
        render_download(PHASE83_ARTIFACTS["report"], text["download_md"], "text/markdown", text)


def render_benchmark(text: Dict[str, Any]) -> None:
    st.title(text["benchmark_suite"])
    benchmark_files = list_benchmark_files()
    if not benchmark_files:
        st.warning(text["no_benchmarks"])
        return
    default_index = 0
    for index, path in enumerate(benchmark_files):
        if path.name == "cybermatch_standard_v1.json":
            default_index = index
            break
    selected_benchmark = st.selectbox(
        text["benchmark_json"],
        benchmark_files,
        index=default_index,
        format_func=lambda path: path.name,
    )
    render_benchmark_metadata(selected_benchmark, text)
    st.code(str(selected_benchmark.relative_to(ROOT)), language="text")
    if st.button(text["run_standard_benchmark"], type="primary", disabled=runner_is_active()):
        start_runner(
            [
                sys.executable,
                "-c",
                "from run_scenarios import run_phase85_standard_benchmark; run_phase85_standard_benchmark()",
            ],
            PHASE85_LOG_PATH,
            "phase85_done",
        )
        st.rerun()
    render_runner_status(text)

    st.subheader("Standard Benchmark Artifacts")
    if not PHASE85_ARTIFACTS["summary_csv"].exists():
        st.warning(text["benchmark_results_missing"])
        st.code(str(PHASE85_OUTPUT_DIR.relative_to(ROOT)), language="text")
        return
    st.dataframe(read_csv_rows(PHASE85_ARTIFACTS["summary_csv"]), use_container_width=True, hide_index=True)
    for key in ("ranking", "scenario_heatmap", "topology_heatmap", "mission_heatmap"):
        if PHASE85_ARTIFACTS[key].exists():
            st.image(str(PHASE85_ARTIFACTS[key]))
    report = read_text(PHASE85_ARTIFACTS["report"])
    if report:
        st.markdown(report)


def main() -> None:
    st.set_page_config(page_title="CyberMatch", layout="wide")
    language = st.sidebar.selectbox("Language / 言語", ["日本語", "English"], index=0)
    text = TEXT[language]
    page = st.sidebar.radio("CyberMatch", text["nav"])
    page_key = text["nav_to_key"][page]
    st.sidebar.caption("Phase7.2 Streamlit MVP")
    st.sidebar.caption(text["scope"])

    if page_key == "home":
        render_home(text)
    elif page_key == "scenario":
        render_scenario(text)
    elif page_key == "products":
        render_products(text)
    elif page_key == "run":
        render_run(text)
    elif page_key == "results":
        render_results(text)
    elif page_key == "benchmark":
        render_benchmark(text)


if __name__ == "__main__":
    main()
