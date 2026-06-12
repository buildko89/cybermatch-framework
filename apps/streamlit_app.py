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
from typing import Any, Dict, List, Optional

import streamlit as st


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PRODUCT_PROFILE_DIR = ROOT / "profiles" / "products"
PHASE63_OUTPUT_DIR = ROOT / "output" / "phase63_mission_products"
PHASE62_OUTPUT_DIR = ROOT / "output" / "phase62_product_profiles"
PHASE63_LOG_PATH = PHASE63_OUTPUT_DIR / "streamlit_phase63_run.log"
PHASE62_LOG_PATH = PHASE62_OUTPUT_DIR / "streamlit_phase62_run.log"

PHASE63_ARTIFACTS = {
    "summary_csv": PHASE63_OUTPUT_DIR / "mission_product_summary.csv",
    "summary_json": PHASE63_OUTPUT_DIR / "mission_product_summary.json",
    "heatmap": PHASE63_OUTPUT_DIR / "mission_product_heatmap.png",
    "variance": PHASE63_OUTPUT_DIR / "mission_variance.png",
    "phase62_comparison": PHASE63_OUTPUT_DIR / "phase63_vs_phase62.png",
    "report": PHASE63_OUTPUT_DIR / "PHASE63_MISSION_PRODUCT_REPORT.md",
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
        "nav": ["ホーム", "シナリオ", "製品", "実行", "結果"],
        "nav_to_key": {
            "ホーム": "home",
            "シナリオ": "scenario",
            "製品": "products",
            "実行": "run",
            "結果": "results",
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
        "primary_runner": "Primary runner:",
        "output": "出力先:",
        "run_phase63": "Phase6.3 Mission-Aware Product Evaluation を実行",
        "stop_run": "実行を停止",
        "running_phase63": "Phase6.3 evaluation を実行中...",
        "runner_failed": "Runner が失敗しました",
        "runner_running": "Evaluation is running.",
        "runner_stopped": "Evaluation を停止しました。",
        "runner_exit_code": "終了コード",
        "runner_not_running": "実行中のrunnerはありません。",
        "phase63_done": "Phase6.3 evaluation が完了しました。",
        "phase62_done": "Phase6.2 evaluation が完了しました。",
        "artifacts_written": "Artifacts written to",
        "optional_phase62": "Optional Phase6.2 runner",
        "run_phase62": "Phase6.2 Product Profile Evaluation を実行",
        "running_phase62": "Phase6.2 evaluation を実行中...",
        "results_title": "結果",
        "results_missing": "Results not found. Run the evaluation first.",
        "results_intro": (
            "この画面は Phase6.3 の生成済みartifactを表示します。画像内の軸や列名は"
            "runnerが生成した英語表記のままですが、下の説明で読み方を確認できます。"
        ),
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
        "nav": ["Home", "Scenario", "Products", "Run", "Results"],
        "nav_to_key": {
            "Home": "home",
            "Scenario": "scenario",
            "Products": "products",
            "Run": "run",
            "Results": "results",
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
        "primary_runner": "Primary runner:",
        "output": "Output:",
        "run_phase63": "Run Phase6.3 Mission-Aware Product Evaluation",
        "stop_run": "Stop run",
        "running_phase63": "Running Phase6.3 evaluation...",
        "runner_failed": "Runner failed",
        "runner_running": "Evaluation is running.",
        "runner_stopped": "Evaluation stopped.",
        "runner_exit_code": "Exit code",
        "runner_not_running": "No runner is currently active.",
        "phase63_done": "Phase6.3 evaluation completed.",
        "artifacts_written": "Artifacts written to",
        "optional_phase62": "Optional Phase6.2 runner",
        "run_phase62": "Run Phase6.2 Product Profile Evaluation",
        "running_phase62": "Running Phase6.2 evaluation...",
        "phase62_done": "Phase6.2 evaluation completed.",
        "results_title": "Results",
        "results_missing": "Results not found. Run the evaluation first.",
        "results_intro": (
            "This page displays generated Phase6.3 artifacts. Chart labels come from "
            "the existing runner output; use the explanations below to interpret each view."
        ),
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


def to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


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
    if not PHASE63_ARTIFACTS["summary_csv"].exists():
        st.warning(text["results_missing"])
        st.code(str(PHASE63_OUTPUT_DIR.relative_to(ROOT)), language="text")
        return

    st.subheader(text["summary_table"])
    rows = read_csv_rows(PHASE63_ARTIFACTS["summary_csv"])
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
        summary_json = read_json(PHASE63_ARTIFACTS["summary_json"])
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


if __name__ == "__main__":
    main()
