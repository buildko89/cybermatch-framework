"""Streamlit MVP for CyberMatch product evaluation artifacts.

This app is intentionally thin: it calls existing Phase6 runners and reads
existing artifact files. It does not add simulation logic.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
import time
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, List, Optional, Set

import streamlit as st


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cybermatch.application.process_control import launch_logged_process, terminate_process
from cybermatch.application.artifacts import discover_files

PRODUCT_PROFILE_DIR = ROOT / "profiles" / "products"
SCENARIO_DIR = ROOT / "scenarios"
SCENARIO_CATALOG_DIR = SCENARIO_DIR / "catalog"
DEMO_SCENARIO_DIR = SCENARIO_DIR / "demos"
BENCHMARK_DIR = ROOT / "benchmarks"
TOPOLOGY_DIR = ROOT / "topologies"
HUNTING_RECIPE_DIR = ROOT / "recipes" / "threat_hunting"
HUNTING_OUTPUT_ROOT = ROOT / "output" / "threat_hunting"
HUNTING_BENCHMARK_OUTPUT_DIR = HUNTING_OUTPUT_ROOT / "cybermatch_hunting_v1"
HUNTING_BENCHMARK_SUMMARY = HUNTING_BENCHMARK_OUTPUT_DIR / "hunting_benchmark_summary.json"
HUNTING_BENCHMARK_CSV = HUNTING_BENCHMARK_OUTPUT_DIR / "hunting_benchmark_summary.csv"
HUNTING_LOG_PATH = HUNTING_OUTPUT_ROOT / "streamlit_hunting_run.log"
HUNTING_EXPERIMENT_LOG_PATH = HUNTING_OUTPUT_ROOT / "streamlit_hunting_experiment.log"
PHASE63_OUTPUT_DIR = ROOT / "output" / "phase63_mission_products"
PHASE62_OUTPUT_DIR = ROOT / "output" / "phase62_product_profiles"
PHASE83_OUTPUT_DIR = ROOT / "output" / "phase83_benchmark_suite"
PHASE85_OUTPUT_DIR = ROOT / "output" / "phase85_standard_benchmark"
PHASE90_OUTPUT_DIR = ROOT / "output" / "phase90_intent_inference"
PHASE91_OUTPUT_DIR = ROOT / "output" / "phase91_behavior_profiles"
PHASE92_OUTPUT_DIR = ROOT / "output" / "phase92_feature_space"
PHASE93_OUTPUT_DIR = ROOT / "output" / "phase93_profilecore"
PHASE94_OUTPUT_DIR = ROOT / "output" / "phase94_archetype_interpretation"
PHASE95_OUTPUT_DIR = ROOT / "output" / "phase95_strategy_layer"
PHASE96_OUTPUT_DIR = ROOT / "output" / "phase96_taxonomy"
PHASE97_OUTPUT_DIR = ROOT / "output" / "phase97_target_strategy"
PHASE98_OUTPUT_DIR = ROOT / "output" / "phase98_strategy_validation"
PHASE99_OUTPUT_DIR = ROOT / "output" / "phase99_decision_graph"
PHASE63_LOG_PATH = PHASE63_OUTPUT_DIR / "streamlit_phase63_run.log"
PHASE62_LOG_PATH = PHASE62_OUTPUT_DIR / "streamlit_phase62_run.log"
PHASE83_LOG_PATH = PHASE83_OUTPUT_DIR / "streamlit_phase83_run.log"
PHASE85_LOG_PATH = PHASE85_OUTPUT_DIR / "streamlit_phase85_run.log"

PHASE63_ARTIFACTS = {
    "summary_csv": PHASE63_OUTPUT_DIR / "mission_product_summary.csv",
    "summary_json": PHASE63_OUTPUT_DIR / "mission_product_summary.json",
    "manifest": PHASE63_OUTPUT_DIR / "run_manifest.json",
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

PHASE90_ARTIFACTS = {
    "summary_csv": PHASE90_OUTPUT_DIR / "intent_inference_summary.csv",
    "summary_json": PHASE90_OUTPUT_DIR / "intent_inference_summary.json",
    "confusion_matrix": PHASE90_OUTPUT_DIR / "mission_confusion_matrix.png",
    "accuracy": PHASE90_OUTPUT_DIR / "mission_accuracy.png",
    "confidence": PHASE90_OUTPUT_DIR / "mission_confidence_distribution.png",
    "report": PHASE90_OUTPUT_DIR / "PHASE90_INTENT_INFERENCE_REPORT.md",
}

PHASE91_ARTIFACTS = {
    "summary_csv": PHASE91_OUTPUT_DIR / "behavior_profile_summary.csv",
    "summary_json": PHASE91_OUTPUT_DIR / "behavior_profile_summary.json",
    "distribution": PHASE91_OUTPUT_DIR / "profile_distribution.png",
    "confidence": PHASE91_OUTPUT_DIR / "profile_confidence_distribution.png",
    "relationship": PHASE91_OUTPUT_DIR / "profile_mission_relationship.png",
    "report": PHASE91_OUTPUT_DIR / "PHASE91_BEHAVIOR_PROFILE_REPORT.md",
}

PHASE92_ARTIFACTS = {
    "summary_csv": PHASE92_OUTPUT_DIR / "feature_space_summary.csv",
    "summary_json": PHASE92_OUTPUT_DIR / "feature_space_summary.json",
    "dominance": PHASE92_OUTPUT_DIR / "feature_dominance.png",
    "mission_heatmap": PHASE92_OUTPUT_DIR / "mission_feature_heatmap.png",
    "profile_heatmap": PHASE92_OUTPUT_DIR / "profile_feature_heatmap.png",
    "critical_path_bias": PHASE92_OUTPUT_DIR / "critical_path_bias.png",
    "report": PHASE92_OUTPUT_DIR / "PHASE92_FEATURE_SPACE_REPORT.md",
}

PHASE93_ARTIFACTS = {
    "summary_csv": PHASE93_OUTPUT_DIR / "profilecore_feature_projection.csv",
    "summary_json": PHASE93_OUTPUT_DIR / "profilecore_analysis.json",
    "pca_variance": PHASE93_OUTPUT_DIR / "pca_variance.png",
    "component_loadings": PHASE93_OUTPUT_DIR / "component_loadings.png",
    "feature_projection": PHASE93_OUTPUT_DIR / "feature_projection.png",
    "archetype_distribution": PHASE93_OUTPUT_DIR / "archetype_distribution.png",
    "report": PHASE93_OUTPUT_DIR / "PHASE93_PROFILECORE_REPORT.md",
}
PHASE94_ARTIFACTS = {
    "summary_csv": PHASE94_OUTPUT_DIR / "archetype_summary.csv",
    "summary_json": PHASE94_OUTPUT_DIR / "archetype_summary.json",
    "feature_comparison": PHASE94_OUTPUT_DIR / "archetype_feature_comparison.png",
    "mission_distribution": PHASE94_OUTPUT_DIR / "archetype_mission_distribution.png",
    "profile_distribution": PHASE94_OUTPUT_DIR / "archetype_profile_distribution.png",
    "distance_matrix": PHASE94_OUTPUT_DIR / "archetype_distance_matrix.png",
    "report": PHASE94_OUTPUT_DIR / "PHASE94_ARCHETYPE_INTERPRETATION_REPORT.md",
}
PHASE95_ARTIFACTS = {
    "summary_csv": PHASE95_OUTPUT_DIR / "strategy_summary.csv",
    "summary_json": PHASE95_OUTPUT_DIR / "strategy_summary.json",
    "strategy_distribution": PHASE95_OUTPUT_DIR / "strategy_distribution.png",
    "mission_strategy_matrix": PHASE95_OUTPUT_DIR / "mission_strategy_matrix.png",
    "strategy_archetype_matrix": PHASE95_OUTPUT_DIR / "strategy_archetype_matrix.png",
    "strategy_profile_matrix": PHASE95_OUTPUT_DIR / "strategy_profile_matrix.png",
    "report": PHASE95_OUTPUT_DIR / "PHASE95_STRATEGY_LAYER_REPORT.md",
}
PHASE96_ARTIFACTS = {
    "summary_csv": PHASE96_OUTPUT_DIR / "taxonomy_summary.csv",
    "summary_json": PHASE96_OUTPUT_DIR / "taxonomy_summary.json",
    "intent_mission_matrix": PHASE96_OUTPUT_DIR / "intent_mission_matrix.png",
    "mission_target_matrix": PHASE96_OUTPUT_DIR / "mission_target_matrix.png",
    "target_strategy_matrix": PHASE96_OUTPUT_DIR / "target_strategy_matrix.png",
    "report": PHASE96_OUTPUT_DIR / "PHASE96_TAXONOMY_REPORT.md",
}
PHASE97_ARTIFACTS = {
    "summary_json": PHASE97_OUTPUT_DIR / "target_strategy_summary.json",
    "target_strategy_matrix": PHASE97_OUTPUT_DIR / "target_strategy_matrix.png",
    "strategy_distribution": PHASE97_OUTPUT_DIR / "strategy_distribution.png",
    "strategy_diversity": PHASE97_OUTPUT_DIR / "strategy_diversity.png",
    "target_specificity": PHASE97_OUTPUT_DIR / "target_specificity.png",
    "strategy_alignment": PHASE97_OUTPUT_DIR / "strategy_alignment.png",
    "report": PHASE97_OUTPUT_DIR / "PHASE97_TARGET_STRATEGY_REPORT.md",
}
PHASE98_ARTIFACTS = {
    "summary_csv": PHASE98_OUTPUT_DIR / "strategy_validation_summary.csv",
    "summary_json": PHASE98_OUTPUT_DIR / "strategy_validation_summary.json",
    "distance_matrix": PHASE98_OUTPUT_DIR / "strategy_distance_matrix.png",
    "distinctiveness": PHASE98_OUTPUT_DIR / "strategy_distinctiveness.png",
    "redundancy": PHASE98_OUTPUT_DIR / "strategy_redundancy.png",
    "target_validation": PHASE98_OUTPUT_DIR / "target_strategy_validation.png",
    "mission_explainability": PHASE98_OUTPUT_DIR / "mission_strategy_explainability.png",
    "report": PHASE98_OUTPUT_DIR / "PHASE98_STRATEGY_VALIDATION_REPORT.md",
}
PHASE99_ARTIFACTS = {
    "summary_csv": PHASE99_OUTPUT_DIR / "decision_graph_summary.csv",
    "summary_json": PHASE99_OUTPUT_DIR / "decision_graph_summary.json",
    "decision_graph": PHASE99_OUTPUT_DIR / "cybermatch.decision_model.decision_graph.png",
    "intent_mission": PHASE99_OUTPUT_DIR / "intent_mission_graph.png",
    "mission_target": PHASE99_OUTPUT_DIR / "mission_target_graph.png",
    "target_strategy": PHASE99_OUTPUT_DIR / "target_strategy_graph.png",
    "strategy_behavior": PHASE99_OUTPUT_DIR / "strategy_behavior_graph.png",
    "report": PHASE99_OUTPUT_DIR / "PHASE99_DECISION_GRAPH_REPORT.md",
}

from apps.streamlit_text import (  # noqa: E402
    PROFILE_COLUMNS,
    MISSION_OPTIONS,
    MISSION_LABELS,
    PRODUCT_CATEGORY_LABELS,
    TOPOLOGY_LABELS,
    TOPOLOGY_DESCRIPTIONS,
    SCENARIO_LABELS,
    SCENARIO_DESCRIPTIONS,
    JAPANESE_REPORT_INFO,
    JAPANESE_REPORT_SECTIONS,
    JAPANESE_REPORT_TERMS,
    TEXT,
)


def canonical_repo_path(path_value: str | Path) -> str:
    # Session values saved on Windows contain backslashes; PureWindowsPath
    # treats both separators as separators on every OS.
    return PureWindowsPath(str(path_value)).as_posix()


def normalized_option_selection(values: Any, options: List[str], *, path_values: bool = False) -> List[str]:
    if values is None:
        return list(options)
    if not isinstance(values, list):
        return []
    normalize = canonical_repo_path if path_values else str
    option_set = set(options)
    return list(dict.fromkeys(normalize(value) for value in values if normalize(value) in option_set))


def load_product_profiles() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path in sorted(PRODUCT_PROFILE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            rows.append({"name": path.stem, "category": "invalid", "error": str(exc), "file": str(path)})
            continue
        row = {column: data.get(column, 0.0) for column in PROFILE_COLUMNS}
        row["file"] = canonical_repo_path(path.relative_to(ROOT))
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


def list_hunting_benchmark_files() -> List[Path]:
    result: List[Path] = []
    for path in list_benchmark_files():
        payload = read_json(path)
        metadata = payload.get("metadata", {}) if isinstance(payload, dict) else {}
        if isinstance(metadata, dict) and metadata.get("type") == "threat_hunting":
            result.append(path)
    return result


def list_hunting_recipe_files() -> List[Path]:
    return discover_files(HUNTING_RECIPE_DIR, "*.json")


def list_hunting_history_files() -> List[Path]:
    return discover_files(HUNTING_BENCHMARK_OUTPUT_DIR, "runs/*/*/histories/*.npz")


def build_hunting_summary_cards(
    rows: List[Dict[str, Any]], manifest: Dict[str, Any]
) -> Dict[str, Any]:
    succeeded = [row for row in rows if row.get("status") == "succeeded"]
    f1_values = [to_float(row.get("f1")) for row in succeeded]
    return {
        "evaluation_matrix_size": int(manifest.get("evaluation_matrix_size", len(rows)) or 0),
        "succeeded_cases": len(succeeded),
        "completeness": round(to_float(manifest.get("benchmark_completeness")), 4),
        "finding_count": sum(int(to_float(row.get("finding_count"))) for row in succeeded),
        "mean_f1": round(mean(f1_values), 4),
    }


def build_hunting_heatmap_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[tuple[str, str, str], List[float]] = {}
    for row in rows:
        if row.get("status") != "succeeded":
            continue
        key = (
            str(row.get("mission_name", "")),
            str(row.get("product_profile", "")),
            str(row.get("recipe_id", "")),
        )
        groups.setdefault(key, []).append(to_float(row.get("f1")))
    return [
        {
            "mission": key[0],
            "product": key[1],
            "recipe": key[2],
            "mean_f1": round(mean(values), 4),
        }
        for key, values in sorted(groups.items())
    ]


def build_hunting_bubble_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "product": str(row.get("product_profile", "")),
            "recipe": str(row.get("recipe_id", "")),
            "noise": str(row.get("noise_profile", "")),
            "f1": to_float(row.get("f1")),
            "false_positives_per_100_steps": to_float(
                row.get("false_positives_per_100_steps")
            ),
            "finding_count": int(to_float(row.get("finding_count"))),
        }
        for row in rows
        if row.get("status") == "succeeded"
    ]


def build_hunting_event_summary(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts: Dict[tuple[str, str], int] = {}
    for event in events:
        key = (str(event.get("event_type", "unknown")), str(event.get("signal_class", "unknown")))
        counts[key] = counts.get(key, 0) + 1
    return [
        {"event_type": key[0], "signal_class": key[1], "count": count}
        for key, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def build_hunting_evidence_timeline(
    events: List[Dict[str, Any]], evidence_event_ids: List[str]
) -> List[Dict[str, Any]]:
    wanted = set(evidence_event_ids)
    return [
        {
            "step": int(event.get("step", 0)),
            "event_type": str(event.get("event_type", "")),
            "signal_class": str(event.get("signal_class", "")),
            "source_role": event.get("source_role"),
            "target_role": event.get("target_role"),
            "event_id": str(event.get("event_id", "")),
        }
        for event in sorted(events, key=lambda value: (int(value.get("step", 0)), str(value.get("event_id", ""))))
        if event.get("event_id") in wanted
    ]


def build_recipe_operation_rows(recipe_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for index, operation in enumerate(recipe_payload.get("operations", []), start=1):
        if not isinstance(operation, dict):
            continue
        parameters = {key: value for key, value in operation.items() if key != "operator"}
        result.append(
            {
                "step": index,
                "operator": str(operation.get("operator", "")),
                "parameters": json.dumps(parameters, ensure_ascii=False, sort_keys=True),
            }
        )
    result.append(
        {
            "step": len(result) + 1,
            "operator": "finding",
            "parameters": json.dumps(recipe_payload.get("finding", {}), ensure_ascii=False, sort_keys=True),
        }
    )
    return result


def build_hunting_model_summary(model_manifest: Any) -> List[Dict[str, Any]]:
    if not isinstance(model_manifest, dict):
        return []
    features = model_manifest.get("feature_schema", [])
    training = model_manifest.get("training_data_ids", [])
    return [
        {
            "plugin": str(model_manifest.get("plugin_id", "")),
            "model": str(model_manifest.get("model_kind", "")),
            "features": ", ".join(str(value) for value in features) if isinstance(features, list) else "",
            "training_data_count": len(training) if isinstance(training, list) else 0,
            "random_seed": model_manifest.get("random_seed"),
            "threshold": round_metric(model_manifest.get("threshold")),
            "model_hash": str(model_manifest.get("model_hash", "")),
        }
    ]


def build_evidence_class_summary(replay_manifest: Any) -> List[Dict[str, Any]]:
    """Expose provenance without implying that replay data is live-SUT evidence."""
    if not isinstance(replay_manifest, dict):
        return []
    source = replay_manifest.get("source", {})
    mapping = replay_manifest.get("mapping", {})
    sut = replay_manifest.get("sut", {})
    if not all(isinstance(value, dict) for value in (source, mapping, sut)):
        return []
    return [
        {
            "evidence_class": str(replay_manifest.get("evidence_class", "unknown")),
            "source": str(source.get("path", "")),
            "source_sha256": str(source.get("sha256", "")),
            "mapping": str(mapping.get("id", "")),
            "mapping_standard": str(mapping.get("standard", "")),
            "sut_adapter": str(sut.get("adapter_id", "")),
        }
    ]


def safe_hunting_artifact_dir(path_value: Any) -> Optional[Path]:
    if not isinstance(path_value, str) or not path_value:
        return None
    path = Path(path_value).resolve()
    output_root = (ROOT / "output").resolve()
    return path if path.is_relative_to(output_root) and path.is_dir() else None


def localize_report_markdown(report: str, report_name: str, locale: str) -> str:
    if locale != "ja" or not report or report.startswith("# 防御策の比較評価レポート") or report.startswith("# CyberMatch 標準ベンチマーク比較レポート"):
        return report

    title, purpose = JAPANESE_REPORT_INFO.get(
        report_name,
        ("CyberMatch 分析レポート", "この分析結果は、攻撃者行動と防御策評価に関する研究用の詳細情報です。"),
    )
    lines = [f"# {title}", "", "## このレポートで分かること", purpose, ""]
    skip_method_body = False
    for source_line in report.splitlines():
        if source_line.startswith("# "):
            continue
        if source_line.startswith("## "):
            section = source_line[3:].strip()
            skip_method_body = section == "Method"
            translated_section = JAPANESE_REPORT_SECTIONS.get(section, "分析の詳細")
            lines.extend([f"## {translated_section}", ""])
            if skip_method_body:
                lines.extend(["この分析は、既に生成された攻撃者行動データを整理・解釈する研究用の分析です。新たな攻撃や防御を実行するものではありません。", ""])
            continue
        if skip_method_body:
            continue
        if source_line and not source_line.startswith(("|", "- ", "`")) and any(character.isalpha() for character in source_line):
            continue
        translated_line = source_line
        for source, target in sorted(JAPANESE_REPORT_TERMS.items(), key=lambda item: len(item[0]), reverse=True):
            translated_line = translated_line.replace(source, target)
        translated_line = translated_line.replace("True", "はい").replace("False", "いいえ")
        lines.append(translated_line)
    return "\n".join(lines).rstrip() + "\n"


def render_generated_report(path: Path, text: Dict[str, Any]) -> None:
    report = read_text(path)
    if report:
        st.markdown(localize_report_markdown(report, path.name, str(text.get("report_locale", "en"))))


def list_scenario_files() -> List[Path]:
    if not SCENARIO_DIR.exists():
        return []
    return sorted(SCENARIO_DIR.glob("*.json"))


def list_catalog_scenario_files() -> List[Path]:
    if not SCENARIO_CATALOG_DIR.exists():
        return []
    return sorted(SCENARIO_CATALOG_DIR.glob("*.json"))


def list_demo_scenario_files() -> List[Path]:
    if not DEMO_SCENARIO_DIR.exists():
        return []
    return sorted(DEMO_SCENARIO_DIR.glob("*.json"))


def demo_selection_values(path: Path) -> Dict[str, Any]:
    scenario = read_json(path)
    if not isinstance(scenario, dict):
        raise ValueError(f"Demo scenario is invalid: {path}")
    missions = scenario.get("missions")
    products = scenario.get("products")
    topology = scenario.get("topology", {})
    evaluation = scenario.get("evaluation", {})
    if not isinstance(missions, list) or not all(mission in MISSION_OPTIONS for mission in missions):
        raise ValueError(f"Demo scenario has invalid missions: {path}")
    if not isinstance(products, list) or not all(isinstance(product, str) for product in products):
        raise ValueError(f"Demo scenario has invalid products: {path}")
    if not isinstance(topology, dict) or not isinstance(topology.get("preset"), str):
        raise ValueError(f"Demo scenario has invalid topology: {path}")
    seeds = evaluation.get("seeds") if isinstance(evaluation, dict) else None
    if seeds is not None and (not isinstance(seeds, list) or not all(isinstance(seed, int) for seed in seeds)):
        raise ValueError(f"Demo scenario has invalid seeds: {path}")
    return {
        "missions": missions,
        "products": products,
        "topology_preset": topology["preset"],
        "seeds": seeds,
    }


def apply_demo_scenario(path: Path) -> None:
    values = demo_selection_values(path)
    topology_path = TOPOLOGY_DIR / f"{values['topology_preset']}.json"
    if not topology_path.is_file():
        raise ValueError(f"Demo scenario topology not found: {values['topology_preset']}")
    st.session_state["selected_missions"] = values["missions"]
    st.session_state["selected_product_paths"] = [canonical_repo_path(product) for product in values["products"]]
    st.session_state["selected_topology_path"] = str(topology_path.relative_to(ROOT))
    st.session_state["selected_demo_scenario_path"] = str(path.relative_to(ROOT))
    st.session_state["selected_demo_seeds"] = values["seeds"]


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
        st.write(display_scenario_name(str(metadata.get("name", ""))))
    with col2:
        st.write(text["scenario_industry"])
        st.code(str(metadata.get("industry", "")), language="text")
    st.write(text["scenario_description"])
    scenario_name = str(metadata.get("name", ""))
    st.write(SCENARIO_DESCRIPTIONS.get(scenario_name, str(metadata.get("description", ""))))


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
    if metadata.get("type") == "threat_hunting":
        matrix_size *= (
            len(benchmark_data.get("recipes", []))
            * len(benchmark_data.get("noise_profiles", []))
            * len(benchmark_data.get("seeds", [0]))
        )
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1:
        st.metric(text["benchmark_name"], str(metadata.get("name", "")))
    with col2:
        st.metric("設定ファイルの版", str(metadata.get("version", "")))
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
        st.write(display_topology_name(str(metadata.get("name", ""))))
    with col2:
        st.write(text["topology_description"])
        topology_name = str(metadata.get("name", ""))
        st.write(TOPOLOGY_DESCRIPTIONS.get(topology_name, str(metadata.get("description", ""))))
    st.write(text["topology_characteristics"])
    if isinstance(characteristics, dict):
        labels = {
            "critical_assets": "重要資産の数",
            "identity_centralization": "ID基盤の集中度",
            "lateral_movement_complexity": "横移動の複雑さ",
            "deception_surface": "デコイを置ける範囲",
            "operational_sensitivity": "業務停止への敏感さ",
        }
        st.dataframe(
            [{"環境特性": labels.get(key, key), "設定値": value} for key, value in characteristics.items()],
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


def display_mission_name(mission: str) -> str:
    return MISSION_LABELS.get(mission, mission)


def display_product_name(row: Dict[str, Any]) -> str:
    category = PRODUCT_CATEGORY_LABELS.get(str(row.get("product_category", "")), str(row.get("product_category", "")))
    name = str(row.get("product_profile_name", ""))
    return f"{category}（{name}）" if category and name else name or category


def display_topology_name(topology_name: str) -> str:
    return TOPOLOGY_LABELS.get(topology_name, topology_name)


def display_scenario_name(scenario_name: str) -> str:
    return SCENARIO_LABELS.get(scenario_name, scenario_name)


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


def build_user_run_summary(manifest: Any, summary_cards: Dict[str, Any]) -> Dict[str, Any]:
    inputs = manifest.get("inputs", {}) if isinstance(manifest, dict) else {}
    product_profiles = inputs.get("product_profiles", {}) if isinstance(inputs, dict) else {}
    product_ids = list(product_profiles) if isinstance(product_profiles, dict) else []
    missions = inputs.get("missions", []) if isinstance(inputs, dict) else []
    seeds = inputs.get("seeds", "") if isinstance(inputs, dict) else ""
    best_product = summary_cards.get("best_product_overall", {})
    return {
        "topology": str(inputs.get("topology", "未記録")) if isinstance(inputs, dict) else "未記録",
        "missions": [str(mission) for mission in missions] if isinstance(missions, list) else [],
        "product_ids": product_ids,
        "seeds": ", ".join(str(seed) for seed in seeds) if isinstance(seeds, list) else str(seeds),
        "best_product_id": str(best_product.get("profile_id", "")),
        "best_product_name": str(best_product.get("name", "")),
        "best_product_score": float(best_product.get("score", 0.0)),
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


def build_decision_recommendations(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    drivers = (
        ("success", "mission_success_delta"),
        ("disruption", "mission_disruption_delta"),
        ("detection", "mission_detection_delta"),
        ("diversion", "diversion_delta"),
    )
    recommendations: List[Dict[str, Any]] = []
    for winner in build_mission_interpretation(rows):
        source_row = next(
            (
                row
                for row in non_baseline_rows(rows)
                if row.get("profile_id") == winner["profile_id"]
                and row.get("mission_name") == winner["mission_name"]
            ),
            {},
        )
        driver_key, metric_key = max(drivers, key=lambda item: abs(to_float(source_row.get(item[1]))))
        recommendations.append(
            {
                "mission_name": winner["mission_name"],
                "profile_id": winner["profile_id"],
                "product_profile_name": winner["product_profile_name"],
                "mission_effectiveness": winner["mission_effectiveness"],
                "driver_key": driver_key,
                "driver_value": round_metric(source_row.get(metric_key)),
            }
        )
    return recommendations


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


def build_phase63_command(
    topology_path: Path,
    missions: List[str],
    product_paths: List[str],
    seeds: Optional[List[int]] = None,
) -> List[str]:
    command = [
        sys.executable,
        str(ROOT / "scripts" / "run_phase63.py"),
        "--topology",
        canonical_repo_path(topology_path.relative_to(ROOT)),
        "--output-dir",
        canonical_repo_path(PHASE63_OUTPUT_DIR.relative_to(ROOT)),
    ]
    for mission in missions:
        command.extend(["--mission", mission])
    for profile_path in product_paths:
        command.extend(["--product", canonical_repo_path(profile_path)])
    for seed in seeds if seeds else [0]:
        command.extend(["--seed", str(seed)])
    return command


def start_runner(command: List[str], log_path: Path, success_key: str) -> None:
    process = launch_logged_process(command, cwd=ROOT, log_path=log_path)
    st.session_state["runner_process"] = process
    st.session_state["runner_log_path"] = str(log_path)
    st.session_state["runner_success_key"] = success_key
    st.session_state["runner_stopped"] = False


def stop_runner() -> bool:
    process = get_runner_process()
    if process is None or process.poll() is not None:
        return False
    terminate_process(process)
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
            with st.expander("実行ログ"):
                st.code(log_text[-6000:], language="text")

    if process is not None and process.poll() is None:
        time.sleep(1)
        st.rerun()


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
    st.info(text["home_how_to"])
    st.markdown(text["current_focus"])


def render_scenario(text: Dict[str, Any]) -> None:
    st.title(text["scenario_title"])
    st.info(text["scenario_page_guide"])
    topology_files = list_topology_files()
    st.subheader(text["topology_library"])
    st.caption(text["topology_guide"])
    if topology_files:
        selected_topology = st.selectbox(text["topology_json"], topology_files, format_func=lambda path: display_topology_name(path.stem))
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
    st.caption(text["scenario_catalog_guide"])
    if catalog_files:
        selected_catalog = st.selectbox(text["scenario_catalog"], catalog_files, format_func=lambda path: display_scenario_name(path.stem))
        st.session_state["selected_catalog_scenario_path"] = str(selected_catalog.relative_to(ROOT))
        render_scenario_metadata(selected_catalog, text)
        st.write(text["selected_scenario_path"])
        st.code(str(selected_catalog.relative_to(ROOT)), language="text")
    else:
        st.warning(text["no_scenarios"])

    scenario_files = list_scenario_files()
    st.subheader(text["scenario_import"])
    st.caption(text["scenario_file_guide"])
    if scenario_files:
        selected = st.selectbox(text["scenario_json"], scenario_files, format_func=lambda path: path.name)
        st.session_state["selected_scenario_path"] = str(selected.relative_to(ROOT))
        st.write(text["selected_scenario_path"])
        st.code(str(selected.relative_to(ROOT)), language="text")
        scenario_data = read_json(selected)
        if scenario_data is not None:
            with st.expander(text["json_detail"]):
                st.json(scenario_data)
    else:
        st.warning(text["no_scenarios"])

    selected_mission = st.selectbox(
        text["scenario_selector"],
        ["攻撃者の目的別に防御策を比較", "防御策プロファイルの基礎比較"],
        index=0,
    )
    st.session_state["selected_runner"] = selected_mission
    selected_mission = st.selectbox(text["mission_selection"], MISSION_OPTIONS, index=0, key="scenario_mission")
    st.session_state["selected_missions"] = [selected_mission]
    st.caption(text["mission_caption"])
    st.code(str(PHASE63_OUTPUT_DIR.relative_to(ROOT)), language="text")


def render_products(text: Dict[str, Any]) -> None:
    st.title(text["products_title"])
    profiles = load_product_profiles()
    if not profiles:
        st.warning(text["no_profiles"])
        return

    profile_paths = [str(row.get("file", "")) for row in profiles]
    profile_names = {str(row.get("file", "")): str(row.get("name", "")) for row in profiles}
    selected_product_defaults = normalized_option_selection(
        st.session_state.get("selected_product_paths"),
        profile_paths,
        path_values=True,
    )
    st.session_state["selected_product_paths"] = selected_product_defaults
    selected_profile_paths = st.multiselect(
        text["comparison_targets"],
        profile_paths,
        default=selected_product_defaults,
        format_func=lambda path: profile_names.get(path, path),
        key="selected_product_paths",
    )
    st.caption(text["product_caption"])
    st.dataframe(profiles, use_container_width=True, hide_index=True)


def render_run(text: Dict[str, Any]) -> None:
    st.title(text["run_title"])
    st.info(text["run_guide"])
    demo_files = list_demo_scenario_files()
    with st.expander(text["demo_scenarios"], expanded=True):
        if demo_files:
            for demo_path in demo_files:
                demo_data = read_json(demo_path)
                metadata = demo_data.get("metadata", {}) if isinstance(demo_data, dict) else {}
                demo = demo_data.get("demo", {}) if isinstance(demo_data, dict) else {}
                st.write(f"**{metadata.get('name', demo_path.stem)}**")
                st.caption(str(metadata.get("description", "")))
                if isinstance(demo, dict) and demo.get("conclusion"):
                    st.write(f"{text['demo_conclusion']}: {demo['conclusion']}")
                st.button(
                    text["apply_demo"],
                    key=f"apply_demo_{demo_path.stem}",
                    on_click=apply_demo_scenario,
                    args=(demo_path,),
                )
            selected_demo_path = st.session_state.get("selected_demo_scenario_path")
            if selected_demo_path:
                st.success(f"{text['demo_applied']}: `{selected_demo_path}`")
        else:
            st.warning(text["no_demo_scenarios"])

    topology_files = list_topology_files()
    selected_topology: Optional[Path] = None
    with st.expander(text["topology_library"], expanded=True):
        st.caption(text["topology_guide"])
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
                format_func=lambda path: display_topology_name(path.stem),
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
                        "from cybermatch.evaluation.runner import run_phase83_benchmark_suite; run_phase83_benchmark_suite()",
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
                format_func=lambda path: display_scenario_name(path.stem),
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

    profiles = load_product_profiles()
    profile_paths = [str(row.get("file", "")) for row in profiles]
    profile_names = {str(row.get("file", "")): str(row.get("name", "")) for row in profiles}
    default_product_paths = normalized_option_selection(
        st.session_state.get("selected_product_paths"),
        profile_paths,
        path_values=True,
    )
    selected_mission_defaults = normalized_option_selection(st.session_state.get("selected_missions"), MISSION_OPTIONS)
    st.session_state["selected_product_paths"] = default_product_paths
    st.session_state["selected_missions"] = selected_mission_defaults
    selected_product_paths = st.multiselect(
        text["comparison_targets"],
        profile_paths,
        default=default_product_paths,
        format_func=lambda path: profile_names.get(path, path),
        key="selected_product_paths",
    )
    selected_missions = st.multiselect(
        text["mission_selection"],
        MISSION_OPTIONS,
        default=selected_mission_defaults,
        key="selected_missions",
    )
    st.caption(text["mission_caption"])

    st.write(text["primary_runner"])
    st.code("scripts/run_phase63.py", language="text")
    st.write(text["output"])
    st.code(str(PHASE63_OUTPUT_DIR.relative_to(ROOT)), language="text")

    run_col, stop_col = st.columns(2)
    with run_col:
        if st.button(text["run_phase63"], type="primary", disabled=runner_is_active()):
            if selected_topology is None:
                st.error(text["select_topology_error"])
                return
            if not selected_missions:
                st.error(text["select_mission_error"])
                return
            if not selected_product_paths:
                st.error(text["select_product_error"])
                return
            selected_demo_seeds = st.session_state.get("selected_demo_seeds")
            command = build_phase63_command(
                selected_topology,
                selected_missions,
                selected_product_paths,
                selected_demo_seeds if isinstance(selected_demo_seeds, list) else None,
            )
            start_runner(
                command,
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
                    "from cybermatch.evaluation.runner import run_phase62_product_profile_evaluation; run_phase62_product_profile_evaluation()",
                ],
                PHASE62_LOG_PATH,
                "phase62_done",
            )
            st.rerun()


def render_results(text: Dict[str, Any]) -> None:
    st.title(text["results_title"])
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
    manifest = read_json(PHASE63_ARTIFACTS["manifest"])
    run_summary = build_user_run_summary(manifest, summary_cards)
    rows_by_profile = {
        str(row.get("profile_id", "")): row
        for row in non_baseline_rows(rows)
        if row.get("profile_id")
    }

    st.subheader(text["run_summary_title"])
    st.caption(text["run_summary_intro"])
    condition_col, arrow_one, target_col, arrow_two, result_col = st.columns([4, 1, 4, 1, 4])
    with condition_col:
        st.info(
            f"**{text['summary_environment']}**\n\n{run_summary['topology']}\n\n"
            f"**{text['summary_missions']}**\n\n"
            f"{'、'.join(display_mission_name(mission) for mission in run_summary['missions']) or '未記録'}"
        )
    with arrow_one:
        st.markdown("### →")
    with target_col:
        product_labels = [display_product_name(rows_by_profile[profile_id]) for profile_id in run_summary["product_ids"] if profile_id in rows_by_profile]
        st.info(
            f"**{text['summary_products']}**\n\n"
            f"{'、'.join(product_labels) or '未記録'}\n\n"
            f"**{text['summary_seed']}**\n\n{run_summary['seeds'] or '未記録'}"
        )
    with arrow_two:
        st.markdown("### →")
    with result_col:
        best_row = rows_by_profile.get(run_summary["best_product_id"], {})
        st.success(
            f"**{text['summary_result']}**\n\n"
            f"{display_product_name(best_row) or run_summary['best_product_id'] or '該当なし'}\n\n"
            f"比較スコア: {run_summary['best_product_score']:.4f}"
        )
    if run_summary["best_product_id"]:
        st.info(
            text["summary_recommendation"].format(
                product=display_product_name(rows_by_profile.get(run_summary["best_product_id"], {}))
                or run_summary["best_product_id"]
            )
        )

    st.subheader(text["decision_conclusion"])
    st.caption(text["decision_conclusion_intro"])
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        best = summary_cards["best_product_overall"]
        st.metric(text["best_product_overall"], best["profile_id"], f"{best['score']:.4f}")
        st.caption(best["name"])
    with col2:
        best_by_mission = summary_cards["best_product_per_mission"]
        st.metric(text["best_product_per_mission"], str(len(set(best_by_mission.values()))))
        st.caption(", ".join(f"{display_mission_name(mission)}: {product}" for mission, product in sorted(best_by_mission.items())))
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
                "攻撃者の目的": display_mission_name(mission),
                "有力候補": display_product_name(rows_by_profile.get(product, {})) or product,
                "比較スコア": round_metric(
                    summary_cards["best_product_per_mission_scores"].get(mission, 0.0)
                ),
            }
            for mission, product in sorted(summary_cards["best_product_per_mission"].items())
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.subheader(text["decision_reason"])
    st.caption(text["decision_reason_intro"])
    for recommendation in build_decision_recommendations(rows):
        driver_label = text[f"decision_driver_{recommendation['driver_key']}"]
        st.write(
            f"**{display_mission_name(recommendation['mission_name'])}**: "
            f"{display_product_name(rows_by_profile.get(recommendation['profile_id'], {}))} — "
            f"比較スコア `{recommendation['mission_effectiveness']:.4f}`、"
            f"{text['decision_primary_driver']}: {driver_label} "
            f"(`{recommendation['driver_value']:+.4f}`)"
        )

    st.subheader(text["decision_comparison"])
    st.caption(text["decision_comparison_intro"])
    pivot_rows = build_product_mission_pivot(rows)
    st.dataframe(pivot_rows, use_container_width=True, hide_index=True)

    with st.expander(text["product_mission_chart"], expanded=False):
        st.caption(text["heatmap_help"])
        if PHASE63_ARTIFACTS["heatmap"].exists():
            st.image(str(PHASE63_ARTIFACTS["heatmap"]))
        else:
            st.warning(f"mission_product_heatmap.png {text['not_found']}")

    st.subheader(text["decision_constraints"])
    st.warning(text["decision_constraints_text"])
    st.info(text["interpretation_notice"])
    if isinstance(manifest, dict):
        st.caption(text["run_conditions"])
        st.dataframe(
            [
                {"項目": text["summary_environment"], "設定内容": run_summary["topology"]},
                {"項目": text["summary_missions"], "設定内容": "、".join(display_mission_name(mission) for mission in run_summary["missions"])},
                {"項目": text["summary_products"], "設定内容": "、".join(run_summary["product_ids"])},
                {"項目": text["summary_seed"], "設定内容": run_summary["seeds"]},
            ],
            use_container_width=True,
            hide_index=True,
        )

    st.subheader(text["advanced_analysis"])
    st.info(text["results_intro"])
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
        st.markdown(localize_report_markdown(report, PHASE63_ARTIFACTS["report"].name, text["report_locale"]))
    else:
        st.warning(f"PHASE63_MISSION_PRODUCT_REPORT.md {text['not_found']}")

    with st.expander(text["json_summary"]):
        if summary_json is None:
            st.warning(f"mission_product_summary.json {text['not_found']}")
        else:
            st.json(summary_json)

    st.subheader(text["downloads"])
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        render_download(PHASE63_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
    with col2:
        render_download(PHASE63_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
    with col3:
        render_download(PHASE63_ARTIFACTS["report"], text["download_md"], "text/markdown", text)
    with col4:
        render_download(PHASE63_ARTIFACTS["manifest"], text["run_manifest"], "application/json", text)

    st.subheader(text["phase90_intent_inference"])
    st.caption(text["phase90_help"])
    if not PHASE90_ARTIFACTS["summary_csv"].exists():
        st.warning(text["phase90_missing"])
        st.code(str(PHASE90_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase90_rows = read_csv_rows(PHASE90_ARTIFACTS["summary_csv"])
        phase90_json = read_json(PHASE90_ARTIFACTS["summary_json"])
        phase90_analysis = phase90_json.get("analysis", {}) if isinstance(phase90_json, dict) else {}
        first_row = phase90_rows[0] if phase90_rows else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(text["true_mission"], str(first_row.get("true_mission", "")))
        with col2:
            st.metric(text["inferred_mission"], str(first_row.get("inferred_mission", "")))
        with col3:
            st.metric("推定の確からしさ", str(first_row.get("mission_confidence", "")))
        with col4:
            st.metric(text["accuracy"], str(phase90_analysis.get("mission_inference_accuracy", "")))
        st.dataframe(phase90_rows, use_container_width=True, hide_index=True)
        for key in ("confusion_matrix", "accuracy", "confidence"):
            if PHASE90_ARTIFACTS[key].exists():
                st.image(str(PHASE90_ARTIFACTS[key]))
        phase90_report = read_text(PHASE90_ARTIFACTS["report"])
        if phase90_report:
            st.markdown(localize_report_markdown(phase90_report, PHASE90_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE90_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE90_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE90_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase91_behavior_profiles"])
    st.caption(text["phase91_help"])
    if not PHASE91_ARTIFACTS["summary_csv"].exists():
        st.warning(text["phase91_missing"])
        st.code(str(PHASE91_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase91_rows = read_csv_rows(PHASE91_ARTIFACTS["summary_csv"])
        phase91_json = read_json(PHASE91_ARTIFACTS["summary_json"])
        phase91_analysis = phase91_json.get("analysis", {}) if isinstance(phase91_json, dict) else {}
        first_row = phase91_rows[0] if phase91_rows else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(text["true_mission"], str(first_row.get("true_mission", "")))
        with col2:
            st.metric(text["behavior_profile"], str(first_row.get("behavior_profile", "")))
        with col3:
            st.metric(text["profile_confidence"], str(first_row.get("profile_confidence", "")))
        with col4:
            st.metric("行動傾向のばらつき", str(phase91_analysis.get("mean_profile_entropy", "")))
        st.dataframe(phase91_rows, use_container_width=True, hide_index=True)
        for key in ("distribution", "confidence", "relationship"):
            if PHASE91_ARTIFACTS[key].exists():
                st.image(str(PHASE91_ARTIFACTS[key]))
        phase91_report = read_text(PHASE91_ARTIFACTS["report"])
        if phase91_report:
            st.markdown(localize_report_markdown(phase91_report, PHASE91_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE91_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE91_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE91_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase92_feature_space"])
    st.caption(text["phase92_help"])
    if not PHASE92_ARTIFACTS["summary_csv"].exists():
        st.warning(text["phase92_missing"])
        st.code(str(PHASE92_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase92_rows = read_csv_rows(PHASE92_ARTIFACTS["summary_csv"])
        phase92_json = read_json(PHASE92_ARTIFACTS["summary_json"])
        phase92_analysis = phase92_json.get("analysis", {}) if isinstance(phase92_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(text["dominant_feature"], str(phase92_analysis.get("dominant_feature", "")))
        with col2:
            st.metric(text["critical_path_bias"], str(phase92_analysis.get("critical_path_bias_score", "")))
        with col3:
            st.metric("目的ごとの特徴の分かれやすさ", str(phase92_analysis.get("mission_feature_separability", "")))
        with col4:
            st.metric("行動傾向ごとの分かれやすさ", str(phase92_analysis.get("profile_feature_separability", "")))
        st.dataframe(phase92_rows, use_container_width=True, hide_index=True)
        for key in ("dominance", "mission_heatmap", "critical_path_bias"):
            if PHASE92_ARTIFACTS[key].exists():
                st.image(str(PHASE92_ARTIFACTS[key]))
        phase92_report = read_text(PHASE92_ARTIFACTS["report"])
        if phase92_report:
            st.markdown(localize_report_markdown(phase92_report, PHASE92_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE92_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE92_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE92_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase93_profilecore"])
    st.caption(text["phase93_help"])
    if not PHASE93_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase93_missing"])
        st.code(str(PHASE93_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase93_rows = read_csv_rows(PHASE93_ARTIFACTS["summary_csv"])
        phase93_json = read_json(PHASE93_ARTIFACTS["summary_json"])
        phase93_analysis = phase93_json.get("analysis", {}) if isinstance(phase93_json, dict) else {}
        distribution = phase93_analysis.get("archetype_distribution", {})
        variance = phase93_analysis.get("pca_explained_variance", [])
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("主な分析軸", str(phase93_analysis.get("dominant_component", "")))
        with col2:
            st.metric("攻撃者タイプ数", str(phase93_analysis.get("archetype_count", "")))
        with col3:
            st.metric("攻撃者タイプのばらつき", str(phase93_analysis.get("archetype_entropy", "")))
        with col4:
            first_variance = variance[0] if isinstance(variance, list) and variance else ""
            st.metric("主な分析軸の説明力", str(first_variance))
        if isinstance(distribution, dict):
            st.dataframe(
                [{"archetype": key, "rows": value} for key, value in sorted(distribution.items())],
                use_container_width=True,
                hide_index=True,
            )
        st.dataframe(phase93_rows, use_container_width=True, hide_index=True)
        for key in ("pca_variance", "component_loadings", "feature_projection", "archetype_distribution"):
            if PHASE93_ARTIFACTS[key].exists():
                st.image(str(PHASE93_ARTIFACTS[key]))
        phase93_report = read_text(PHASE93_ARTIFACTS["report"])
        if phase93_report:
            st.markdown(localize_report_markdown(phase93_report, PHASE93_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE93_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE93_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE93_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase94_archetype"])
    st.caption(text["phase94_help"])
    if not PHASE94_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase94_missing"])
        st.code(str(PHASE94_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase94_rows = read_csv_rows(PHASE94_ARTIFACTS["summary_csv"])
        phase94_json = read_json(PHASE94_ARTIFACTS["summary_json"])
        phase94_analysis = phase94_json.get("analysis", {}) if isinstance(phase94_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        distance = phase94_analysis.get("archetype_feature_distance", {})
        distance_values = []
        if isinstance(distance, dict):
            for left, row in distance.items():
                if isinstance(row, dict):
                    for right, value in row.items():
                        if str(left) < str(right):
                            try:
                                distance_values.append(float(value))
                            except (TypeError, ValueError):
                                pass
        mean_distance = sum(distance_values) / len(distance_values) if distance_values else 0.0
        with col1:
            st.metric("攻撃者タイプ数", str(phase94_analysis.get("archetype_count", "")))
        with col2:
            st.metric("タイプ間の特徴差", f"{mean_distance:.3f}")
        with col3:
            st.metric("目的の重なり", str(phase94_analysis.get("archetype_mission_overlap", "")))
        with col4:
            st.metric("解釈しやすさ", str(phase94_analysis.get("archetype_interpretability_score", "")))
        st.markdown(f"**{text['archetype_summary']}**" if "archetype_summary" in text else "**Archetype Summary**")
        st.dataframe(phase94_rows, use_container_width=True, hide_index=True)
        signature = phase94_analysis.get("archetype_signature", {})
        if isinstance(signature, dict):
            st.markdown(f"**{text['archetype_signature']}**")
            st.dataframe(
                [{"archetype": key, "signature": "; ".join(value) if isinstance(value, list) else str(value)} for key, value in sorted(signature.items())],
                use_container_width=True,
                hide_index=True,
            )
        st.markdown(f"**{text['feature_comparison']}**")
        for key in ("feature_comparison", "distance_matrix"):
            if PHASE94_ARTIFACTS[key].exists():
                st.image(str(PHASE94_ARTIFACTS[key]))
        st.markdown(f"**{text['mission_relationship']}**")
        for key in ("mission_distribution", "profile_distribution"):
            if PHASE94_ARTIFACTS[key].exists():
                st.image(str(PHASE94_ARTIFACTS[key]))
        phase94_report = read_text(PHASE94_ARTIFACTS["report"])
        if phase94_report:
            st.markdown(localize_report_markdown(phase94_report, PHASE94_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE94_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE94_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE94_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase95_strategy"])
    st.caption(text["phase95_help"])
    if not PHASE95_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase95_missing"])
        st.code(str(PHASE95_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase95_rows = read_csv_rows(PHASE95_ARTIFACTS["summary_csv"])
        phase95_json = read_json(PHASE95_ARTIFACTS["summary_json"])
        phase95_analysis = phase95_json.get("analysis", {}) if isinstance(phase95_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(text["strategy"], str(phase95_analysis.get("strategy_distribution", ""))[:80])
        with col2:
            confidence_values = []
            for row in phase95_rows:
                try:
                    confidence_values.append(float(row.get("strategy_confidence", 0.0)))
                except (TypeError, ValueError):
                    pass
            mean_confidence = sum(confidence_values) / len(confidence_values) if confidence_values else 0.0
            st.metric(text["strategy_confidence"], f"{mean_confidence:.3f}")
        with col3:
            st.metric("戦略のばらつき", str(phase95_analysis.get("strategy_entropy", "")))
        with col4:
            st.metric("戦略の一致率", str(phase95_analysis.get("strategy_match_rate", "")))
        st.dataframe(phase95_rows, use_container_width=True, hide_index=True)
        if PHASE95_ARTIFACTS["strategy_distribution"].exists():
            st.image(str(PHASE95_ARTIFACTS["strategy_distribution"]))
        st.markdown(f"**{text['mission_relationship']}**")
        if PHASE95_ARTIFACTS["mission_strategy_matrix"].exists():
            st.image(str(PHASE95_ARTIFACTS["mission_strategy_matrix"]))
        st.markdown(f"**{text['archetype_relationship']}**")
        for key in ("strategy_archetype_matrix", "strategy_profile_matrix"):
            if PHASE95_ARTIFACTS[key].exists():
                st.image(str(PHASE95_ARTIFACTS[key]))
        phase95_report = read_text(PHASE95_ARTIFACTS["report"])
        if phase95_report:
            st.markdown(localize_report_markdown(phase95_report, PHASE95_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE95_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE95_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE95_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase96_taxonomy"])
    st.caption(text["phase96_help"])
    if not PHASE96_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase96_missing"])
        st.code(str(PHASE96_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase96_rows = read_csv_rows(PHASE96_ARTIFACTS["summary_csv"])
        phase96_json = read_json(PHASE96_ARTIFACTS["summary_json"])
        phase96_analysis = phase96_json.get("analysis", {}) if isinstance(phase96_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("意図の種類数", str(phase96_analysis.get("intent_count", "")))
        with col2:
            st.metric("攻撃者目的数", str(phase96_analysis.get("mission_count", "")))
        with col3:
            st.metric("攻撃対象数", str(phase96_analysis.get("target_count", "")))
        with col4:
            st.metric("関係定義の充足度", str(phase96_analysis.get("taxonomy_completeness", "")))
        st.markdown(f"**{text['taxonomy_explorer']}**")
        st.dataframe(phase96_rows, use_container_width=True, hide_index=True)
        st.markdown(f"**{text['mission_relationship']}**")
        for key in ("intent_mission_matrix", "mission_target_matrix"):
            if PHASE96_ARTIFACTS[key].exists():
                st.image(str(PHASE96_ARTIFACTS[key]))
        st.markdown(f"**{text['target_relationship']}**")
        if PHASE96_ARTIFACTS["target_strategy_matrix"].exists():
            st.image(str(PHASE96_ARTIFACTS["target_strategy_matrix"]))
        phase96_report = read_text(PHASE96_ARTIFACTS["report"])
        if phase96_report:
            st.markdown(localize_report_markdown(phase96_report, PHASE96_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE96_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE96_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE96_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase97_target_strategy"])
    st.caption(text["phase97_help"])
    if not PHASE97_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase97_missing"])
        st.code(str(PHASE97_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase97_json = read_json(PHASE97_ARTIFACTS["summary_json"])
        phase97_rows = phase97_json.get("rows", []) if isinstance(phase97_json, dict) else []
        phase97_analysis = phase97_json.get("analysis", {}) if isinstance(phase97_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(text["strategy"], str(phase97_analysis.get("strategy_distribution", ""))[:80])
        with col2:
            st.metric("戦略の多様性", str(phase97_analysis.get("strategy_diversity", "")))
        with col3:
            st.metric("対象への特化度", str(phase97_analysis.get("target_specificity_score", "")))
        with col4:
            st.metric(text["alignment_score"], str(phase97_analysis.get("strategy_target_alignment", "")))
        st.dataframe(phase97_rows, use_container_width=True, hide_index=True)
        st.markdown(f"**{text['target_strategy_mapping']}**")
        for key in ("target_strategy_matrix", "strategy_distribution", "strategy_diversity", "target_specificity", "strategy_alignment"):
            if PHASE97_ARTIFACTS[key].exists():
                st.image(str(PHASE97_ARTIFACTS[key]))
        phase97_report = read_text(PHASE97_ARTIFACTS["report"])
        if phase97_report:
            st.markdown(localize_report_markdown(phase97_report, PHASE97_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2 = st.columns(2)
        with col1:
            render_download(PHASE97_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col2:
            render_download(PHASE97_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase98_strategy_validation"])
    st.caption(text["phase98_help"])
    if not PHASE98_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase98_missing"])
        st.code(str(PHASE98_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase98_json = read_json(PHASE98_ARTIFACTS["summary_json"])
        phase98_summary = phase98_json.get("strategy_summary", []) if isinstance(phase98_json, dict) else []
        phase98_analysis = phase98_json.get("analysis", {}) if isinstance(phase98_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("検証結果", str(phase98_analysis.get("strategy_validation_pass", "")))
        with col2:
            st.metric(text["distinctiveness"], str(phase98_analysis.get("strategy_distinctiveness", "")))
        with col3:
            st.metric(text["redundancy"], str(phase98_analysis.get("strategy_redundancy", "")))
        with col4:
            st.metric(text["explainability"], str(phase98_analysis.get("strategy_explainability", "")))
        st.dataframe(phase98_summary, use_container_width=True, hide_index=True)
        for key in ("distance_matrix", "distinctiveness", "redundancy", "target_validation", "mission_explainability"):
            if PHASE98_ARTIFACTS[key].exists():
                st.image(str(PHASE98_ARTIFACTS[key]))
        phase98_report = read_text(PHASE98_ARTIFACTS["report"])
        if phase98_report:
            st.markdown(localize_report_markdown(phase98_report, PHASE98_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE98_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE98_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE98_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase99_decision_graph"])
    st.caption(text["phase99_help"])
    if not PHASE99_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase99_missing"])
        st.code(str(PHASE99_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase99_json = read_json(PHASE99_ARTIFACTS["summary_json"])
        phase99_rows = phase99_json.get("rows", []) if isinstance(phase99_json, dict) else []
        phase99_analysis = phase99_json.get("analysis", {}) if isinstance(phase99_json, dict) else {}
        phase99_nodes = phase99_json.get("nodes", {}) if isinstance(phase99_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("経路モデルの検証結果", str(phase99_analysis.get("graph_valid", "")))
        with col2:
            st.metric("判断要素数", str(phase99_analysis.get("decision_graph_nodes", "")))
        with col3:
            st.metric("関係数", str(phase99_analysis.get("decision_graph_edges", "")))
        with col4:
            st.metric("経路数", str(phase99_analysis.get("decision_path_count", "")))
        if PHASE99_ARTIFACTS["decision_graph"].exists():
            st.image(str(PHASE99_ARTIFACTS["decision_graph"]))
        st.markdown(f"**{text['decision_path_explorer']}**")
        st.dataframe(phase99_rows, use_container_width=True, hide_index=True)
        st.markdown(f"**{text['node_explorer']}**")
        node_rows = [{"layer": layer, "nodes": ", ".join(nodes) if isinstance(nodes, list) else str(nodes)} for layer, nodes in phase99_nodes.items()]
        st.dataframe(node_rows, use_container_width=True, hide_index=True)
        for key in ("intent_mission", "mission_target", "target_strategy", "strategy_behavior"):
            if PHASE99_ARTIFACTS[key].exists():
                st.image(str(PHASE99_ARTIFACTS[key]))
        phase99_report = read_text(PHASE99_ARTIFACTS["report"])
        if phase99_report:
            st.markdown(localize_report_markdown(phase99_report, PHASE99_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE99_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE99_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE99_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

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
        st.markdown(localize_report_markdown(benchmark_report, PHASE83_ARTIFACTS["report"].name, text["report_locale"]))
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
                "from cybermatch.evaluation.runner import run_phase85_standard_benchmark; run_phase85_standard_benchmark()",
            ],
            PHASE85_LOG_PATH,
            "phase85_done",
        )
        st.rerun()
    render_runner_status(text)

    st.subheader("横断ベンチマーク比較の結果")
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
        st.markdown(localize_report_markdown(report, PHASE85_ARTIFACTS["report"].name, text["report_locale"]))


def _hunting_labels(locale: str) -> Dict[str, str]:
    if locale == "ja":
        return {
            "title": "脅威ハンティング",
            "intro": "観測可能なテレメトリだけを共通レシピで分析し、製品能力・ノイズ・攻撃目的ごとの検出品質を比較します。Findingは防御policyへ自動反映されません。",
            "benchmark": "ハンティング・ベンチマーク",
            "run": "smoke benchmarkを実行",
            "immutable": "既存結果を保護するため、同じ出力先は上書きしません。再実行する場合は既存出力を退避してください。",
            "missing": "結果がありません。smoke benchmarkを実行してください。",
            "wizard": "レシピ選択とパラメータ",
            "focus": "調査したい仮説",
            "recipe": "ハンティングレシピ",
            "pipeline": "分析パイプライン",
            "overrides": "recipe override（manifestへ保存）",
            "experiment": "選択した履歴でパラメータ実験を実行",
            "history": "入力履歴",
            "product": "製品プロファイル",
            "results": "評価結果",
            "data_summary": "データ概要",
            "metrics": "評価指標",
            "findings": "Finding一覧",
            "timeline": "根拠イベントのタイムライン",
            "heatmap": "Mission × Product × Recipe ヒートマップ",
            "distribution": "製品別F1分布",
            "bubble": "検出品質とアナリスト負荷",
            "downloads": "再現用artifactのダウンロード",
            "done": "脅威ハンティング実行が完了しました。",
        }
    return {
        "title": "Threat Hunting",
        "intro": "Analyze defender-observable telemetry with shared recipes and compare detection quality across products, noise profiles, and missions. Findings are not fed back into defender policy.",
        "benchmark": "Hunting benchmark",
        "run": "Run smoke benchmark",
        "immutable": "Existing outputs are immutable. Move the current output before running the same benchmark again.",
        "missing": "No results found. Run the smoke benchmark first.",
        "wizard": "Recipe and parameters",
        "focus": "Investigation hypothesis",
        "recipe": "Hunting recipe",
        "pipeline": "Analysis pipeline",
        "overrides": "Recipe overrides (saved to manifest)",
        "experiment": "Run parameter experiment on selected history",
        "history": "Input history",
        "product": "Product profile",
        "results": "Evaluation results",
        "data_summary": "Data summary",
        "metrics": "Evaluation metrics",
        "findings": "Findings",
        "timeline": "Evidence timeline",
        "heatmap": "Mission × Product × Recipe heatmap",
        "distribution": "F1 distribution by product",
        "bubble": "Detection quality and analyst burden",
        "downloads": "Download reproducibility artifacts",
        "done": "Threat-hunting run completed.",
    }


def _render_hunting_artifact(artifact_dir: Path, labels: Dict[str, str]) -> None:
    from cybermatch_core.threat_hunting import (
        load_threat_hunting_artifacts,
        load_threat_hunting_report,
    )

    try:
        artifacts = load_threat_hunting_artifacts(artifact_dir)
        report = load_threat_hunting_report(artifact_dir)
    except ValueError as exc:
        st.error(str(exc))
        return
    events = [event.to_dict() for event in artifacts.events]
    findings = [finding.to_dict() for finding in artifacts.findings]
    metrics = dict(report.evaluation.metrics)
    model_reference = artifacts.manifest.get("model_manifest")
    model_path = None
    model_payload = None
    replay_manifest_path = artifact_dir.parent / "replay_manifest.json"
    replay_manifest = read_json(replay_manifest_path) if replay_manifest_path.is_file() else None
    if isinstance(model_reference, dict) and model_reference.get("path") == "models/model_manifest.json":
        model_path = artifact_dir / "models" / "model_manifest.json"
        model_payload = read_json(model_path)

    st.subheader(labels["data_summary"])
    provenance_rows = build_evidence_class_summary(replay_manifest)
    if provenance_rows:
        st.info(
            "Evidence classification is explicit: synthetic-only, replay-backed, and "
            "external-sut-backed results are not interchangeable."
        )
        st.dataframe(provenance_rows, use_container_width=True, hide_index=True)
    event_cards = st.columns(4)
    event_cards[0].metric("Events", len(events))
    event_cards[1].metric("Event types", len({event["event_type"] for event in events}))
    event_cards[2].metric("Signal classes", len({event["signal_class"] for event in events}))
    event_cards[3].metric("Steps", report.evaluation.total_steps)
    st.dataframe(build_hunting_event_summary(events), use_container_width=True, hide_index=True)

    st.subheader(labels["metrics"])
    metric_cards = st.columns(5)
    metric_cards[0].metric("Precision", round_metric(metrics.get("precision")))
    metric_cards[1].metric("Recall", round_metric(metrics.get("recall")))
    metric_cards[2].metric("F1", round_metric(metrics.get("f1")))
    metric_cards[3].metric("Findings", int(to_float(metrics.get("finding_count"))))
    metric_cards[4].metric(
        "FP / 100 steps", round_metric(metrics.get("false_positives_per_100_steps"))
    )
    with st.expander("All metrics"):
        st.dataframe(
            [{"metric": key, "value": value} for key, value in sorted(metrics.items())],
            use_container_width=True,
            hide_index=True,
        )
    if model_payload is not None:
        st.subheader("Model provenance")
        st.dataframe(build_hunting_model_summary(model_payload), use_container_width=True, hide_index=True)

    st.subheader(labels["findings"])
    if findings:
        st.dataframe(findings, use_container_width=True, hide_index=True)
        finding_ids = [str(finding["finding_id"]) for finding in findings]
        selected_id = st.selectbox("Finding ID", finding_ids, key=f"finding_{artifact_dir.name}")
        selected = next(finding for finding in findings if finding["finding_id"] == selected_id)
        st.subheader(labels["timeline"])
        st.dataframe(
            build_hunting_evidence_timeline(events, list(selected["evidence_event_ids"])),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No findings for this product / recipe / noise combination.")

    with st.expander(labels["downloads"], expanded=False):
        manifest = artifact_dir / "threat_hunting_manifest.json"
        cols = st.columns(4)
        with cols[0]:
            render_download(manifest, "Manifest", "application/json", {"missing": "Missing"})
        with cols[1]:
            render_download(artifact_dir / "findings.csv", "Findings CSV", "text/csv", {"missing": "Missing"})
        with cols[2]:
            render_download(artifact_dir / "metrics.json", "Metrics JSON", "application/json", {"missing": "Missing"})
        with cols[3]:
            render_download(artifact_dir / "THREAT_HUNTING_REPORT.md", "Report", "text/markdown", {"missing": "Missing"})
        if model_path is not None:
            render_download(model_path, "Model manifest", "application/json", {"missing": "Missing"})


def render_hunting(text: Dict[str, Any]) -> None:
    import altair as alt

    locale = str(text.get("report_locale", "en"))
    labels = _hunting_labels(locale)
    st.title(labels["title"])
    st.info(labels["intro"])

    benchmark_files = list_hunting_benchmark_files()
    st.subheader(labels["benchmark"])
    if not benchmark_files:
        st.warning("benchmarks/cybermatch_hunting_v1.json not found")
        return
    selected_benchmark = st.selectbox(
        "Benchmark JSON", benchmark_files, format_func=lambda path: path.name, key="hunting_benchmark"
    )
    render_benchmark_metadata(selected_benchmark, text)
    if HUNTING_BENCHMARK_SUMMARY.exists():
        st.caption(labels["immutable"])
    if st.button(
        labels["run"],
        type="primary",
        disabled=runner_is_active() or HUNTING_BENCHMARK_OUTPUT_DIR.exists(),
    ):
        start_runner(
            [sys.executable, str(ROOT / "scripts" / "run_scenario.py"), str(selected_benchmark)],
            HUNTING_LOG_PATH,
            "hunting_done",
        )
        st.rerun()
    render_runner_status({**text, "hunting_done": labels["done"]})

    st.subheader(labels["wizard"])
    recipe_files = list_hunting_recipe_files()
    focus_options = {
        "ja": ["重要資産への接近", "認証情報からの横移動"],
        "en": ["Critical-asset approach", "Credential-driven lateral movement"],
    }[locale]
    focus = st.selectbox(labels["focus"], focus_options)
    default_recipe = 1 if ("認証" in focus or "Credential" in focus) else 0
    default_recipe = min(default_recipe, max(len(recipe_files) - 1, 0))
    if not recipe_files:
        st.warning("recipes/threat_hunting/*.json not found")
        return
    selected_recipe = st.selectbox(
        labels["recipe"], recipe_files, index=default_recipe, format_func=lambda path: path.stem
    )
    recipe_payload = read_json(selected_recipe)
    if not isinstance(recipe_payload, dict):
        st.error(f"Invalid recipe: {selected_recipe}")
        return
    st.caption(str(recipe_payload.get("hypothesis", "")))
    st.dataframe(build_recipe_operation_rows(recipe_payload), use_container_width=True, hide_index=True)

    overrides: Dict[str, int | float] = {}
    operations = [value for value in recipe_payload.get("operations", []) if isinstance(value, dict)]
    window = next((value for value in operations if value.get("operator") == "window"), None)
    sequence = next((value for value in operations if value.get("operator") == "sequence"), None)
    finding = recipe_payload.get("finding", {})
    condition = finding.get("condition") if isinstance(finding, dict) else None
    parameter_columns = st.columns(3)
    if window is not None:
        overrides["window_size_steps"] = int(
            parameter_columns[0].number_input(
                "Window steps", min_value=1, max_value=1000, value=int(window.get("size_steps", 5))
            )
        )
    if sequence is not None:
        overrides["sequence_max_span_steps"] = int(
            parameter_columns[0].number_input(
                "Sequence span", min_value=1, max_value=1000, value=int(sequence.get("max_span_steps", 8))
            )
        )
    if isinstance(condition, dict) and isinstance(condition.get("value"), (int, float)):
        overrides["finding_threshold"] = float(
            parameter_columns[1].number_input(
                "Finding threshold", min_value=0.0, value=float(condition["value"]), step=0.5
            )
        )
    overrides["finding_score"] = float(
        parameter_columns[2].slider(
            "Finding score", min_value=0.0, max_value=1.0, value=float(finding.get("score", 0.5)), step=0.05
        )
    )
    override_json = json.dumps(overrides, ensure_ascii=False, sort_keys=True)
    st.code(override_json, language="json")
    st.download_button(
        labels["overrides"],
        data=override_json + "\n",
        file_name="recipe_overrides.json",
        mime="application/json",
    )

    history_files = list_hunting_history_files()
    hunting_products = [
        path
        for path in sorted(PRODUCT_PROFILE_DIR.glob("*.json"))
        if isinstance(read_json(path), dict) and "hunting" in read_json(path)
    ]
    if history_files and hunting_products:
        selected_history = st.selectbox(
            labels["history"], history_files, format_func=lambda path: str(path.relative_to(HUNTING_OUTPUT_ROOT))
        )
        selected_product = st.selectbox(
            labels["product"], hunting_products, format_func=lambda path: path.stem, key="hunting_product"
        )
        if st.button(labels["experiment"], disabled=runner_is_active()):
            run_id = f"ui_{int(time.time() * 1000)}"
            output_dir = HUNTING_OUTPUT_ROOT / "ui_runs" / run_id
            config_path = selected_history.with_suffix(".config.json")
            config_payload = read_json(config_path)
            seed = int(config_payload.get("seed", 0)) if isinstance(config_payload, dict) else 0
            command = [
                sys.executable,
                str(ROOT / "scripts" / "run_threat_hunting_evaluation.py"),
                "--history",
                str(selected_history),
                "--recipe",
                str(selected_recipe.relative_to(ROOT)),
                "--output",
                str(output_dir),
                "--scenario-id",
                "gui_parameter_experiment",
                "--campaign-id",
                selected_history.stem,
                "--seed",
                str(seed),
                "--product-profile",
                str(selected_product.relative_to(ROOT)),
                "--recipe-overrides",
                override_json,
            ]
            st.session_state["hunting_ui_artifact"] = str(output_dir)
            start_runner(command, HUNTING_EXPERIMENT_LOG_PATH, "hunting_done")
            st.rerun()

    payload = read_json(HUNTING_BENCHMARK_SUMMARY)
    if not isinstance(payload, dict):
        st.warning(labels["missing"])
        return
    manifest = payload.get("manifest", {})
    rows = payload.get("detail_rows", [])
    if not isinstance(manifest, dict) or not isinstance(rows, list):
        st.error("Invalid hunting benchmark summary")
        return

    st.subheader(labels["results"])
    cards = build_hunting_summary_cards(rows, manifest)
    card_columns = st.columns(5)
    card_columns[0].metric("Matrix", cards["evaluation_matrix_size"])
    card_columns[1].metric("Succeeded", cards["succeeded_cases"])
    card_columns[2].metric("Completeness", cards["completeness"])
    card_columns[3].metric("Findings", cards["finding_count"])
    card_columns[4].metric("Mean F1", cards["mean_f1"])

    heatmap_rows = build_hunting_heatmap_rows(rows)
    st.subheader(labels["heatmap"])
    st.altair_chart(
        alt.Chart(alt.Data(values=heatmap_rows))
        .mark_rect()
        .encode(
            x=alt.X("recipe:N", title="Recipe"),
            y=alt.Y("product:N", title="Product"),
            color=alt.Color("mean_f1:Q", scale=alt.Scale(domain=[0, 1])),
            column=alt.Column("mission:N", title="Mission"),
            tooltip=["mission", "product", "recipe", "mean_f1"],
        ),
        use_container_width=True,
    )
    bubble_rows = build_hunting_bubble_rows(rows)
    chart_columns = st.columns(2)
    with chart_columns[0]:
        st.subheader(labels["distribution"])
        st.altair_chart(
            alt.Chart(alt.Data(values=bubble_rows))
            .mark_boxplot()
            .encode(x=alt.X("product:N", title="Product"), y=alt.Y("f1:Q", title="F1"), color="product:N"),
            use_container_width=True,
        )
    with chart_columns[1]:
        st.subheader(labels["bubble"])
        st.altair_chart(
            alt.Chart(alt.Data(values=bubble_rows))
            .mark_circle(opacity=0.75)
            .encode(
                x=alt.X("false_positives_per_100_steps:Q", title="False positives / 100 steps"),
                y=alt.Y("f1:Q", title="F1"),
                size=alt.Size("finding_count:Q", title="Findings"),
                color=alt.Color("product:N", title="Product"),
                tooltip=["product", "recipe", "noise", "f1", "finding_count"],
            ),
            use_container_width=True,
        )

    succeeded_rows = [row for row in rows if row.get("status") == "succeeded"]
    if succeeded_rows:
        selected_index = st.selectbox(
            "Evaluation case",
            list(range(len(succeeded_rows))),
            format_func=lambda index: " / ".join(
                str(succeeded_rows[index].get(key, ""))
                for key in ("mission_name", "product_profile", "recipe_id", "noise_profile", "seed")
            ),
        )
        artifact_dir = safe_hunting_artifact_dir(succeeded_rows[selected_index].get("artifact_dir"))
        if artifact_dir is not None:
            _render_hunting_artifact(artifact_dir, labels)

    ui_artifact = safe_hunting_artifact_dir(st.session_state.get("hunting_ui_artifact"))
    if ui_artifact is not None and (ui_artifact / "metrics.json").is_file():
        st.divider()
        st.subheader("Latest parameter experiment")
        _render_hunting_artifact(ui_artifact, labels)

    download_columns = st.columns(2)
    with download_columns[0]:
        render_download(HUNTING_BENCHMARK_CSV, "Benchmark CSV", "text/csv", {"missing": "Missing"})
    with download_columns[1]:
        render_download(HUNTING_BENCHMARK_SUMMARY, "Benchmark JSON", "application/json", {"missing": "Missing"})


def main() -> None:
    st.set_page_config(page_title="CyberMatch", layout="wide")
    language = st.sidebar.selectbox("Language / 言語", ["日本語", "English"], index=0)
    text = TEXT[language]
    page = st.sidebar.radio("CyberMatch", text["nav"])
    page_key = text["nav_to_key"][page]
    st.sidebar.caption("CyberMatch Dashboard MVP")
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
    elif page_key == "hunting":
        render_hunting(text)


if __name__ == "__main__":
    main()
