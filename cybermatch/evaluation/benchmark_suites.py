"""Phase8.x benchmark suites extracted from ``cybermatch.evaluation.runner``.

Covers the scenario catalog (8.2), benchmark suite (8.3), topology library
(8.4), and standard benchmark (8.5). ``cybermatch.evaluation.runner`` keeps
re-exporting every name defined here, so existing imports keep working.
"""

from __future__ import annotations

import csv
import json
import os
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt
import numpy as np

from cybermatch.evaluation.statistics import to_float as _to_float
from cybermatch.evaluation.runner import (
    _report_mission_label,
    _report_product_label,
    run_phase63_mission_aware_product_evaluation,
)


PHASE82_SCENARIO_CATALOG_COLUMNS = [
    "scenario_name",
    "industry",
    "scenario_complexity",
    "critical_asset_count",
    "identity_dependency",
    "operational_sensitivity",
    "deception_effectiveness",
    "product_profile",
    "product_category",
    "mission_name",
    "base_mission_effectiveness",
    "scenario_adjusted_effectiveness",
]


PHASE82_LEVEL_VALUES = {
    "low": 1.0,
    "medium": 2.0,
    "high": 3.0,
}


def _phase82_level_value(value: object) -> float:
    return PHASE82_LEVEL_VALUES.get(str(value), 2.0)


def _phase82_scenario_complexity(characteristics: Dict[str, object]) -> float:
    critical_component = _to_float(characteristics.get("critical_asset_count")) / 5.0
    identity_component = _phase82_level_value(characteristics.get("identity_dependency")) / 3.0
    operational_component = _phase82_level_value(characteristics.get("operational_sensitivity")) / 3.0
    return float(np.mean([critical_component, identity_component, operational_component]))


def _phase82_adjustment_factor(
    characteristics: Dict[str, object],
    mission_name: str,
    product_category: str,
) -> float:
    complexity = _phase82_scenario_complexity(characteristics)
    identity = _phase82_level_value(characteristics.get("identity_dependency")) - 2.0
    operational = _phase82_level_value(characteristics.get("operational_sensitivity")) - 2.0
    deception = _phase82_level_value(characteristics.get("deception_effectiveness")) - 2.0
    critical = _to_float(characteristics.get("critical_asset_count")) - 3.0

    factor = 1.0 + 0.08 * (complexity - 0.6)
    if mission_name == "profit":
        factor += 0.03 * identity
    elif mission_name == "achievement":
        factor += 0.025 * operational
    elif mission_name == "persistence":
        factor += 0.03 * identity
    elif mission_name == "critical_hunter":
        factor += 0.025 * critical

    if product_category == "deception":
        factor += 0.05 * deception
    elif product_category == "xdr":
        factor += 0.03 * identity
    elif product_category == "ips":
        factor += 0.025 * operational
    elif product_category == "honeypot":
        factor += 0.02 * critical
    elif product_category == "ids":
        factor += 0.02 * identity

    return max(0.5, min(1.5, factor))


def _phase82_load_phase63_rows() -> List[Dict[str, object]]:
    summary_path = os.path.join("output", "phase63_mission_products", "mission_product_summary.json")
    if not os.path.exists(summary_path):
        return run_phase63_mission_aware_product_evaluation(seeds=[0])
    with open(summary_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return list(data.get("rows", []))


def _phase82_build_rows(scenarios: List[Dict[str, object]], phase63_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    base_rows = [row for row in phase63_rows if row.get("profile_id") != "baseline"]
    for scenario in scenarios:
        metadata = scenario.get("metadata", {})
        characteristics = scenario.get("characteristics", {})
        scenario_name = str(metadata.get("name", ""))
        industry = str(metadata.get("industry", ""))
        complexity = _phase82_scenario_complexity(characteristics)
        for base_row in base_rows:
            product_category = str(base_row.get("product_category", ""))
            mission_name = str(base_row.get("mission_name", ""))
            base_score = _to_float(base_row.get("mission_effectiveness"))
            adjusted = base_score * _phase82_adjustment_factor(characteristics, mission_name, product_category)
            rows.append(
                {
                    "scenario_name": scenario_name,
                    "industry": industry,
                    "scenario_complexity": round(complexity, 4),
                    "critical_asset_count": characteristics.get("critical_asset_count"),
                    "identity_dependency": characteristics.get("identity_dependency"),
                    "operational_sensitivity": characteristics.get("operational_sensitivity"),
                    "deception_effectiveness": characteristics.get("deception_effectiveness"),
                    "product_profile": base_row.get("profile_id"),
                    "product_category": product_category,
                    "mission_name": mission_name,
                    "base_mission_effectiveness": round(base_score, 6),
                    "scenario_adjusted_effectiveness": round(adjusted, 6),
                }
            )
    return rows


def _phase82_matrix(
    rows: List[Dict[str, object]],
    row_key: str,
    column_key: str,
    value_key: str = "scenario_adjusted_effectiveness",
) -> Tuple[List[str], List[str], np.ndarray]:
    row_labels = sorted({str(row.get(row_key)) for row in rows})
    column_labels = sorted({str(row.get(column_key)) for row in rows})
    grid = np.zeros((len(row_labels), len(column_labels)), dtype=float)
    for i, row_label in enumerate(row_labels):
        for j, column_label in enumerate(column_labels):
            values = [
                _to_float(row.get(value_key))
                for row in rows
                if str(row.get(row_key)) == row_label and str(row.get(column_key)) == column_label
            ]
            grid[i, j] = float(np.mean(values)) if values else 0.0
    return row_labels, column_labels, grid


def _plot_phase82_heatmap(
    rows: List[Dict[str, object]],
    row_key: str,
    column_key: str,
    title: str,
    save_path: str,
) -> None:
    row_labels, column_labels, grid = _phase82_matrix(rows, row_key, column_key)
    fig, ax = plt.subplots(figsize=(11, 6))
    image = ax.imshow(grid, cmap="viridis", aspect="auto", vmin=0.0, vmax=max(1.0, float(np.max(grid)) if grid.size else 1.0))
    ax.set_title(title)
    ax.set_xticks(np.arange(len(column_labels)))
    ax.set_xticklabels(column_labels, rotation=25, ha="right")
    ax.set_yticks(np.arange(len(row_labels)))
    ax.set_yticklabels(row_labels)
    fig.colorbar(image, ax=ax, label="scenario_adjusted_effectiveness")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _phase82_analysis(rows: List[Dict[str, object]]) -> Dict[str, object]:
    scenario_names = sorted({str(row.get("scenario_name")) for row in rows})
    scenario_scores = {
        scenario_name: float(np.mean([_to_float(row.get("scenario_adjusted_effectiveness")) for row in rows if row.get("scenario_name") == scenario_name]))
        for scenario_name in scenario_names
    }
    product_winners = {}
    mission_winners = {}
    for scenario_name in scenario_names:
        scenario_rows = [row for row in rows if row.get("scenario_name") == scenario_name]
        products = sorted({str(row.get("product_profile")) for row in scenario_rows})
        missions = sorted({str(row.get("mission_name")) for row in scenario_rows})
        product_scores = {
            product: float(np.mean([_to_float(row.get("scenario_adjusted_effectiveness")) for row in scenario_rows if row.get("product_profile") == product]))
            for product in products
        }
        mission_scores = {
            mission: float(np.mean([_to_float(row.get("scenario_adjusted_effectiveness")) for row in scenario_rows if row.get("mission_name") == mission]))
            for mission in missions
        }
        product_winners[scenario_name] = max(product_scores, key=product_scores.get) if product_scores else ""
        mission_winners[scenario_name] = max(mission_scores, key=mission_scores.get) if mission_scores else ""
    return {
        "scenario_scores": scenario_scores,
        "best_product_by_scenario": product_winners,
        "best_mission_coverage_by_scenario": mission_winners,
        "scenario_differences_observed": len({round(score, 6) for score in scenario_scores.values()}) > 1,
    }


def _write_phase82_outputs(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "scenario_catalog_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE82_SCENARIO_CATALOG_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE82_SCENARIO_CATALOG_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "scenario_catalog_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)
    _plot_phase82_heatmap(rows, "scenario_name", "industry", "Scenario Catalog Comparison", os.path.join(output_dir, "scenario_comparison_heatmap.png"))
    _plot_phase82_heatmap(rows, "scenario_name", "mission_name", "Scenario x Mission Matrix", os.path.join(output_dir, "scenario_mission_matrix.png"))
    _plot_phase82_heatmap(rows, "scenario_name", "product_profile", "Scenario x Product Matrix", os.path.join(output_dir, "scenario_product_matrix.png"))
    _write_phase82_report(rows, analysis, output_dir)


def _write_phase82_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    scenario_names = sorted({str(row.get("scenario_name")) for row in rows})
    lines = [
        "# Phase8.2 Scenario Catalog Evaluation Report",
        "",
        "## Research Question",
        "Scenarioの違いによって Product評価結果やMission評価結果は変化するか？",
        "",
        "## Interpretation Boundary",
        "Phase8.2 uses scenario characteristics as a lightweight interpretation layer over existing Phase6.3 mission-aware product results. It does not add simulation logic, attackers, defenders, RL, LLMs, external APIs, or real product integration.",
        "",
        "## Scenario Summary",
        "| scenario | industry | complexity | best_product | best_mission_coverage | mean_score |",
        "|---|---|---:|---|---|---:|",
    ]
    for scenario_name in scenario_names:
        first = next(row for row in rows if row.get("scenario_name") == scenario_name)
        lines.append(
            f"| {scenario_name} | {first.get('industry')} | {_to_float(first.get('scenario_complexity')):.3f} | "
            f"{analysis.get('best_product_by_scenario', {}).get(scenario_name)} | "
            f"{analysis.get('best_mission_coverage_by_scenario', {}).get(scenario_name)} | "
            f"{_to_float(analysis.get('scenario_scores', {}).get(scenario_name)):.3f} |"
        )
    lines.extend(
        [
            "",
            "## Validation",
            f"- Scenario differences observed: `{analysis.get('scenario_differences_observed')}`.",
            "",
            "## Output Artifacts",
            "- `scenario_catalog_summary.csv`",
            "- `scenario_catalog_summary.json`",
            "- `scenario_comparison_heatmap.png`",
            "- `scenario_mission_matrix.png`",
            "- `scenario_product_matrix.png`",
        ]
    )
    with open(os.path.join(output_dir, "PHASE82_SCENARIO_CATALOG_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run_phase82_scenario_catalog_evaluation(
    output_dir: str = os.path.join("output", "phase82_scenario_catalog"),
    catalog_dir: str = os.path.join("scenarios", "catalog"),
) -> List[Dict[str, object]]:
    from cybermatch.loaders.scenario_loader import load_scenario_catalog

    scenarios = load_scenario_catalog(catalog_dir)
    phase63_rows = _phase82_load_phase63_rows()
    rows = _phase82_build_rows(scenarios, phase63_rows)
    analysis = _phase82_analysis(rows)
    _write_phase82_outputs(rows, analysis, output_dir)
    return rows


PHASE83_BENCHMARK_SUMMARY_COLUMNS = [
    "benchmark_name",
    "product_profile",
    "benchmark_score",
    "benchmark_rank",
    "scenario_coverage",
    "mission_coverage",
    "product_coverage",
    "consistency_score",
    "variance_score",
]


def _phase83_product_id_from_path(path_value: str) -> str:
    return os.path.splitext(os.path.basename(path_value))[0]


def _phase83_benchmark_rows(config: Dict[str, object]) -> List[Dict[str, object]]:
    from cybermatch.loaders.scenario_loader import load_scenario

    scenarios = [load_scenario(str(path)) for path in config.get("scenarios", [])]
    scenario_names = {str(scenario.get("metadata", {}).get("name")) for scenario in scenarios}
    mission_names = {str(mission) for mission in config.get("missions", [])}
    product_ids = {_phase83_product_id_from_path(str(path)) for path in config.get("products", [])}
    phase63_rows = _phase82_load_phase63_rows()
    rows = _phase82_build_rows(scenarios, phase63_rows)
    return [
        row
        for row in rows
        if row.get("scenario_name") in scenario_names
        and row.get("mission_name") in mission_names
        and row.get("product_profile") in product_ids
    ]


def _phase83_summary_rows(config: Dict[str, object], detail_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    benchmark_name = str(config.get("metadata", {}).get("name", ""))
    scenario_count = len(config.get("scenarios", []))
    mission_count = len(config.get("missions", []))
    product_count = len(config.get("products", []))
    product_ids = sorted({_phase83_product_id_from_path(str(path)) for path in config.get("products", [])})
    scored_rows: List[Dict[str, object]] = []
    for product_id in product_ids:
        product_rows = [row for row in detail_rows if row.get("product_profile") == product_id]
        values = [_to_float(row.get("scenario_adjusted_effectiveness")) for row in product_rows]
        scenario_coverage = len({row.get("scenario_name") for row in product_rows}) / scenario_count if scenario_count else 0.0
        mission_coverage = len({row.get("mission_name") for row in product_rows}) / mission_count if mission_count else 0.0
        expected_product_rows = scenario_count * mission_count
        product_coverage = len(product_rows) / expected_product_rows if expected_product_rows else 0.0
        variance = float(np.var(values)) if values else 0.0
        consistency = max(0.0, 1.0 - min(1.0, variance))
        scored_rows.append(
            {
                "benchmark_name": benchmark_name,
                "product_profile": product_id,
                "benchmark_score": round(float(np.mean(values)) if values else 0.0, 6),
                "benchmark_rank": 0,
                "scenario_coverage": round(scenario_coverage, 6),
                "mission_coverage": round(mission_coverage, 6),
                "product_coverage": round(product_coverage, 6),
                "consistency_score": round(consistency, 6),
                "variance_score": round(variance, 6),
            }
        )
    scored_rows.sort(key=lambda row: _to_float(row.get("benchmark_score")), reverse=True)
    for index, row in enumerate(scored_rows, start=1):
        row["benchmark_rank"] = index
    return scored_rows


def _phase83_group_winners(detail_rows: List[Dict[str, object]], group_key: str) -> Dict[str, str]:
    winners: Dict[str, str] = {}
    groups = sorted({str(row.get(group_key)) for row in detail_rows})
    for group in groups:
        group_rows = [row for row in detail_rows if str(row.get(group_key)) == group]
        products = sorted({str(row.get("product_profile")) for row in group_rows})
        product_scores = {
            product: float(np.mean([_to_float(row.get("scenario_adjusted_effectiveness")) for row in group_rows if row.get("product_profile") == product]))
            for product in products
        }
        winners[group] = max(product_scores, key=product_scores.get) if product_scores else ""
    return winners


def _phase83_analysis(summary_rows: List[Dict[str, object]], detail_rows: List[Dict[str, object]]) -> Dict[str, object]:
    strongest = summary_rows[0].get("product_profile") if summary_rows else ""
    most_consistent = max(summary_rows, key=lambda row: _to_float(row.get("consistency_score"))).get("product_profile") if summary_rows else ""
    highest_variance = max(summary_rows, key=lambda row: _to_float(row.get("variance_score"))).get("product_profile") if summary_rows else ""
    return {
        "strongest_overall": strongest,
        "strongest_by_mission": _phase83_group_winners(detail_rows, "mission_name"),
        "strongest_by_scenario": _phase83_group_winners(detail_rows, "scenario_name"),
        "most_consistent": most_consistent,
        "highest_variance": highest_variance,
        "benchmark_matrix_complete": all(
            _to_float(row.get("scenario_coverage")) == 1.0 and _to_float(row.get("mission_coverage")) == 1.0
            for row in summary_rows
        ),
    }


def _plot_phase83_bar(
    rows: List[Dict[str, object]],
    value_key: str,
    title: str,
    ylabel: str,
    save_path: str,
) -> None:
    labels = [str(row.get("product_profile")) for row in rows]
    values = [_to_float(row.get(value_key)) for row in rows]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(labels)), values, color="#4e79a7")
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase83_heatmap(
    detail_rows: List[Dict[str, object]],
    group_key: str,
    title: str,
    save_path: str,
) -> None:
    product_labels = sorted({str(row.get("product_profile")) for row in detail_rows})
    group_labels = sorted({str(row.get(group_key)) for row in detail_rows})
    grid = np.zeros((len(product_labels), len(group_labels)), dtype=float)
    for i, product in enumerate(product_labels):
        for j, group in enumerate(group_labels):
            values = [
                _to_float(row.get("scenario_adjusted_effectiveness"))
                for row in detail_rows
                if row.get("product_profile") == product and row.get(group_key) == group
            ]
            grid[i, j] = float(np.mean(values)) if values else 0.0
    fig, ax = plt.subplots(figsize=(11, 6))
    image = ax.imshow(grid, cmap="viridis", aspect="auto", vmin=0.0, vmax=max(1.0, float(np.max(grid)) if grid.size else 1.0))
    ax.set_title(title)
    ax.set_xticks(np.arange(len(group_labels)))
    ax.set_xticklabels(group_labels, rotation=25, ha="right")
    ax.set_yticks(np.arange(len(product_labels)))
    ax.set_yticklabels(product_labels)
    fig.colorbar(image, ax=ax, label="benchmark_score")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase83_outputs(
    summary_rows: List[Dict[str, object]],
    detail_rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "benchmark_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE83_BENCHMARK_SUMMARY_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE83_BENCHMARK_SUMMARY_COLUMNS} for row in summary_rows])
    with open(os.path.join(output_dir, "benchmark_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"summary_rows": summary_rows, "detail_rows": detail_rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)
    _plot_phase83_bar(summary_rows, "benchmark_score", "Benchmark Product Ranking", "benchmark_score", os.path.join(output_dir, "benchmark_product_ranking.png"))
    _plot_phase83_heatmap(detail_rows, "scenario_name", "Benchmark Scenario Heatmap", os.path.join(output_dir, "benchmark_scenario_heatmap.png"))
    _plot_phase83_heatmap(detail_rows, "mission_name", "Benchmark Mission Heatmap", os.path.join(output_dir, "benchmark_mission_heatmap.png"))
    _plot_phase83_bar(summary_rows, "consistency_score", "Benchmark Consistency", "consistency_score", os.path.join(output_dir, "benchmark_consistency.png"))
    _write_phase83_report(summary_rows, analysis, output_dir)


def _write_phase83_report(summary_rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase8.3 Benchmark Suite Report",
        "",
        "## Research Question",
        "Scenario x Mission x Product を横断した場合、製品ごとの強み・弱みを再現可能に評価できるか？",
        "",
        "## Interpretation Boundary",
        "This benchmark is not a product certification or a single strongest product claim. It provides reproducible comparison across scenario, mission, and product dimensions using existing CyberMatch artifacts.",
        "",
        "## Product Ranking",
        "| rank | product | benchmark_score | consistency_score | variance_score |",
        "|---:|---|---:|---:|---:|",
    ]
    for row in summary_rows:
        lines.append(
            f"| {row.get('benchmark_rank')} | {row.get('product_profile')} | "
            f"{_to_float(row.get('benchmark_score')):.3f} | "
            f"{_to_float(row.get('consistency_score')):.3f} | "
            f"{_to_float(row.get('variance_score')):.3f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            f"- Strongest overall: `{analysis.get('strongest_overall')}`.",
            f"- Strongest by mission: `{analysis.get('strongest_by_mission')}`.",
            f"- Strongest by scenario: `{analysis.get('strongest_by_scenario')}`.",
            f"- Most consistent: `{analysis.get('most_consistent')}`.",
            f"- Highest variance: `{analysis.get('highest_variance')}`.",
            f"- Benchmark matrix complete: `{analysis.get('benchmark_matrix_complete')}`.",
            "",
            "## Output Artifacts",
            "- `benchmark_summary.csv`",
            "- `benchmark_summary.json`",
            "- `benchmark_product_ranking.png`",
            "- `benchmark_scenario_heatmap.png`",
            "- `benchmark_mission_heatmap.png`",
            "- `benchmark_consistency.png`",
        ]
    )
    with open(os.path.join(output_dir, "PHASE83_BENCHMARK_SUITE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run_phase83_benchmark_suite(
    benchmark_path: str = os.path.join("benchmarks", "product_evaluation_benchmark.json"),
    output_dir: str = os.path.join("output", "phase83_benchmark_suite"),
) -> List[Dict[str, object]]:
    from cybermatch.loaders.benchmark_loader import load_benchmark

    config = load_benchmark(benchmark_path)
    detail_rows = _phase83_benchmark_rows(config)
    summary_rows = _phase83_summary_rows(config, detail_rows)
    analysis = _phase83_analysis(summary_rows, detail_rows)
    _write_phase83_outputs(summary_rows, detail_rows, analysis, output_dir)
    return summary_rows


PHASE84_TOPOLOGY_COLUMNS = [
    "topology_name",
    "topology_score",
    "topology_complexity",
    "identity_centralization",
    "lateral_movement_complexity",
    "deception_surface",
    "operational_sensitivity",
    "critical_assets",
    "product_profile",
    "product_category",
    "mission_name",
    "base_mission_effectiveness",
    "topology_adjusted_effectiveness",
]


def _phase84_level_value(value: object) -> float:
    return PHASE82_LEVEL_VALUES.get(str(value), 2.0)


def _phase84_topology_complexity(characteristics: Dict[str, object]) -> float:
    critical_component = _to_float(characteristics.get("critical_assets")) / 10.0
    identity_component = _phase84_level_value(characteristics.get("identity_centralization")) / 3.0
    lateral_component = _phase84_level_value(characteristics.get("lateral_movement_complexity")) / 3.0
    operational_component = _phase84_level_value(characteristics.get("operational_sensitivity")) / 3.0
    return float(np.mean([critical_component, identity_component, lateral_component, operational_component]))


def _phase84_adjustment_factor(characteristics: Dict[str, object], mission_name: str, product_category: str) -> float:
    complexity = _phase84_topology_complexity(characteristics)
    identity = _phase84_level_value(characteristics.get("identity_centralization")) - 2.0
    lateral = _phase84_level_value(characteristics.get("lateral_movement_complexity")) - 2.0
    deception = _phase84_level_value(characteristics.get("deception_surface")) - 2.0
    operational = _phase84_level_value(characteristics.get("operational_sensitivity")) - 2.0
    critical = (_to_float(characteristics.get("critical_assets")) - 5.0) / 5.0

    factor = 1.0 + 0.08 * (complexity - 0.55)
    if mission_name == "profit":
        factor += 0.03 * identity
    elif mission_name == "achievement":
        factor += 0.025 * operational
    elif mission_name == "persistence":
        factor += 0.03 * lateral
    elif mission_name == "critical_hunter":
        factor += 0.035 * critical

    if product_category == "deception":
        factor += 0.05 * deception
    elif product_category == "xdr":
        factor += 0.03 * identity
    elif product_category == "ips":
        factor += 0.025 * lateral
    elif product_category == "honeypot":
        factor += 0.025 * critical
    elif product_category == "ids":
        factor += 0.02 * identity

    return max(0.5, min(1.5, factor))


def _phase84_build_rows(topologies: List[Dict[str, object]], phase63_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    base_rows = [row for row in phase63_rows if row.get("profile_id") != "baseline"]
    for topology in topologies:
        metadata = topology.get("metadata", {})
        characteristics = topology.get("characteristics", {})
        topology_name = str(metadata.get("name", ""))
        complexity = _phase84_topology_complexity(characteristics)
        for base_row in base_rows:
            product_category = str(base_row.get("product_category", ""))
            mission_name = str(base_row.get("mission_name", ""))
            base_score = _to_float(base_row.get("mission_effectiveness"))
            adjusted = base_score * _phase84_adjustment_factor(characteristics, mission_name, product_category)
            rows.append(
                {
                    "topology_name": topology_name,
                    "topology_score": round(adjusted, 6),
                    "topology_complexity": round(complexity, 4),
                    "identity_centralization": characteristics.get("identity_centralization"),
                    "lateral_movement_complexity": characteristics.get("lateral_movement_complexity"),
                    "deception_surface": characteristics.get("deception_surface"),
                    "operational_sensitivity": characteristics.get("operational_sensitivity"),
                    "critical_assets": characteristics.get("critical_assets"),
                    "product_profile": base_row.get("profile_id"),
                    "product_category": product_category,
                    "mission_name": mission_name,
                    "base_mission_effectiveness": round(base_score, 6),
                    "topology_adjusted_effectiveness": round(adjusted, 6),
                }
            )
    return rows


def _phase84_matrix(
    rows: List[Dict[str, object]],
    row_key: str,
    column_key: str,
) -> Tuple[List[str], List[str], np.ndarray]:
    row_labels = sorted({str(row.get(row_key)) for row in rows})
    column_labels = sorted({str(row.get(column_key)) for row in rows})
    grid = np.zeros((len(row_labels), len(column_labels)), dtype=float)
    for i, row_label in enumerate(row_labels):
        for j, column_label in enumerate(column_labels):
            values = [
                _to_float(row.get("topology_adjusted_effectiveness"))
                for row in rows
                if str(row.get(row_key)) == row_label and str(row.get(column_key)) == column_label
            ]
            grid[i, j] = float(np.mean(values)) if values else 0.0
    return row_labels, column_labels, grid


def _plot_phase84_heatmap(rows: List[Dict[str, object]], row_key: str, column_key: str, title: str, save_path: str) -> None:
    row_labels, column_labels, grid = _phase84_matrix(rows, row_key, column_key)
    fig, ax = plt.subplots(figsize=(11, 6))
    image = ax.imshow(grid, cmap="viridis", aspect="auto", vmin=0.0, vmax=max(1.0, float(np.max(grid)) if grid.size else 1.0))
    ax.set_title(title)
    ax.set_xticks(np.arange(len(column_labels)))
    ax.set_xticklabels(column_labels, rotation=25, ha="right")
    ax.set_yticks(np.arange(len(row_labels)))
    ax.set_yticklabels(row_labels)
    fig.colorbar(image, ax=ax, label="topology_adjusted_effectiveness")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _phase84_analysis(rows: List[Dict[str, object]]) -> Dict[str, object]:
    topology_names = sorted({str(row.get("topology_name")) for row in rows})
    topology_scores = {
        topology: float(np.mean([_to_float(row.get("topology_adjusted_effectiveness")) for row in rows if row.get("topology_name") == topology]))
        for topology in topology_names
    }
    best_product_by_topology = {}
    best_mission_by_topology = {}
    for topology in topology_names:
        topology_rows = [row for row in rows if row.get("topology_name") == topology]
        products = sorted({str(row.get("product_profile")) for row in topology_rows})
        missions = sorted({str(row.get("mission_name")) for row in topology_rows})
        product_scores = {
            product: float(np.mean([_to_float(row.get("topology_adjusted_effectiveness")) for row in topology_rows if row.get("product_profile") == product]))
            for product in products
        }
        mission_scores = {
            mission: float(np.mean([_to_float(row.get("topology_adjusted_effectiveness")) for row in topology_rows if row.get("mission_name") == mission]))
            for mission in missions
        }
        best_product_by_topology[topology] = max(product_scores, key=product_scores.get) if product_scores else ""
        best_mission_by_topology[topology] = max(mission_scores, key=mission_scores.get) if mission_scores else ""
    return {
        "topology_scores": topology_scores,
        "best_product_by_topology": best_product_by_topology,
        "best_mission_by_topology": best_mission_by_topology,
        "topology_differences_observed": len({round(score, 6) for score in topology_scores.values()}) > 1,
    }


def _write_phase84_outputs(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "topology_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE84_TOPOLOGY_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE84_TOPOLOGY_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "topology_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)
    _plot_phase84_heatmap(rows, "topology_name", "identity_centralization", "Topology Comparison", os.path.join(output_dir, "topology_comparison_heatmap.png"))
    _plot_phase84_heatmap(rows, "topology_name", "mission_name", "Topology x Mission Matrix", os.path.join(output_dir, "topology_mission_matrix.png"))
    _plot_phase84_heatmap(rows, "topology_name", "product_profile", "Topology x Product Matrix", os.path.join(output_dir, "topology_product_matrix.png"))
    _write_phase84_report(rows, analysis, output_dir)


def _write_phase84_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    topology_names = sorted({str(row.get("topology_name")) for row in rows})
    lines = [
        "# Phase8.4 Enterprise Topology Library Report",
        "",
        "## Research Question",
        "Topology Preset の違いによって Mission評価 Product評価 は変化するか？",
        "",
        "## Interpretation Boundary",
        "Phase8.4 uses topology characteristics as a lightweight interpretation layer over existing Phase6.3 mission-aware product results. It does not add a network simulator or change simulation logic.",
        "",
        "## Topology Summary",
        "| topology | complexity | best_product | best_mission_coverage | mean_score |",
        "|---|---:|---|---|---:|",
    ]
    for topology_name in topology_names:
        first = next(row for row in rows if row.get("topology_name") == topology_name)
        lines.append(
            f"| {topology_name} | {_to_float(first.get('topology_complexity')):.3f} | "
            f"{analysis.get('best_product_by_topology', {}).get(topology_name)} | "
            f"{analysis.get('best_mission_by_topology', {}).get(topology_name)} | "
            f"{_to_float(analysis.get('topology_scores', {}).get(topology_name)):.3f} |"
        )
    lines.extend(
        [
            "",
            "## Validation",
            f"- Topology differences observed: `{analysis.get('topology_differences_observed')}`.",
            "",
            "## Output Artifacts",
            "- `topology_summary.csv`",
            "- `topology_summary.json`",
            "- `topology_comparison_heatmap.png`",
            "- `topology_mission_matrix.png`",
            "- `topology_product_matrix.png`",
        ]
    )
    with open(os.path.join(output_dir, "PHASE84_TOPOLOGY_LIBRARY_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run_phase84_topology_evaluation(
    output_dir: str = os.path.join("output", "phase84_topology_library"),
    topology_dir: str = os.path.join("topologies"),
) -> List[Dict[str, object]]:
    from cybermatch.loaders.topology_loader import list_available_topologies, load_topology

    topologies = [load_topology(str(path)) for path in list_available_topologies(topology_dir)]
    phase63_rows = _phase82_load_phase63_rows()
    rows = _phase84_build_rows(topologies, phase63_rows)
    analysis = _phase84_analysis(rows)
    _write_phase84_outputs(rows, analysis, output_dir)
    return rows


PHASE85_STANDARD_COLUMNS = [
    "benchmark_name",
    "benchmark_version",
    "product_profile",
    "benchmark_score",
    "benchmark_rank",
    "benchmark_completeness",
    "coverage_score",
    "reproducibility_score",
    "evaluation_matrix_size",
    "consistency_score",
    "variance_score",
]


def _phase85_detail_rows(config: Dict[str, object]) -> List[Dict[str, object]]:
    from cybermatch.loaders.scenario_loader import load_scenario
    from cybermatch.loaders.topology_loader import load_topology

    scenarios = [load_scenario(str(path)) for path in config.get("scenarios", [])]
    topologies = [load_topology(str(path)) for path in config.get("topologies", [])]
    missions = {str(mission) for mission in config.get("missions", [])}
    products = {_phase83_product_id_from_path(str(path)) for path in config.get("products", [])}
    phase63_rows = [row for row in _phase82_load_phase63_rows() if row.get("profile_id") != "baseline"]
    rows: List[Dict[str, object]] = []
    for scenario in scenarios:
        scenario_metadata = scenario.get("metadata", {})
        scenario_characteristics = scenario.get("characteristics", {})
        scenario_name = str(scenario_metadata.get("name", ""))
        industry = str(scenario_metadata.get("industry", ""))
        for topology in topologies:
            topology_metadata = topology.get("metadata", {})
            topology_characteristics = topology.get("characteristics", {})
            topology_name = str(topology_metadata.get("name", ""))
            for base_row in phase63_rows:
                product_id = str(base_row.get("profile_id", ""))
                mission_name = str(base_row.get("mission_name", ""))
                if product_id not in products or mission_name not in missions:
                    continue
                product_category = str(base_row.get("product_category", ""))
                base_score = _to_float(base_row.get("mission_effectiveness"))
                scenario_score = base_score * _phase82_adjustment_factor(scenario_characteristics, mission_name, product_category)
                standard_score = scenario_score * _phase84_adjustment_factor(topology_characteristics, mission_name, product_category)
                rows.append(
                    {
                        "scenario_name": scenario_name,
                        "industry": industry,
                        "topology_name": topology_name,
                        "mission_name": mission_name,
                        "product_profile": product_id,
                        "product_category": product_category,
                        "base_mission_effectiveness": round(base_score, 6),
                        "standard_score": round(standard_score, 6),
                    }
                )
    return rows


def _phase85_summary_rows(config: Dict[str, object], detail_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    metadata = config.get("metadata", {})
    benchmark_name = str(metadata.get("name", ""))
    benchmark_version = str(metadata.get("version", ""))
    scenario_count = len(config.get("scenarios", []))
    topology_count = len(config.get("topologies", []))
    mission_count = len(config.get("missions", []))
    product_ids = sorted({_phase83_product_id_from_path(str(path)) for path in config.get("products", [])})
    matrix_size = scenario_count * topology_count * mission_count * len(product_ids)
    expected_product_rows = scenario_count * topology_count * mission_count
    rows: List[Dict[str, object]] = []
    for product_id in product_ids:
        product_rows = [row for row in detail_rows if row.get("product_profile") == product_id]
        values = [_to_float(row.get("standard_score")) for row in product_rows]
        coverage = len(product_rows) / expected_product_rows if expected_product_rows else 0.0
        variance = float(np.var(values)) if values else 0.0
        consistency = max(0.0, 1.0 - min(1.0, variance))
        rows.append(
            {
                "benchmark_name": benchmark_name,
                "benchmark_version": benchmark_version,
                "product_profile": product_id,
                "benchmark_score": round(float(np.mean(values)) if values else 0.0, 6),
                "benchmark_rank": 0,
                "benchmark_completeness": round(coverage, 6),
                "coverage_score": round(coverage, 6),
                "reproducibility_score": 1.0 if config.get("seeds") == [0] else 0.9,
                "evaluation_matrix_size": matrix_size,
                "consistency_score": round(consistency, 6),
                "variance_score": round(variance, 6),
            }
        )
    rows.sort(key=lambda row: _to_float(row.get("benchmark_score")), reverse=True)
    for index, row in enumerate(rows, start=1):
        row["benchmark_rank"] = index
    return rows


def _phase85_group_winners(detail_rows: List[Dict[str, object]], group_key: str) -> Dict[str, str]:
    winners: Dict[str, str] = {}
    groups = sorted({str(row.get(group_key)) for row in detail_rows})
    for group in groups:
        group_rows = [row for row in detail_rows if str(row.get(group_key)) == group]
        products = sorted({str(row.get("product_profile")) for row in group_rows})
        product_scores = {
            product: float(np.mean([_to_float(row.get("standard_score")) for row in group_rows if row.get("product_profile") == product]))
            for product in products
        }
        winners[group] = max(product_scores, key=product_scores.get) if product_scores else ""
    return winners


def _phase85_analysis(summary_rows: List[Dict[str, object]], detail_rows: List[Dict[str, object]]) -> Dict[str, object]:
    return {
        "strongest_overall": summary_rows[0].get("product_profile") if summary_rows else "",
        "strongest_by_mission": _phase85_group_winners(detail_rows, "mission_name"),
        "strongest_by_scenario": _phase85_group_winners(detail_rows, "scenario_name"),
        "strongest_by_topology": _phase85_group_winners(detail_rows, "topology_name"),
        "most_consistent": max(summary_rows, key=lambda row: _to_float(row.get("consistency_score"))).get("product_profile") if summary_rows else "",
        "highest_variance": max(summary_rows, key=lambda row: _to_float(row.get("variance_score"))).get("product_profile") if summary_rows else "",
        "benchmark_completeness": min([_to_float(row.get("benchmark_completeness")) for row in summary_rows], default=0.0),
        "evaluation_matrix_size": summary_rows[0].get("evaluation_matrix_size") if summary_rows else 0,
    }


def _plot_phase85_bar(rows: List[Dict[str, object]], value_key: str, title: str, ylabel: str, save_path: str) -> None:
    labels = [str(row.get("product_profile")) for row in rows]
    values = [_to_float(row.get(value_key)) for row in rows]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(labels)), values, color="#4e79a7")
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase85_heatmap(detail_rows: List[Dict[str, object]], group_key: str, title: str, save_path: str) -> None:
    product_labels = sorted({str(row.get("product_profile")) for row in detail_rows})
    group_labels = sorted({str(row.get(group_key)) for row in detail_rows})
    grid = np.zeros((len(product_labels), len(group_labels)), dtype=float)
    for i, product in enumerate(product_labels):
        for j, group in enumerate(group_labels):
            values = [
                _to_float(row.get("standard_score"))
                for row in detail_rows
                if row.get("product_profile") == product and row.get(group_key) == group
            ]
            grid[i, j] = float(np.mean(values)) if values else 0.0
    fig, ax = plt.subplots(figsize=(11, 6))
    image = ax.imshow(grid, cmap="viridis", aspect="auto", vmin=0.0, vmax=max(1.0, float(np.max(grid)) if grid.size else 1.0))
    ax.set_title(title)
    ax.set_xticks(np.arange(len(group_labels)))
    ax.set_xticklabels(group_labels, rotation=25, ha="right")
    ax.set_yticks(np.arange(len(product_labels)))
    ax.set_yticklabels(product_labels)
    fig.colorbar(image, ax=ax, label="standard_score")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase85_outputs(summary_rows: List[Dict[str, object]], detail_rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "standard_benchmark_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE85_STANDARD_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE85_STANDARD_COLUMNS} for row in summary_rows])
    with open(os.path.join(output_dir, "standard_benchmark_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"summary_rows": summary_rows, "detail_rows": detail_rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)
    _plot_phase85_bar(summary_rows, "benchmark_score", "Standard Product Ranking", "benchmark_score", os.path.join(output_dir, "standard_product_ranking.png"))
    _plot_phase85_heatmap(detail_rows, "scenario_name", "Standard Scenario Heatmap", os.path.join(output_dir, "standard_scenario_heatmap.png"))
    _plot_phase85_heatmap(detail_rows, "topology_name", "Standard Topology Heatmap", os.path.join(output_dir, "standard_topology_heatmap.png"))
    _plot_phase85_heatmap(detail_rows, "mission_name", "Standard Mission Heatmap", os.path.join(output_dir, "standard_mission_heatmap.png"))
    _write_phase85_report(summary_rows, analysis, output_dir)


def _write_phase85_report(summary_rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    first = summary_rows[0] if summary_rows else {}
    lines = [
        "# CyberMatch 標準ベンチマーク比較レポート",
        "",
        "## このレポートで分かること",
        "複数の想定シナリオ・環境・攻撃者目的を横断したときに、防御策プロファイルがどのような傾向を示すかを確認できます。",
        "",
        "## 結論",
        f"- **総合的に高い候補**: `{_report_product_label(analysis.get('strongest_overall'))}`",
        f"- **結果が最も安定している候補**: `{_report_product_label(analysis.get('most_consistent'))}`",
        f"- **条件による差が最も大きい候補**: `{_report_product_label(analysis.get('highest_variance'))}`",
        "",
        "## 比較条件の範囲",
        f"- ベンチマーク設定の版: `{first.get('benchmark_version', '')}`",
        f"- 比較パターン数: `{analysis.get('evaluation_matrix_size')}`",
        f"- 比較条件の充足度: `{analysis.get('benchmark_completeness')}`",
        "",
        "## 防御策の横断比較",
        "| 順位 | 防御策 | 横断比較スコア | 結果の安定性 | 条件による差 |",
        "|---:|---|---:|---:|---:|",
    ]
    for row in summary_rows:
        lines.append(
            f"| {row.get('benchmark_rank')} | {_report_product_label(row.get('product_profile'))} | "
            f"{_to_float(row.get('benchmark_score')):.3f} | "
            f"{_to_float(row.get('consistency_score')):.3f} | "
            f"{_to_float(row.get('variance_score')):.3f} |"
        )
    lines.extend(
        [
            "",
            "## 攻撃者の目的ごとの有力候補",
        ]
    )
    strongest_by_mission = analysis.get("strongest_by_mission", {})
    if isinstance(strongest_by_mission, dict):
        for mission, product in sorted(strongest_by_mission.items()):
            lines.append(f"- **{_report_mission_label(mission)}**: `{_report_product_label(product)}`")
    lines.extend(
        [
            "",
            "## 結果の読み方",
            "- **横断比較スコア**: 複数の比較条件を平均した相対スコアです。高いほど、この標準条件セットで比較的高い効果を示します。",
            "- **結果の安定性**: 条件が変わっても結果が大きく変わりにくい度合いです。高いほど安定しています。",
            "- **条件による差**: シナリオ・環境・攻撃者目的により結果が変化する度合いです。高いほど、個別条件を確認する必要があります。",
            "",
            "## 注意事項",
            "このレポートはCyberMatchの標準条件での比較結果です。実製品の認証、実環境での効果の保証、またはすべての条件での最適製品を示すものではありません。個別の提案では、対象環境と攻撃者目的を指定した比較結果も確認してください。",
        ]
    )
    with open(os.path.join(output_dir, "PHASE85_STANDARD_BENCHMARK_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run_phase85_standard_benchmark(
    benchmark_path: str = os.path.join("benchmarks", "cybermatch_standard_v1.json"),
    output_dir: str = os.path.join("output", "phase85_standard_benchmark"),
) -> List[Dict[str, object]]:
    from cybermatch.loaders.benchmark_loader import load_benchmark

    config = load_benchmark(benchmark_path)
    detail_rows = _phase85_detail_rows(config)
    summary_rows = _phase85_summary_rows(config, detail_rows)
    analysis = _phase85_analysis(summary_rows, detail_rows)
    _write_phase85_outputs(summary_rows, detail_rows, analysis, output_dir)
    return summary_rows
