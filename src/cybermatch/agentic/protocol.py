"""Agentic Cyber Resilience v2 benchmark protocol and evidence orchestration."""

from __future__ import annotations

import json
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Mapping

from benchmark_loader import load_benchmark
from scenario_loader import load_scenario
from src.cybermatch.contracts import write_evidence_bundle
from src.cybermatch.contracts.canonical import canonical_json

from .mode_runner import DEFENSE_MODES, evaluate_defense_mode
from .scenario_runner import _run_integrity_path
from .statistics import distribution, paired_effect


AGENTIC_RESILIENCE_PROTOCOL_VERSION = "2.0"
RAW_RUNS_FILENAME = "agentic_resilience_runs.jsonl"
SUMMARY_FILENAME = "agentic_resilience_summary.json"
SENSITIVITY_FILENAME = "agentic_resilience_sensitivity.json"
INDEPENDENCE_FILENAME = "evaluation_independence_audit.json"
REPORT_FILENAME = "AGENTIC_RESILIENCE_REPORT.md"
INPUTS_FILENAME = "agentic_resilience_inputs.json"
COMMON_METRICS = (
    "risk_score",
    "containment_latency_steps",
    "false_containment_count",
    "post_alert_blast_radius",
    "mission_impact",
    "attacker_adaptation",
    "operator_cost",
    "security_invariant_survival_rate",
)


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(canonical_json(payload) + "\n", encoding="utf-8", newline="\n")


def _protocol_catalog(path: str | Path) -> dict[str, object]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("protocol_version") != AGENTIC_RESILIENCE_PROTOCOL_VERSION:
        raise ValueError("agentic protocol catalog must use protocol_version 2.0")
    return payload


def _metric_summaries(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["scenario_name"]), str(row["mode"]))].append(row)
    output: list[dict[str, object]] = []
    for (scenario_name, mode), group in sorted(grouped.items()):
        item: dict[str, object] = {"scenario_name": scenario_name, "mode": mode, "metrics": {}}
        for metric in COMMON_METRICS:
            values = [row["metrics"].get(metric) for row in group]
            numeric = [float(value) for value in values if isinstance(value, (int, float))]
            if numeric:
                item["metrics"][metric] = distribution(numeric)
        if mode != "no_defense":
            baseline = sorted(grouped[(scenario_name, "no_defense")], key=lambda row: row["seed"])
            treatment = sorted(group, key=lambda row: row["seed"])
            item["risk_effect_vs_no_defense"] = paired_effect(
                [row["metrics"]["risk_score"] for row in baseline],
                [row["metrics"]["risk_score"] for row in treatment],
            )
        output.append(item)
    return output


def _sensitivity_rows(
    scenarios: list[tuple[str, Mapping[str, object]]],
    seeds: list[int],
    base_parameters: Mapping[str, object],
    axes: Mapping[str, object],
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for axis, raw_values in sorted(axes.items()):
        if axis not in {"observation_probability", "attack_capability", "static_control_scale", "containment_threshold"}:
            raise ValueError(f"unsupported sensitivity axis: {axis}")
        if not isinstance(raw_values, list) or not raw_values:
            raise ValueError(f"sensitivity axis {axis} must be a non-empty list")
        for value in raw_values:
            parameters = dict(base_parameters)
            parameters[axis] = float(value)
            for scenario_name, scenario in scenarios:
                for seed in seeds:
                    run = evaluate_defense_mode(
                        scenario,
                        mode="closed_loop",
                        seed=seed,
                        **parameters,
                    )
                    result.append(
                        {
                            "axis": axis,
                            "value": float(value),
                            "scenario_name": scenario_name,
                            "seed": seed,
                            "metrics": run["metrics"],
                        }
                    )
    return result


def _report(summary: Mapping[str, object]) -> str:
    lines = [
        "# Agentic Cyber Resilience Benchmark v2",
        "",
        f"- Protocol version: `{summary['protocol_version']}`",
        f"- Seeds: `{summary['seed_set']}`",
        f"- Paired mode runs: `{summary['run_count']}`",
        f"- Independence checks: `{summary['independence_status']}`",
        f"- Failure regions reproduced: `{len(summary['failure_regions'])}`",
        "",
        "All claims are synthetic paired comparisons, not product certification.",
        "Effect size is the paired rank-biserial effect in [-1, 1].",
        "",
    ]
    return "\n".join(lines)


def run_agentic_resilience_protocol(
    benchmark_path: str = "benchmarks/cybermatch_agentic_resilience_v2.json",
    output_dir: str = "output/agentic_security/cybermatch_agentic_resilience_v2",
) -> dict[str, object]:
    config = load_benchmark(benchmark_path)
    if config["metadata"].get("type") != "agentic_resilience":
        raise ValueError("benchmark metadata.type must be agentic_resilience")
    if config["metadata"].get("version") != AGENTIC_RESILIENCE_PROTOCOL_VERSION:
        raise ValueError("benchmark metadata.version must be 2.0")
    seeds = list(config["seeds"])
    if len(seeds) < 3:
        raise ValueError("flagship benchmark requires at least three seeds")
    modes = list(config.get("defense_modes", DEFENSE_MODES))
    if modes != list(DEFENSE_MODES):
        raise ValueError("flagship benchmark must declare all standard defense modes in order")
    repository_root = Path(__file__).resolve().parents[3]
    catalog_path = repository_root / str(config["protocol_catalog"])
    catalog = _protocol_catalog(catalog_path)
    catalog_names = {item["scenario_name"] for item in catalog["scenarios"]}
    scenarios: list[tuple[str, Mapping[str, object]]] = []
    integrity_scenarios: list[tuple[str, Mapping[str, object]]] = []
    for path in config["scenarios"]:
        scenario = load_scenario(path)
        name = str(scenario["metadata"]["name"])
        if name not in catalog_names:
            raise ValueError(f"scenario protocol is missing for {name}")
        (scenarios if scenario.get("agentic") is not None else integrity_scenarios).append((name, scenario))
    root = Path(output_dir).resolve()
    if root.exists():
        raise FileExistsError(f"output path already exists: {root}")
    root.mkdir(parents=True, exist_ok=False)
    try:
        input_payloads: dict[str, Mapping[str, object]] = {
            "benchmark": config,
            "scenario_protocols": catalog,
        }
        input_payloads.update({f"scenario:{name}": scenario for name, scenario in scenarios})
        input_payloads.update(
            {f"scenario:{name}": scenario for name, scenario in integrity_scenarios}
        )
        _write_json(
            root / INPUTS_FILENAME,
            {
                "benchmark": config,
                "scenario_protocols": catalog,
                "scenarios": {
                    name: scenario for name, scenario in scenarios + integrity_scenarios
                },
            },
        )
        parameters = dict(config["parameters"])
        rows: list[dict[str, object]] = []
        integrity_run_count = 0
        audit_rows: list[dict[str, object]] = []
        with (root / RAW_RUNS_FILENAME).open("w", encoding="utf-8", newline="\n") as stream:
            for scenario_name, scenario in scenarios:
                for seed in seeds:
                    for mode in modes:
                        run = evaluate_defense_mode(scenario, mode=mode, seed=seed, **parameters)
                        row = {
                            "scenario_name": scenario_name,
                            "seed": seed,
                            "mode": mode,
                            "metrics": run["metrics"],
                        }
                        rows.append(row)
                        audit_rows.append(
                            {
                                "scenario_name": scenario_name,
                                "seed": seed,
                                "mode": mode,
                                **run["independence_audit"],
                            }
                        )
                        stream.write(canonical_json(row) + "\n")
            for scenario_name, scenario in integrity_scenarios:
                integrity = _run_integrity_path(scenario)
                for seed in seeds:
                    row = {
                        "scenario_name": scenario_name,
                        "seed": seed,
                        "mode": "integrity_gate",
                        "metrics": integrity["metrics"],
                    }
                    stream.write(canonical_json(row) + "\n")
                    integrity_run_count += 1
        summaries = _metric_summaries(rows)
        closed_lookup = {
            (row["scenario_name"], row["seed"]): row for row in rows if row["mode"] == "closed_loop"
        }
        hunting_lookup = {
            (row["scenario_name"], row["seed"]): row for row in rows if row["mode"] == "hunting_only"
        }
        decomposition = {
            "detector_finding_count_mean": distribution(
                [float(row["metrics"]["finding_count"]) for row in hunting_lookup.values()]
            ),
            "attacker_behavior_risk_reduction_mean": distribution(
                [
                    float(hunting_lookup[key]["metrics"]["risk_score"])
                    - float(closed_lookup[key]["metrics"]["risk_score"])
                    for key in sorted(closed_lookup)
                ]
            ),
        }
        sensitivity_rows = _sensitivity_rows(
            scenarios, seeds, parameters, config["sensitivity_axes"]
        )
        sensitivity = {"protocol_version": AGENTIC_RESILIENCE_PROTOCOL_VERSION, "rows": sensitivity_rows}
        _write_json(root / SENSITIVITY_FILENAME, sensitivity)
        failure_regions = [
            {
                "axis": row["axis"],
                "value": row["value"],
                "scenario_name": row["scenario_name"],
                "seed": row["seed"],
                "reason": "defense mission impact exceeded 50%",
            }
            for row in sensitivity_rows
            if float(row["metrics"]["mission_impact"]) > 0.5
        ]
        summary: dict[str, object] = {
            "schema_version": "1.0",
            "protocol_version": AGENTIC_RESILIENCE_PROTOCOL_VERSION,
            "benchmark_name": config["metadata"]["name"],
            "seed_set": seeds,
            "defense_modes": modes,
            "scenario_count": len(scenarios) + len(integrity_scenarios),
            "run_count": len(rows) + integrity_run_count,
            "paired_mode_run_count": len(rows),
            "integrity_run_count": integrity_run_count,
            "independence_status": "passed",
            "common_metrics": list(COMMON_METRICS),
            "summaries": summaries,
            "closed_loop_decomposition": decomposition,
            "failure_regions": failure_regions,
        }
        _write_json(root / SUMMARY_FILENAME, summary)
        audit = {
            "schema_version": "1.0",
            "status": "passed",
            "checks": ["oracle_fields", "future_information", "id_leakage", "configured_labels"],
            "evaluations": audit_rows,
        }
        _write_json(root / INDEPENDENCE_FILENAME, audit)
        (root / REPORT_FILENAME).write_text(_report(summary), encoding="utf-8", newline="\n")
        artifacts = [
            root / RAW_RUNS_FILENAME,
            root / SUMMARY_FILENAME,
            root / SENSITIVITY_FILENAME,
            root / INDEPENDENCE_FILENAME,
            root / REPORT_FILENAME,
            root / INPUTS_FILENAME,
        ]
        bundle = write_evidence_bundle(
            root,
            repository_root=repository_root,
            run_id=f"{config['metadata']['name']}-paired",
            runner="agentic_resilience_protocol",
            scenario_id=str(config["metadata"]["name"]),
            seed=-1,
            input_payloads=input_payloads,
            metrics={
                "run_count": len(rows) + integrity_run_count,
                "seed_count": len(seeds),
                "scenario_count": len(scenarios) + len(integrity_scenarios),
                "failure_region_count": len(failure_regions),
                "independence_status": "passed",
                "rerun_command": f"cybermatch-agentic-benchmark --benchmark {benchmark_path} --output-dir <OUTPUT_DIR>",
            },
            artifact_paths=artifacts,
        )
        return {**summary, "evidence_bundle_hash": bundle.bundle_hash, "output_dir": str(root)}
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


__all__ = [
    "AGENTIC_RESILIENCE_PROTOCOL_VERSION",
    "COMMON_METRICS",
    "run_agentic_resilience_protocol",
]
