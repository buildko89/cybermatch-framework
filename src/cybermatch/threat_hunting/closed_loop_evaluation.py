"""Paired open/closed-loop and attacker-stealth sensitivity evaluation."""

from __future__ import annotations

import csv
import json
import shutil
from dataclasses import asdict
from pathlib import Path
from statistics import fmean
from typing import Mapping, Sequence

import numpy as np

from src.cybermatch.config.simulation_config import SimulationConfig
from src.cybermatch.simulation.simulator import CyberDefenseSimulator

from .models import canonical_json


CLOSED_LOOP_SUMMARY_FILENAME = "closed_loop_summary.json"
CLOSED_LOOP_CSV_FILENAME = "closed_loop_summary.csv"
CLOSED_LOOP_REPORT_FILENAME = "THREAT_HUNTING_CLOSED_LOOP_REPORT.md"
STEALTH_PROFILE_NAMES = ("zero", "linear", "saturation", "strong")
STEALTH_PARAMETER_FIELDS = (
    "attacker_stealth_enabled",
    "c2_jitter_ratio",
    "dns_tunnel_chunk_size",
    "process_masquerading",
    "domain_homoglyph_enabled",
    "hunting_awareness_threshold",
    "sleep_or_slowdown_factor",
)


def normalize_stealth_sweep(value: object) -> tuple[dict[str, object], ...]:
    """Validate the four required sensitivity profiles and fill neutral defaults."""

    if not isinstance(value, list) or not value:
        raise ValueError("hunting.stealth_sweep must be a non-empty list")
    defaults = SimulationConfig()
    allowed = {"name", *STEALTH_PARAMETER_FIELDS}
    profiles: list[dict[str, object]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError(f"hunting.stealth_sweep[{index}] must be an object")
        unknown = sorted(set(item) - allowed)
        if unknown:
            raise ValueError(
                f"hunting.stealth_sweep[{index}] has unknown fields: {', '.join(unknown)}"
            )
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"hunting.stealth_sweep[{index}].name must be a non-empty string")
        profile = {field: getattr(defaults, field) for field in STEALTH_PARAMETER_FIELDS}
        profile.update(dict(item))
        profile["name"] = name.strip()
        # Reuse SimulationConfig's numeric and boolean validation at the final
        # configuration boundary; keep profile validation focused on the schema.
        profiles.append(profile)

    names = tuple(profile["name"] for profile in profiles)
    if len(set(names)) != len(names):
        raise ValueError("hunting.stealth_sweep profile names must be unique")
    if set(names) != set(STEALTH_PROFILE_NAMES):
        required = ", ".join(STEALTH_PROFILE_NAMES)
        raise ValueError(f"hunting.stealth_sweep must define exactly: {required}")
    profiles.sort(key=lambda profile: STEALTH_PROFILE_NAMES.index(str(profile["name"])))

    zero = profiles[0]
    neutral = {
        "attacker_stealth_enabled": False,
        "c2_jitter_ratio": 0.0,
        "dns_tunnel_chunk_size": 0,
        "process_masquerading": False,
        "domain_homoglyph_enabled": False,
        "sleep_or_slowdown_factor": 1.0,
    }
    if any(zero[field] != expected for field, expected in neutral.items()):
        raise ValueError("the zero stealth profile must have neutral effect parameters")
    if any(not bool(profile["attacker_stealth_enabled"]) for profile in profiles[1:]):
        raise ValueError("linear, saturation, and strong profiles must enable attacker stealth")
    return tuple(profiles)


def _build_case_config(
    *,
    scenario_name: str,
    mission: str,
    seed: int,
    loop_mode: str,
    profile: Mapping[str, object],
    hunting: Mapping[str, object],
) -> SimulationConfig:
    values = asdict(SimulationConfig())
    overrides = hunting.get("simulation_overrides", {})
    if not isinstance(overrides, Mapping):
        raise ValueError("hunting.simulation_overrides must be an object")
    values.update(dict(overrides))
    values.update({field: profile[field] for field in STEALTH_PARAMETER_FIELDS})
    recipes = list(hunting.get("recipes", []))
    campaign_id = f"{scenario_name}:{mission}:{profile['name']}:{seed}"
    values.update(
        {
            "T": int(hunting.get("simulation_steps", values["T"])),
            "seed": seed,
            "show_plot": False,
            "output_metrics": False,
            "save_history": False,
            "attacker_enabled": True,
            "attacker_lateral_enabled": True,
            "attacker_mission": mission,
            "mission_objectives_enabled": True,
            "observable_events_enabled": True,
            "critical_path_events_enabled": True,
            "threat_hunting_enabled": True,
            "threat_hunting_typed_telemetry_enabled": True,
            "threat_hunting_feedback_enabled": loop_mode == "closed_loop",
            "threat_hunting_recipe_paths": recipes,
            "threat_hunting_campaign_id": campaign_id,
            "threat_hunting_scenario_id": scenario_name,
        }
    )
    config = SimulationConfig(**values)
    config.validate()
    return config


def _decision_neutralization_score(history: Mapping[str, object], config: SimulationConfig) -> float:
    confidence = np.asarray(history.get("confidence", []), dtype=float)
    frustration = np.asarray(history.get("frustration", []), dtype=float)
    replanning = np.asarray(history.get("ai_replanning_cost", []), dtype=float)
    retreated = np.asarray(history.get("attacker_retreated", []), dtype=bool)
    confidence_component = 1.0 - float(confidence[-1]) if confidence.size else 0.0
    frustration_final = float(frustration[-1]) if frustration.size else 0.0
    frustration_component = frustration_final / (
        frustration_final + max(float(config.frustration_retreat_threshold), 1.0)
    )
    replanning_final = float(replanning[-1]) if replanning.size else 0.0
    replanning_component = replanning_final / (replanning_final + 1.0)
    retreat_component = float(bool(retreated[-1])) if retreated.size else 0.0
    return float(
        np.clip(
            0.35 * confidence_component
            + 0.25 * frustration_component
            + 0.25 * replanning_component
            + 0.15 * retreat_component,
            0.0,
            1.0,
        )
    )


def _run_case(config: SimulationConfig) -> dict[str, object]:
    simulator = CyberDefenseSimulator(config)
    history = simulator.run()
    metrics = simulator.calculate_metrics()
    detected = np.asarray(history.get("attacker_detected", []), dtype=bool)
    success = np.asarray(history.get("attacker_success", []), dtype=bool)
    slowdown = np.asarray(history.get("attacker_slowdown", []), dtype=bool)
    return {
        "steps": int(metrics["steps"]),
        "detection_rate": float(np.mean(detected)) if detected.size else 0.0,
        "attacker_success_rate": float(np.mean(success)) if success.size else 0.0,
        "neutralization_score": float(metrics["neutralization_score"]),
        "decision_neutralization_score": _decision_neutralization_score(history, config),
        "critical_true_gain_total": float(metrics["attacker_critical_true_gain_total"]),
        "attacker_retreated": bool(metrics["attacker_retreated"]),
        "feedback_action_count": int(simulator.threat_hunting_feedback_action_count),
        "feedback_active_steps": int(
            np.count_nonzero(history.get("threat_hunting_active_feedback_count", []))
        ),
        "attacker_slowdown_steps": int(np.count_nonzero(slowdown)),
    }


def _attach_paired_lifts(rows: list[dict[str, object]]) -> None:
    indexed = {
        (row["mission"], row["seed"], row["stealth_profile"], row["loop_mode"]): row
        for row in rows
    }
    for row in rows:
        key_base = (row["mission"], row["seed"], "zero", row["loop_mode"])
        base = indexed.get(key_base)
        open_row = indexed.get(
            (row["mission"], row["seed"], row["stealth_profile"], "open_loop")
        )
        if base is None or open_row is None:
            raise ValueError("closed-loop evaluation requires paired modes and the zero profile")
        row["stealth_detection_evasion_lift"] = float(
            base["detection_rate"] - row["detection_rate"]
        )
        row["stealth_neutralization_lift"] = float(
            base["neutralization_score"] - row["neutralization_score"]
        )
        row["decision_neutralization_lift"] = (
            float(row["decision_neutralization_score"] - open_row["decision_neutralization_score"])
            if row["loop_mode"] == "closed_loop"
            else 0.0
        )


def _sensitivity_rows(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    numeric = (
        "detection_rate",
        "attacker_success_rate",
        "neutralization_score",
        "stealth_detection_evasion_lift",
        "stealth_neutralization_lift",
        "decision_neutralization_lift",
        "feedback_action_count",
    )
    for profile_name in STEALTH_PROFILE_NAMES:
        for loop_mode in ("open_loop", "closed_loop"):
            selected = [
                row
                for row in rows
                if row["stealth_profile"] == profile_name and row["loop_mode"] == loop_mode
            ]
            if not selected:
                continue
            aggregate = {
                "stealth_profile": profile_name,
                "loop_mode": loop_mode,
                "case_count": len(selected),
            }
            aggregate.update(
                {field: fmean(float(row[field]) for row in selected) for field in numeric}
            )
            aggregate.update(
                {field: selected[0][field] for field in STEALTH_PARAMETER_FIELDS}
            )
            result.append(aggregate)
    return result


def _write_csv(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    fieldnames = list(rows[0]) if rows else []
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _report_text(summary: Mapping[str, object]) -> str:
    lines = [
        "# Threat Hunting Closed-Loop Sensitivity Report",
        "",
        f"- Scenario: `{summary['scenario_name']}`",
        f"- Seeds: `{', '.join(str(seed) for seed in summary['seeds'])}`",
        "- `stealth_neutralization_lift`: matched zero-profile defender neutralization minus the current profile; positive means stealth reduced defender neutralization.",
        "- `decision_neutralization_lift`: closed-loop decision neutralization minus its matched open-loop case.",
        "",
        "| profile | loop | cases | detection | attacker success | neutralization | stealth lift | decision lift | feedback actions |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary["sensitivity"]:
        lines.append(
            "| {stealth_profile} | {loop_mode} | {case_count} | {detection_rate:.3f} | "
            "{attacker_success_rate:.3f} | {neutralization_score:.3f} | "
            "{stealth_neutralization_lift:.3f} | {decision_neutralization_lift:.3f} | "
            "{feedback_action_count:.2f} |".format(**row)
        )
    return "\n".join(lines) + "\n"


def run_hunting_closed_loop_evaluation(
    scenario: Mapping[str, object],
    *,
    output_dir: str | Path | None = None,
    seeds: Sequence[int] | None = None,
) -> list[dict[str, object]]:
    """Run a paired H5 matrix and write machine-readable and Markdown reports."""

    metadata = scenario.get("metadata", {})
    evaluation = scenario.get("evaluation", {})
    hunting = scenario.get("hunting", {})
    if not all(isinstance(value, Mapping) for value in (metadata, evaluation, hunting)):
        raise ValueError("scenario metadata, evaluation, and hunting must be objects")
    scenario_name = metadata.get("name")
    if not isinstance(scenario_name, str) or not scenario_name:
        raise ValueError("scenario metadata.name is required")
    missions = scenario.get("missions", [])
    if not isinstance(missions, list) or not missions:
        raise ValueError("scenario missions must be a non-empty list")
    configured_seeds = seeds if seeds is not None else evaluation.get("seeds", [0])
    if not isinstance(configured_seeds, Sequence) or isinstance(configured_seeds, (str, bytes)):
        raise ValueError("evaluation seeds must be a sequence")
    if not configured_seeds or any(
        isinstance(seed, bool) or not isinstance(seed, int) or seed < 0
        for seed in configured_seeds
    ):
        raise ValueError("evaluation seeds must contain non-negative integers")
    selected_seeds = tuple(configured_seeds)
    profiles = normalize_stealth_sweep(hunting.get("stealth_sweep"))
    root = Path(
        output_dir
        or evaluation.get("output_dir")
        or f"output/threat_hunting/{scenario_name}_closed_loop"
    ).resolve()
    if root.exists():
        raise FileExistsError(f"output path already exists: {root}")

    rows: list[dict[str, object]] = []
    root.mkdir(parents=True, exist_ok=False)
    try:
        for mission in missions:
            for seed in selected_seeds:
                for profile in profiles:
                    for loop_mode in ("open_loop", "closed_loop"):
                        config = _build_case_config(
                            scenario_name=scenario_name,
                            mission=str(mission),
                            seed=seed,
                            loop_mode=loop_mode,
                            profile=profile,
                            hunting=hunting,
                        )
                        result = _run_case(config)
                        row = {
                            "scenario_name": scenario_name,
                            "mission": str(mission),
                            "seed": seed,
                            "stealth_profile": profile["name"],
                            "loop_mode": loop_mode,
                            **{field: profile[field] for field in STEALTH_PARAMETER_FIELDS},
                            **result,
                        }
                        rows.append(row)
        _attach_paired_lifts(rows)
        sensitivity = _sensitivity_rows(rows)
        summary = {
            "schema_version": "1.0",
            "scenario_name": scenario_name,
            "seeds": list(selected_seeds),
            "paired_seed_comparison": True,
            "case_count": len(rows),
            "rows": rows,
            "sensitivity": sensitivity,
        }
        (root / CLOSED_LOOP_SUMMARY_FILENAME).write_text(
            canonical_json(summary) + "\n", encoding="utf-8", newline="\n"
        )
        _write_csv(root / CLOSED_LOOP_CSV_FILENAME, rows)
        (root / CLOSED_LOOP_REPORT_FILENAME).write_text(
            _report_text(summary), encoding="utf-8", newline="\n"
        )
        return rows
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


__all__ = [
    "CLOSED_LOOP_CSV_FILENAME",
    "CLOSED_LOOP_REPORT_FILENAME",
    "CLOSED_LOOP_SUMMARY_FILENAME",
    "STEALTH_PARAMETER_FIELDS",
    "STEALTH_PROFILE_NAMES",
    "normalize_stealth_sweep",
    "run_hunting_closed_loop_evaluation",
]
