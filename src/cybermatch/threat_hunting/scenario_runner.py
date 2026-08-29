"""Scenario orchestration for offline threat-hunting product evaluation."""

from __future__ import annotations

import csv
import json
import shutil
from dataclasses import asdict, replace
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np

from src.cybermatch.config.simulation_config import SimulationConfig
from src.cybermatch.models.product import HuntingCapabilities, ProductProfile, load_product_profile
from src.cybermatch.simulation.simulator import CyberDefenseSimulator

from .adapters import GROUND_TRUTH_HISTORY_KEYS, OBSERVED_HISTORY_KEYS, HistoryGroundTruthAdapter, HistoryObservationAdapter
from .artifacts import ThreatHuntingArtifactWriter
from .config import ThreatHuntingRunConfig
from .engine import ThreatHuntingEngine
from .evaluation import ThreatHuntingEvaluator
from .models import HuntEvent, canonical_json, stable_identifier
from .recipes import (
    ThreatHuntingRecipe,
    ThreatHuntingRecipeLoader,
    apply_recipe_overrides,
    default_recipe_root,
    normalize_recipe_overrides,
)
from .reporting import ThreatHuntingReportWriter


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SUMMARY_JSON_FILENAME = "hunting_scenario_summary.json"
SUMMARY_CSV_FILENAME = "hunting_scenario_summary.csv"
RUN_MANIFEST_FILENAME = "hunting_run_manifest.json"


def _repo_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else REPOSITORY_ROOT / path


def _case_identifier(dimensions: Mapping[str, object]) -> str:
    return stable_identifier("hunt-case", dimensions)


def _noise_overrides(profile: str) -> dict[str, bool]:
    if profile == "none":
        return {"noise_injection_enabled": False, "adversarial_signal_enabled": False}
    if profile == "moderate":
        return {"noise_injection_enabled": True, "adversarial_signal_enabled": False}
    if profile == "adversarial":
        return {"noise_injection_enabled": True, "adversarial_signal_enabled": True}
    raise ValueError(f"unsupported hunting noise profile: {profile}")


def _simulation_config(
    *,
    mission: str,
    noise_profile: str,
    seed: int,
    hunting: Mapping[str, object],
) -> SimulationConfig:
    values = asdict(SimulationConfig())
    overrides = hunting.get("simulation_overrides", {})
    if not isinstance(overrides, Mapping):
        raise ValueError("hunting.simulation_overrides must be an object")
    values.update(dict(overrides))
    values.update(_noise_overrides(noise_profile))
    values.update(
        {
            "T": int(hunting.get("simulation_steps", values["T"])),
            "seed": seed,
            "show_plot": False,
            "output_metrics": True,
            "save_history": True,
            "threat_hunting_enabled": True,
            "observable_events_enabled": True,
            "critical_path_events_enabled": True,
            "attacker_enabled": True,
            "attacker_lateral_enabled": True,
            "attacker_mission": mission,
            "mission_objectives_enabled": True,
        }
    )
    config = SimulationConfig(**values)
    config.validate()
    return config


def _simulate_history(config: SimulationConfig) -> Mapping[str, object]:
    """Run one source simulation; isolated for deterministic smoke-test substitution."""

    return CyberDefenseSimulator(config).run()


def _write_replay_history(history: Mapping[str, object], path: Path) -> None:
    keys = (*OBSERVED_HISTORY_KEYS, *sorted(GROUND_TRUTH_HISTORY_KEYS))
    replay = {key: np.asarray(history[key]) for key in keys if key in history}
    if not any(key in replay for key in OBSERVED_HISTORY_KEYS):
        raise ValueError("simulation history contains no defender-observable event fields")
    np.savez(path, **replay)


def _recipe_tags(recipe: ThreatHuntingRecipe) -> frozenset[str]:
    tags = recipe.metadata.get("tags", [])
    if not isinstance(tags, list):
        return frozenset()
    return frozenset(tag for tag in tags if isinstance(tag, str))


def _recipe_required_depth(recipe: ThreatHuntingRecipe) -> int:
    required = 0
    for operation in recipe.operations:
        parameters = operation.parameters
        if operation.operator == "sequence":
            required = max(required, int(parameters.get("max_span_steps", 0)))
        elif operation.operator == "window":
            required = max(required, int(parameters.get("size_steps", 0)))
    return required


def _recipe_supported(recipe: ThreatHuntingRecipe, capabilities: HuntingCapabilities | None) -> bool:
    if capabilities is None:
        return True
    supported_tags = frozenset(capabilities.supported_recipe_tags)
    tags = _recipe_tags(recipe)
    if supported_tags and tags and not supported_tags.intersection(tags):
        return False
    return not (
        capabilities.correlation_depth_steps
        and _recipe_required_depth(recipe) > capabilities.correlation_depth_steps
    )


def _product_events(
    events: Sequence[HuntEvent], capabilities: HuntingCapabilities | None
) -> list[HuntEvent]:
    if capabilities is None:
        return list(events)
    allowed = frozenset(capabilities.observable_event_types)
    latency = capabilities.ingest_latency_steps
    selected = [event for event in events if not allowed or event.event_type in allowed]
    if latency:
        delayed: list[HuntEvent] = []
        for event in selected:
            step = event.step + latency
            ordinal = event.attributes.get("ordinal", 0)
            event_id = stable_identifier(
                "event",
                {
                    "schema_version": event.schema_version,
                    "campaign_id": event.campaign_id,
                    "step": step,
                    "ordinal": ordinal,
                    "event_type": event.event_type,
                },
            )
            delayed.append(replace(event, event_id=event_id, step=step))
        selected = delayed
    return sorted(selected, key=lambda event: (event.step, event.event_id))


def _profile_id(path: str) -> str:
    return Path(path).stem


def _load_recipes(paths: Sequence[str]) -> list[ThreatHuntingRecipe]:
    root = default_recipe_root().resolve()
    loader = ThreatHuntingRecipeLoader(root)
    recipes: list[ThreatHuntingRecipe] = []
    for value in paths:
        path = _repo_path(value).resolve()
        if not path.is_relative_to(root):
            raise ValueError(f"recipe must be below {root}: {value}")
        recipes.append(loader.load(path.relative_to(root)))
    return recipes


def _write_json(path: Path, payload: object) -> None:
    path.write_text(canonical_json(payload) + "\n", encoding="utf-8", newline="\n")


def _write_summary_csv(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    fixed = [
        "case_id",
        "status",
        "scenario_name",
        "topology_name",
        "mission_name",
        "product_profile",
        "recipe_id",
        "noise_profile",
        "seed",
        "event_count",
        "finding_count",
        "precision",
        "recall",
        "f1",
        "false_positives_per_100_steps",
        "mean_time_to_detect_steps",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fixed, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def run_hunting_history_evaluation(
    *,
    history_path: str | Path,
    recipe_path: str,
    output_dir: str | Path,
    scenario_id: str,
    campaign_id: str,
    seed: int | None = None,
    product_profile_path: str | None = None,
    recipe_overrides: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Run one GUI/CLI evaluation through the same H1/H2 contracts."""

    source = Path(history_path)
    if not source.is_absolute():
        source = _repo_path(str(source))
    recipe = _load_recipes([recipe_path])[0]
    normalized_overrides = normalize_recipe_overrides(recipe_overrides)
    recipe = apply_recipe_overrides(recipe, normalized_overrides)
    profile = (
        load_product_profile(str(_repo_path(product_profile_path)))
        if product_profile_path is not None
        else None
    )
    observed = HistoryObservationAdapter().adapt(
        source,
        campaign_id=campaign_id,
        scenario_id=scenario_id,
        seed=seed,
    )
    events = _product_events(observed, profile.hunting if profile is not None else None)
    run_config = ThreatHuntingRunConfig()
    findings = ThreatHuntingEngine(run_config).run(recipe, events)
    truth = HistoryGroundTruthAdapter().adapt(source, campaign_id=campaign_id)
    with np.load(source, allow_pickle=False) as archive:
        lengths = [len(archive[key]) for key in OBSERVED_HISTORY_KEYS if key in archive]
    total_steps = max(
        max(lengths, default=0),
        max((event.step + 1 for event in events), default=0),
    )
    artifact_paths = ThreatHuntingArtifactWriter(output_dir).write(
        events=events,
        findings=findings,
        recipe=recipe,
        config=run_config,
        source_history=source,
        campaign_id=campaign_id,
        scenario_id=scenario_id,
        seed=seed,
        recipe_overrides=normalized_overrides,
    )
    evaluation = ThreatHuntingEvaluator().evaluate(
        findings,
        truth,
        events=events,
        total_steps=total_steps,
    )
    report_paths = ThreatHuntingReportWriter(output_dir).write(
        evaluation=evaluation,
        findings=findings,
        ground_truth=truth,
    )
    return {
        "output_dir": str(report_paths.output_dir),
        "event_count": len(events),
        "finding_count": len(findings),
        "artifact_hash": report_paths.artifact_hash,
        "h1_artifact_hash": artifact_paths.artifact_hash,
        "recipe_id": recipe.recipe_id,
        "recipe_hash": recipe.recipe_hash,
        "recipe_overrides": normalized_overrides,
        "metrics": dict(evaluation.metrics),
    }


def run_hunting_recipe_evaluation(
    scenario: Mapping[str, object],
    *,
    output_dir: str | None = None,
    topology_preset: str | None = None,
    missions: Sequence[str] | None = None,
    product_paths: Sequence[str] | None = None,
    recipe_paths: Sequence[str] | None = None,
    noise_profiles: Sequence[str] | None = None,
    seeds: Sequence[int] | None = None,
) -> list[dict[str, object]]:
    """Execute the full product/recipe/noise/seed matrix for one scenario."""

    metadata = scenario.get("metadata", {})
    evaluation = scenario.get("evaluation", {})
    hunting = scenario.get("hunting", {})
    if not isinstance(metadata, Mapping) or not isinstance(evaluation, Mapping) or not isinstance(hunting, Mapping):
        raise ValueError("scenario metadata, evaluation, and hunting must be objects")
    scenario_name = str(metadata.get("name", ""))
    if not scenario_name:
        raise ValueError("scenario metadata.name is required")
    baseline_runs = int(hunting.get("baseline_runs", 0))
    if baseline_runs:
        raise ValueError("baseline_runs requires a baseline-capable recipe, which is not enabled in PR-H3A")

    selected_missions = list(missions if missions is not None else scenario.get("missions", []))
    selected_products = list(product_paths if product_paths is not None else scenario.get("products", []))
    selected_recipes = list(recipe_paths if recipe_paths is not None else hunting.get("recipes", []))
    selected_noise = list(noise_profiles if noise_profiles is not None else hunting.get("noise_profiles", ["none"]))
    configured_seeds = evaluation.get("seeds")
    if seeds is not None:
        selected_seeds = list(seeds)
    elif configured_seeds is not None:
        selected_seeds = list(configured_seeds)
    else:
        selected_seeds = list(range(int(hunting.get("evaluation_runs", 1))))
    topology_name = topology_preset or str(scenario.get("topology", {}).get("preset", "default_enterprise"))
    root = Path(output_dir or evaluation.get("output_dir") or f"output/threat_hunting/{scenario_name}").resolve()
    if root.exists():
        raise FileExistsError(f"output path already exists: {root}")

    profiles: list[tuple[str, ProductProfile]] = [
        (_profile_id(path), load_product_profile(str(_repo_path(path)))) for path in selected_products
    ]
    recipes = _load_recipes(selected_recipes)
    run_config = ThreatHuntingRunConfig()
    rows: list[dict[str, object]] = []
    root.mkdir(parents=True, exist_ok=False)
    histories_dir = root / "histories"
    histories_dir.mkdir()
    try:
        for mission in selected_missions:
            for noise_profile in selected_noise:
                for seed in selected_seeds:
                    source_dimensions = {
                        "scenario": scenario_name,
                        "topology": topology_name,
                        "mission": mission,
                        "noise": noise_profile,
                        "seed": seed,
                    }
                    source_id = stable_identifier("hunt-source", source_dimensions)
                    config = _simulation_config(
                        mission=mission,
                        noise_profile=noise_profile,
                        seed=seed,
                        hunting=hunting,
                    )
                    history = _simulate_history(config)
                    history_path = histories_dir / f"{source_id}.npz"
                    config_path = histories_dir / f"{source_id}.config.json"
                    _write_replay_history(history, history_path)
                    config.to_json(str(config_path))
                    campaign_id = source_id
                    observed = HistoryObservationAdapter().adapt(
                        history_path,
                        campaign_id=campaign_id,
                        scenario_id=scenario_name,
                        seed=seed,
                    )
                    truth = HistoryGroundTruthAdapter().adapt(history_path, campaign_id=campaign_id)
                    total_source_steps = len(history.get("observable_events", []))
                    for profile_id, profile in profiles:
                        events = _product_events(observed, profile.hunting)
                        for recipe in recipes:
                            dimensions = {
                                **source_dimensions,
                                "product": profile_id,
                                "recipe": recipe.recipe_id,
                            }
                            case_id = _case_identifier(dimensions)
                            row: dict[str, object] = {
                                "case_id": case_id,
                                "status": "unsupported",
                                "scenario_name": scenario_name,
                                "topology_name": topology_name,
                                "mission_name": mission,
                                "product_profile": profile_id,
                                "product_family": profile.product_family,
                                "hunting_mode": profile.hunting_mode,
                                "recipe_id": recipe.recipe_id,
                                "noise_profile": noise_profile,
                                "seed": seed,
                                "event_count": len(events),
                                "finding_count": 0,
                            }
                            if not _recipe_supported(recipe, profile.hunting):
                                rows.append(row)
                                continue
                            findings = ThreatHuntingEngine(run_config).run(recipe, events)
                            case_dir = root / "runs" / case_id
                            artifact_dir = case_dir / "artifacts"
                            case_dir.mkdir(parents=True, exist_ok=False)
                            ThreatHuntingArtifactWriter(artifact_dir).write(
                                events=events,
                                findings=findings,
                                recipe=recipe,
                                config=run_config,
                                source_history=history_path,
                                campaign_id=campaign_id,
                                scenario_id=scenario_name,
                                seed=seed,
                            )
                            total_steps = max(
                                total_source_steps,
                                max((event.step + 1 for event in events), default=0),
                            )
                            result = ThreatHuntingEvaluator().evaluate(
                                findings,
                                truth,
                                events=events,
                                total_steps=total_steps,
                            )
                            report_paths = ThreatHuntingReportWriter(artifact_dir).write(
                                evaluation=result,
                                findings=findings,
                                ground_truth=truth,
                            )
                            row.update(result.metrics)
                            row.update(
                                {
                                    "status": "succeeded",
                                    "finding_count": len(findings),
                                    "artifact_dir": str(artifact_dir),
                                    "artifact_hash": report_paths.artifact_hash,
                                    "source_history": str(history_path),
                                }
                            )
                            _write_json(case_dir / "case.json", {"dimensions": dimensions, "result": row})
                            rows.append(row)

        expected = (
            len(selected_missions)
            * len(selected_products)
            * len(selected_recipes)
            * len(selected_noise)
            * len(selected_seeds)
        )
        succeeded = sum(row["status"] == "succeeded" for row in rows)
        manifest = {
            "schema_version": "1.0",
            "runner": "hunting_recipe_evaluation",
            "scenario_name": scenario_name,
            "topology_name": topology_name,
            "baseline_runs": baseline_runs,
            "evaluation_matrix_size": expected,
            "succeeded_cases": succeeded,
            "completeness": succeeded / expected if expected else 0.0,
        }
        _write_json(root / RUN_MANIFEST_FILENAME, manifest)
        _write_json(root / SUMMARY_JSON_FILENAME, {"manifest": manifest, "rows": rows})
        _write_summary_csv(root / SUMMARY_CSV_FILENAME, rows)
        return rows
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


__all__ = [
    "RUN_MANIFEST_FILENAME",
    "SUMMARY_CSV_FILENAME",
    "SUMMARY_JSON_FILENAME",
    "run_hunting_history_evaluation",
    "run_hunting_recipe_evaluation",
]
