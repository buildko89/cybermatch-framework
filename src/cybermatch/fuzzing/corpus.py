"""Seed loading and deterministic fuzz-case generation."""

from __future__ import annotations

import hashlib
import random
from dataclasses import asdict, replace
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np

from scenario_loader import load_scenario
from src.cybermatch.config.simulation_config import SimulationConfig
from src.cybermatch.simulation.simulator import CyberDefenseSimulator
from src.cybermatch.threat_hunting import (
    GroundTruthLabel,
    HistoryGroundTruthAdapter,
    HistoryObservationAdapter,
    load_threat_hunting_artifacts,
    load_threat_hunting_report,
    stable_identifier,
)
from src.cybermatch.threat_hunting.closed_loop_evaluation import normalize_stealth_sweep

from .analysis_guidance import score_analysis_guidance
from .constraints import validate_semantic_events
from .models import FUZZING_SCHEMA_VERSION, FuzzCase, SeedInput
from .mutators import apply_mutation, reidentify_events
from .scheduler import schedule_cases, semantic_signature
from .specs import FuzzCampaignSpec


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class FuzzCorpusError(ValueError):
    """Raised when a seed corpus cannot be loaded or constrained safely."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_path(value: str | Path, repository_root: Path) -> Path:
    requested = Path(value)
    if requested.is_absolute():
        raise FuzzCorpusError("base input and recipe paths must be repository-relative")
    resolved = (repository_root / requested).resolve()
    root = repository_root.resolve()
    if not resolved.is_relative_to(root) or resolved == root:
        raise FuzzCorpusError(f"path escapes repository root: {value}")
    return resolved


def _noise_overrides(profile: str) -> dict[str, bool]:
    if profile == "none":
        return {"noise_injection_enabled": False, "adversarial_signal_enabled": False}
    if profile == "moderate":
        return {"noise_injection_enabled": True, "adversarial_signal_enabled": False}
    if profile == "adversarial":
        return {"noise_injection_enabled": True, "adversarial_signal_enabled": True}
    raise FuzzCorpusError(f"unsupported noise profile: {profile}")


def _scenario_history(scenario: Mapping[str, object]) -> tuple[Mapping[str, object], str, str, int]:
    metadata = scenario.get("metadata", {})
    evaluation = scenario.get("evaluation", {})
    hunting = scenario.get("hunting", {})
    missions = scenario.get("missions", [])
    if not isinstance(metadata, Mapping) or not isinstance(evaluation, Mapping) or not isinstance(hunting, Mapping):
        raise FuzzCorpusError("scenario metadata, evaluation, and hunting must be objects")
    if not isinstance(missions, list) or not missions:
        raise FuzzCorpusError("scenario missions must be a non-empty list")
    scenario_id = str(metadata["name"])
    configured_seeds = evaluation.get("seeds", [0])
    if not isinstance(configured_seeds, list) or not configured_seeds:
        raise FuzzCorpusError("scenario evaluation.seeds must be a non-empty list")
    seed = configured_seeds[0]
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise FuzzCorpusError("scenario seed must be a non-negative integer")
    values = asdict(SimulationConfig())
    overrides = hunting.get("simulation_overrides", {})
    if not isinstance(overrides, Mapping):
        raise FuzzCorpusError("hunting.simulation_overrides must be an object")
    values.update(dict(overrides))
    runner = evaluation.get("runner")
    if runner == "hunting_closed_loop_evaluation":
        profiles = normalize_stealth_sweep(hunting.get("stealth_sweep"))
        zero = profiles[0]
        for field_name, value in zero.items():
            if field_name != "name":
                values[field_name] = value
    else:
        noise_profiles = hunting.get("noise_profiles", ["none"])
        if not isinstance(noise_profiles, list) or not noise_profiles:
            raise FuzzCorpusError("hunting.noise_profiles must be a non-empty list")
        values.update(_noise_overrides(str(noise_profiles[0])))
    campaign_id = stable_identifier(
        "fuzz-seed",
        {"scenario_id": scenario_id, "mission": missions[0], "seed": seed},
    )
    values.update(
        {
            "T": int(hunting.get("simulation_steps", values["T"])),
            "seed": seed,
            "show_plot": False,
            "output_metrics": False,
            "save_history": False,
            "attacker_enabled": True,
            "attacker_lateral_enabled": True,
            "attacker_mission": str(missions[0]),
            "mission_objectives_enabled": True,
            "observable_events_enabled": True,
            "critical_path_events_enabled": True,
            "threat_hunting_enabled": True,
            "threat_hunting_typed_telemetry_enabled": True,
            "threat_hunting_feedback_enabled": False,
            "threat_hunting_campaign_id": campaign_id,
            "threat_hunting_scenario_id": scenario_id,
        }
    )
    config = SimulationConfig(**values)
    config.validate()
    return CyberDefenseSimulator(config).run(), campaign_id, scenario_id, seed


def _derived_analysis_guidance(history: Mapping[str, object]) -> dict[str, float]:
    """Derive bounded seed priorities without exposing them to the target."""

    def vector(name: str, dtype):
        try:
            return np.asarray(history.get(name, []), dtype=dtype).reshape(-1)
        except (TypeError, ValueError):
            return np.asarray([], dtype=dtype)

    success = vector("attacker_success", bool)
    detected = vector("attacker_detected", bool)
    common = min(success.size, detected.size)
    successful_steps = int(np.count_nonzero(success[:common])) if common else 0
    missed_steps = (
        int(np.count_nonzero(success[:common] & ~detected[:common])) if common else 0
    )
    detection_gap = missed_steps / successful_steps if successful_steps else 0.0
    confidence = vector("confidence", float)
    inference_uncertainty = (
        float(np.clip(1.0 - confidence[-1], 0.0, 1.0)) if confidence.size else 0.0
    )
    detection_latency = 0.0
    if successful_steps:
        first_success = int(np.flatnonzero(success[:common])[0])
        later_detections = np.flatnonzero(detected[:common] & (np.arange(common) >= first_success))
        detection_latency = (
            min(float(later_detections[0] - first_success) / max(common - 1, 1), 1.0)
            if later_detections.size
            else 1.0
        )
    return {
        "inference_uncertainty": inference_uncertainty,
        "decision_path_rarity": 0.0,
        "detection_gap": float(np.clip(detection_gap, 0.0, 1.0)),
        "detection_latency_norm": detection_latency,
        "containment_gap": 0.0,
        "semantic_novelty": 0.0,
    }


def _load_scenario_seed(path: Path, repository_root: Path) -> SeedInput:
    scenario = load_scenario(str(path))
    history, campaign_id, scenario_id, seed = _scenario_history(scenario)
    events = tuple(
        HistoryObservationAdapter().adapt(
            history,
            campaign_id=campaign_id,
            scenario_id=scenario_id,
            seed=seed,
        )
    )
    truth = tuple(HistoryGroundTruthAdapter().adapt(history, campaign_id=campaign_id))
    relative = path.relative_to(repository_root).as_posix()
    analysis = scenario.get("fuzzing_analysis_guidance", {})
    if not isinstance(analysis, Mapping):
        raise FuzzCorpusError("scenario fuzzing_analysis_guidance must be an object")
    combined_analysis = _derived_analysis_guidance(history)
    combined_analysis.update(dict(analysis))
    source_hash = _sha256_file(path)
    return SeedInput(
        seed_id=stable_identifier("seed-input", {"path": relative, "sha256": source_hash}),
        source_path=relative,
        source_hash=source_hash,
        scenario_id=scenario_id,
        seed=seed,
        events=events,
        ground_truth=truth,
        analysis=combined_analysis,
    )


def _load_artifact_seed(path: Path, repository_root: Path) -> SeedInput:
    loaded = load_threat_hunting_artifacts(path)
    labels_path = path / "ground_truth" / "labels.json"
    truth: tuple[GroundTruthLabel, ...] = ()
    if labels_path.is_file():
        truth = load_threat_hunting_report(path).ground_truth
    manifest = loaded.manifest
    seed_value = manifest.get("seed")
    if isinstance(seed_value, bool) or not isinstance(seed_value, int) or seed_value < 0:
        seed_value = 0
    relative = path.relative_to(repository_root).as_posix()
    return SeedInput(
        seed_id=stable_identifier("seed-input", {"path": relative, "sha256": loaded.artifact_hash}),
        source_path=relative,
        source_hash=loaded.artifact_hash,
        scenario_id=str(manifest.get("scenario_id", "artifact_seed")),
        seed=seed_value,
        events=loaded.events,
        ground_truth=truth,
    )


def load_seed_input(value: str, *, repository_root: str | Path = REPOSITORY_ROOT) -> SeedInput:
    root = Path(repository_root).resolve()
    path = _repo_path(value, root)
    try:
        if path.is_dir():
            return _load_artifact_seed(path, root)
        if path.suffix.lower() == ".json" and path.is_file():
            return _load_scenario_seed(path, root)
    except FuzzCorpusError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise FuzzCorpusError(f"unable to load seed {value}: {exc}") from exc
    raise FuzzCorpusError(f"base input must be a scenario JSON or artifact directory: {value}")


def _retag_truth(
    truth: Sequence[GroundTruthLabel],
    case_id: str,
    event_id_map: Mapping[str, str],
) -> tuple[GroundTruthLabel, ...]:
    result: list[GroundTruthLabel] = []
    for label in truth:
        attributes = dict(label.attributes)
        for key in ("event_id", "source_event_id"):
            value = attributes.get(key)
            if isinstance(value, str) and value in event_id_map:
                attributes[key] = event_id_map[value]
        declared = attributes.get("event_ids")
        if isinstance(declared, str):
            attributes["event_ids"] = ",".join(
                event_id_map.get(value.strip(), value.strip())
                for value in declared.split(",")
                if value.strip()
            )
        label_id = stable_identifier(
            "fuzz-truth",
            {"case_id": case_id, "source_label_id": label.label_id, "attributes": attributes},
        )
        result.append(
            replace(label, label_id=label_id, campaign_id=case_id, attributes=attributes)
        )
    return tuple(result)


def _case_from_seed(
    spec: FuzzCampaignSpec,
    seed_input: SeedInput,
    case_index: int,
) -> FuzzCase:
    case_seed = spec.campaign_seed + case_index
    rng = random.Random(case_seed)
    events = tuple(seed_input.events)
    max_operations = min(spec.limits.max_mutations_per_case, len(spec.mutators))
    operation_count = 1 + case_index % max_operations
    selected = rng.choices(
        spec.mutators,
        weights=[mutator.weight for mutator in spec.mutators],
        k=operation_count,
    )
    records = []
    for operation_index, mutator in enumerate(selected):
        events, record = apply_mutation(events, mutator, rng, operation_index)
        records.append(record)
        try:
            validate_semantic_events(events, max_events=spec.limits.max_events_per_case)
        except ValueError as exc:
            raise FuzzCorpusError(f"case {case_index} violates semantic constraints: {exc}") from exc
    case_id = stable_identifier(
        "fuzz-case",
        {
            "campaign_id": spec.campaign_id,
            "campaign_seed": spec.campaign_seed,
            "case_seed": case_seed,
            "base_input_id": seed_input.seed_id,
            "mutations": [record.to_dict() for record in records],
        },
    )
    reidentified = reidentify_events(events, case_id)
    original_to_new = {
        original.event_id: changed.event_id
        for original, changed in zip(
            sorted(events, key=lambda event: (event.step, event.event_id)),
            reidentified,
        )
    }
    guidance = score_analysis_guidance(seed_input.analysis)
    truth = _retag_truth(seed_input.ground_truth, case_id, original_to_new)
    control_events = reidentify_events(seed_input.events, case_id)
    control_id_map = {
        original.event_id: changed.event_id
        for original, changed in zip(
            sorted(seed_input.events, key=lambda event: (event.step, event.event_id)),
            control_events,
        )
    }
    control_truth = _retag_truth(seed_input.ground_truth, case_id, control_id_map)
    provisional = FuzzCase(
        schema_version=FUZZING_SCHEMA_VERSION,
        campaign_id=spec.campaign_id,
        case_id=case_id,
        campaign_seed=spec.campaign_seed,
        case_seed=case_seed,
        base_input_id=seed_input.seed_id,
        base_input_hash=seed_input.source_hash,
        analysis_guidance=guidance,
        mutations=tuple(records),
        events=reidentified,
        ground_truth=truth,
        control_events=control_events,
        control_ground_truth=control_truth,
    )
    enriched = dict(guidance)
    enriched["semantic_signature"] = semantic_signature(provisional)
    return replace(provisional, analysis_guidance=enriched)


def generate_cases(
    spec: FuzzCampaignSpec,
    *,
    repository_root: str | Path = REPOSITORY_ROOT,
) -> tuple[FuzzCase, ...]:
    selected_inputs = spec.base_inputs[: min(len(spec.base_inputs), spec.limits.max_cases)]
    seeds = tuple(
        load_seed_input(value, repository_root=repository_root) for value in selected_inputs
    )
    cases = [
        _case_from_seed(spec, seeds[index % len(seeds)], index)
        for index in range(spec.limits.max_cases)
    ]
    return schedule_cases(cases)


__all__ = [
    "FuzzCorpusError",
    "REPOSITORY_ROOT",
    "generate_cases",
    "load_seed_input",
]
