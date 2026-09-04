"""Strict JSON campaign specifications for analysis-guided fuzzing."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .models import ExecutionLimits, FUZZING_SCHEMA_VERSION, JsonValue, frozen_json_mapping, json_copy


CAMPAIGN_MODES = frozenset({"semantic"})
TARGET_ADAPTERS = frozenset(
    {"threat_hunting_engine", "threat_hunting_closed_loop", "external_sut"}
)
ORACLE_IDS = frozenset(
    {
        "no_unhandled_exception",
        "deterministic_replay",
        "ground_truth_detection",
        "detection_latency",
        "containment",
        "open_closed_metamorphic",
        "external_execution_health",
    }
)
MUTATOR_PARAMETER_FIELDS = {
    "shift_step": frozenset({"range", "values"}),
    "drop_event": frozenset({"max_count"}),
    "duplicate_semantic_event": frozenset({"max_count"}),
    "insert_benign_noise": frozenset({"max_count", "event_types"}),
    "boundary_numeric_attribute": frozenset({"values"}),
    "feedback_timing": frozenset({"delays"}),
    "topology_path": frozenset({"paths", "max_post_alert_blast_radius"}),
    "defense_failure_domain": frozenset({"domains", "max_count"}),
}

DEFENSE_FAILURE_DOMAINS = frozenset(
    {"monitoring", "edge_blocking", "redirect", "additional_auth"}
)
EXTERNAL_FORMATS = frozenset({"jsonl", "csv"})
EXTERNAL_TRANSPORTS = frozenset({"mock", "command"})
EXTERNAL_TARGET_FIELDS = frozenset(
    {
        "transport",
        "mapping_path",
        "input_format",
        "output_format",
        "sut_id",
        "sut_version",
        "max_retries",
        "retry_backoff_ms",
        "timeout_seconds",
        "rate_limit_per_second",
        "command_id",
        "command_allowlist",
        "allow_external_execution",
    }
)


class FuzzSpecError(ValueError):
    """Raised when a campaign specification is unsafe or ambiguous."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FuzzSpecError(f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise FuzzSpecError(f"{name} must be an object")
    return value


def _exact_fields(
    value: Mapping[str, object],
    name: str,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required - optional)
    if missing:
        raise FuzzSpecError(f"{name} is missing fields: {', '.join(missing)}")
    if unknown:
        raise FuzzSpecError(f"{name} has unknown fields: {', '.join(unknown)}")


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FuzzSpecError(f"{name} must be a non-empty string")
    return value


def _strings(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise FuzzSpecError(f"{name} must be a non-empty array")
    result = tuple(_string(item, name) for item in value)
    if len(set(result)) != len(result):
        raise FuzzSpecError(f"{name} must not contain duplicates")
    return result


def _optional_strings(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise FuzzSpecError(f"{name} must be an array")
    result = tuple(_string(item, name) for item in value)
    if len(set(result)) != len(result):
        raise FuzzSpecError(f"{name} must not contain duplicates")
    return result


def _non_negative_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FuzzSpecError(f"{name} must be a non-negative integer")
    return value


def _validate_external_config(value: Mapping[str, object]) -> Mapping[str, JsonValue]:
    required = {
        "transport",
        "mapping_path",
        "input_format",
        "output_format",
        "sut_id",
        "sut_version",
        "max_retries",
        "retry_backoff_ms",
        "timeout_seconds",
        "rate_limit_per_second",
    }
    _exact_fields(value, "target.external", required, set(EXTERNAL_TARGET_FIELDS) - required)
    transport = _string(value["transport"], "target.external.transport")
    if transport not in EXTERNAL_TRANSPORTS:
        raise FuzzSpecError("target.external.transport is unsupported")
    for name in ("mapping_path", "sut_id", "sut_version"):
        _string(value[name], f"target.external.{name}")
    for name in ("input_format", "output_format"):
        selected = _string(value[name], f"target.external.{name}")
        if selected not in EXTERNAL_FORMATS:
            raise FuzzSpecError(f"target.external.{name} is unsupported")
    _non_negative_integer(value["max_retries"], "target.external.max_retries")
    _non_negative_integer(value["retry_backoff_ms"], "target.external.retry_backoff_ms")
    _positive_number(value["timeout_seconds"], "target.external.timeout_seconds")
    _positive_number(value["rate_limit_per_second"], "target.external.rate_limit_per_second")
    command_fields = {"command_id", "command_allowlist", "allow_external_execution"}
    present = command_fields & set(value)
    if transport == "command":
        if present != command_fields:
            raise FuzzSpecError(
                "command transport requires command_id, command_allowlist, and allow_external_execution"
            )
        _string(value["command_id"], "target.external.command_id")
        _string(value["command_allowlist"], "target.external.command_allowlist")
        if value["allow_external_execution"] is not True:
            raise FuzzSpecError(
                "command transport requires allow_external_execution=true explicit opt-in"
            )
    elif present:
        raise FuzzSpecError("mock transport must not define command execution fields")
    return frozen_json_mapping(value, "target.external")


def _positive_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FuzzSpecError(f"{name} must be a positive finite number")
    result = float(value)
    if not math.isfinite(result) or result <= 0.0:
        raise FuzzSpecError(f"{name} must be a positive finite number")
    return result


@dataclass(frozen=True)
class FuzzTargetSpec:
    adapter: str
    recipes: tuple[str, ...]
    external: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.adapter not in TARGET_ADAPTERS:
            raise FuzzSpecError(f"target.adapter is unsupported: {self.adapter}")
        recipes = tuple(self.recipes)
        if any(not isinstance(value, str) or not value for value in recipes):
            raise FuzzSpecError("target.recipes must contain non-empty strings")
        if len(set(recipes)) != len(recipes):
            raise FuzzSpecError("target.recipes must not contain duplicates")
        external = frozen_json_mapping(self.external, "target.external")
        if self.adapter == "external_sut":
            external = _validate_external_config(external)
            if external["transport"] == "mock" and not recipes:
                raise FuzzSpecError("mock external target requires at least one recipe")
        else:
            if not recipes:
                raise FuzzSpecError("internal target requires at least one recipe")
            if external:
                raise FuzzSpecError("target.external is only valid for external_sut")
        object.__setattr__(self, "recipes", recipes)
        object.__setattr__(self, "external", external)

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"adapter": self.adapter, "recipes": list(self.recipes)}
        if self.external:
            result["external"] = json_copy(dict(self.external), "target.external")
        return result


@dataclass(frozen=True)
class MutatorSpec:
    mutator_id: str
    weight: float
    parameters: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.mutator_id not in MUTATOR_PARAMETER_FIELDS:
            raise FuzzSpecError(f"mutator is unsupported: {self.mutator_id}")
        object.__setattr__(self, "weight", _positive_number(self.weight, "mutator.weight"))
        parameters = frozen_json_mapping(self.parameters, "mutator parameters")
        unknown = sorted(set(parameters) - MUTATOR_PARAMETER_FIELDS[self.mutator_id])
        if unknown:
            raise FuzzSpecError(
                f"mutator {self.mutator_id} has unknown parameters: {', '.join(unknown)}"
            )
        if self.mutator_id == "feedback_timing":
            delays = parameters.get("delays")
            if (
                not isinstance(delays, list)
                or not delays
                or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in delays)
            ):
                raise FuzzSpecError("feedback_timing.delays must contain non-negative integers")
        elif self.mutator_id == "topology_path":
            paths = parameters.get("paths")
            if not isinstance(paths, list) or not paths:
                raise FuzzSpecError("topology_path.paths must be a non-empty array")
            for index, path in enumerate(paths):
                if not isinstance(path, Mapping):
                    raise FuzzSpecError(f"topology_path.paths[{index}] must be an object")
                _exact_fields(
                    path,
                    f"topology_path.paths[{index}]",
                    {"source_node", "target_node", "boundary_id", "prohibited"},
                )
                for field_name in ("source_node", "target_node"):
                    value = path[field_name]
                    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                        raise FuzzSpecError(
                            f"topology_path.paths[{index}].{field_name} must be a non-negative integer"
                        )
                _string(path["boundary_id"], f"topology_path.paths[{index}].boundary_id")
                if not isinstance(path["prohibited"], bool):
                    raise FuzzSpecError(
                        f"topology_path.paths[{index}].prohibited must be a boolean"
                    )
            maximum = parameters.get("max_post_alert_blast_radius", 0)
            if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 0:
                raise FuzzSpecError(
                    "topology_path.max_post_alert_blast_radius must be a non-negative integer"
                )
        elif self.mutator_id == "defense_failure_domain":
            domains = parameters.get("domains")
            if (
                not isinstance(domains, list)
                or not domains
                or any(value not in DEFENSE_FAILURE_DOMAINS for value in domains)
                or len(set(domains)) != len(domains)
            ):
                raise FuzzSpecError(
                    "defense_failure_domain.domains must contain unique supported domains"
                )
            maximum = parameters.get("max_count", 1)
            if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
                raise FuzzSpecError("defense_failure_domain.max_count must be a positive integer")
        object.__setattr__(self, "parameters", parameters)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.mutator_id,
            "weight": self.weight,
            **json_copy(dict(self.parameters), "mutator parameters"),
        }


@dataclass(frozen=True)
class FuzzCampaignSpec:
    schema_version: str
    campaign_id: str
    mode: str
    base_inputs: tuple[str, ...]
    target: FuzzTargetSpec
    campaign_seed: int
    limits: ExecutionLimits
    mutators: tuple[MutatorSpec, ...]
    oracles: tuple[str, ...]
    output_dir: str

    def __post_init__(self) -> None:
        if self.schema_version != FUZZING_SCHEMA_VERSION:
            raise FuzzSpecError(f"schema_version must be {FUZZING_SCHEMA_VERSION!r}")
        _string(self.campaign_id, "id")
        if self.mode not in CAMPAIGN_MODES:
            raise FuzzSpecError(f"mode must be one of: {', '.join(sorted(CAMPAIGN_MODES))}")
        if not self.base_inputs:
            raise FuzzSpecError("base_inputs must not be empty")
        if any(not isinstance(value, str) or not value for value in self.base_inputs):
            raise FuzzSpecError("base_inputs must contain non-empty strings")
        if len(set(self.base_inputs)) != len(self.base_inputs):
            raise FuzzSpecError("base_inputs must not contain duplicates")
        if isinstance(self.campaign_seed, bool) or not isinstance(self.campaign_seed, int) or self.campaign_seed < 0:
            raise FuzzSpecError("generation.campaign_seed must be a non-negative integer")
        if not self.mutators:
            raise FuzzSpecError("mutators must not be empty")
        if len({mutator.mutator_id for mutator in self.mutators}) != len(self.mutators):
            raise FuzzSpecError("mutator IDs must not contain duplicates")
        if not self.oracles or any(value not in ORACLE_IDS for value in self.oracles):
            raise FuzzSpecError("oracles contains an unsupported oracle")
        if len(set(self.oracles)) != len(self.oracles):
            raise FuzzSpecError("oracles must not contain duplicates")
        _string(self.output_dir, "output_dir")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "id": self.campaign_id,
            "mode": self.mode,
            "base_inputs": list(self.base_inputs),
            "target": self.target.to_dict(),
            "generation": {
                "campaign_seed": self.campaign_seed,
                **self.limits.to_dict(),
            },
            "mutators": [mutator.to_dict() for mutator in self.mutators],
            "oracles": list(self.oracles),
            "output_dir": self.output_dir,
        }


def validate_campaign_spec(payload: Mapping[str, object]) -> FuzzCampaignSpec:
    root = _mapping(payload, "campaign")
    _exact_fields(
        root,
        "campaign",
        {"schema_version", "id", "mode", "base_inputs", "target", "generation", "mutators", "oracles", "output_dir"},
    )
    target = _mapping(root["target"], "target")
    _exact_fields(target, "target", {"adapter", "recipes"}, {"external"})
    generation = _mapping(root["generation"], "generation")
    _exact_fields(
        generation,
        "generation",
        {"campaign_seed", "max_cases", "max_events_per_case", "max_mutations_per_case"},
        {"max_runtime_seconds"},
    )
    raw_mutators = root["mutators"]
    if not isinstance(raw_mutators, list) or not raw_mutators:
        raise FuzzSpecError("mutators must be a non-empty array")
    mutators: list[MutatorSpec] = []
    for index, raw in enumerate(raw_mutators):
        item = _mapping(raw, f"mutators[{index}]")
        _exact_fields(item, f"mutators[{index}]", {"id", "weight"}, set(item) - {"id", "weight"})
        mutator_id = _string(item["id"], f"mutators[{index}].id")
        mutators.append(
            MutatorSpec(
                mutator_id=mutator_id,
                weight=_positive_number(item["weight"], f"mutators[{index}].weight"),
                parameters={key: value for key, value in item.items() if key not in {"id", "weight"}},
            )
        )
    try:
        limits = ExecutionLimits(
            max_cases=generation["max_cases"],
            max_events_per_case=generation["max_events_per_case"],
            max_mutations_per_case=generation["max_mutations_per_case"],
            max_runtime_seconds=generation.get("max_runtime_seconds", 10.0),
        )
    except ValueError as exc:
        raise FuzzSpecError(str(exc)) from exc
    return FuzzCampaignSpec(
        schema_version=_string(root["schema_version"], "schema_version"),
        campaign_id=_string(root["id"], "id"),
        mode=_string(root["mode"], "mode"),
        base_inputs=_strings(root["base_inputs"], "base_inputs"),
        target=FuzzTargetSpec(
            adapter=_string(target["adapter"], "target.adapter"),
            recipes=_optional_strings(target["recipes"], "target.recipes"),
            external=_mapping(target.get("external", {}), "target.external"),
        ),
        campaign_seed=generation["campaign_seed"],
        limits=limits,
        mutators=tuple(mutators),
        oracles=_strings(root["oracles"], "oracles"),
        output_dir=_string(root["output_dir"], "output_dir"),
    )


def load_campaign_spec(path: str | Path) -> FuzzCampaignSpec:
    source = Path(path)
    if not source.is_file():
        raise FuzzSpecError(f"campaign file not found: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except FuzzSpecError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FuzzSpecError(f"unable to read campaign: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise FuzzSpecError("campaign root must be an object")
    return validate_campaign_spec(payload)


__all__ = [
    "CAMPAIGN_MODES",
    "DEFENSE_FAILURE_DOMAINS",
    "EXTERNAL_FORMATS",
    "EXTERNAL_TARGET_FIELDS",
    "EXTERNAL_TRANSPORTS",
    "FuzzCampaignSpec",
    "FuzzSpecError",
    "FuzzTargetSpec",
    "MUTATOR_PARAMETER_FIELDS",
    "MutatorSpec",
    "ORACLE_IDS",
    "TARGET_ADAPTERS",
    "load_campaign_spec",
    "validate_campaign_spec",
]
