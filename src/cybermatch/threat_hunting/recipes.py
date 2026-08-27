"""Declarative threat-hunting recipe schema and safe JSON loading."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import FINDING_SEVERITIES, SCHEMA_VERSION, canonical_json


HUNT_EVENT_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "step",
        "campaign_id",
        "scenario_id",
        "seed",
        "actor_id",
        "coalition_id",
        "event_type",
        "source_node",
        "target_node",
        "source_role",
        "target_role",
        "signal_class",
        "attributes.source_history_keys",
        "attributes.ordinal",
    }
)
FILTER_PREDICATES = frozenset(
    {"eq", "ne", "in", "contains", "regex", "gt", "gte", "lt", "lte"}
)
DERIVE_FUNCTIONS = frozenset({"length", "coalesce", "difference"})
AGGREGATE_FUNCTIONS = frozenset(
    {"count", "sum", "avg", "min", "max", "distinct_count", "values"}
)
RANK_FUNCTIONS = frozenset({"top", "rare", "sort"})
WINDOW_KINDS = frozenset({"fixed", "tumbling"})
OPERATOR_REGISTRY = frozenset({"filter", "derive", "window", "aggregate", "rank", "sequence"})

_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "version",
        "title",
        "hypothesis",
        "source",
        "required_fields",
        "group_by",
        "operations",
        "finding",
        "metadata",
    }
)
_REQUIRED_TOP_LEVEL_FIELDS = _TOP_LEVEL_FIELDS - {"metadata"}


class RecipeValidationError(ValueError):
    """Raised when a recipe violates the schema or execution contract."""


class RecipeLoadError(RecipeValidationError):
    """Raised when a recipe path or JSON document is unsafe or invalid."""


def _require_mapping(value: object, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise RecipeValidationError(f"{field_name} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise RecipeValidationError(f"{field_name} keys must be strings")
    return value


def _require_exact_fields(
    payload: Mapping[str, object],
    *,
    field_name: str,
    required: set[str] | frozenset[str],
    optional: set[str] | frozenset[str] = frozenset(),
) -> None:
    missing = sorted(set(required) - set(payload))
    unknown = sorted(set(payload) - set(required) - set(optional))
    if missing:
        raise RecipeValidationError(f"{field_name} is missing fields: {', '.join(missing)}")
    if unknown:
        raise RecipeValidationError(f"{field_name} has unknown fields: {', '.join(unknown)}")


def _require_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RecipeValidationError(f"{field_name} must be a non-empty string")
    return value


def _require_bool(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise RecipeValidationError(f"{field_name} must be a boolean")
    return value


def _require_integer(
    value: object,
    field_name: str,
    *,
    minimum: int = 0,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise RecipeValidationError(f"{field_name} must be a {qualifier} integer")
    return value


def _require_number(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RecipeValidationError(f"{field_name} must be a finite number")
    result = float(value)
    if result != result or result in (float("inf"), float("-inf")):
        raise RecipeValidationError(f"{field_name} must be a finite number")
    return result


def _require_string_list(
    value: object,
    field_name: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise RecipeValidationError(f"{field_name} must be an array of strings")
    items = tuple(_require_string(item, field_name) for item in value)
    if not items and not allow_empty:
        raise RecipeValidationError(f"{field_name} must not be empty")
    if len(set(items)) != len(items):
        raise RecipeValidationError(f"{field_name} must not contain duplicates")
    return items


def _json_copy(value: object, field_name: str) -> object:
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise RecipeValidationError(f"{field_name} must contain JSON values") from exc


@dataclass(frozen=True)
class RecipeOperation:
    """One validated operation with an immutable canonical representation."""

    operator: str
    _parameters_json: str

    @property
    def parameters(self) -> dict[str, object]:
        return json.loads(self._parameters_json)

    def to_dict(self) -> dict[str, object]:
        return {"operator": self.operator, **self.parameters}


@dataclass(frozen=True)
class RecipeFinding:
    severity: str
    title: str
    reason: str
    score: float
    _condition_json: str | None = None

    @property
    def condition(self) -> dict[str, object] | None:
        return None if self._condition_json is None else json.loads(self._condition_json)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "severity": self.severity,
            "title": self.title,
            "reason": self.reason,
            "score": self.score,
        }
        if self.condition is not None:
            payload["condition"] = self.condition
        return payload


@dataclass(frozen=True)
class ThreatHuntingRecipe:
    schema_version: str
    recipe_id: str
    version: str
    title: str
    hypothesis: str
    source: str
    required_fields: tuple[str, ...]
    group_by: tuple[str, ...]
    operations: tuple[RecipeOperation, ...]
    finding: RecipeFinding
    _metadata_json: str = "{}"

    @property
    def metadata(self) -> dict[str, object]:
        return json.loads(self._metadata_json)

    @property
    def recipe_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "id": self.recipe_id,
            "version": self.version,
            "title": self.title,
            "hypothesis": self.hypothesis,
            "source": self.source,
            "required_fields": list(self.required_fields),
            "group_by": list(self.group_by),
            "operations": [operation.to_dict() for operation in self.operations],
            "finding": self.finding.to_dict(),
        }
        if self.metadata:
            payload["metadata"] = self.metadata
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ThreatHuntingRecipe":
        return validate_recipe(payload)


def _validate_field_reference(
    field: object,
    field_name: str,
    available_fields: set[str],
    required_fields: set[str],
) -> str:
    result = _require_string(field, field_name)
    if result not in available_fields:
        raise RecipeValidationError(f"{field_name} references unavailable field {result!r}")
    if result in HUNT_EVENT_FIELDS and result not in required_fields:
        raise RecipeValidationError(
            f"{field_name} field {result!r} must be declared in required_fields"
        )
    return result


def _operation(
    raw_operation: object,
    index: int,
    available_fields: set[str],
    required_fields: set[str],
    group_by: set[str],
) -> RecipeOperation:
    name = f"operations[{index}]"
    payload = _require_mapping(raw_operation, name)
    operator = _require_string(payload.get("operator"), f"{name}.operator")
    if operator not in OPERATOR_REGISTRY:
        raise RecipeValidationError(f"{name}.operator is unknown: {operator}")

    if operator == "filter":
        _require_exact_fields(
            payload,
            field_name=name,
            required={"operator", "field", "predicate", "value"},
        )
        _validate_field_reference(payload["field"], f"{name}.field", available_fields, required_fields)
        predicate = _require_string(payload["predicate"], f"{name}.predicate")
        if predicate not in FILTER_PREDICATES:
            raise RecipeValidationError(f"{name}.predicate is unknown: {predicate}")
        value = _json_copy(payload["value"], f"{name}.value")
        if predicate == "in" and (
            not isinstance(value, list) or not value
        ):
            raise RecipeValidationError(f"{name}.value must be a non-empty array for 'in'")
        if predicate == "regex" and not isinstance(value, str):
            raise RecipeValidationError(f"{name}.value must be a string for 'regex'")
        if predicate in {"gt", "gte", "lt", "lte"}:
            _require_number(value, f"{name}.value")

    elif operator == "derive":
        _require_exact_fields(
            payload,
            field_name=name,
            required={"operator", "function", "as"},
            optional={"field", "fields"},
        )
        function = _require_string(payload["function"], f"{name}.function")
        if function not in DERIVE_FUNCTIONS:
            raise RecipeValidationError(f"{name}.function is unknown: {function}")
        alias = _require_string(payload["as"], f"{name}.as")
        if alias in available_fields:
            raise RecipeValidationError(f"{name}.as must define a new field")
        if function == "length":
            if "field" not in payload or "fields" in payload:
                raise RecipeValidationError(f"{name} length requires exactly one field")
            _validate_field_reference(payload["field"], f"{name}.field", available_fields, required_fields)
        else:
            if "fields" not in payload or "field" in payload:
                raise RecipeValidationError(f"{name} {function} requires fields")
            fields = _require_string_list(payload["fields"], f"{name}.fields")
            if function == "difference" and len(fields) != 2:
                raise RecipeValidationError(f"{name}.fields must contain exactly two fields")
            for field in fields:
                _validate_field_reference(field, f"{name}.fields", available_fields, required_fields)
        available_fields.add(alias)

    elif operator == "window":
        _require_exact_fields(
            payload,
            field_name=name,
            required={"operator", "kind", "size_steps"},
            optional={"start_step"},
        )
        kind = _require_string(payload["kind"], f"{name}.kind")
        if kind not in WINDOW_KINDS:
            raise RecipeValidationError(f"{name}.kind is unknown: {kind}")
        _require_integer(payload["size_steps"], f"{name}.size_steps", minimum=1)
        if kind == "fixed":
            _require_integer(payload.get("start_step", 0), f"{name}.start_step")
        elif "start_step" in payload:
            raise RecipeValidationError(f"{name}.start_step is only valid for a fixed window")
        if "step" not in required_fields:
            raise RecipeValidationError("window operations require 'step' in required_fields")
        available_fields.update({"window_start", "window_end"})

    elif operator == "aggregate":
        _require_exact_fields(
            payload,
            field_name=name,
            required={"operator", "function", "as"},
            optional={"field"},
        )
        function = _require_string(payload["function"], f"{name}.function")
        if function not in AGGREGATE_FUNCTIONS:
            raise RecipeValidationError(f"{name}.function is unknown: {function}")
        alias = _require_string(payload["as"], f"{name}.as")
        if function == "count":
            if "field" in payload:
                raise RecipeValidationError(f"{name} count must not specify field")
        else:
            if "field" not in payload:
                raise RecipeValidationError(f"{name} {function} requires field")
            _validate_field_reference(payload["field"], f"{name}.field", available_fields, required_fields)
        preserved = set(available_fields) & {"window_start", "window_end"}
        preserved.update(field for field in available_fields if field in group_by)
        if alias in preserved:
            raise RecipeValidationError(f"{name}.as must not replace a grouping field")
        available_fields.clear()
        available_fields.update(preserved | {alias})

    elif operator == "rank":
        _require_exact_fields(
            payload,
            field_name=name,
            required={"operator", "kind", "field", "limit"},
            optional={"direction"},
        )
        kind = _require_string(payload["kind"], f"{name}.kind")
        if kind not in RANK_FUNCTIONS:
            raise RecipeValidationError(f"{name}.kind is unknown: {kind}")
        _validate_field_reference(payload["field"], f"{name}.field", available_fields, required_fields)
        _require_integer(payload["limit"], f"{name}.limit", minimum=1)
        direction = payload.get("direction", "asc")
        if direction not in ("asc", "desc"):
            raise RecipeValidationError(f"{name}.direction must be 'asc' or 'desc'")
        if kind != "sort" and "direction" in payload:
            raise RecipeValidationError(f"{name}.direction is only valid for sort")

    else:
        _require_exact_fields(
            payload,
            field_name=name,
            required={"operator", "items", "max_span_steps"},
            optional={"overlap"},
        )
        if "event_type" not in available_fields or "step" not in available_fields:
            raise RecipeValidationError(
                "sequence operations require available 'event_type' and 'step' fields"
            )
        items = payload["items"]
        if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)) or not items:
            raise RecipeValidationError(f"{name}.items must be a non-empty array")
        for item_index, raw_item in enumerate(items):
            item_name = f"{name}.items[{item_index}]"
            item = _require_mapping(raw_item, item_name)
            _require_exact_fields(
                item,
                field_name=item_name,
                required={"event_type"},
                optional={"within_steps"},
            )
            event_types = item["event_type"]
            if isinstance(event_types, str):
                _require_string(event_types, f"{item_name}.event_type")
            else:
                _require_string_list(event_types, f"{item_name}.event_type")
            if "within_steps" in item:
                if item_index == 0:
                    raise RecipeValidationError(
                        f"{item_name}.within_steps is not valid for the first item"
                    )
                _require_integer(item["within_steps"], f"{item_name}.within_steps")
        _require_integer(payload["max_span_steps"], f"{name}.max_span_steps")
        _require_bool(payload.get("overlap", False), f"{name}.overlap")
        preserved = set(available_fields) & {"window_start", "window_end"}
        preserved.update(field for field in available_fields if field in group_by)
        available_fields.clear()
        available_fields.update(preserved | {"sequence_count"})

    normalized = dict(_json_copy(payload, name))
    normalized.pop("operator")
    return RecipeOperation(
        operator=operator,
        _parameters_json=json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )


def _validate_finding(
    raw_finding: object,
    available_fields: set[str],
    required_fields: set[str],
) -> RecipeFinding:
    payload = _require_mapping(raw_finding, "finding")
    _require_exact_fields(
        payload,
        field_name="finding",
        required={"severity", "title", "reason", "score"},
        optional={"condition"},
    )
    severity = _require_string(payload["severity"], "finding.severity")
    if severity not in FINDING_SEVERITIES:
        raise RecipeValidationError(f"finding.severity is invalid: {severity}")
    score = _require_number(payload["score"], "finding.score")
    if not 0.0 <= score <= 1.0:
        raise RecipeValidationError("finding.score must be between 0 and 1")

    condition_json = None
    if "condition" in payload:
        condition = _require_mapping(payload["condition"], "finding.condition")
        _require_exact_fields(
            condition,
            field_name="finding.condition",
            required={"field", "predicate", "value"},
        )
        _validate_field_reference(
            condition["field"],
            "finding.condition.field",
            available_fields,
            required_fields,
        )
        predicate = _require_string(condition["predicate"], "finding.condition.predicate")
        if predicate not in FILTER_PREDICATES - {"regex"}:
            raise RecipeValidationError(f"finding.condition.predicate is invalid: {predicate}")
        if predicate == "in" and (
            not isinstance(condition["value"], Sequence)
            or isinstance(condition["value"], (str, bytes, bytearray))
            or not condition["value"]
        ):
            raise RecipeValidationError(
                "finding.condition.value must be a non-empty array for 'in'"
            )
        if predicate in {"gt", "gte", "lt", "lte"}:
            _require_number(condition["value"], "finding.condition.value")
        condition_copy = _json_copy(condition, "finding.condition")
        condition_json = json.dumps(
            condition_copy,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    return RecipeFinding(
        severity=severity,
        title=_require_string(payload["title"], "finding.title"),
        reason=_require_string(payload["reason"], "finding.reason"),
        score=score,
        _condition_json=condition_json,
    )


def validate_recipe(payload: Mapping[str, object]) -> ThreatHuntingRecipe:
    """Validate and normalize one schema-version 1.0 recipe."""

    recipe = _require_mapping(payload, "recipe")
    missing = sorted(_REQUIRED_TOP_LEVEL_FIELDS - set(recipe))
    unknown = sorted(set(recipe) - _TOP_LEVEL_FIELDS)
    if missing:
        raise RecipeValidationError("recipe is missing fields: " + ", ".join(missing))
    if unknown:
        raise RecipeValidationError("recipe has unknown fields: " + ", ".join(unknown))

    schema_version = _require_string(recipe["schema_version"], "schema_version")
    if schema_version != SCHEMA_VERSION:
        raise RecipeValidationError(f"schema_version must be {SCHEMA_VERSION!r}")
    source = _require_string(recipe["source"], "source")
    if source != "observed":
        raise RecipeValidationError("source must be 'observed'")

    required_fields = _require_string_list(recipe["required_fields"], "required_fields")
    unsupported_fields = sorted(set(required_fields) - HUNT_EVENT_FIELDS)
    if unsupported_fields:
        raise RecipeValidationError(
            "required_fields are not available from HistoryObservationAdapter: "
            + ", ".join(unsupported_fields)
        )
    group_by = _require_string_list(recipe["group_by"], "group_by", allow_empty=True)
    undeclared_groups = sorted(set(group_by) - set(required_fields))
    if undeclared_groups:
        raise RecipeValidationError(
            "group_by fields must be declared in required_fields: " + ", ".join(undeclared_groups)
        )

    raw_operations = recipe["operations"]
    if not isinstance(raw_operations, Sequence) or isinstance(
        raw_operations, (str, bytes, bytearray)
    ) or not raw_operations:
        raise RecipeValidationError("operations must be a non-empty array")
    available_fields = set(required_fields)
    operations = tuple(
        _operation(operation, index, available_fields, set(required_fields), set(group_by))
        for index, operation in enumerate(raw_operations)
    )
    finding = _validate_finding(recipe["finding"], available_fields, set(required_fields))
    metadata = _json_copy(recipe.get("metadata", {}), "metadata")
    if not isinstance(metadata, dict):
        raise RecipeValidationError("metadata must be an object")

    return ThreatHuntingRecipe(
        schema_version=schema_version,
        recipe_id=_require_string(recipe["id"], "id"),
        version=_require_string(recipe["version"], "version"),
        title=_require_string(recipe["title"], "title"),
        hypothesis=_require_string(recipe["hypothesis"], "hypothesis"),
        source=source,
        required_fields=required_fields,
        group_by=group_by,
        operations=operations,
        finding=finding,
        _metadata_json=json.dumps(
            metadata,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RecipeLoadError(f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


class ThreatHuntingRecipeLoader:
    """Load recipes strictly below one configured root directory."""

    def __init__(self, recipe_root: str | Path):
        self._recipe_root = Path(recipe_root).resolve()
        if not self._recipe_root.is_dir():
            raise RecipeLoadError(f"recipe root is not a directory: {self._recipe_root}")
        self._loaded: dict[tuple[str, str], Path] = {}

    @property
    def recipe_root(self) -> Path:
        return self._recipe_root

    def load(self, relative_path: str | Path) -> ThreatHuntingRecipe:
        requested = Path(relative_path)
        if requested.is_absolute():
            raise RecipeLoadError("recipe path must be relative to the configured root")
        path = (self._recipe_root / requested).resolve()
        if not path.is_relative_to(self._recipe_root) or path == self._recipe_root:
            raise RecipeLoadError("recipe path escapes the configured root")
        if path.suffix.lower() != ".json":
            raise RecipeLoadError("recipe path must use the .json extension")
        if not path.is_file():
            raise RecipeLoadError(f"recipe file not found: {requested}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
        except RecipeLoadError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RecipeLoadError(f"unable to read recipe {requested}: {exc}") from exc
        recipe = validate_recipe(payload)
        identity = (recipe.recipe_id, recipe.version)
        if identity in self._loaded:
            previous = self._loaded[identity]
            raise RecipeLoadError(
                f"duplicate recipe id/version {identity[0]!r}/{identity[1]!r}: "
                f"{previous.name}, {path.name}"
            )
        self._loaded[identity] = path
        return recipe

    def load_many(self, relative_paths: Iterable[str | Path]) -> tuple[ThreatHuntingRecipe, ...]:
        return tuple(self.load(path) for path in relative_paths)


def default_recipe_root() -> Path:
    return Path(__file__).resolve().parents[3] / "recipes" / "threat_hunting"


__all__ = [
    "AGGREGATE_FUNCTIONS",
    "DERIVE_FUNCTIONS",
    "FILTER_PREDICATES",
    "HUNT_EVENT_FIELDS",
    "OPERATOR_REGISTRY",
    "RANK_FUNCTIONS",
    "WINDOW_KINDS",
    "RecipeFinding",
    "RecipeLoadError",
    "RecipeOperation",
    "RecipeValidationError",
    "ThreatHuntingRecipe",
    "ThreatHuntingRecipeLoader",
    "default_recipe_root",
    "validate_recipe",
]
