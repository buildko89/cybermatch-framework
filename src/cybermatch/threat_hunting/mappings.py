"""Validated field mappings for vendor-neutral external telemetry."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .models import JsonScalar, SCHEMA_VERSION, canonical_json, stable_identifier


EXTERNAL_EVENT_FIELDS = frozenset(
    {
        "event_id",
        "step",
        "actor_id",
        "coalition_id",
        "event_type",
        "source_node",
        "target_node",
        "source_role",
        "target_role",
        "signal_class",
    }
)


class ExternalMappingError(ValueError):
    """Raised when an external telemetry mapping is unsafe or incomplete."""


def _string_mapping(value: object, name: str) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise ExternalMappingError(f"{name} must be an object")
    normalized: dict[str, str] = {}
    for target, source in value.items():
        if not isinstance(target, str) or not target.strip():
            raise ExternalMappingError(f"{name} keys must be non-empty strings")
        if not isinstance(source, str) or not source.strip():
            raise ExternalMappingError(f"{name} values must be non-empty strings")
        normalized[target] = source
    if len(set(normalized.values())) != len(normalized):
        raise ExternalMappingError(f"{name} source fields must be unique")
    return MappingProxyType(normalized)


def _scalar_mapping(value: object, name: str) -> Mapping[str, JsonScalar]:
    if not isinstance(value, Mapping):
        raise ExternalMappingError(f"{name} must be an object")
    normalized: dict[str, JsonScalar] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            raise ExternalMappingError(f"{name} keys must be non-empty strings")
        if item is not None and not isinstance(item, (str, int, float, bool)):
            raise ExternalMappingError(f"{name}.{key} must be a JSON scalar")
        if isinstance(item, float) and not math.isfinite(item):
            raise ExternalMappingError(f"{name}.{key} must be finite")
        normalized[key] = item
    return MappingProxyType(normalized)


@dataclass(frozen=True)
class ExternalFieldMapping:
    """Explicit mapping from CSV/JSONL fields to :class:`HuntEvent` fields."""

    mapping_id: str
    field_map: Mapping[str, str]
    attribute_map: Mapping[str, str] = field(default_factory=dict)
    defaults: Mapping[str, JsonScalar] = field(default_factory=dict)
    timezone: str = "UTC"
    timestamp_field: str | None = None
    timestamp_format: str | None = None
    step_seconds: float = 1.0
    reject_unknown_fields: bool = True
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.mapping_id, str) or not self.mapping_id.strip():
            raise ExternalMappingError("mapping_id must be a non-empty string")
        if self.schema_version != SCHEMA_VERSION:
            raise ExternalMappingError(f"schema_version must be {SCHEMA_VERSION!r}")
        fields = _string_mapping(self.field_map, "field_map")
        unknown_targets = sorted(set(fields) - EXTERNAL_EVENT_FIELDS)
        if unknown_targets:
            raise ExternalMappingError("unknown HuntEvent fields: " + ", ".join(unknown_targets))
        attributes = _string_mapping(self.attribute_map, "attribute_map")
        if set(attributes.values()) & set(fields.values()):
            raise ExternalMappingError("field_map and attribute_map source fields must not overlap")
        defaults = _scalar_mapping(self.defaults, "defaults")
        unknown_defaults = sorted(set(defaults) - EXTERNAL_EVENT_FIELDS - set(attributes))
        if unknown_defaults:
            raise ExternalMappingError("unknown default fields: " + ", ".join(unknown_defaults))
        if "event_type" not in fields and "event_type" not in defaults:
            raise ExternalMappingError("event_type must be mapped or supplied as a default")
        if "step" not in fields and self.timestamp_field is None:
            raise ExternalMappingError("step or timestamp_field is required")
        if self.timestamp_field is not None:
            if not isinstance(self.timestamp_field, str) or not self.timestamp_field.strip():
                raise ExternalMappingError("timestamp_field must be a non-empty string")
            if self.timestamp_field in set(fields.values()) | set(attributes.values()):
                raise ExternalMappingError("timestamp_field must not overlap another source field")
        if self.timestamp_format is not None and (
            not isinstance(self.timestamp_format, str) or not self.timestamp_format.strip()
        ):
            raise ExternalMappingError("timestamp_format must be a non-empty string")
        if isinstance(self.step_seconds, bool) or not isinstance(self.step_seconds, (int, float)):
            raise ExternalMappingError("step_seconds must be a finite positive number")
        seconds = float(self.step_seconds)
        if not math.isfinite(seconds) or seconds <= 0:
            raise ExternalMappingError("step_seconds must be a finite positive number")
        if not isinstance(self.reject_unknown_fields, bool):
            raise ExternalMappingError("reject_unknown_fields must be boolean")
        try:
            ZoneInfo(self.timezone)
        except (TypeError, ZoneInfoNotFoundError) as exc:
            raise ExternalMappingError(f"unknown timezone: {self.timezone!r}") from exc
        object.__setattr__(self, "field_map", fields)
        object.__setattr__(self, "attribute_map", attributes)
        object.__setattr__(self, "defaults", defaults)
        object.__setattr__(self, "step_seconds", seconds)

    @property
    def source_fields(self) -> frozenset[str]:
        fields = set(self.field_map.values()) | set(self.attribute_map.values())
        if self.timestamp_field is not None:
            fields.add(self.timestamp_field)
        return frozenset(fields)

    @property
    def mapping_hash(self) -> str:
        return stable_identifier("mapping", self.to_dict(), length=64).split("_", 1)[1]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "mapping_id": self.mapping_id,
            "field_map": dict(self.field_map),
            "attribute_map": dict(self.attribute_map),
            "defaults": dict(self.defaults),
            "timezone": self.timezone,
            "timestamp_field": self.timestamp_field,
            "timestamp_format": self.timestamp_format,
            "step_seconds": self.step_seconds,
            "reject_unknown_fields": self.reject_unknown_fields,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ExternalFieldMapping":
        if not isinstance(payload, Mapping):
            raise ExternalMappingError("mapping payload must be an object")
        try:
            return cls(**dict(payload))
        except TypeError as exc:
            raise ExternalMappingError(f"invalid mapping fields: {exc}") from exc


def mapping_manifest(mapping: ExternalFieldMapping) -> dict[str, object]:
    """Return the canonical auditable mapping descriptor."""

    payload = mapping.to_dict()
    return {"mapping": payload, "sha256": mapping.mapping_hash, "canonical": canonical_json(payload)}


__all__ = [
    "EXTERNAL_EVENT_FIELDS",
    "ExternalFieldMapping",
    "ExternalMappingError",
    "mapping_manifest",
]
