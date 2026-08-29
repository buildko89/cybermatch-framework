import json
import numpy as np
from dataclasses import dataclass
from collections.abc import Mapping, Sequence


def _string_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"hunting.{field_name} must be a list of strings")
    result = tuple(value)
    if any(not isinstance(item, str) or not item.strip() for item in result):
        raise ValueError(f"hunting.{field_name} must contain non-empty strings")
    if len(set(result)) != len(result):
        raise ValueError(f"hunting.{field_name} must not contain duplicates")
    return result


def _unit_score(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"hunting.{field_name} must be a number between 0 and 1")
    result = float(value)
    if not np.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError(f"hunting.{field_name} must be between 0 and 1")
    return result


def _non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"hunting.{field_name} must be a non-negative integer")
    return value


@dataclass(frozen=True)
class HuntingCapabilities:
    """Optional defender-side hunting capabilities for a product profile."""

    telemetry_visibility: tuple[str, ...] = ()
    observable_event_types: tuple[str, ...] = ()
    correlation_depth_steps: int = 0
    baseline_quality: float = 0.0
    enrichment_quality: float = 0.0
    ingest_latency_steps: int = 0
    supported_recipe_tags: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "HuntingCapabilities":
        if not isinstance(payload, Mapping):
            raise ValueError("product profile hunting must be a JSON object")
        allowed = {
            "telemetry_visibility",
            "observable_event_types",
            "correlation_depth_steps",
            "baseline_quality",
            "enrichment_quality",
            "ingest_latency_steps",
            "supported_recipe_tags",
        }
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise ValueError(f"product profile hunting has unknown fields: {', '.join(unknown)}")
        return cls(
            telemetry_visibility=_string_tuple(
                payload.get("telemetry_visibility", []), "telemetry_visibility"
            ),
            observable_event_types=_string_tuple(
                payload.get("observable_event_types", []), "observable_event_types"
            ),
            correlation_depth_steps=_non_negative_int(
                payload.get("correlation_depth_steps", 0), "correlation_depth_steps"
            ),
            baseline_quality=_unit_score(
                payload.get("baseline_quality", 0.0), "baseline_quality"
            ),
            enrichment_quality=_unit_score(
                payload.get("enrichment_quality", 0.0), "enrichment_quality"
            ),
            ingest_latency_steps=_non_negative_int(
                payload.get("ingest_latency_steps", 0), "ingest_latency_steps"
            ),
            supported_recipe_tags=_string_tuple(
                payload.get("supported_recipe_tags", []), "supported_recipe_tags"
            ),
        )


@dataclass
class ProductProfile:
    name: str
    category: str
    detection_boost: float = 0.0
    interruption_boost: float = 0.0
    diversion_boost: float = 0.0
    confidence_boost: float = 0.0
    false_positive_penalty: float = 0.0
    latency_penalty: float = 0.0
    maintenance_penalty: float = 0.0
    product_family: str | None = None
    hunting_mode: str | None = None
    hunting: HuntingCapabilities | None = None


def load_product_profile(path: str) -> ProductProfile:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError("product profile must be a JSON object")
    missing = [field_name for field_name in ("name", "category") if field_name not in payload]
    if missing:
        raise ValueError(f"product profile missing required fields: {', '.join(missing)}")
    category = str(payload["category"]).lower()
    if category not in ("ids", "ips", "honeypot", "deception", "xdr"):
        raise ValueError("product profile category must be one of: ids, ips, honeypot, deception, xdr")

    def _score(name: str) -> float:
        return float(np.clip(float(payload.get(name, 0.0) or 0.0), 0.0, 1.0))

    def _optional_string(name: str) -> str | None:
        value = payload.get(name)
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"product profile {name} must be a non-empty string when provided")
        return value

    hunting_payload = payload.get("hunting")
    hunting = None if hunting_payload is None else HuntingCapabilities.from_dict(hunting_payload)

    # Future hooks only:
    # - Enterprise Product Profile
    # - Vendor Product Profile
    # - Scenario Specific Product Profile
    return ProductProfile(
        name=str(payload["name"]),
        category=category,
        detection_boost=_score("detection_boost"),
        interruption_boost=_score("interruption_boost"),
        diversion_boost=_score("diversion_boost"),
        confidence_boost=_score("confidence_boost"),
        false_positive_penalty=_score("false_positive_penalty"),
        latency_penalty=_score("latency_penalty"),
        maintenance_penalty=_score("maintenance_penalty"),
        product_family=_optional_string("product_family"),
        hunting_mode=_optional_string("hunting_mode"),
        hunting=hunting,
    )


__all__ = ["HuntingCapabilities", "ProductProfile", "load_product_profile"]
