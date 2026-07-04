import json
import numpy as np
from dataclasses import dataclass

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
    )
