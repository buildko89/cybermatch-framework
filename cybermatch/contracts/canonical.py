"""Canonical serialization shared by evaluation evidence contracts."""

from __future__ import annotations

import hashlib
import json
from typing import Mapping


def canonical_json(payload: Mapping[str, object]) -> str:
    """Return deterministic JSON suitable for identifiers and integrity hashes."""

    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_sha256(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


__all__ = ["canonical_json", "canonical_sha256"]
