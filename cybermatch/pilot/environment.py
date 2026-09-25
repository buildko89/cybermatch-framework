"""Minimal allowlisted .env loader for pilot operational settings."""

from __future__ import annotations

import os
from pathlib import Path

from .policy import LLMPolicyError


ALLOWED_ENV_KEYS = frozenset(
    {"ORCAROUTER_API_KEY", "CYBERMATCH_PILOT_LLM_CONFIG"}
)


def load_pilot_environment(repository_root: str | Path) -> tuple[str, ...]:
    """Load allowlisted values from ``.env`` without overriding the process."""

    path = Path(repository_root).resolve() / ".env"
    if not path.exists():
        return ()
    loaded: list[str] = []
    seen: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LLMPolicyError("pilot .env could not be read") from exc
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise LLMPolicyError(f"pilot .env line {line_number} is invalid")
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if key not in ALLOWED_ENV_KEYS:
            raise LLMPolicyError(f"pilot .env key is not allowed: {key}")
        if key in seen:
            raise LLMPolicyError(f"pilot .env contains duplicate key: {key}")
        seen.add(key)
        value = _unquote(raw_value.strip(), line_number)
        if value and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return tuple(loaded)


def _unquote(value: str, line_number: int) -> str:
    if not value:
        return ""
    if value[0] in {'"', "'"}:
        if len(value) < 2 or value[-1] != value[0]:
            raise LLMPolicyError(f"pilot .env line {line_number} has unmatched quotes")
        return value[1:-1]
    return value


__all__ = ["ALLOWED_ENV_KEYS", "load_pilot_environment"]
