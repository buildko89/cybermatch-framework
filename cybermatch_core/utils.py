"""Repository path helpers for CyberMatch modules."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def resolve_repo_path(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return ROOT / path


__all__ = [
    "ROOT",
    "resolve_repo_path",
]
