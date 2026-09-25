"""Filesystem discovery operations shared by result consumers."""

from collections.abc import Mapping
from pathlib import Path


def discover_files(root: str | Path, pattern: str) -> list[Path]:
    """Return deterministically ordered matches, or an empty list for no root."""
    directory = Path(root)
    if not directory.exists():
        return []
    return sorted(path for path in directory.glob(pattern) if path.is_file())


def missing_artifacts(artifacts: Mapping[str, Path]) -> dict[str, Path]:
    """Return named expected artifacts that are not regular files."""
    return {name: path for name, path in artifacts.items() if not path.is_file()}
