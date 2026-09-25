"""Serialization helpers for tabular evaluation artifacts."""

import csv
import json
from collections.abc import Mapping, Sequence
from pathlib import Path


def write_rows(
    rows: Sequence[Mapping[str, object]],
    columns: Sequence[str],
    csv_path: str | Path,
    json_path: str | Path,
) -> None:
    """Write the same rows as stable UTF-8 CSV and human-readable JSON."""
    with Path(csv_path).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    with Path(json_path).open("w", encoding="utf-8") as stream:
        json.dump(rows, stream, indent=4, ensure_ascii=False)
