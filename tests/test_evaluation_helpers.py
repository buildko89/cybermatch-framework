import csv
import json

import pytest

from src.cybermatch.evaluation.artifact_io import write_rows
from src.cybermatch.evaluation.statistics import mean_or_none, std_or_none, to_float


def test_statistics_helpers_preserve_runner_semantics() -> None:
    assert to_float(None) == 0.0
    assert to_float("") == 0.0
    assert to_float("2.5") == 2.5
    assert mean_or_none([]) is None
    assert std_or_none([]) is None
    assert mean_or_none([1.0, 2.0, 3.0]) == 2.0
    assert std_or_none([1.0, 2.0, 3.0]) == pytest.approx(0.816496580927726)


def test_write_rows_emits_matching_csv_and_json(tmp_path) -> None:
    rows = [{"name": "防御", "score": 1.25}, {"name": "decoy", "score": 0.5}]
    columns = ["name", "score"]
    csv_path = tmp_path / "rows.csv"
    json_path = tmp_path / "rows.json"

    write_rows(rows, columns, csv_path, json_path)

    with csv_path.open(encoding="utf-8", newline="") as stream:
        assert list(csv.DictReader(stream)) == [
            {"name": "防御", "score": "1.25"},
            {"name": "decoy", "score": "0.5"},
        ]
    assert json.loads(json_path.read_text(encoding="utf-8")) == rows
