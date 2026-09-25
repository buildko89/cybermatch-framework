import json

import pytest

from cybermatch.evaluation import benchmark_suites


def test_explicit_baseline_must_exist_and_is_recorded(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        benchmark_suites._phase82_load_phase63_rows(str(tmp_path / "missing.json"))

    summary = tmp_path / "mission_product_summary.json"
    summary.write_text(json.dumps({"rows": [{"profile_id": "sample_ids"}]}), encoding="utf-8")
    assert benchmark_suites._phase82_load_phase63_rows(str(summary)) == [{"profile_id": "sample_ids"}]

    benchmark_suites._write_baseline_provenance(str(tmp_path / "out"), str(summary))
    provenance = json.loads((tmp_path / "out" / benchmark_suites.BASELINE_PROVENANCE_FILENAME).read_text(encoding="utf-8"))
    assert provenance["explicit_baseline"] is True
    assert len(provenance["baseline_summary_sha256"]) == 64
