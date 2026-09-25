import json
from pathlib import Path

import pytest

from cybermatch.contracts import collect_input_payloads, load_evidence_bundle, write_directory_evidence_bundle
from cybermatch.evaluation import benchmark_suites
from cybermatch.evaluation.seed_robustness import (
    SEED_ROBUSTNESS_REPORT,
    phase63_rows_by_seed,
    summarize,
    write_seed_robustness,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _run_row(seed: int, profile: str, category: str, success: float, detection: float) -> dict:
    return {
        "scenario": f"phase63_profit_attacker__{profile}__profit__balanced",
        "seed": seed,
        "product_category": category,
        "product_profile_name": profile,
        "product_name": profile,
        "mission_success_score": success,
        "campaign_disruption_score": 0.1,
        "mean_attack_detection_prob": detection,
        "attacker_diversion_score": 0.0,
        "evaluation_score": 0.5 if category != "baseline" else 0.0,
        "product_effectiveness": 0.4 if category != "baseline" else 0.0,
    }


def test_phase63_rows_are_rebuilt_per_seed(tmp_path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    rows = [
        _run_row(0, "baseline", "baseline", 0.9, 0.0),
        _run_row(0, "sample_ids", "ids", 0.5, 0.6),
        _run_row(1, "baseline", "baseline", 0.9, 0.0),
        _run_row(1, "sample_ids", "ids", 0.7, 0.3),
    ]
    (runs / "summary_runs.json").write_text(json.dumps(rows), encoding="utf-8")

    by_seed = phase63_rows_by_seed(str(tmp_path), None)

    assert sorted(by_seed) == [0, 1]
    ids = {seed: next(r for r in seed_rows if r["profile_id"] == "sample_ids") for seed, seed_rows in by_seed.items()}
    # Seed 0 prevented more mission success and detected more, so it must score higher.
    assert ids[0]["mission_effectiveness"] > ids[1]["mission_effectiveness"]


def test_summarize_reports_confidence_interval_and_first_place_share() -> None:
    rows_by_seed = {
        0: [{"p": "a", "m": "x", "s": 0.9}, {"p": "b", "m": "x", "s": 0.1}],
        1: [{"p": "a", "m": "x", "s": 0.2}, {"p": "b", "m": "x", "s": 0.8}],
        2: [{"p": "a", "m": "x", "s": 0.7}, {"p": "b", "m": "x", "s": 0.3}],
    }
    summary = summarize(rows_by_seed, candidate_key="p", score_key="s", group_key="m")

    a = next(row for row in summary["rows"] if row["candidate"] == "a")
    assert a["count"] == 3
    assert a["ci95_low"] < a["mean"] < a["ci95_high"]
    assert a["top_share"] == pytest.approx(2 / 3, abs=1e-6)
    assert summary["groups"]["x"] == {"most_frequent_winner": "a", "winner_share": pytest.approx(2 / 3, abs=1e-6), "stable": False}


def test_seed_robustness_report_explains_single_seed(tmp_path) -> None:
    summary = summarize({0: [{"p": "a", "s": 0.5}]}, candidate_key="p", score_key="s")
    write_seed_robustness(str(tmp_path), summary, title="t", score_label="スコア", group_label="範囲")
    text = (tmp_path / SEED_ROBUSTNESS_REPORT).read_text(encoding="utf-8")
    assert "seed が1件のため" in text


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


def test_input_payloads_follow_referenced_repository_assets() -> None:
    payloads = collect_input_payloads(["scenarios/demos/demo_vendor_comparison.json"], repository_root=REPOSITORY_ROOT)
    assert "scenarios/demos/demo_vendor_comparison.json" in payloads
    assert "profiles/products/sample_ids.json" in payloads
    assert "topologies/enterprise.json" in payloads


def test_directory_bundle_hashes_every_file_and_detects_tampering(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CYBERMATCH_CODE_REVISION", "test-revision")
    (tmp_path / "report.md").write_text("# report\n", encoding="utf-8")
    (tmp_path / "runs").mkdir()
    (tmp_path / "runs" / "rows.json").write_text("[]", encoding="utf-8")

    bundle = write_directory_evidence_bundle(
        tmp_path,
        repository_root=REPOSITORY_ROOT,
        runner="phase63_mission_aware_product",
        scenario_id="demo",
        seeds=[0, 1],
        input_paths=["scenarios/demos/demo_vendor_comparison.json"],
        metrics={"row_count": 2},
    )

    assert bundle.run.manifest.seed == -1
    assert {artifact.path for artifact in bundle.run.artifacts} == {"report.md", "runs/rows.json"}
    assert load_evidence_bundle(tmp_path).bundle_hash == bundle.bundle_hash
    (tmp_path / "report.md").write_text("# changed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mismatch"):
        load_evidence_bundle(tmp_path)
