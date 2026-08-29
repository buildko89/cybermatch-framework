import csv
import json

import pytest

from cybermatch_core.threat_hunting import (
    AnalystCostProfile,
    HistoryGroundTruthAdapter,
    HistoryObservationAdapter,
    ThreatHuntingArtifactWriter,
    ThreatHuntingEngine,
    ThreatHuntingEvaluator,
    ThreatHuntingRecipeLoader,
    ThreatHuntingReportError,
    ThreatHuntingReportExistsError,
    ThreatHuntingReportWriter,
    ThreatHuntingRunConfig,
    default_recipe_root,
    load_threat_hunting_artifacts,
    load_threat_hunting_report,
)


def _history():
    return {
        "observable_events": [
            "credential_use",
            "critical_path_entry",
            "critical_path_progress|critical_path_near_target",
            "critical_path_progress|critical_path_near_target",
        ],
        "critical_path_events": [
            "",
            "critical_path_entry",
            "critical_path_progress|critical_path_near_target",
            "critical_path_progress|critical_path_near_target",
        ],
        "critical_compromise": [False, False, True, True],
        "attacker_success": [False, True, False, False],
        "attacker_selected_target": [1, 2, 2, 2],
        "true_mission_history": ["profit", "profit", "profit", "profit"],
    }


def _write_evaluation(output_dir, *, cost_profile=None):
    history = _history()
    events = HistoryObservationAdapter().adapt(
        history,
        campaign_id="campaign",
        scenario_id="scenario",
        seed=5,
    )
    labels = HistoryGroundTruthAdapter().adapt(history, campaign_id="campaign")
    recipe = ThreatHuntingRecipeLoader(default_recipe_root()).load(
        "critical_path_approach_v1.json"
    )
    config = ThreatHuntingRunConfig()
    findings = ThreatHuntingEngine(config).run(recipe, events)
    ThreatHuntingArtifactWriter(output_dir).write(
        events=events,
        findings=findings,
        recipe=recipe,
        config=config,
        source_history=history,
        campaign_id="campaign",
        scenario_id="scenario",
        seed=5,
    )
    evaluation = ThreatHuntingEvaluator().evaluate(
        findings,
        labels,
        events=events,
        total_steps=4,
        cost_profile=cost_profile,
    )
    paths = ThreatHuntingReportWriter(output_dir).write(
        evaluation=evaluation,
        findings=findings,
        ground_truth=labels,
    )
    return paths, evaluation, labels, findings


def _cost_profile():
    return AnalystCostProfile(
        profile_id="report-profile",
        w_triage=1,
        w_evidence=0.25,
        w_context=2,
        w_escalation=3,
        w_false_positive=4,
        w_false_evidence=0.5,
    )


def test_reporting_writes_reloadable_evaluation_artifacts_and_manifest_provenance(tmp_path):
    paths, evaluation, labels, findings = _write_evaluation(
        tmp_path / "run", cost_profile=_cost_profile()
    )

    loaded = load_threat_hunting_report(paths.output_dir)
    base = load_threat_hunting_artifacts(paths.output_dir)

    assert loaded.evaluation.to_dict() == evaluation.to_dict()
    assert loaded.ground_truth == tuple(labels)
    assert loaded.artifact_hash == paths.artifact_hash == base.artifact_hash
    assert loaded.manifest["evaluation_mode"] is True
    assert loaded.manifest["truth_matching_policy"]["sha256"] == (
        evaluation.matching_policy.policy_hash
    )
    assert loaded.manifest["cost_profile"]["sha256"] == (
        evaluation.cost_profile.profile_hash
    )
    assert set(loaded.manifest["artifacts"]).issuperset(
        {
            "metrics.json",
            "findings.csv",
            "THREAT_HUNTING_REPORT.md",
            "ground_truth/labels.json",
            "ground_truth/matching.json",
        }
    )

    rows = list(csv.DictReader(paths.findings_csv.read_text(encoding="utf-8").splitlines()))
    assert len(rows) == len(findings)
    assert {row["truth_status"] for row in rows} <= {"true_positive", "false_positive"}
    assert "Analyst burden" in paths.report.read_text(encoding="utf-8")


def test_reporting_without_cost_profile_uses_null_weighted_metrics(tmp_path):
    paths, evaluation, *_ = _write_evaluation(tmp_path / "run")

    metrics = json.loads(paths.metrics.read_text(encoding="utf-8"))

    assert metrics["metrics"]["operational_burden"] is None
    assert metrics["metrics"]["wasted_burden"] is None
    assert metrics["metrics"]["hunting_value_score"] is None
    assert "hunting_roi" not in metrics["metrics"]
    assert evaluation.cost_profile is None
    assert "no AnalystCostProfile" in paths.report.read_text(encoding="utf-8")


def test_same_evaluation_inputs_produce_identical_reports_and_bundle_hashes(tmp_path):
    first, *_ = _write_evaluation(tmp_path / "first", cost_profile=_cost_profile())
    second, *_ = _write_evaluation(tmp_path / "second", cost_profile=_cost_profile())

    assert first.artifact_hash == second.artifact_hash
    for relative in (
        "metrics.json",
        "findings.csv",
        "THREAT_HUNTING_REPORT.md",
        "ground_truth/labels.json",
        "ground_truth/matching.json",
        "threat_hunting_manifest.json",
    ):
        assert (first.output_dir / relative).read_bytes() == (
            second.output_dir / relative
        ).read_bytes()


def test_report_writer_never_overwrites_existing_artifacts(tmp_path):
    paths, evaluation, labels, findings = _write_evaluation(tmp_path / "run")

    with pytest.raises(ThreatHuntingReportExistsError, match="already exists"):
        ThreatHuntingReportWriter(paths.output_dir).write(
            evaluation=evaluation,
            findings=findings,
            ground_truth=labels,
        )


def test_report_loader_detects_tampering(tmp_path):
    paths, *_ = _write_evaluation(tmp_path / "run")
    paths.metrics.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ThreatHuntingReportError, match="hash verification failed"):
        load_threat_hunting_report(paths.output_dir)
