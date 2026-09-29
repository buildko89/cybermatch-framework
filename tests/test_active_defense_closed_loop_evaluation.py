from dataclasses import replace
from pathlib import Path

from cybermatch.contracts import ScopedResponseAction, load_evidence_bundle
from cybermatch.threat_hunting.active_defense import (
    ActiveDefenseEvaluationRunner, FindingAuthorization, LoggingHygieneConfig,
    LoggingHygieneTransform, StatefulResponseActionSink, TelemetryFamilyRule,
    load_active_defense_evaluation_inputs, write_active_defense_evaluation_outputs,
)


ROOT = Path(__file__).resolve().parents[1]
SPEC = "configs/active_defense/runs/t3_synthetic_closed_loop_evaluation_v1.json"
POLICY_HASH = "0" * 64


def _inputs(*, profiles=1, operations=None):
    loaded = load_active_defense_evaluation_inputs(ROOT, SPEC)
    spec = replace(loaded.spec, seeds=(0,))
    return replace(loaded, spec=spec, hygiene_profiles=loaded.hygiene_profiles[:profiles],
                   operations=loaded.operations if operations is None else tuple(operations))


def _action(run_id: str, *, tenant_id="tenant-a", subject="synthetic-id-001", finding="finding-001"):
    return ScopedResponseAction.create(
        run_id=run_id, tenant_id=tenant_id, finding_ids=(finding,), action_type="revoke_identity",
        scope_kind="identity", subject_refs=(subject,), requested_step=2, effective_step=3,
        expires_step=5, policy_hash=POLICY_HASH, reason_code="verified_identity_chain",
    )


def test_logging_hygiene_is_deterministic_and_changes_observation_only():
    source = {
        "event_id": "event-001", "observed_step": 2, "available_step": 2,
        "observation": {"event_type": "process_start", "signal_class": "telemetry",
                        "identity_ref": "synthetic-id-001", "node_ref": "node-1", "workload_ref": None,
                        "telemetry_family": "process", "exposure_class": None, "auth_result": "success",
                        "process_name": "tool.exe", "parent_process": "services.exe"},
    }
    rule = TelemetryFamilyRule(0, 3, ("auth_result",), 10)
    config = LoggingHygieneConfig.create(profile_id="field-and-delay", family_rules={"process": rule})
    transform = LoggingHygieneTransform(config)
    first = transform.apply((source,), seed=7)
    assert first == transform.apply((source,), seed=7)
    assert source["available_step"] == 2
    assert first.observations[0]["available_step"] == 5
    assert "process_name" not in first.observations[0]["observation"]


def test_retention_expiry_and_drop_are_reported_separately():
    source = {"event_id": "event-001", "observed_step": 2, "available_step": 2,
              "observation": {"event_type": "x", "signal_class": "telemetry", "identity_ref": "id-1",
                              "node_ref": "node-1", "workload_ref": None,
                              "telemetry_family": "network", "exposure_class": None}}
    expiry = LoggingHygieneConfig.create(
        profile_id="expiry", family_rules={"network": TelemetryFamilyRule(0, 5, (), 5)})
    dropped = LoggingHygieneConfig.create(
        profile_id="drop", family_rules={"network": TelemetryFamilyRule(10_000, 0, (), 10)})
    assert LoggingHygieneTransform(expiry).apply((source,), seed=0).expired_event_ids == ("event-001",)
    assert LoggingHygieneTransform(dropped).apply((source,), seed=0).dropped_event_ids == ("event-001",)


def test_response_sink_is_scoped_idempotent_next_step_and_run_isolated():
    sink = StatefulResponseActionSink(
        run_id="run-a", tenant_id="tenant-a", known_identities=("synthetic-id-001", "synthetic-id-002"),
        finding_authorizations=(FindingAuthorization("finding-001", "tenant-a", ("synthetic-id-001",)),),
    )
    action = _action("run-a")
    assert sink.submit(action) is None and sink.submit(action) is None
    assert not sink.is_identity_revoked("synthetic-id-001", step=2)
    assert sink.advance(3)[0].status == "applied"
    assert sink.is_identity_revoked("synthetic-id-001", step=3)
    assert not sink.is_identity_revoked("synthetic-id-002", step=3)
    assert len(sink.actions) == 1 and len(sink.receipts) == 1
    assert sink.advance(5)[0].status == "expired"
    assert not sink.is_identity_revoked("synthetic-id-001", step=5)
    rejected = sink.submit(_action("run-b"))
    assert rejected is not None and rejected.reason_code == "run_mismatch"


def test_unknown_subject_is_rejected_without_effect():
    sink = StatefulResponseActionSink(
        run_id="run-a", tenant_id="tenant-a", known_identities=("synthetic-id-001",),
        finding_authorizations=(FindingAuthorization("finding-001", "tenant-a", ("unknown-id",)),),
    )
    rejected = sink.submit(_action("run-a", subject="unknown-id"))
    assert rejected is not None and rejected.reason_code == "unknown_subject"
    sink.advance(3)
    assert not sink.is_identity_revoked("unknown-id", step=3)


def test_four_modes_share_graph_and_closed_modes_prevent_reauthentication_path():
    result = ActiveDefenseEvaluationRunner(_inputs()).run()
    runs = {item.mode_id: item for item in result.runs}
    assert len({item.potential_graph_hash for item in runs.values()}) == 1
    assert runs["B0_internal_open"].metrics["critical_reach_count"] == 1
    assert runs["B1_context_open"].metrics["critical_reach_count"] == 1
    assert runs["B2_internal_closed"].metrics["critical_reach_count"] == 0
    assert runs["B3_context_closed"].metrics["critical_reach_count"] == 0
    closed = runs["B3_context_closed"]
    by_id = {item.operation_id: item for item in closed.outcomes}
    assert by_id["op-004-session-continues"].status == "succeeded"
    assert by_id["op-005-reauth"].reason_code == "identity_revoked"
    assert by_id["op-005b-legitimate-reauth"].reason_code == "identity_revoked"
    assert by_id["op-006-critical"].reason_code == "no_active_session"
    assert closed.metrics["false_response_count"] == 1
    assert closed.metrics["lead_time_steps"] == 2
    assert closed.metrics["exposure_precision"] == 0.5
    assert closed.metrics["exposure_recall"] == 1.0
    assert closed.metrics["hypothesis_hit_rate"] == 1.0
    assert closed.metrics["dwell_duration_steps"] == 4
    assert closed.metrics["analyst_cost_units"] == 17
    assert [item.status for item in closed.receipts] == ["applied", "expired"]


def test_evaluator_label_change_does_not_change_detector_or_action():
    base = _inputs()
    changed = replace(base, operations=tuple(replace(item, legitimate=not item.legitimate)
                                              for item in base.operations))
    first = ActiveDefenseEvaluationRunner(base)._run_one("B3_context_closed", base.hygiene_profiles[0], 0)
    second = ActiveDefenseEvaluationRunner(changed)._run_one("B3_context_closed", changed.hygiene_profiles[0], 0)
    assert [item.to_dict() for item in first.findings] == [item.to_dict() for item in second.findings]
    assert [item.to_dict() for item in first.actions] == [item.to_dict() for item in second.actions]


def test_no_attack_has_null_time_metrics_and_no_response():
    inputs = _inputs(operations=())
    run = ActiveDefenseEvaluationRunner(inputs)._run_one("B3_context_closed", inputs.hygiene_profiles[0], 0)
    assert run.metrics["campaign_started"] is False
    assert run.metrics["time_to_detection_steps"] is None
    assert not run.findings and not run.actions and not run.receipts


def test_output_bundle_can_be_reloaded(tmp_path):
    inputs = _inputs()
    result = ActiveDefenseEvaluationRunner(inputs).run()
    destination = tmp_path / "t3-output"
    summary = write_active_defense_evaluation_outputs(
        result=result, inputs=inputs, output_dir=destination, repository_root=ROOT)
    assert load_evidence_bundle(destination).bundle_hash == summary["bundle_hash"]
    assert (destination / "actions.jsonl").is_file()
    assert "能動防御・閉ループ評価" in (destination / "report.md").read_text(encoding="utf-8")
