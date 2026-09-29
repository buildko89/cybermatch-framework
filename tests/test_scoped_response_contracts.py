"""対象限定対処契約の境界値・非漏洩・後方互換を検証する。"""

from dataclasses import FrozenInstanceError, replace
import json

import pytest

from cybermatch_core.contracts import AssetSchemaError, SchemaRegistry, canonical_json
from cybermatch_core.scoped_response import (
    ResponseReceipt, ResponseValidationError, ScopedResponseAction,
    ScopedResponseController, to_legacy_node_feedback,
)
from cybermatch.threat_hunting.models import Finding, HuntEvent

POLICY = "a" * 64


def action(**overrides):
    values = dict(
        run_id="run-a", tenant_id="tenant-a", finding_ids=("finding-a",),
        action_type="revoke_identity", scope_kind="identity", subject_refs=("identity-a",),
        requested_step=0, effective_step=1, expires_step=3,
        policy_hash=POLICY, reason_code="observed_credential_reuse",
    )
    values.update(overrides)
    return ScopedResponseAction.create(**values)


def observed(*, finding_id="finding-a", event_id="obs-001", step=0, **attrs):
    values = dict(run_id="run-a", tenant_id="tenant-a", available_step=step,
                  identity_ref="identity-a", node_ref="node-a", workload_ref="workload-a")
    values.update(attrs)
    event = HuntEvent(
        schema_version="1.0", event_id=event_id, step=step, campaign_id="stream-a",
        scenario_id="case-a", seed=0, actor_id=None, coalition_id=None,
        event_type="credential_use", source_node=0, target_node=1,
        source_role=None, target_role=None, signal_class="telemetry", attributes=values,
    )
    finding = Finding(
        schema_version="1.0", finding_id=finding_id, recipe_id="fixture",
        recipe_version="1.0", severity="high", score=0.9, campaign_id="stream-a",
        actor_id=None, start_step=step, end_step=step, title="合成観測",
        reason="観測証拠に基づく試験", evidence_event_ids=(event_id,),
    )
    return finding, (event,)


def controller():
    result = ScopedResponseController(
        run_id="run-a", tenant_id="tenant-a",
        subjects={"identity": ("identity-a", "identity-b"), "node": ("node-a",), "workload": ("workload-a",)},
        policy_hashes=(POLICY,),
    )
    result.tick(0)
    result.register_finding(*observed())
    return result


def test_action_roundtrip_and_immutable_sorted_copied_refs():
    refs = ["identity-b", "identity-a", "identity-a"]
    first = action(subject_refs=refs)
    refs.append("identity-c")
    assert first.subject_refs == ("identity-a", "identity-b")
    assert first == action(subject_refs=("identity-a", "identity-b"))
    assert ScopedResponseAction.from_dict(json.loads(canonical_json(first.to_dict()))) == first
    with pytest.raises(FrozenInstanceError):
        first.run_id = "changed"
    assert action(run_id="run-b").action_id != action().action_id
    assert action(tenant_id="tenant-b").action_id != action().action_id


@pytest.mark.parametrize("change", [
    {"subject_refs": ()}, {"subject_refs": "identity-a"}, {"finding_ids": ()},
    {"run_id": " "}, {"tenant_id": " tenant-a"},
    {"effective_step": 0}, {"effective_step": True}, {"requested_step": -1},
    {"expires_step": 1}, {"expires_step": 3.0}, {"expires_step": float("nan")},
    {"scope_kind": "node"}, {"action_type": "disable_everything"},
    {"policy_hash": "A" * 64}, {"reason_code": "contains private email@example"},
])
def test_action_rejects_invalid_contract(change):
    with pytest.raises(ResponseValidationError):
        action(**change)


@pytest.mark.parametrize("change", [
    {"schema_version": "2.0"}, {"action_id": "response_" + "0" * 64},
    {"expires_step": 5}, {"ground_truth": "attacker"},
    {"subject_refs": ["identity-a", "identity-a"]},
])
def test_wire_rejects_tampering_unknown_fields_and_noncanonical_arrays(change):
    payload = action().to_dict()
    payload.update(change)
    with pytest.raises(ResponseValidationError):
        ScopedResponseAction.from_dict(payload)


def test_action_half_open_interval():
    request = action()
    assert [request.active_at(t) for t in range(5)] == [False, True, True, False, False]
    with pytest.raises(ResponseValidationError):
        request.active_at(True)


def receipt(**overrides):
    req = action()
    values = dict(
        action_id=req.action_id, run_id=req.run_id, status="applied",
        recorded_step=1, effect_start_step=1, effect_end_step=3,
        affected_subject_refs=req.subject_refs, reason_code="scheduled_action_applied",
    )
    values.update(overrides)
    return ResponseReceipt(**values)


def test_receipt_roundtrip_and_action_binding():
    r = receipt()
    assert ResponseReceipt.from_dict(r.to_dict()) == r
    r.validate_for(action())
    with pytest.raises(ResponseValidationError):
        r.validate_for(action(run_id="run-b"))
    with pytest.raises(ResponseValidationError):
        receipt(affected_subject_refs=("identity-b",)).validate_for(action())


@pytest.mark.parametrize("change", [
    {"status": "pending"}, {"recorded_step": False}, {"schema_version": "2.0"},
    {"status": "rejected"}, {"effect_start_step": None}, {"effect_end_step": 1},
    {"recorded_step": 2}, {"status": "expired", "recorded_step": 2},
    {"affected_subject_refs": ()},
])
def test_receipt_rejects_impossible_effects(change):
    with pytest.raises(ResponseValidationError):
        receipt(**change)


def test_rejected_receipt_has_no_effect():
    r = receipt(status="rejected", recorded_step=0, effect_start_step=None,
                effect_end_step=None, affected_subject_refs=(), reason_code="unknown_subject")
    r.validate_for(action())
    assert ResponseReceipt.from_dict(r.to_dict()) == r


def test_registry_checks_cross_field_invariants_and_hash():
    registry = SchemaRegistry()
    registry.validate("scoped_response_action", action().to_dict())
    registry.validate("scoped_response_receipt", receipt().to_dict())
    bad = action().to_dict()
    bad["effective_step"] = 0
    with pytest.raises(AssetSchemaError):
        registry.validate("scoped_response_action", bad)
    bad = receipt().to_dict()
    bad["recorded_step"] = 2
    with pytest.raises(AssetSchemaError):
        registry.validate("scoped_response_receipt", bad)


def test_request_is_not_applied_until_next_step_and_is_idempotent():
    control = controller()
    request = action()
    assert control.submit(request) is None
    assert control.submit(request) is None
    assert control.receipts == ()
    assert not control.is_blocked("identity", "identity-a")
    assert control.tick(1)[0].status == "applied"
    assert control.is_blocked("identity", "identity-a")
    assert not control.is_blocked("identity", "identity-b")
    # nodeを観測していてもidentity対処だけでnodeを隔離しない。
    assert not control.is_blocked("node", "node-a")
    assert control.submit(request).status == "applied"
    assert len(control.receipts) == 1
    control.tick(2)
    assert control.tick(3)[0].status == "expired"
    assert not control.is_blocked("identity", "identity-a")
    assert control.submit(request).status == "expired"
    assert len(control.receipts) == 2


@pytest.mark.parametrize("change, reason", [
    ({"run_id": "run-b"}, "run_mismatch"),
    ({"tenant_id": "tenant-b"}, "tenant_mismatch"),
    ({"policy_hash": "b" * 64}, "unapproved_policy"),
    ({"subject_refs": ("unknown",)}, "unknown_subject"),
    ({"subject_refs": ("identity-b",)}, "unsupported_subject"),
    ({"finding_ids": ("unobserved",)}, "unobserved_finding"),
])
def test_controller_rejections_are_recorded_without_effect(change, reason):
    control = controller()
    r = control.submit(action(**change))
    assert r.status == "rejected" and r.reason_code == reason
    assert r.affected_subject_refs == ()
    control.tick(1)
    assert not control.is_blocked("identity", "identity-a")
    assert not control.is_blocked("identity", "identity-b")


@pytest.mark.parametrize("attrs", [
    {"tenant_id": "tenant-b"}, {"run_id": "run-b"},
    {"available_step": 1}, {"available_step": False},
    {"ground_truth": "malicious"},
])
def test_finding_rejects_cross_boundary_and_future_observation(attrs):
    control = controller()
    with pytest.raises(ResponseValidationError):
        control.register_finding(*observed(finding_id="finding-b", **attrs))


def test_finding_rejects_missing_evidence_and_redefinition():
    control = controller()
    finding, events = observed()
    with pytest.raises(ResponseValidationError):
        control.register_finding(finding, ())
    with pytest.raises(ResponseValidationError):
        control.register_finding(replace(finding, score=0.5), events)
    with pytest.raises(ResponseValidationError):
        control.register_finding(finding, (*events, *events))


def test_old_evidence_cannot_extend_duration_but_new_evidence_can():
    control = controller()
    control.submit(action())
    control.tick(1)
    refused = control.submit(action(requested_step=1, effective_step=2, expires_step=5))
    assert refused.reason_code == "no_new_evidence"
    control.register_finding(*observed(finding_id="finding-b", event_id="obs-002", step=1))
    control.submit(action(finding_ids=("finding-b",), requested_step=1, effective_step=2, expires_step=5))
    control.tick(2)
    control.tick(3)
    assert control.is_blocked("identity", "identity-a")
    control.tick(4)
    control.tick(5)
    assert not control.is_blocked("identity", "identity-a")
    assert [r.status for r in control.receipts].count("applied") == 2


def test_clock_cannot_rewind_skip_or_late_apply():
    control = controller()
    for value in (0, 2, True, -1):
        with pytest.raises(ResponseValidationError):
            control.tick(value)
    control.tick(1)
    with pytest.raises(ResponseValidationError):
        control.submit(action())
    assert control.actions == ()


def test_new_evidence_with_old_event_ids_cannot_extend_response():
    control = controller()
    control.submit(action())
    control.tick(1)
    finding, events = observed(finding_id="alternative-finding-id")
    control.register_finding(finding, events)
    rejected = control.submit(action(
        finding_ids=("alternative-finding-id",), requested_step=1, effective_step=2, expires_step=5,
    ))
    assert rejected.reason_code == "no_new_evidence"


def test_node_and_workload_scope_are_separate():
    control = controller()
    control.submit(action(action_type="quarantine_zone", scope_kind="node", subject_refs=("node-a",)))
    control.submit(action(action_type="pause_workload", scope_kind="workload", subject_refs=("workload-a",)))
    control.tick(1)
    assert control.is_blocked("node", "node-a")
    assert control.is_blocked("workload", "workload-a")
    assert not control.is_blocked("identity", "identity-a")


def test_controller_identity_and_inventory_cannot_change_through_public_api():
    refs = ["identity-a"]
    control = ScopedResponseController(
        run_id="run-a", tenant_id="tenant-a", subjects={"identity": refs}, policy_hashes=(POLICY,),
    )
    refs.append("identity-b")
    with pytest.raises(AttributeError):
        control.run_id = "run-b"
    with pytest.raises(AttributeError):
        control.tenant_id = "tenant-b"
    control.tick(0)
    control.register_finding(*observed(identity_ref="identity-b"))
    assert control.submit(action(subject_refs=("identity-b",))).reason_code == "unknown_subject"


def test_other_subjects_new_event_cannot_extend_existing_subject_action():
    control = controller()
    control.submit(action())
    control.tick(1)
    first, old_events = observed()
    _, new_events = observed(finding_id="f-b", event_id="obs-002", step=1, identity_ref="identity-b")
    combined = replace(first, finding_id="combined", end_step=1,
                       evidence_event_ids=("obs-001", "obs-002"))
    control.register_finding(combined, (*old_events, *new_events))
    denied = control.submit(action(finding_ids=("combined",), requested_step=1, effective_step=2, expires_step=8))
    assert denied.reason_code == "no_new_evidence"


def test_same_event_id_cannot_change_subject_in_a_different_finding():
    control = controller()
    with pytest.raises(ResponseValidationError):
        control.register_finding(*observed(finding_id="f-b", identity_ref="identity-b"))


def test_legacy_node_conversion_is_explicit_and_preserves_single_finding():
    request = action(action_type="quarantine_zone", scope_kind="node", subject_refs=("node-a",))
    feedback = to_legacy_node_feedback(request, run_id="run-a", tenant_id="tenant-a", node_ids={"node-a": 3})
    assert feedback.target_nodes == (3,)
    assert feedback.duration_steps == 2
    assert feedback.finding_id == "finding-a"
    for invalid in (action(), action(action_type="pause_workload", scope_kind="workload", subject_refs=("workload-a",))):
        with pytest.raises(ResponseValidationError):
            to_legacy_node_feedback(invalid, run_id="run-a", tenant_id="tenant-a", node_ids={"node-a": 3})
    for nodes in ({}, {"node-a": True}, {"node-a": -1}):
        with pytest.raises(ResponseValidationError):
            to_legacy_node_feedback(request, run_id="run-a", tenant_id="tenant-a", node_ids=nodes)
    with pytest.raises(ResponseValidationError):
        to_legacy_node_feedback(request, run_id="run-b", tenant_id="tenant-a", node_ids={"node-a": 3})
    with pytest.raises(ResponseValidationError):
        to_legacy_node_feedback(action(
            action_type="quarantine_zone", scope_kind="node", subject_refs=("node-a",), finding_ids=("f1", "f2"),
        ), run_id="run-a", tenant_id="tenant-a", node_ids={"node-a": 3})
