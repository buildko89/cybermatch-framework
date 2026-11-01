"""Tests for CyberMatch Pilot hybrid triage pipeline."""
from __future__ import annotations

import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator

from cybermatch.pilot.triage_pipeline import (
    DEFAULT_TRIAGE_SYSTEM_PROMPT,
    TemplateTriageGateway,
    TriagePipeline,
    build_triage_user_prompt,
    extract_context,
    render_triage_report,
)


@pytest.fixture
def sample_events_01a():
    return [
        {
            "event_id": "ctx_v1_01a_e1",
            "summary": "【作業背景】2026-10-30 10:05:00〜10:05:10 JST、lab_itゾーンにて対象設備CTRL-01の温度上限値の表示照合を実施。操作端末はLAB-PC-01、担当者はLAB-OP-01（個別アカウント: lab_maint_01）。作業目的は温度上限値の表示照合。",
        },
        {
            "event_id": "ctx_v1_01a_e2",
            "summary": "【承認票原文(LAB-CHG-001)】許可操作は『GET /config/temp_limit』。",
        },
        {
            "event_id": "ctx_v1_01a_e3",
            "summary": "【権限・初期状態】作業前の設備初期状態は『温度上限80℃、設定リビジョン41』。",
        },
        {
            "event_id": "ctx_v1_01a_e4",
            "summary": "【操作監査(audit_log)】request='GET /config/temp_limit' status=completed",
        },
        {
            "event_id": "ctx_v1_01a_e5",
            "summary": "【結果照合(verify_log)】作業後の設備状態は『温度上限80℃、設定リビジョン41』。",
        },
    ]


@pytest.fixture
def sample_events_01b():
    return [
        {
            "event_id": "ctx_v1_01b_e1",
            "summary": "【作業背景】2026-10-30 10:05:00〜10:05:10 JST、lab_itゾーンにて対象設備CTRL-01の温度上限値の変更。操作端末はLAB-PC-01、担当者はLAB-OP-01（個別アカウント: lab_maint_01）。作業目的は温度上限値の表示照合。",
        },
        {
            "event_id": "ctx_v1_01b_e2",
            "summary": "【承認票原文(LAB-CHG-001)】許可操作は『GET /config/temp_limit』。",
        },
        {
            "event_id": "ctx_v1_01b_e3",
            "summary": "【権限・初期状態】作業前の設備初期状態は『温度上限80℃、設定リビジョン41』。",
        },
        {
            "event_id": "ctx_v1_01b_e4",
            "summary": "【操作監査(audit_log)】request='PUT /config/temp_limit value=95' status=completed",
        },
        {
            "event_id": "ctx_v1_01b_e5",
            "summary": "【結果照合(verify_log)】作業後の設備状態は『温度上限95℃、設定リビジョン42』。",
        },
    ]


def test_triage_schema_validity():
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "cybermatch/schemas/pilot-pipeline-triage.schema.json"
    )
    assert schema_path.exists()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)


def test_deterministic_extraction_benign(sample_events_01a):
    ctx = extract_context(sample_events_01a)
    assert ctx["device"] == "CTRL-01"
    assert ctx["zone"] == "lab_it"
    assert ctx["terminal"] == "LAB-PC-01"
    assert ctx["operator"] == "LAB-OP-01"
    assert ctx["account"] == "lab_maint_01"
    assert ctx["approved_operation"] == "GET /config/temp_limit"
    assert ctx["actual_operation"] == "GET /config/temp_limit"
    assert ctx["initial_state"] == "温度上限80℃、設定リビジョン41"
    assert ctx["final_state"] == "温度上限80℃、設定リビジョン41"
    assert ctx["diff_detected"] is False
    assert ctx["machine_assessment"] == "benign"


def test_deterministic_extraction_suspicious(sample_events_01b):
    ctx = extract_context(sample_events_01b)
    assert ctx["device"] == "CTRL-01"
    assert ctx["approved_operation"] == "GET /config/temp_limit"
    assert ctx["actual_operation"] == "PUT /config/temp_limit value=95"
    assert ctx["diff_detected"] is True
    assert ctx["machine_assessment"] == "suspicious"
    assert any("逸脱" in d for d in ctx["diff_details"])
    assert any("変更" in d for d in ctx["diff_details"])


def test_triage_user_prompt_formatting(sample_events_01a):
    ctx = extract_context(sample_events_01a)
    prompt = build_triage_user_prompt(ctx)
    assert "CTRL-01" in prompt
    assert "GET /config/temp_limit" in prompt
    assert "benign" in prompt


def test_render_triage_report_5w1h(sample_events_01b):
    ctx = extract_context(sample_events_01b)
    ctx["session_id"] = "ctx_v1_01b"

    mock_ai_resp = {
        "assessment": "suspicious",
        "summary": "LAB-OP-01は承認範囲外のPUT操作を実行し、CTRL-01の温度上限を80℃から95℃に変更しました。",
        "decision_reason": "承認されたGET操作ではなくPUT操作が実行され、設備状態が変更されたため。",
        "priority": "high",
        "priority_reason": "承認外の状態変更が成功したため高優先度で調査。",
        "action_recommendation": "操作履歴と設定変更ログを直ちに確認すること。",
    }

    report = render_triage_report(ctx, mock_ai_resp)

    # 5W1H の確認
    assert "いつ (When)" in report
    assert "どこで (Where)" in report
    assert "誰が (Who)" in report
    assert "何を・結果 (What)" in report
    assert "なぜ (Why)" in report
    assert "どのように (How)" in report

    # 必須メタデータの確認
    assert "CTRL-01" in report
    assert "LAB-OP-01" in report
    assert "lab_maint_01" in report
    assert "PUT /config/temp_limit value=95" in report
    assert "要調査（逸脱検知）" in report
    assert "高 (High)" in report


def test_template_triage_gateway_benign(sample_events_01a):
    pipeline = TriagePipeline()
    result = pipeline.run_triage(sample_events_01a, session_id="test_01a")

    assert result["session_id"] == "test_01a"
    assert result["ai_response"]["assessment"] == "benign"
    assert result["ai_response"]["priority"] == "low"
    assert "承認範囲内（通常）" in result["report_markdown"]
    assert "CTRL-01" in result["report_markdown"]


def test_template_triage_gateway_suspicious(sample_events_01b):
    pipeline = TriagePipeline()
    result = pipeline.run_triage(sample_events_01b, session_id="test_01b")

    assert result["session_id"] == "test_01b"
    assert result["ai_response"]["assessment"] == "suspicious"
    assert result["ai_response"]["priority"] == "high"
    assert "要調査（逸脱検知）" in result["report_markdown"]
    assert "PUT /config/temp_limit value=95" in result["report_markdown"]


def test_extract_context_empty_events_unknown():
    """T01 / R03: Empty events input must yield unknown (Fail-Safe), not benign."""
    ctx = extract_context([])
    assert ctx["machine_assessment"] == "unknown"
    assert ctx["diff_detected"] is False
    assert "Fail-Safe" in ctx["machine_summary"]
    assert "events_empty" in ctx["missing_elements"]


def test_extract_context_unsupported_format_unknown():
    """T02 / R03: Unrecognized format without structured tags must yield unknown (Fail-Safe)."""
    raw_events = [
        {"event_id": "raw_1", "summary": "operation=DELETE /production status=200"}
    ]
    ctx = extract_context(raw_events)
    assert ctx["machine_assessment"] == "unknown"
    assert ctx["diff_detected"] is False
    assert "no_structured_tags_matched" in ctx["missing_elements"]


def test_extract_context_approved_put_benign():
    """T03 / R07: Approved PUT operation with expected state change must yield benign."""
    approved_put_events = [
        {
            "event_id": "ctx_put_e1",
            "summary": "【作業背景】2026-10-30 11:00:00 JST、lab_itゾーンにて対象設備CTRL-01の温度上限値の定期保守変更。操作端末はLAB-PC-01、担当者はLAB-OP-01（個別アカウント: lab_maint_01）。作業目的は定期保守変更。",
        },
        {
            "event_id": "ctx_put_e2",
            "summary": "【承認票原文(LAB-CHG-002)】許可操作は『PUT /config/temp_limit value=95』。",
        },
        {
            "event_id": "ctx_put_e3",
            "summary": "【権限・初期状態】作業前の設備初期状態は『温度上限80℃、設定リビジョン41』。",
        },
        {
            "event_id": "ctx_put_e4",
            "summary": "【操作監査(audit_log)】request='PUT /config/temp_limit value=95' status=completed",
        },
        {
            "event_id": "ctx_put_e5",
            "summary": "【結果照合(verify_log)】作業後の設備状態は『温度上限95℃、設定リビジョン42』。",
        },
    ]
    ctx = extract_context(approved_put_events)
    assert ctx["machine_assessment"] == "benign"
    assert ctx["diff_detected"] is False
    assert "承認範囲内の保守操作" in ctx["machine_summary"]
    assert any("正常に変更確認 (承認範囲内)" in d for d in ctx["diff_details"])


def test_extract_context_missing_ticket_unknown():
    """Missing approval ticket must yield unknown (Fail-Safe)."""
    missing_ticket_events = [
        {
            "event_id": "ctx_no_ticket_e1",
            "summary": "【作業背景】2026-10-30 11:00:00 JST、lab_itゾーンにて対象設備CTRL-01の操作。操作端末はLAB-PC-01、担当者はLAB-OP-01（個別アカウント: lab_maint_01）。作業目的は確認。",
        },
        {
            "event_id": "ctx_no_ticket_e4",
            "summary": "【操作監査(audit_log)】request='POST /control/reboot' status=completed",
        },
    ]
    ctx = extract_context(missing_ticket_events)
    assert ctx["machine_assessment"] == "unknown"
    assert "missing_approved_operation" in ctx["missing_elements"]


class FaultyGateway:
    """Mock gateway that raises an error to test pipeline resilience."""

    def summarize(self, ctx):
        raise RuntimeError("LLM inference service unavailable (OOM / network timeout)")


class MalformedResponseGateway:
    """Mock gateway that returns malformed JSON dictionary."""

    def summarize(self, ctx):
        return {"assessment": "benign"}  # missing summary, priority, etc.


def test_pipeline_gateway_exception_fallback(sample_events_01b):
    """T04 / R08: Pipeline must gracefully fallback to deterministic template on gateway exception."""
    pipeline = TriagePipeline(gateway=FaultyGateway())
    result = pipeline.run_triage(sample_events_01b, session_id="test_fault_01")

    assert result["fallback_used"] is True
    assert "RuntimeError" in result["fallback_reason"]
    assert result["ai_response"]["fallback_used"] is True
    assert result["ai_response"]["assessment"] == "suspicious"
    assert "フォールバックして生成されました" in result["report_markdown"]


def test_pipeline_gateway_malformed_response_fallback(sample_events_01a):
    """Pipeline must fallback when gateway returns incomplete/malformed response."""
    pipeline = TriagePipeline(gateway=MalformedResponseGateway())
    result = pipeline.run_triage(sample_events_01a, session_id="test_malformed_01")

    assert result["fallback_used"] is True
    assert "malformed or incomplete" in result["fallback_reason"]
    assert result["ai_response"]["assessment"] == "benign"


def test_pipeline_unknown_assessment_fail_safe():
    """R03: When assessment is unknown, pipeline enforces Fail-Safe warning in report and prevents AI override."""
    class OverrideAttemptGateway:
        def summarize(self, ctx):
            return {
                "assessment": "benign",  # AI tries to override machine unknown!
                "summary": "AI attempts to report benign.",
                "decision_reason": "AI assumption.",
                "priority": "low",
                "priority_reason": "AI assumption.",
                "action_recommendation": "None.",
            }

    pipeline = TriagePipeline(gateway=OverrideAttemptGateway())
    result = pipeline.run_triage([], session_id="test_unknown_01")

    # Fail-Safe check: machine unknown must NOT be overridden by AI
    assert result["context"]["machine_assessment"] == "unknown"
    assert result["ai_response"]["assessment"] == "unknown"
    assert result["ai_response"]["priority"] == "medium"
    assert "自動遮断・防護ルールの自動適用は禁止されています" in result["report_markdown"]


def test_scoped_mitigation_schema_validity():
    """Phase 0: scoped-mitigation.schema.json must be valid Draft 2020-12 schema."""
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "cybermatch/schemas/scoped-mitigation.schema.json"
    )
    assert schema_path.exists()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)


def test_scoped_mitigation_schema_valid_payload():
    """Phase 0: Valid scoped mitigation policy payload passes schema validation."""
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "cybermatch/schemas/scoped-mitigation.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    valid_payload = {
        "schema_version": "1.0",
        "policy_id": "mitigation_" + "a" * 64,
        "tenant_id": "tenant-prod-alpha",
        "target_asset": "api-gateway-01",
        "target_path_scope": "/api/v1/control/temp_limit",
        "action_type": "scoped_path_block",
        "pre_approved_template_id": "tmpl_scoped_block_v1",
        "lifecycle_state": "Validated",
        "ttl_seconds": 3600,
        "config_snapshot_revision": "rev_20261101_42",
        "validation_bundle_hash": "b" * 64,
        "action_parameters": {
            "http_methods": ["POST", "PUT"],
            "block_response_code": 403,
        },
        "recovery_policy": {
            "rollback_action": "restore_previous_config",
            "trigger_conditions": ["latency_spike", "ttl_expired"],
            "max_latency_increase_pct": 5.0,
            "max_error_rate_pct": 1.0,
        },
        "kill_switch_registered": True,
        "operator_approval_ref": "TICKET-APPROVE-9981",
        "audit_metadata": {
            "created_at_utc": "2026-11-01T10:00:00Z",
            "proposed_by": "pilot-triage-pipeline-v1",
            "golden_replay_suite_id": "suite_golden_prod_oct2026",
            "golden_replay_sample_count": 3500,
        },
    }

    errors = list(validator.iter_errors(valid_payload))
    assert not errors, f"Validation errors: {errors}"


def test_scoped_mitigation_schema_invalid_payload():
    """Phase 0: Missing required fields or invalid TTL must fail schema validation."""
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "cybermatch/schemas/scoped-mitigation.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    invalid_payload = {
        "schema_version": "1.0",
        "policy_id": "invalid_policy_id",  # Invalid pattern
        "tenant_id": "tenant-prod-alpha",
        # Missing target_asset, target_path_scope, action_type, etc.
    }

    errors = list(validator.iter_errors(invalid_payload))
    assert len(errors) > 0


