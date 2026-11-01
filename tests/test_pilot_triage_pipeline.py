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

