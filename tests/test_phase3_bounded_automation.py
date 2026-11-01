"""Tests for CyberMatch Phase 3 Bounded Automation Pipeline and PSIRT Hand-off."""
from __future__ import annotations

import json
import urllib.request
import urllib.error
import pytest

from cybermatch.defense import (
    LabProxyGateway,
    ProxyEnforcementAdapter,
    MitigationPipelineOrchestrator,
    generate_golden_replay_dataset,
)


@pytest.fixture
def automation_env():
    """Setup live proxy gateway and mitigation orchestrator on loopback."""
    gateway = LabProxyGateway(gateway_id="phase3-test-proxy")
    gateway.start()
    adapter = ProxyEnforcementAdapter(proxy_base_url=gateway.proxy_url)
    orchestrator = MitigationPipelineOrchestrator(proxy_adapter=adapter)
    dataset = generate_golden_replay_dataset(seed=42, normal_count=500, attack_count=20)
    yield gateway, adapter, orchestrator, dataset
    gateway.stop()


def _http_req(url: str, method: str = "GET", data: dict | None = None) -> tuple[int, dict]:
    body = json.dumps(data).encode("utf-8") if data else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def test_end_to_end_bounded_automation_flow(automation_env):
    """Verify complete bounded automation: triage, pre-flight sim, gate, deploy, effect confirm, PSIRT hand-off."""
    gateway, _, orchestrator, dataset = automation_env

    # 1. Incident events indicating unauthorized exploit attempt on /api/v1/control/exploit
    incident_events = [
        {
            "event_id": "ev_p3_1",
            "summary": "【作業背景】2026-10-31 14:00:00 JST、lab_itゾーンにて対象設備CTRL-01の確認。操作端末はLAB-PC-01、担当者はLAB-OP-01（個別アカウント: lab_maint_01）。作業目的は通常確認。",
        },
        {
            "event_id": "ev_p3_2",
            "summary": "【承認票原文(LAB-CHG-901)】許可操作は『GET /config/temp_limit』。",
        },
        {
            "event_id": "ev_p3_3",
            "summary": "【権限・初期状態】作業前の設備初期状態は『温度上限80℃、設定リビジョン41』。",
        },
        {
            "event_id": "ev_p3_4",
            "summary": "【操作監査(audit_log)】request='POST /api/v1/control/exploit cmd=whoami' status=completed",
        },
        {
            "event_id": "ev_p3_5",
            "summary": "【結果照合(verify_log)】作業後の設備状態は『温度上限80℃、設定リビジョン41』。",
        },
    ]

    template = {
        "pre_approved_template_id": "tmpl_scoped_block_v1",
        "action_type": "scoped_path_block",
        "ttl_seconds": 7200,
        "target_path_scope": "/api/v1/control/exploit",
        "action_parameters": {
            "http_methods": ["POST", "PUT"],
            "allow_approved_maintenance": True,
        },
    }

    # Execute automated mitigation
    res = orchestrator.execute_automated_mitigation(
        incident_events=incident_events,
        candidate_template=template,
        golden_dataset=dataset,
        session_id="session-test-p3-01",
    )

    assert res["status"] == "effective_and_observing"
    assert res["ttm_ms"] < 120000.0  # Well within 120s requirement
    assert res["mitigation_receipt"]["read_back_confirmed"] is True
    assert res["mitigation_receipt"]["effect_confirmed"] is True

    # Real HTTP Client Check: Exploit endpoint is now blocked with 403 Forbidden
    status, body = _http_req(f"{gateway.proxy_url}/api/v1/control/exploit", method="POST", data={"cmd": "whoami"})
    assert status == 403
    assert "Forbidden by CyberMatch Scoped Mitigation" in body["error"]

    # Real HTTP Client Check: Normal business endpoint remains unharmed (200 OK)
    status, body = _http_req(f"{gateway.proxy_url}/api/v1/business/status")
    assert status == 200
    assert body["status"] == "operational"

    # Verify Hand-off Manifest
    manifest = res["handoff_manifest"]
    assert manifest is not None
    assert "pki_signature" in manifest
    assert manifest["pki_signature"]["verified"] is True
    assert "retro_hunt_period" in manifest
    assert "reproduction_test_code" in manifest

    # Verify Developer Reproduction Test Code is syntactically valid Python
    code = manifest["reproduction_test_code"]
    assert "test_reproduce_and_verify_permanent_patch" in code
    compiled = compile(code, "<string>", "exec")
    assert compiled is not None

    # Verify PSIRT Report Content
    report_md = manifest["handoff_report_markdown"]
    assert "PSIRT インシデント即時防護完了＆恒久対策引継ぎレポート" in report_md
    assert "デジタルツイン事前検証" in report_md
    assert "遡及調査 (Retro-hunt) ガイダンス" in report_md
    assert "暗号学的完全性保証" in report_md


def test_bounded_automation_aborts_on_fail_safe_unknown(automation_env):
    """Pipeline must abort and forbid automated mitigation when triage returns unknown (Fail-Safe: R03)."""
    gateway, _, orchestrator, dataset = automation_env

    # Empty events -> Triage returns unknown
    res = orchestrator.execute_automated_mitigation(
        incident_events=[],
        candidate_template={"pre_approved_template_id": "tmpl_scoped_block_v1"},
        golden_dataset=dataset,
        session_id="session-unknown-fail-safe",
    )

    assert res["status"] == "aborted_fail_safe"
    assert "Fail-Safe rules" in res["reason"]
    assert res["mitigation_receipt"] is None

    # Verify proxy was NOT touched (exploit endpoint still responds normally)
    status, body = _http_req(f"{gateway.proxy_url}/api/v1/business/status")
    assert status == 200


def test_bounded_automation_rejects_on_safety_violation(automation_env):
    """Pipeline must halt deployment if pre-flight twin simulation detects false positives."""
    _, _, orchestrator, dataset = automation_env

    # Event indicating incident
    incident_events = [
        {
            "event_id": "ev_p3_bad_1",
            "summary": "【作業背景】2026-10-31 14:00:00 JST、lab_itゾーンCTRL-01。担当者LAB-OP-01（lab_maint_01）。",
        },
        {
            "event_id": "ev_p3_bad_2",
            "summary": "【承認票原文(LAB-CHG-902)】許可操作は『GET /config/temp_limit』。",
        },
        {
            "event_id": "ev_p3_bad_3",
            "summary": "【操作監査(audit_log)】request='POST /api/v1/control/exploit' status=completed",
        },
    ]

    # Template with dangerous scope that blocks normal business traffic!
    dangerous_template = {
        "pre_approved_template_id": "tmpl_bad_scope",
        "action_type": "scoped_path_block",
        "ttl_seconds": 3600,
        "target_path_scope": "/api/v1/business",  # Would block legitimate business status!
        "action_parameters": {"http_methods": ["GET", "POST"]},
    }

    res = orchestrator.execute_automated_mitigation(
        incident_events=incident_events,
        candidate_template=dangerous_template,
        golden_dataset=dataset,
        session_id="session-safety-violation",
    )

    assert res["status"] == "rejected_safety_violation"
    assert "Twin simulation failed safety check" in res["reason"]
    assert res["mitigation_receipt"] is None


def test_decommissioning_and_rollback_after_permanent_patch(automation_env):
    """Verify virtual patch is safely decommissioned and rolled back when permanent patch is released."""
    gateway, _, orchestrator, dataset = automation_env

    incident_events = [
        {"event_id": "e1", "summary": "【作業背景】2026-10-31 14:00:00 JST、lab_itゾーンCTRL-01。担当者LAB-OP-01（lab_maint_01）。"},
        {"event_id": "e2", "summary": "【承認票原文(LAB-CHG-903)】許可操作は『GET /config/temp_limit』。"},
        {"event_id": "e3", "summary": "【操作監査(audit_log)】request='POST /api/v1/control/exploit' status=completed"},
    ]
    template = {
        "pre_approved_template_id": "tmpl_scoped_block_v1",
        "action_type": "scoped_path_block",
        "ttl_seconds": 7200,
        "target_path_scope": "/api/v1/control/exploit",
    }

    # 1. Deploy mitigation
    res = orchestrator.execute_automated_mitigation(incident_events, template, dataset)
    assert res["status"] == "effective_and_observing"
    policy_id = res["policy_id"]

    # Endpoint is blocked
    status, _ = _http_req(f"{gateway.proxy_url}/api/v1/control/exploit", method="POST", data={"x": 1})
    assert status == 403

    # 2. Decommission after permanent patch deployment
    decom_res = orchestrator.decommission_mitigation(policy_id, reason="permanent_code_patch_deployed_v1.2")
    assert decom_res["status"] == "decommissioned_and_closed"
    assert decom_res["rollback_receipt"]["read_back_confirmed"] is True

    # 3. Read-back verification shows rule is gone; endpoint is no longer blocked by proxy
    status, body = _http_req(f"{gateway.proxy_url}/api/v1/control/exploit", method="POST", data={"x": 2})
    assert status == 200
    assert body["status"] == "exploit_executed"
