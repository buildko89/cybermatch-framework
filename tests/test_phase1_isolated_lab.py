"""Tests for CyberMatch Phase 1 Isolated Lab: Reverse Proxy Gateway & Enforcement Adapter."""
from __future__ import annotations

import json
import urllib.request
import urllib.error
import pytest

from cybermatch.defense import (
    LabProxyGateway,
    ProxyEnforcementAdapter,
    ExecutionGateError,
    RevisionConflictError,
    ReadBackMismatchError,
    EffectConfirmationError,
)


@pytest.fixture
def lab_env():
    """Start local backend and proxy gateway on random available loopback ports."""
    gateway = LabProxyGateway(gateway_id="test-lab-proxy-01")
    gateway.start()
    adapter = ProxyEnforcementAdapter(proxy_base_url=gateway.proxy_url)
    yield gateway, adapter
    gateway.stop()


def _http_get(url: str) -> tuple[int, dict]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _http_post(url: str, data: dict) -> tuple[int, dict]:
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def test_baseline_traffic_before_mitigation(lab_env):
    """Verify normal business API and vulnerable endpoint respond 200 OK before mitigation."""
    gateway, _ = lab_env

    # 1. Normal business status API
    status, body = _http_get(f"{gateway.proxy_url}/api/v1/business/status")
    assert status == 200
    assert body["status"] == "operational"

    # 2. Simulated exploit endpoint reaches backend before defense is deployed
    status, body = _http_post(f"{gateway.proxy_url}/api/v1/control/exploit", {"cmd": "whoami"})
    assert status == 200
    assert body["status"] == "exploit_executed"


def test_execution_gate_rejects_broad_scope(lab_env):
    """Execution Gate must reject overly broad scopes like / or /*."""
    _, adapter = lab_env
    cfg = adapter.get_proxy_config()

    invalid_policy = {
        "schema_version": "1.0",
        "policy_id": "mitigation_" + "1" * 64,
        "tenant_id": "tenant-test",
        "target_asset": "lab-proxy",
        "target_path_scope": "/*",  # Overly broad
        "action_type": "scoped_path_block",
        "lifecycle_state": "Validated",
        "ttl_seconds": 3600,
        "config_snapshot_revision": cfg["revision"],
        "validation_bundle_hash": "2" * 64,
        "recovery_policy": {
            "rollback_action": "restore_previous_config",
            "trigger_conditions": ["latency_spike"],
        },
        "kill_switch_registered": True,
    }

    with pytest.raises(ExecutionGateError, match="strictly forbidden"):
        adapter.apply_mitigation(invalid_policy)


def test_execution_gate_rejects_excessive_ttl(lab_env):
    """Execution Gate must reject TTL exceeding action limit (rate_limit > 7200s)."""
    _, adapter = lab_env
    cfg = adapter.get_proxy_config()

    invalid_policy = {
        "schema_version": "1.0",
        "policy_id": "mitigation_" + "3" * 64,
        "tenant_id": "tenant-test",
        "target_asset": "lab-proxy",
        "target_path_scope": "/api/v1/control/rate_limited",
        "action_type": "rate_limit",
        "lifecycle_state": "Validated",
        "ttl_seconds": 86400,  # Exceeds rate_limit max of 7200s
        "config_snapshot_revision": cfg["revision"],
        "validation_bundle_hash": "4" * 64,
        "recovery_policy": {
            "rollback_action": "restore_previous_config",
            "trigger_conditions": ["ttl_expired"],
        },
        "kill_switch_registered": True,
    }

    with pytest.raises(ExecutionGateError, match="exceeds max allowed"):
        adapter.apply_mitigation(invalid_policy)


def test_execution_gate_revision_conflict(lab_env):
    """Execution Gate must detect concurrency conflict when revision does not match."""
    _, adapter = lab_env

    conflicting_policy = {
        "schema_version": "1.0",
        "policy_id": "mitigation_" + "5" * 64,
        "tenant_id": "tenant-test",
        "target_asset": "lab-proxy",
        "target_path_scope": "/api/v1/control/exploit",
        "action_type": "scoped_path_block",
        "lifecycle_state": "Validated",
        "ttl_seconds": 3600,
        "config_snapshot_revision": "rev_9999_outdated",  # Mismatched revision
        "validation_bundle_hash": "6" * 64,
        "recovery_policy": {
            "rollback_action": "restore_previous_config",
            "trigger_conditions": ["ttl_expired"],
        },
        "kill_switch_registered": True,
    }

    with pytest.raises(RevisionConflictError, match="revision mismatch"):
        adapter.apply_mitigation(conflicting_policy)


def test_successful_mitigation_and_effect_verification(lab_env):
    """End-to-end test: Deploy mitigation, verify read-back, confirm effect, check normal traffic."""
    gateway, adapter = lab_env
    cfg = adapter.get_proxy_config()

    policy_id = "mitigation_" + "7" * 64
    policy = {
        "schema_version": "1.0",
        "policy_id": policy_id,
        "tenant_id": "tenant-prod-lab",
        "target_asset": "lab-reverse-proxy-01",
        "target_path_scope": "/api/v1/control/exploit",
        "action_type": "scoped_path_block",
        "lifecycle_state": "Validated",
        "ttl_seconds": 3600,
        "config_snapshot_revision": cfg["revision"],
        "validation_bundle_hash": "8" * 64,
        "action_parameters": {
            "http_methods": ["POST"],
        },
        "recovery_policy": {
            "rollback_action": "restore_previous_config",
            "trigger_conditions": ["latency_spike", "ttl_expired"],
            "max_latency_increase_pct": 5.0,
            "max_error_rate_pct": 1.0,
        },
        "kill_switch_registered": True,
        "operator_approval_ref": "TICKET-LAB-001",
    }

    # Apply mitigation with read-back and effect verification
    receipt = adapter.apply_mitigation(policy, verify_effect=True)

    assert receipt["policy_id"] == policy_id
    assert receipt["read_back_confirmed"] is True
    assert receipt["effect_confirmed"] is True
    assert receipt["lifecycle_state"] == "Observing"
    assert receipt["receipt_id"].startswith("receipt_")

    # Client test: Exploit endpoint is now BLOCKED by proxy with 403 Forbidden!
    status, body = _http_post(f"{gateway.proxy_url}/api/v1/control/exploit", {"cmd": "cat /etc/passwd"})
    assert status == 403
    assert body["error"] == "Forbidden by CyberMatch Scoped Mitigation"
    assert body["policy_id"] == policy_id

    # Normal business endpoint continues to function without interruption (HTTP 200)
    status, body = _http_get(f"{gateway.proxy_url}/api/v1/business/status")
    assert status == 200
    assert body["status"] == "operational"


def test_rollback_lifecycle(lab_env):
    """Verify rollback removes rule, read-back confirms, and traffic is restored."""
    gateway, adapter = lab_env
    cfg = adapter.get_proxy_config()

    policy_id = "mitigation_" + "9" * 64
    policy = {
        "schema_version": "1.0",
        "policy_id": policy_id,
        "tenant_id": "tenant-prod-lab",
        "target_asset": "lab-reverse-proxy-01",
        "target_path_scope": "/api/v1/control/exploit",
        "action_type": "scoped_path_block",
        "lifecycle_state": "Validated",
        "ttl_seconds": 1800,
        "config_snapshot_revision": cfg["revision"],
        "validation_bundle_hash": "a" * 64,
        "recovery_policy": {
            "rollback_action": "restore_previous_config",
            "trigger_conditions": ["ttl_expired"],
        },
        "kill_switch_registered": True,
    }

    adapter.apply_mitigation(policy, verify_effect=True)

    # Exploit is blocked
    status, _ = _http_post(f"{gateway.proxy_url}/api/v1/control/exploit", {"test": 1})
    assert status == 403

    # Rollback mitigation
    rollback_receipt = adapter.rollback_mitigation(policy_id, reason="testing_rollback")
    assert rollback_receipt["lifecycle_state"] == "Closed"
    assert rollback_receipt["read_back_confirmed"] is True

    # After rollback, endpoint is accessible again (not blocked by proxy)
    status, body = _http_post(f"{gateway.proxy_url}/api/v1/control/exploit", {"test": 2})
    assert status == 200
    assert body["status"] == "exploit_executed"


def test_kill_switch_emergency_stop(lab_env):
    """Verify out-of-band kill-switch halts new mitigations and returns 503."""
    gateway, adapter = lab_env

    # Activate kill switch
    ks_receipt = adapter.trigger_kill_switch(active=True, reason="manual_emergency_test")
    assert ks_receipt["kill_switch_active"] is True

    # 1. Any incoming request receives 503 while kill switch is active
    status, body = _http_get(f"{gateway.proxy_url}/api/v1/business/status")
    assert status == 503
    assert "Kill-Switch Active" in body["error"]

    # 2. Execution gate rejects any new mitigation while kill switch is active
    cfg = adapter.get_proxy_config()
    policy = {
        "schema_version": "1.0",
        "policy_id": "mitigation_" + "b" * 64,
        "tenant_id": "tenant-test",
        "target_asset": "lab-proxy",
        "target_path_scope": "/api/v1/test",
        "action_type": "scoped_path_block",
        "lifecycle_state": "Validated",
        "ttl_seconds": 3600,
        "config_snapshot_revision": cfg["revision"],
        "validation_bundle_hash": "c" * 64,
        "recovery_policy": {
            "rollback_action": "restore_previous_config",
            "trigger_conditions": ["ttl_expired"],
        },
        "kill_switch_registered": True,
    }
    with pytest.raises(ExecutionGateError, match="Kill-Switch is currently ACTIVE"):
        adapter.apply_mitigation(policy)

    # Deactivate kill switch
    adapter.trigger_kill_switch(active=False, reason="emergency_cleared")
    status, body = _http_get(f"{gateway.proxy_url}/api/v1/business/status")
    assert status == 200
    assert body["status"] == "operational"
