"""Tests for CyberMatch Phase 4 Active Deception and Honey-Patching Research."""
from __future__ import annotations

import json
import urllib.request
import urllib.error
import pytest

from cybermatch.defense import (
    LabProxyGateway,
    ProxyEnforcementAdapter,
    HoneyPatchResponder,
    Phase4DeceptionBenchmark,
)


@pytest.fixture
def lab_env():
    gateway = LabProxyGateway(gateway_id="proxy-phase4-decoy-lab")
    gateway.start()
    adapter = ProxyEnforcementAdapter(proxy_base_url=gateway.proxy_url)
    yield gateway, adapter
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


def test_honeypatch_responder_generation_and_safety():
    """Verify synthetic decoy payloads contain canary markers and enforce defensive DoS caps."""
    responder = HoneyPatchResponder(seed=42)

    # 1. Generate decoy response for command injection
    decoy = responder.generate_decoy_response(
        path="/api/v1/control/exploit",
        method="POST",
        request_body={"cmd": "whoami"},
        policy_id="policy_test_decoy_01",
    )

    assert decoy["status"] == "success"
    assert "uid=0" in decoy["output"] or "Decoy" in decoy["output"] or "secret_tokens" in decoy["output"]
    assert "canary_marker" in decoy
    assert decoy["sandbox_env"] == "isolated_canary"

    # 2. Defensive DoS protection: verify sandbox terminates after excessive queries
    for _ in range(55):
        over_decoy = responder.generate_decoy_response(
            path="/api/v1/control/exploit",
            method="POST",
            request_body={"cmd": "flood_test"},
            policy_id="policy_test_decoy_01",
        )

    assert over_decoy["status"] == "terminated"
    assert "exceeded" in over_decoy["error"]


def test_proxy_gateway_live_decoy_redirect(lab_env):
    """Verify live Reverse Proxy returns convincing 200 OK decoy instead of 403 when decoy_redirect is active."""
    gateway, adapter = lab_env
    cfg = adapter.get_proxy_config()

    policy_id = "mitigation_" + "d" * 64
    policy = {
        "schema_version": "1.0",
        "policy_id": policy_id,
        "tenant_id": "tenant-lab-p4",
        "target_asset": "proxy-phase4-decoy-lab",
        "target_path_scope": "/api/v1/control/exploit",
        "action_type": "decoy_redirect",  # Active Deception / Honey-Patching
        "lifecycle_state": "Validated",
        "ttl_seconds": 3600,
        "config_snapshot_revision": cfg["revision"],
        "validation_bundle_hash": "e" * 64,
        "action_parameters": {
            "http_methods": ["POST"],
        },
        "recovery_policy": {
            "rollback_action": "restore_previous_config",
            "trigger_conditions": ["ttl_expired"],
        },
        "kill_switch_registered": True,
    }

    # Apply mitigation in decoy_redirect mode
    receipt = adapter.apply_mitigation(policy, verify_effect=True)
    assert receipt["action_type"] == "decoy_redirect"
    assert receipt["read_back_confirmed"] is True
    assert receipt["effect_confirmed"] is True

    # Attacker requests vulnerable endpoint -> receives 200 OK with Decoy Canary Marker (NOT 403!)
    status, body = _http_req(f"{gateway.proxy_url}/api/v1/control/exploit", method="POST", data={"cmd": "whoami"})
    assert status == 200
    assert body["status"] == "success"
    assert "canary_marker" in body
    assert body["environment"] == "decoy_sandbox"

    # Normal business endpoint continues unaffected
    status, body = _http_req(f"{gateway.proxy_url}/api/v1/business/status")
    assert status == 200
    assert body["status"] == "operational"


def test_phase4_comparative_benchmark_hypothesis():
    """Verify 4-condition comparative benchmark demonstrates deception waste without defense DoS."""
    benchmark = Phase4DeceptionBenchmark(episodes_per_condition=50, seed=42)
    results = benchmark.run_benchmark()

    c1 = results["no_defense"]
    c2 = results["standard_block"]
    c3 = results["scoped_containment"]
    c4 = results["honey_patching"]

    # Condition 1: No defense has near 100% compromise
    assert c1.compromise_rate_pct >= 95.0

    # Condition 2: Standard block prompts immediate re-planning, but bypass paths are found
    assert c2.avg_attacker_adaptations > 0

    # Condition 4: Honey-Patching traps the attacker in the decoy sandbox
    # Attacker waste ratio must be substantially higher (> 40% of queries spent on fake artifacts)
    assert c4.avg_deception_waste_ratio > 40.0
    assert c4.avg_attacker_tokens > c1.avg_attacker_tokens

    # Compromise rate on real critical assets must be substantially lower than Condition 2
    assert c4.compromise_rate_pct < c2.compromise_rate_pct

    # Defensive overhead must be lightweight (< 2.0 ms per episode)
    assert c4.defense_overhead_ms < 2.0
