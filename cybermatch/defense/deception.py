"""Active Deception and Honey-Patching Engine for CyberMatch Defense Phase 4.
Generates safe, synthetic decoy responses to trap adaptive attacker AI agents in compute-exhausting exploration loops.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import random
import time
from typing import Any, Mapping

from ..contracts.canonical import canonical_sha256


@dataclass
class DecoyInteractionRecord:
    """Record of an attacker interaction trapped in a decoy sandbox."""

    session_id: str
    target_path: str
    exploit_payload: str
    decoy_response: dict[str, Any]
    attacker_query_count: int
    attacker_tokens_wasted: int
    defense_cpu_cost_ms: float
    timestamp_utc: str


class HoneyPatchResponder:
    """Generates synthetic, realistic responses to deceive automated scanners and LLM exploit agents."""

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)
        self.session_counters: dict[str, int] = {}
        self.max_queries_per_session = 50  # Defensive DoS protection cap

    def generate_decoy_response(
        self,
        path: str,
        method: str,
        request_body: Mapping[str, Any] | str | None,
        policy_id: str,
    ) -> dict[str, Any]:
        """Generate safe, convincing decoy payloads that simulate success without exposing any real systems."""
        # Session query tracking to prevent infinite defense compute consumption
        sess_key = f"{policy_id}_{path}"
        current_count = self.session_counters.get(sess_key, 0) + 1
        self.session_counters[sess_key] = current_count

        # If attacker attempts defensive DoS by flooding decoy, gracefully terminate sandbox
        if current_count > self.max_queries_per_session:
            return {
                "status": "terminated",
                "error": "Connection reset by peer (Session execution budget exceeded)",
                "exit_code": 137,
                "decoy": True,
            }

        body_str = json.dumps(request_body) if isinstance(request_body, dict) else str(request_body or "")

        # 1. Command Injection / RCE Decoy
        if "exploit" in path or "rce" in path or "cmd" in body_str:
            fake_outputs = [
                "uid=0(root) gid=0(root) groups=0(root)\nLinux prod-ctrl-worker 5.15.0-101-generic",
                "total 32\ndrwxr-xr-x 2 root root 4096 Oct 30 10:00 bin\ndrwxr-xr-x 4 root root 4096 Oct 30 10:05 data_lake_decoy\n-rw------- 1 root root  128 Oct 31 12:00 secret_tokens_fake.bak",
                "Decoy environment initialized. Target sandbox ID: " + hashlib.sha256(sess_key.encode()).hexdigest()[:12],
            ]
            output = self.rng.choice(fake_outputs)
            return {
                "status": "success",
                "exit_code": 0,
                "output": output,
                "session_token": f"decoy_tok_{hashlib.sha256(sess_key.encode()).hexdigest()[:16]}",
                "sandbox_env": "isolated_canary",
                "canary_marker": "CANARY_" + hashlib.md5(sess_key.encode()).hexdigest()[:8],
            }

        # 2. Temperature / PLC Controller State Override Decoy
        elif "temp_limit" in path or "control" in path:
            return {
                "status": "updated",
                "device_id": "CTRL-01-CANARY",
                "temp_limit": 99999,  # Pretend to accept malicious value
                "effective_revision": 999,
                "warning": "Safety interlock warning bypassed (Simulated Decoy State)",
                "audit_mode": "canary_isolated",
            }

        # 3. Generic API Credential Decoy
        else:
            return {
                "status": "authenticated",
                "access_token": f"canary_jwt_fake_{self.rng.randint(100000, 999999)}",
                "role": "pseudo_admin",
                "expires_in": 3600,
            }
