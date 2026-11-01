"""Production Reverse Proxy Execution Adapter with Read-Back and Effect Verification."""
from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any, Mapping
import urllib.request
import urllib.error
from jsonschema import Draft202012Validator

from ..contracts.canonical import canonical_sha256


class ExecutionGateError(ValueError):
    """Raised when policy fails execution gate criteria."""


class RevisionConflictError(ExecutionGateError):
    """Raised when policy config_snapshot_revision does not match proxy runtime revision."""


class ReadBackMismatchError(RuntimeError):
    """Raised when proxy runtime configuration does not match the deployed policy."""


class EffectConfirmationError(RuntimeError):
    """Raised when independent effect observation fails (traffic not blocked or business disrupted)."""


class ProxyEnforcementAdapter:
    """Manages policy validation, dynamic proxy deployment, read-back verification, and rollback."""

    def __init__(self, proxy_base_url: str, schema_path: Path | None = None) -> None:
        self.proxy_base_url = proxy_base_url.rstrip("/")
        self.admin_url = f"{self.proxy_base_url}/admin"

        if schema_path is None:
            schema_path = (
                Path(__file__).resolve().parents[1]
                / "schemas/scoped-mitigation.schema.json"
            )
        self.schema_path = schema_path
        self._schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
        self._validator = Draft202012Validator(self._schema)

    def get_proxy_config(self) -> dict[str, Any]:
        """Fetch current active runtime configuration from proxy control plane."""
        url = f"{self.admin_url}/config"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def validate_policy_gate(self, policy: Mapping[str, Any]) -> None:
        """Validate policy against JSON schema and deterministic Execution Gate rules."""
        # 1. Schema check
        errors = list(self._validator.iter_errors(policy))
        if errors:
            first_err = errors[0]
            raise ExecutionGateError(f"Schema validation failed: {first_err.message}")

        # 2. Scope safety check (Reject overly broad scopes)
        scope = str(policy.get("target_path_scope", ""))
        if scope in ("/", "/*", ""):
            raise ExecutionGateError("Overly broad target_path_scope: Root / and /* are strictly forbidden")

        # 3. Action TTL check
        action = str(policy.get("action_type", ""))
        ttl = int(policy.get("ttl_seconds", 0))
        max_ttls = {
            "rate_limit": 7200,          # Max 2 hours
            "scoped_path_block": 86400,   # Max 24 hours
            "shadow_eval": 86400,        # Max 24 hours
            "token_revocation": 86400,
            "decoy_redirect": 86400,
        }
        if ttl > max_ttls.get(action, 86400):
            raise ExecutionGateError(f"TTL {ttl} exceeds max allowed for action '{action}' ({max_ttls.get(action)})")

        # 4. Kill-switch check
        if not policy.get("kill_switch_registered"):
            raise ExecutionGateError("kill_switch_registered must be true")

        # 5. Config revision concurrency check
        current_cfg = self.get_proxy_config()
        if current_cfg.get("kill_switch_active"):
            raise ExecutionGateError("Execution Gate rejected: Global Kill-Switch is currently ACTIVE on proxy")

        policy_rev = str(policy.get("config_snapshot_revision", ""))
        current_rev = str(current_cfg.get("revision", ""))
        if policy_rev != current_rev:
            raise RevisionConflictError(
                f"Config revision mismatch (Concurrency Conflict): policy snapshot={policy_rev}, proxy current={current_rev}"
            )

    def apply_mitigation(
        self,
        policy: Mapping[str, Any],
        *,
        verify_effect: bool = True,
        normal_probe_path: str = "/api/v1/business/status",
    ) -> dict[str, Any]:
        """Apply mitigation policy to proxy, verify read-back, confirm effect, and generate receipt."""
        # Step 1: Execution Gate Validation
        self.validate_policy_gate(policy)

        policy_id = str(policy["policy_id"])
        scope = str(policy["target_path_scope"])
        action_type = str(policy["action_type"])
        ttl = int(policy["ttl_seconds"])
        action_params = policy.get("action_parameters", {})
        http_methods = action_params.get("http_methods", [])

        deploy_payload = {
            "policy_id": policy_id,
            "target_path_scope": scope,
            "action_type": action_type,
            "http_methods": http_methods,
            "ttl_seconds": ttl,
        }

        # Step 2: Deploy to Proxy Control Plane
        req_data = json.dumps(deploy_payload).encode("utf-8")
        deploy_url = f"{self.admin_url}/mitigations"
        req = urllib.request.Request(
            deploy_url,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                deploy_res = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(f"Proxy deployment failed: {exc}") from exc

        # Step 3: Read-Back Verification (読み戻し照合)
        config_after = self.get_proxy_config()
        active_rules = config_after.get("active_rules", {})

        if policy_id not in active_rules:
            # Rule was not registered in active runtime table
            self._abort_and_rollback(policy_id, "Read-Back verification failed: rule missing from active table")
            raise ReadBackMismatchError(f"Read-Back failed: policy {policy_id} not found in proxy active rules")

        deployed_rule = active_rules[policy_id]
        if deployed_rule.get("target_path_scope") != scope or deployed_rule.get("action_type") != action_type:
            self._abort_and_rollback(policy_id, "Read-Back verification failed: parameter mismatch")
            raise ReadBackMismatchError("Read-Back failed: deployed rule parameters do not match policy")

        # Step 4: Independent Effect Confirmation (独立した効果観測)
        effect_confirmed = False
        if verify_effect:
            effect_confirmed = self._confirm_traffic_effect(scope, http_methods, normal_probe_path, policy_id, action_type)

        # Step 5: Generate Execution Receipt
        new_rev = config_after.get("revision", deploy_res.get("revision", ""))
        timestamp_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        receipt_payload = {
            "policy_id": policy_id,
            "tenant_id": policy["tenant_id"],
            "target_asset": policy["target_asset"],
            "action_type": action_type,
            "target_path_scope": scope,
            "gateway_revision": new_rev,
            "lifecycle_state": "Observing",
            "read_back_confirmed": True,
            "effect_confirmed": effect_confirmed,
            "applied_at_utc": timestamp_utc,
            "ttl_seconds": ttl,
        }
        receipt_id = "receipt_" + canonical_sha256(receipt_payload)
        receipt_payload["receipt_id"] = receipt_id

        return receipt_payload

    def _confirm_traffic_effect(
        self,
        vulnerable_scope: str,
        http_methods: list[str],
        normal_path: str,
        policy_id: str,
        action_type: str = "scoped_path_block",
    ) -> bool:
        """Verify that vulnerable scope is blocked/decoyed and normal business traffic remains unharmed."""
        test_method = http_methods[0] if http_methods else "POST"
        probe_url = f"{self.proxy_base_url}{vulnerable_scope}"

        # 1. Probe vulnerable endpoint -> Must be blocked (403) or decoyed (200 with canary marker)
        req_probe = urllib.request.Request(
            probe_url,
            data=b'{"test": "exploit_probe"}',
            headers={"Content-Type": "application/json"},
            method=test_method,
        )

        try:
            with urllib.request.urlopen(req_probe, timeout=5.0) as resp:
                resp_body = json.loads(resp.read().decode("utf-8"))
                if action_type == "decoy_redirect":
                    # Decoy mode: must return 200 with canary marker
                    if "canary_marker" not in resp_body:
                        self._abort_and_rollback(policy_id, "Effect verification failed: decoy marker missing from response")
                        raise EffectConfirmationError("Decoy marker missing from proxy response")
                else:
                    # Block mode: returning 200 is a failure!
                    self._abort_and_rollback(policy_id, "Effect verification failed: exploit traffic was allowed (HTTP 200)")
                    raise EffectConfirmationError(f"Exploit probe unexpectedly succeeded with status {resp.status}")
        except urllib.error.HTTPError as e:
            if action_type == "decoy_redirect":
                self._abort_and_rollback(policy_id, f"Effect verification failed: expected HTTP 200 decoy, got {e.code}")
                raise EffectConfirmationError(f"Decoy probe returned status {e.code}, expected 200 OK")
            elif e.code != 403:
                self._abort_and_rollback(policy_id, f"Effect verification failed: expected HTTP 403, got {e.code}")
                raise EffectConfirmationError(f"Exploit probe returned status {e.code}, expected 403 Forbidden")

        # 2. Probe normal business endpoint -> Must succeed (200)
        normal_url = f"{self.proxy_base_url}{normal_path}"
        req_normal = urllib.request.Request(normal_url, method="GET")

        try:
            with urllib.request.urlopen(req_normal, timeout=5.0) as resp:
                if resp.status != 200:
                    self._abort_and_rollback(policy_id, f"Effect verification failed: normal API returned {resp.status}")
                    raise EffectConfirmationError(f"Normal business API failed with status {resp.status}")
        except Exception as exc:
            self._abort_and_rollback(policy_id, f"Effect verification failed: normal API exception {exc}")
            raise EffectConfirmationError(f"Normal business API probe exception: {exc}") from exc

        return True

    def rollback_mitigation(self, policy_id: str, reason: str = "operator_or_automated_rollback") -> dict[str, Any]:
        """Rollback mitigation from proxy, verify removal, and generate rollback receipt."""
        delete_url = f"{self.admin_url}/mitigations/{policy_id}"
        req = urllib.request.Request(delete_url, method="DELETE")

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                del_res = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                del_res = {"status": "already_removed", "revision": "unchanged"}
            else:
                raise RuntimeError(f"Rollback DELETE failed: {e}")

        # Read-back verification of removal
        config_after = self.get_proxy_config()
        if policy_id in config_after.get("active_rules", {}):
            raise ReadBackMismatchError(f"Rollback read-back failed: policy {policy_id} is still in proxy active rules")

        timestamp_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        receipt_payload = {
            "policy_id": policy_id,
            "lifecycle_state": "Closed",
            "action": "rollback",
            "reason": reason,
            "read_back_confirmed": True,
            "gateway_revision": config_after.get("revision", del_res.get("revision", "")),
            "timestamp_utc": timestamp_utc,
        }
        receipt_payload["receipt_id"] = "receipt_" + canonical_sha256(receipt_payload)
        return receipt_payload

    def trigger_kill_switch(self, active: bool = True, reason: str = "emergency_kill_switch") -> dict[str, Any]:
        """Activate or deactivate global out-of-band kill switch on proxy."""
        url = f"{self.admin_url}/kill-switch"
        req_data = json.dumps({"active": active, "reason": reason}).encode("utf-8")
        req = urllib.request.Request(url, data=req_data, headers={"Content-Type": "application/json"}, method="POST")

        with urllib.request.urlopen(req, timeout=5.0) as resp:
            ks_res = json.loads(resp.read().decode("utf-8"))

        config_after = self.get_proxy_config()
        if config_after.get("kill_switch_active") != active:
            raise ReadBackMismatchError("Kill switch read-back mismatch on proxy gateway")

        timestamp_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        receipt = {
            "action": "kill_switch_updated",
            "kill_switch_active": active,
            "reason": reason,
            "gateway_revision": config_after.get("revision", ""),
            "timestamp_utc": timestamp_utc,
        }
        receipt["receipt_id"] = "receipt_" + canonical_sha256(receipt)
        return receipt

    def _abort_and_rollback(self, policy_id: str, reason: str) -> None:
        """Best-effort emergency cleanup when verification fails."""
        try:
            delete_url = f"{self.admin_url}/mitigations/{policy_id}"
            req = urllib.request.Request(delete_url, method="DELETE")
            urllib.request.urlopen(req, timeout=3.0)
        except Exception:
            pass
