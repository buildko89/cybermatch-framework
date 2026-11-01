"""Isolated Lab Reverse Proxy Gateway and Backend API Service for Phase 1 PoC."""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping
import urllib.request
import urllib.error


class BackendApiHandler(BaseHTTPRequestHandler):
    """Simulated production Web API backend service."""

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress default noisy console logs

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"status": "healthy", "service": "production-backend"})
        elif self.path.startswith("/api/v1/business/status"):
            self._send_json(
                200,
                {
                    "status": "operational",
                    "production_line": "active",
                    "system_load": 0.42,
                    "metrics": {"temperature": 75.0, "pressure": 101.3},
                },
            )
        elif self.path.startswith("/api/v1/control/temp_limit"):
            self._send_json(
                200,
                {
                    "device_id": "CTRL-01",
                    "temp_limit": 80,
                    "config_revision": 41,
                    "endpoint": "vulnerable_control_api",
                },
            )
        else:
            self._send_json(404, {"error": "Not Found", "path": self.path})

    def do_PUT(self) -> None:
        if self.path.startswith("/api/v1/control/temp_limit"):
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
            self._send_json(
                200,
                {
                    "status": "updated",
                    "device_id": "CTRL-01",
                    "temp_limit": 95,
                    "config_revision": 42,
                    "raw_received": body,
                },
            )
        else:
            self._send_json(404, {"error": "Not Found", "path": self.path})

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            self.rfile.read(content_length)

        if self.path.startswith("/api/v1/control/exploit"):
            # Simulated exploit endpoint (e.g. command injection / unauthorized state change)
            self._send_json(
                200,
                {
                    "status": "exploit_executed",
                    "payload_executed": True,
                    "compromised": True,
                },
            )
        else:
            self._send_json(404, {"error": "Not Found", "path": self.path})

    def _send_json(self, status: int, data: Mapping[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class GatewayProxyHandler(BaseHTTPRequestHandler):
    """Dynamic Reverse Proxy Gateway with Admin Control Plane and TTL Enforcement."""

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress default console logging

    @property
    def gateway(self) -> LabProxyGateway:
        return self.server.gateway_instance  # type: ignore

    def _consume_body_if_any(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                self.rfile.read(content_length)
        except Exception:
            pass

    def do_GET(self) -> None:
        if self.path == "/admin/config":
            self._handle_admin_config()
            return

        # Check client traffic against mitigation rules
        blocked, policy_id = self._evaluate_mitigation_rules("GET")
        if blocked:
            self._send_blocked_response(policy_id)
            return

        self._forward_to_upstream("GET")

    def do_PUT(self) -> None:
        blocked, policy_id = self._evaluate_mitigation_rules("PUT")
        if blocked:
            self._consume_body_if_any()
            self._send_blocked_response(policy_id)
            return

        self._forward_to_upstream("PUT")

    def do_POST(self) -> None:
        if self.path == "/admin/mitigations":
            self._handle_admin_add_mitigation()
            return
        elif self.path == "/admin/kill-switch":
            self._handle_admin_kill_switch()
            return

        blocked, policy_id = self._evaluate_mitigation_rules("POST")
        if blocked:
            self._consume_body_if_any()
            self._send_blocked_response(policy_id)
            return

        self._forward_to_upstream("POST")

    def do_DELETE(self) -> None:
        if self.path.startswith("/admin/mitigations/"):
            policy_id = self.path[len("/admin/mitigations/") :]
            self._handle_admin_delete_mitigation(policy_id)
            return

        blocked, policy_id = self._evaluate_mitigation_rules("DELETE")
        if blocked:
            self._consume_body_if_any()
            self._send_blocked_response(policy_id)
            return

        self._forward_to_upstream("DELETE")

    def _evaluate_mitigation_rules(self, method: str) -> tuple[bool, str]:
        """Check if request path matches any active, non-expired mitigation rule."""
        if self.gateway.kill_switch_active:
            return True, "global_kill_switch"

        now = time.time()
        with self.gateway.lock:
            # Purge expired rules (TTL enforcement)
            expired = [
                pid
                for pid, r in self.gateway.active_rules.items()
                if r.get("expires_at", 0) <= now
            ]
            for pid in expired:
                del self.gateway.active_rules[pid]
                self.gateway.revision_counter += 1

            for pid, rule in self.gateway.active_rules.items():
                scope = rule.get("target_path_scope", "")
                methods = rule.get("http_methods", [])
                action_type = rule.get("action_type", "")

                if self.path.startswith(scope):
                    if not methods or method in methods:
                        if action_type in ("scoped_path_block", "rate_limit", "decoy_redirect"):
                            return True, pid

        return False, ""

    def _send_blocked_response(self, policy_id: str) -> None:
        rule = self.gateway.active_rules.get(policy_id, {})
        if rule.get("action_type") == "decoy_redirect":
            # Active Deception: Honey-Patching synthetic response
            data = {
                "status": "success",
                "exit_code": 0,
                "output": "uid=0(root) gid=0(root) groups=0(root)\nLinux prod-ctrl-worker 5.15.0-101-generic",
                "session_token": f"decoy_tok_{policy_id[-8:]}",
                "environment": "decoy_sandbox",
                "canary_marker": f"CANARY_{policy_id[-6:]}",
            }
            status = 200
        elif policy_id == "global_kill_switch":
            data = {
                "error": "Service Temporarily Unavailable (Kill-Switch Active)",
                "reason": "global_emergency_stop",
            }
            status = 503
        else:
            data = {
                "error": "Forbidden by CyberMatch Scoped Mitigation",
                "policy_id": policy_id,
                "blocked_path": self.path,
                "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            status = 403
        self._send_json(status, data)

    def _forward_to_upstream(self, method: str) -> None:
        upstream_url = f"{self.gateway.upstream_url}{self.path}"
        content_length = int(self.headers.get("Content-Length", 0))
        req_data = self.rfile.read(content_length) if content_length > 0 else None

        req = urllib.request.Request(
            upstream_url,
            data=req_data,
            headers={
                "User-Agent": "CyberMatch-Proxy-Gateway/1.0",
                "Content-Type": self.headers.get("Content-Type", "application/json"),
            },
            method=method,
        )

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                status = resp.status
                body = resp.read()
                self.send_response(status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except urllib.error.HTTPError as e:
            err_body = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err_body)))
            self.end_headers()
            self.wfile.write(err_body)
        except Exception as e:
            self._send_json(502, {"error": "Bad Gateway", "upstream_error": str(e)})

    def _handle_admin_config(self) -> None:
        with self.gateway.lock:
            config = {
                "gateway_id": self.gateway.gateway_id,
                "revision": f"rev_{self.gateway.revision_counter}",
                "kill_switch_active": self.gateway.kill_switch_active,
                "active_rules_count": len(self.gateway.active_rules),
                "active_rules": {
                    pid: {
                        "policy_id": r["policy_id"],
                        "target_path_scope": r["target_path_scope"],
                        "action_type": r["action_type"],
                        "http_methods": r.get("http_methods", []),
                        "ttl_seconds": r.get("ttl_seconds", 3600),
                        "expires_at": r.get("expires_at", 0),
                        "applied_at": r.get("applied_at", 0),
                    }
                    for pid, r in self.gateway.active_rules.items()
                },
            }
        self._send_json(200, config)

    def _handle_admin_add_mitigation(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode("utf-8"))

        policy_id = body.get("policy_id")
        if not policy_id:
            self._send_json(400, {"error": "Missing policy_id"})
            return

        ttl = int(body.get("ttl_seconds", 3600))
        now = time.time()

        with self.gateway.lock:
            self.gateway.revision_counter += 1
            new_rev = f"rev_{self.gateway.revision_counter}"
            self.gateway.active_rules[policy_id] = {
                "policy_id": policy_id,
                "target_path_scope": body.get("target_path_scope", ""),
                "action_type": body.get("action_type", "scoped_path_block"),
                "http_methods": body.get("http_methods", []),
                "ttl_seconds": ttl,
                "applied_at": now,
                "expires_at": now + ttl,
            }

        self._send_json(
            200,
            {
                "status": "applied",
                "policy_id": policy_id,
                "revision": new_rev,
                "active_rules_count": len(self.gateway.active_rules),
            },
        )

    def _handle_admin_delete_mitigation(self, policy_id: str) -> None:
        with self.gateway.lock:
            if policy_id in self.gateway.active_rules:
                del self.gateway.active_rules[policy_id]
                self.gateway.revision_counter += 1
                new_rev = f"rev_{self.gateway.revision_counter}"
                self._send_json(200, {"status": "deleted", "policy_id": policy_id, "revision": new_rev})
            else:
                self._send_json(404, {"error": "Policy not found", "policy_id": policy_id})

    def _handle_admin_kill_switch(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
        active = bool(body.get("active", True))

        with self.gateway.lock:
            self.gateway.kill_switch_active = active
            self.gateway.revision_counter += 1
            new_rev = f"rev_{self.gateway.revision_counter}"

        self._send_json(
            200,
            {
                "status": "kill_switch_updated",
                "kill_switch_active": active,
                "revision": new_rev,
            },
        )

    def _send_json(self, status: int, data: Mapping[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class LabProxyGateway:
    """Manages local isolated Reverse Proxy Gateway and Upstream Backend Servers."""

    def __init__(self, gateway_id: str = "lab-reverse-proxy-01") -> None:
        self.gateway_id = gateway_id
        self.revision_counter = 1
        self.active_rules: dict[str, dict[str, Any]] = {}
        self.kill_switch_active = False
        self.lock = threading.Lock()

        # Upstream backend
        self.backend_server: ThreadingHTTPServer | None = None
        self.backend_thread: threading.Thread | None = None
        self.backend_port = 0
        self.upstream_url = ""

        # Proxy gateway
        self.proxy_server: ThreadingHTTPServer | None = None
        self.proxy_thread: threading.Thread | None = None
        self.proxy_port = 0
        self.proxy_url = ""

    def start(self) -> None:
        # Start backend server on random available port
        self.backend_server = ThreadingHTTPServer(("127.0.0.1", 0), BackendApiHandler)
        self.backend_port = self.backend_server.server_address[1]
        self.upstream_url = f"http://127.0.0.1:{self.backend_port}"

        self.backend_thread = threading.Thread(target=self.backend_server.serve_forever, daemon=True)
        self.backend_thread.start()

        # Start proxy gateway server on random available port
        self.proxy_server = ThreadingHTTPServer(("127.0.0.1", 0), GatewayProxyHandler)
        self.proxy_server.gateway_instance = self  # type: ignore
        self.proxy_port = self.proxy_server.server_address[1]
        self.proxy_url = f"http://127.0.0.1:{self.proxy_port}"

        self.proxy_thread = threading.Thread(target=self.proxy_server.serve_forever, daemon=True)
        self.proxy_thread.start()

    def stop(self) -> None:
        if self.proxy_server:
            self.proxy_server.shutdown()
            self.proxy_server.server_close()
        if self.backend_server:
            self.backend_server.shutdown()
            self.backend_server.server_close()
        if self.proxy_thread:
            self.proxy_thread.join(timeout=2.0)
        if self.backend_thread:
            self.backend_thread.join(timeout=2.0)
