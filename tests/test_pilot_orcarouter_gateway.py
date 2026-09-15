from __future__ import annotations

import json
from pathlib import Path
import urllib.error

import pytest

from src.cybermatch.pilot.ai import grounded_explanation
from src.cybermatch.pilot.orcarouter import OrcaRouterError, OrcaRouterExplanationGateway
from src.cybermatch.pilot.policy import LLMPolicyError
from src.cybermatch.pilot.policy import ProviderErrorClass


pytestmark = [pytest.mark.phase3, pytest.mark.threat_hunting]
ROOT = Path(__file__).resolve().parents[1]


class FakeResponse:
    def __init__(self, payload: object, headers: dict[str, str] | None = None) -> None:
        self.data = json.dumps(payload).encode("utf-8") if not isinstance(payload, bytes) else payload
        self.headers = headers or {}

    def read(self, size: int) -> bytes:
        return self.data[:size]

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _config() -> dict[str, object]:
    payload = json.loads((ROOT / "configs/pilot/orcarouter.example.json").read_text("utf-8"))
    payload["orcarouter"]["usage_log_path"] = "usage.jsonl"
    payload["orcarouter"]["allowed_resolved_models"] = [
        "provider/free-model",
        "provider/alias-model",
    ]
    return payload


def _view() -> dict[str, object]:
    return {
        "bundle_hash": "a" * 64,
        "metrics": {"f1": 0.75},
        "artifacts": [{"path": "hunting/metrics.json"}],
        "limitations": ["Replay evidence is not live production evidence."],
    }


def _answer() -> dict[str, object]:
    return {
        "schema_version": "1.1",
        "conclusion": "The replay produced F1=0.75.",
        "claims": [{
            "text": "Measured F1 is 0.75.",
            "metric": "f1",
            "evidence_path": "hunting/metrics.json",
            "confidence": "measured",
        }],
        "limitations": ["Replay evidence is not live production evidence."],
        "limitation_codes": ["replay_not_live_production"],
        "recommended_human_decision": "Review the evidence.",
        "bundle_hash": "a" * 64,
    }


def test_orca_adapter_builds_request_parses_answer_and_records_non_content_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}
    envelope = {
        "id": "completion-1",
        "model": "provider/free-model",
        "choices": [{"message": {"content": json.dumps(_answer())}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150, "cost_usd": 0.0},
    }

    def opener(request: object, timeout: float) -> FakeResponse:
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(envelope, {"x-orca-request-id": "orca-1", "x-orca-fallback-level": "0"})

    monkeypatch.chdir(tmp_path)
    gateway = OrcaRouterExplanationGateway(_config(), api_key="test-key", opener=opener)
    result = grounded_explanation(_view(), gateway)

    request = captured["request"]
    body = json.loads(request.data)
    assert request.full_url == "https://api.orcarouter.ai/v1/chat/completions"
    assert body["model"] == "orcarouter/free"
    assert body["response_format"] == {"type": "json_object"}
    assert body["messages"][1]["content"]
    assert result["audit"]["request_id"] == "orca-1"
    assert result["audit"]["resolved_model"] == "provider/free-model"
    assert result["audit"]["total_tokens"] == 150
    usage_text = (tmp_path / "usage.jsonl").read_text("utf-8")
    assert "test-key" not in usage_text
    assert "The replay produced" not in usage_text


def test_orca_adapter_requires_api_key_before_network_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ORCAROUTER_API_KEY", raising=False)
    with pytest.raises(LLMPolicyError, match="API key"):
        OrcaRouterExplanationGateway(_config(), opener=lambda *args, **kwargs: None).explain(_view())


def test_orca_adapter_rejects_markdown_wrapped_json() -> None:
    envelope = {"choices": [{"message": {"content": "```json\n{}\n```"}}]}
    gateway = OrcaRouterExplanationGateway(
        _config(), api_key="test-key", opener=lambda *args, **kwargs: FakeResponse(envelope)
    )
    with pytest.raises(OrcaRouterError, match="strict JSON") as caught:
        gateway.explain(_view())
    assert caught.value.failure.safe_message == "Orca Router content is not strict JSON"


def test_orca_adapter_rejects_oversize_response() -> None:
    payload = b"x" * 2048
    config = _config()
    config["orcarouter"]["max_response_bytes"] = 1024
    gateway = OrcaRouterExplanationGateway(
        config, api_key="test-key", opener=lambda *args, **kwargs: FakeResponse(payload)
    )
    with pytest.raises(OrcaRouterError, match="exceeds"):
        gateway.explain(_view())


def test_orca_error_preserves_sanitized_provider_failure() -> None:
    error = urllib.error.HTTPError(
        "https://api.orcarouter.ai/v1/chat/completions", 401, "secret body", {}, None
    )
    gateway = OrcaRouterExplanationGateway(
        _config(), api_key="test-key", opener=lambda *args, **kwargs: (_ for _ in ()).throw(error)
    )

    with pytest.raises(OrcaRouterError) as caught:
        gateway.explain(_view())

    assert caught.value.failure.error_class is ProviderErrorClass.AUTHENTICATION
    assert caught.value.failure.status_code == 401
    assert "secret body" not in str(caught.value)


def test_orca_retries_only_bounded_http_failures_and_honors_retry_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    attempts = 0
    sleeps: list[float] = []
    envelope = {
        "model": "provider/free-model",
        "choices": [{"message": {"content": json.dumps(_answer())}}],
    }

    def opener(*args: object, **kwargs: object) -> FakeResponse:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise urllib.error.HTTPError("https://example", 429, "limited", {"Retry-After": "2"}, None)
        return FakeResponse(envelope)

    gateway = OrcaRouterExplanationGateway(
        _config(), api_key="test-key", opener=opener, sleeper=sleeps.append
    )
    assert gateway.explain(_view()).answer == _answer()
    assert attempts == 2
    assert sleeps == [2.0]


def test_orca_does_not_retry_non_retryable_http_failure() -> None:
    attempts = 0

    def opener(*args: object, **kwargs: object) -> FakeResponse:
        nonlocal attempts
        attempts += 1
        raise urllib.error.HTTPError("https://example", 400, "bad", {}, None)

    gateway = OrcaRouterExplanationGateway(_config(), api_key="test-key", opener=opener)
    with pytest.raises(OrcaRouterError):
        gateway.explain(_view())
    assert attempts == 1


def test_orca_does_not_retry_free_tier_429_without_retry_after() -> None:
    attempts = 0

    def opener(*args: object, **kwargs: object) -> FakeResponse:
        nonlocal attempts
        attempts += 1
        raise urllib.error.HTTPError("https://example", 429, "limited", {}, None)

    gateway = OrcaRouterExplanationGateway(_config(), api_key="test-key", opener=opener)
    with pytest.raises(OrcaRouterError) as caught:
        gateway.explain(_view())

    assert caught.value.failure.error_class is ProviderErrorClass.RATE_LIMITED
    assert attempts == 1


def test_orca_accepts_orcarouter_header_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    envelope = {
        "model": "provider/alias-model",
        "choices": [{"message": {"content": json.dumps(_answer())}}],
    }
    headers = {
        "X-OrcaRouter-Resolved-Model": "provider/alias-model",
        "X-OrcaRouter-Request-Id": "alias-request",
        "X-OrcaRouter-Fallback-Level": "1",
        "X-OrcaRouter-Fallback-Model": "provider/backup",
        "X-OrcaRouter-Cost-Usd": "0.25",
    }
    gateway = OrcaRouterExplanationGateway(
        _config(), api_key="test-key", opener=lambda *args, **kwargs: FakeResponse(envelope, headers)
    )
    metadata = gateway.explain(_view()).metadata
    assert metadata["resolved_model"] == "provider/alias-model"
    assert metadata["request_id"] == "alias-request"
    assert metadata["fallback_level"] == 1
    assert metadata["fallback_model"] == "provider/backup"
    assert metadata["cost_usd"] == 0.25


def test_orca_named_router_accepts_requested_alias_in_response_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    envelope = {
        "model": "provider-internal-model-name",
        "choices": [{"message": {"content": json.dumps(_answer())}}],
    }
    headers = {"X-Orca-Resolved-Model": "provider/free-model"}
    gateway = OrcaRouterExplanationGateway(
        _config(),
        api_key="test-key",
        opener=lambda *args, **kwargs: FakeResponse(envelope, headers),
    )

    metadata = gateway.explain(_view()).metadata

    assert metadata["requested_model"] == "orcarouter/free"
    assert metadata["resolved_model"] == "provider/free-model"


def test_usage_log_failure_warns_without_losing_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "usage.jsonl").mkdir()
    envelope = {
        "model": "provider/free-model",
        "choices": [{"message": {"content": json.dumps(_answer())}}],
    }
    gateway = OrcaRouterExplanationGateway(
        _config(), api_key="test-key", opener=lambda *args, **kwargs: FakeResponse(envelope)
    )
    with pytest.warns(RuntimeWarning, match="usage audit"):
        explanation = gateway.explain(_view())
    assert explanation.answer == _answer()


def test_provider_and_grounding_failures_fall_back_with_audit() -> None:
    http_error = urllib.error.HTTPError("https://example", 503, "down", {}, None)
    provider = OrcaRouterExplanationGateway(
        _config(), api_key="test-key", opener=lambda *args, **kwargs: (_ for _ in ()).throw(http_error)
    )
    provider_result = grounded_explanation(_view(), provider)
    assert provider_result["audit"]["validation_status"] == "fallback"
    assert provider_result["audit"]["failure_class"] == "upstream_unavailable"
    assert provider_result["audit"]["failure_detail"] == (
        "LLM provider request failed with HTTP 503"
    )
    assert provider_result["audit"]["fallback_model"] == "pilot-fallback-v1"

    invalid_answer = _answer()
    invalid_answer["claims"][0]["metric"] = "hallucinated"

    class InvalidGroundingGateway:
        provider_id = "test-provider"
        model_id = "test-model"

        def explain(self, result_view: object) -> dict[str, object]:
            return invalid_answer

    grounding_result = grounded_explanation(_view(), InvalidGroundingGateway())
    assert grounding_result["audit"]["validation_status"] == "fallback"
    assert grounding_result["audit"]["failure_class"] == "grounding_validation"

    invalid_schema = _answer()
    del invalid_schema["schema_version"]

    class InvalidSchemaGateway:
        provider_id = "test-provider"
        model_id = "test-model"

        def explain(self, result_view: object) -> dict[str, object]:
            return invalid_schema

    schema_result = grounded_explanation(_view(), InvalidSchemaGateway())
    assert schema_result["audit"]["validation_status"] == "fallback"
    assert schema_result["audit"]["failure_class"] == "schema_validation"
