from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from src.cybermatch.pilot.ai import grounded_explanation
from src.cybermatch.pilot.contracts import validate_contract
from src.cybermatch.pilot.grounding import validate_ai_answer
from src.cybermatch.pilot.policy import (
    CYBERMATCH_EXPLANATION_TASK,
    LLMPolicyError,
    ProviderErrorClass,
    classify_http_failure,
    resolve_effective_route,
    validate_orcarouter_config,
)


pytestmark = [pytest.mark.phase3, pytest.mark.threat_hunting]
ROOT = Path(__file__).resolve().parents[1]


def _config() -> dict[str, object]:
    return json.loads(
        (ROOT / "configs" / "pilot" / "orcarouter.example.json").read_text("utf-8")
    )


def _view() -> dict[str, object]:
    return {
        "bundle_hash": "a" * 64,
        "metrics": {"f1": 1.0},
        "artifacts": [{"path": "hunting/metrics.json"}],
        "limitations": [
            "This result is replay-backed and does not establish live production effectiveness."
        ],
    }


def test_approved_free_route_is_resolved_and_config_is_schema_valid() -> None:
    payload = _config()
    validate_orcarouter_config(payload)

    route = resolve_effective_route(payload)

    assert route.task == CYBERMATCH_EXPLANATION_TASK
    assert route.primary_model == "orcarouter/free"
    assert route.fallback_models == ()
    assert route.models == ("orcarouter/free",)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("api_key", "sk-embedded"),
        ("token", "embedded"),
        ("password", "embedded"),
    ],
)
def test_embedded_secret_fields_are_rejected(field: str, value: str) -> None:
    payload = _config()
    raw = payload["orcarouter"]
    assert isinstance(raw, dict)
    raw[field] = value

    with pytest.raises(LLMPolicyError, match="must reference an environment variable"):
        validate_orcarouter_config(payload)


def test_unapproved_endpoint_is_rejected() -> None:
    payload = _config()
    raw = payload["orcarouter"]
    assert isinstance(raw, dict)
    raw["base_url"] = "https://example.invalid/v1"

    with pytest.raises(LLMPolicyError, match="base_url"):
        validate_orcarouter_config(payload)


def test_unapproved_caller_task_is_rejected_before_route_resolution() -> None:
    with pytest.raises(LLMPolicyError, match="task is not approved"):
        resolve_effective_route(_config(), task="user_supplied_task")


def test_free_only_checks_task_specific_effective_route() -> None:
    payload = _config()
    raw = payload["orcarouter"]
    assert isinstance(raw, dict)
    raw["allowed_models"] = ["orcarouter/free", "provider/paid-model"]
    raw["task_routing"] = {
        CYBERMATCH_EXPLANATION_TASK: {
            "primary_model": "provider/paid-model",
            "fallback_models": [],
        }
    }

    with pytest.raises(LLMPolicyError, match="non-free effective model"):
        resolve_effective_route(payload)


def test_effective_route_rechecks_allowed_models() -> None:
    payload = _config()
    raw = payload["orcarouter"]
    assert isinstance(raw, dict)
    raw["model"] = "provider/unapproved-free"

    with pytest.raises(LLMPolicyError, match="outside allowed_models"):
        resolve_effective_route(payload)


def test_free_only_rejects_explicit_fallback_even_when_free() -> None:
    payload = _config()
    raw = payload["orcarouter"]
    assert isinstance(raw, dict)
    raw["allowed_models"] = ["orcarouter/free", "provider/backup-free"]
    raw["fallback_models"] = ["provider/backup-free"]

    with pytest.raises(LLMPolicyError, match="does not allow explicit fallbacks"):
        resolve_effective_route(payload)


def test_usage_log_must_be_repository_relative() -> None:
    payload = _config()
    raw = payload["orcarouter"]
    assert isinstance(raw, dict)
    raw["usage_log_path"] = "C:/sensitive/usage.jsonl"

    with pytest.raises(LLMPolicyError, match="repository-relative"):
        validate_orcarouter_config(payload)


def test_resolved_model_allowlist_must_not_be_empty() -> None:
    payload = _config()
    raw = payload["orcarouter"]
    assert isinstance(raw, dict)
    raw["allowed_resolved_models"] = []

    with pytest.raises(LLMPolicyError, match="non-empty"):
        validate_orcarouter_config(payload)


@pytest.mark.parametrize(
    ("status", "expected", "retryable"),
    [
        (401, ProviderErrorClass.AUTHENTICATION, False),
        (403, ProviderErrorClass.AUTHORIZATION, False),
        (408, ProviderErrorClass.TIMEOUT, True),
        (429, ProviderErrorClass.RATE_LIMITED, True),
        (503, ProviderErrorClass.UPSTREAM_UNAVAILABLE, True),
        (400, ProviderErrorClass.INVALID_RESPONSE, False),
    ],
)
def test_provider_http_error_taxonomy(
    status: int, expected: ProviderErrorClass, retryable: bool
) -> None:
    failure = classify_http_failure(status)

    assert failure.error_class is expected
    assert failure.retryable is retryable
    assert failure.status_code == status
    assert failure.safe_message == f"LLM provider request failed with HTTP {status}"


def test_template_answer_and_audit_satisfy_hardened_contracts() -> None:
    explanation = grounded_explanation(_view())

    assert explanation["answer"]["schema_version"] == "1.1"
    assert "replay_not_live_production" in explanation["answer"]["limitation_codes"]
    assert explanation["audit"]["validation_status"] == "fallback"
    assert explanation["audit"]["failure_detail"] is None
    validate_contract("ai_answer", explanation["answer"])
    validate_contract("llm_audit", explanation["audit"])


def test_ai_answer_cannot_remove_result_view_limitation() -> None:
    view = _view()
    answer = copy.deepcopy(grounded_explanation(view)["answer"])
    answer["limitations"] = ["A different limitation."]

    with pytest.raises(ValueError, match="removed a required"):
        validate_ai_answer(answer, view)
