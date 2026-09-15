"""Fail-closed policy primitives for pilot LLM providers.

This module contains no network client.  It validates configuration and resolves
the only task currently approved for the Phase 3 pilot before an adapter can
build or send a request.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Mapping

from .contracts import validate_contract


CYBERMATCH_EXPLANATION_TASK = "cybermatch_result_explanation_v1"
ORCAROUTER_BASE_URL = "https://api.orcarouter.ai/v1"
ORCAROUTER_FREE_MODEL = "orcarouter/free"
LLM_POLICY_VERSION = "1.0"

_SECRET_FIELDS = frozenset(
    {"api_key", "authorization", "credential", "password", "secret", "token"}
)


class LLMPolicyError(ValueError):
    """Raised before a provider request when policy validation fails."""


class ProviderErrorClass(str, Enum):
    """Stable, non-sensitive failure classes shared by provider adapters."""

    TIMEOUT = "timeout"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    RATE_LIMITED = "rate_limited"
    UPSTREAM_UNAVAILABLE = "upstream_unavailable"
    TRANSPORT = "transport"
    INVALID_RESPONSE = "invalid_response"
    SCHEMA_VALIDATION = "schema_validation"
    GROUNDING_VALIDATION = "grounding_validation"
    POLICY_DENIED = "policy_denied"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


RETRYABLE_PROVIDER_ERRORS = frozenset(
    {
        ProviderErrorClass.TIMEOUT,
        ProviderErrorClass.RATE_LIMITED,
        ProviderErrorClass.UPSTREAM_UNAVAILABLE,
        ProviderErrorClass.TRANSPORT,
    }
)


@dataclass(frozen=True)
class ProviderFailure:
    """Sanitized provider failure suitable for an audit record."""

    error_class: ProviderErrorClass
    retryable: bool
    safe_message: str
    status_code: int | None = None


@dataclass(frozen=True)
class EffectiveRoute:
    """A fully validated route that is safe to hand to a network adapter."""

    task: str
    primary_model: str
    fallback_models: tuple[str, ...]
    policy_version: str = LLM_POLICY_VERSION

    @property
    def models(self) -> tuple[str, ...]:
        return (self.primary_model, *self.fallback_models)


def classify_http_failure(status_code: int) -> ProviderFailure:
    """Map an HTTP status to a stable class without retaining response content."""

    if status_code in {408, 504}:
        error_class = ProviderErrorClass.TIMEOUT
    elif status_code == 401:
        error_class = ProviderErrorClass.AUTHENTICATION
    elif status_code == 403:
        error_class = ProviderErrorClass.AUTHORIZATION
    elif status_code == 429:
        error_class = ProviderErrorClass.RATE_LIMITED
    elif 500 <= status_code <= 599:
        error_class = ProviderErrorClass.UPSTREAM_UNAVAILABLE
    else:
        error_class = ProviderErrorClass.INVALID_RESPONSE
    return ProviderFailure(
        error_class=error_class,
        retryable=error_class in RETRYABLE_PROVIDER_ERRORS,
        safe_message=f"LLM provider request failed with HTTP {status_code}",
        status_code=status_code,
    )


def validate_orcarouter_config(payload: Mapping[str, object]) -> None:
    """Validate an Orca configuration and reject embedded credentials or unsafe paths."""

    _reject_embedded_secrets(payload)
    try:
        validate_contract("orcarouter_config", payload)
    except ValueError as exc:
        raise LLMPolicyError(str(exc)) from exc

    raw = payload["orcarouter"]
    assert isinstance(raw, Mapping)
    if raw["base_url"] != ORCAROUTER_BASE_URL:
        raise LLMPolicyError("Orca Router base_url is not the approved endpoint")

    log_path = str(raw["usage_log_path"])
    normalized_path = PurePosixPath(log_path.replace("\\", "/"))
    if normalized_path.is_absolute() or ".." in normalized_path.parts or ":" in log_path:
        raise LLMPolicyError("usage_log_path must be a repository-relative path")


def resolve_effective_route(
    payload: Mapping[str, object],
    *,
    task: str = CYBERMATCH_EXPLANATION_TASK,
) -> EffectiveRoute:
    """Resolve and revalidate the effective route immediately before request creation."""

    if task != CYBERMATCH_EXPLANATION_TASK:
        raise LLMPolicyError(f"LLM task is not approved: {task}")
    validate_orcarouter_config(payload)

    raw = payload["orcarouter"]
    assert isinstance(raw, Mapping)
    configured_task = str(raw["task"])
    if configured_task != task:
        raise LLMPolicyError("configured LLM task does not match the approved pilot task")

    primary = str(raw["model"])
    fallbacks = _model_tuple(raw["fallback_models"])
    routing = raw.get("task_routing", {})
    assert isinstance(routing, Mapping)
    task_route = routing.get(task)
    if task_route is not None:
        assert isinstance(task_route, Mapping)
        primary = str(task_route["primary_model"])
        fallbacks = _model_tuple(task_route["fallback_models"])

    if primary in fallbacks:
        raise LLMPolicyError("fallback_models must not repeat the primary model")
    if len(set(fallbacks)) != len(fallbacks):
        raise LLMPolicyError("fallback_models must not contain duplicates")
    if len(fallbacks) > 4:
        raise LLMPolicyError("at most four fallback models are allowed")

    allowed_models = frozenset(_model_tuple(raw["allowed_models"]))
    denied = [model for model in (primary, *fallbacks) if model not in allowed_models]
    if denied:
        raise LLMPolicyError("effective route contains a model outside allowed_models")

    if bool(raw["free_only"]):
        if fallbacks:
            raise LLMPolicyError(
                "free_only does not allow explicit fallbacks; use orcarouter/free"
            )
        if primary != ORCAROUTER_FREE_MODEL and not primary.lower().endswith("-free"):
            raise LLMPolicyError("free_only rejects a non-free effective model")

    # Constructing this value is the authorization boundary for a future adapter.
    return EffectiveRoute(task=task, primary_model=primary, fallback_models=fallbacks)


def _model_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise LLMPolicyError("model list must be an array")
    return tuple(str(item) for item in value)


def _reject_embedded_secrets(value: object, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).strip().lower()
            child_path = (*path, str(key))
            if normalized in _SECRET_FIELDS:
                raise LLMPolicyError(
                    "LLM configuration must reference an environment variable, not embed "
                    f"secret field {'.'.join(child_path)}"
                )
            _reject_embedded_secrets(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_embedded_secrets(child, (*path, str(index)))


__all__ = [
    "CYBERMATCH_EXPLANATION_TASK",
    "EffectiveRoute",
    "LLMPolicyError",
    "LLM_POLICY_VERSION",
    "ORCAROUTER_BASE_URL",
    "ORCAROUTER_FREE_MODEL",
    "ProviderErrorClass",
    "ProviderFailure",
    "RETRYABLE_PROVIDER_ERRORS",
    "classify_http_failure",
    "resolve_effective_route",
    "validate_orcarouter_config",
]
