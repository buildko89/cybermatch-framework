"""Orca Router adapter for evidence-grounded pilot explanations."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import time
from typing import Any, Callable, Mapping
import urllib.error
import urllib.request
import warnings
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .ai import GatewayExplanation
from .policy import (
    EffectiveRoute,
    LLMPolicyError,
    ProviderErrorClass,
    ProviderFailure,
    classify_http_failure,
    resolve_effective_route,
)
from .prompts import SYSTEM_PROMPT, build_explanation_prompt


class OrcaRouterError(RuntimeError):
    """Raised when Orca Router cannot return a bounded, parseable response."""

    def __init__(self, message: str, failure: ProviderFailure) -> None:
        super().__init__(message)
        self.failure = failure


class OrcaRouterExplanationGateway:
    provider_id = "orcarouter"

    def __init__(
        self,
        config: Mapping[str, object],
        *,
        api_key: str | None = None,
        opener: Callable[..., Any] = urllib.request.urlopen,
        sleeper: Callable[[float], None] = time.sleep,
        repository_root: str | Path | None = None,
    ) -> None:
        self.config = config
        self.route: EffectiveRoute = resolve_effective_route(config)
        raw = config["orcarouter"]
        assert isinstance(raw, Mapping)
        self._raw = raw
        self.model_id = self.route.primary_model
        self._api_key = api_key
        self._opener = opener
        self._sleeper = sleeper
        self._repository_root = (
            Path(repository_root).resolve() if repository_root is not None else None
        )

    def explain(self, result_view: Mapping[str, object]) -> GatewayExplanation:
        api_key = self._api_key or os.environ.get(str(self._raw["api_key_env"]))
        if not api_key:
            raise LLMPolicyError("Orca Router API key environment variable is not set")

        prompt = build_explanation_prompt(result_view)
        request_body = self.build_request_body(result_view)
        request = urllib.request.Request(
            f"{self._raw['base_url']}/chat/completions",
            data=json.dumps(request_body, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "X-OrcaRouter-App": str(self._raw["partner_tag"]),
                "X-OrcaRouter-Include-Cost": str(self._raw["include_cost"]).lower(),
            },
            method="POST",
        )
        started = time.perf_counter()
        envelope, headers = self._request_with_retry(request)
        latency_ms = round((time.perf_counter() - started) * 1000, 2)

        answer, response_model, response_id, usage = _parse_envelope(envelope)
        header_model = _header(headers, "resolved-model")
        if (
            header_model is not None
            and response_model is not None
            and not self.route.primary_model.startswith("orcarouter/")
            and response_model != header_model
        ):
            raise _invalid_response(
                "Orca Router returned conflicting resolved model metadata "
                f"(response={response_model}, header={header_model})"
            )
        resolved_model = header_model or response_model
        allowed_resolved = {
            str(item) for item in self._raw.get("allowed_resolved_models", [])
        }
        if resolved_model not in allowed_resolved:
            failure = ProviderFailure(
                ProviderErrorClass.POLICY_DENIED,
                False,
                "LLM provider resolved an unapproved model",
            )
            raise OrcaRouterError(failure.safe_message, failure)
        metadata = {
            "requested_model": self.route.primary_model,
            "resolved_model": resolved_model,
            "request_id": _header(headers, "request-id") or response_id,
            "fallback_level": _int_or_none(_header(headers, "fallback-level")),
            "fallback_model": _header(headers, "fallback-model"),
            "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            "prompt_tokens": _int_or_none(usage.get("prompt_tokens")),
            "completion_tokens": _int_or_none(usage.get("completion_tokens")),
            "total_tokens": _int_or_none(usage.get("total_tokens")),
            "cost_usd": (
                usage.get("cost_usd")
                if usage.get("cost_usd") is not None
                else _float_or_none(_header(headers, "cost-usd"))
            ),
            "latency_ms": latency_ms,
        }
        _validate_response_metadata(metadata)
        try:
            usage_path = self._raw.get("usage_log_path")
            if usage_path and self._repository_root is not None:
                usage_path = self._repository_root / str(usage_path)
            _record_usage(usage_path, metadata, result_view)
        except OSError as exc:
            warnings.warn(
                f"Orca Router usage audit could not be written: {type(exc).__name__}",
                RuntimeWarning,
                stacklevel=2,
            )
        return GatewayExplanation(answer=answer, metadata=metadata)

    def build_request_body(
        self, result_view: Mapping[str, object]
    ) -> dict[str, object]:
        """Return the exact non-secret JSON body used for the provider request."""

        prompt = build_explanation_prompt(result_view)
        request_body: dict[str, object] = {
            "model": self.route.primary_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": self._raw["temperature"],
            # Orca Router supports the OpenAI JSON mode across the free
            # router's current DeepSeek pool.  The prompt still defines the
            # semantic contract; this field prevents markdown-wrapped JSON
            # from being returned before our strict parser sees the content.
            "response_format": {"type": "json_object"},
        }
        if self.route.fallback_models:
            request_body["models"] = list(self.route.models)
            request_body["route"] = "fallback"
        return request_body

    def _request_with_retry(
        self, request: urllib.request.Request
    ) -> tuple[object, Mapping[str, object]]:
        max_retries = int(self._raw["max_retries"])
        timeout = float(self._raw["timeout_seconds"])
        for retry_index in range(max_retries + 1):
            try:
                response = self._opener(request, timeout=timeout)
                with response:
                    limit = int(self._raw["max_response_bytes"])
                    data = response.read(limit + 1)
                    if len(data) > limit:
                        raise _invalid_response(
                            "Orca Router response exceeds the configured limit"
                        )
                    try:
                        envelope = json.loads(data.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise _invalid_response(
                            "Orca Router response envelope is not valid JSON"
                        ) from exc
                    headers = response.headers
                return envelope, headers
            except urllib.error.HTTPError as exc:
                failure = classify_http_failure(exc.code)
                if retry_index < max_retries and _retryable_http_status(exc.code):
                    if exc.code == 429:
                        retry_after = _header(
                            exc.headers, "retry-after", include_unprefixed=True
                        )
                        # A free-tier 429 without Retry-After is a prompt-size
                        # rejection. Retrying the unchanged request cannot
                        # succeed and needlessly consumes another API call.
                        if retry_after is None:
                            raise OrcaRouterError(failure.safe_message, failure) from exc
                        delay = _retry_after_seconds(exc.headers, maximum=timeout)
                        if delay > 0:
                            self._sleeper(delay)
                    continue
                raise OrcaRouterError(failure.safe_message, failure) from exc
            except OrcaRouterError:
                raise
            except (TimeoutError, socket.timeout) as exc:
                failure = ProviderFailure(
                    ProviderErrorClass.TIMEOUT, True, "LLM provider request timed out"
                )
                raise OrcaRouterError(failure.safe_message, failure) from exc
            except (OSError, urllib.error.URLError) as exc:
                failure = ProviderFailure(
                    ProviderErrorClass.TRANSPORT, True, "LLM provider transport failed"
                )
                raise OrcaRouterError(failure.safe_message, failure) from exc
            except Exception as exc:
                failure = ProviderFailure(
                    ProviderErrorClass.UNKNOWN, False, "LLM provider request failed"
                )
                raise OrcaRouterError(failure.safe_message, failure) from exc
        raise AssertionError("unreachable retry state")


def _parse_envelope(envelope: object) -> tuple[Mapping[str, object], str | None, str | None, Mapping[str, object]]:
    if not isinstance(envelope, Mapping):
        raise _invalid_response("Orca Router response must be an object")
    choices = envelope.get("choices")
    if not isinstance(choices, list) or not choices:
        raise _invalid_response("Orca Router returned no completion choices")
    first = choices[0]
    if not isinstance(first, Mapping) or not isinstance(first.get("message"), Mapping):
        raise _invalid_response("Orca Router returned an invalid completion choice")
    content = first["message"].get("content")
    if not isinstance(content, str) or not content.strip():
        raise _invalid_response("Orca Router returned empty content")
    try:
        answer = json.loads(content)
    except json.JSONDecodeError as exc:
        raise _invalid_response("Orca Router content is not strict JSON") from exc
    if not isinstance(answer, Mapping):
        raise _invalid_response("Orca Router content must be a JSON object")
    usage = envelope.get("usage")
    return answer, _optional_str(envelope.get("model")), _optional_str(envelope.get("id")), usage if isinstance(usage, Mapping) else {}


def _record_usage(path: object, metadata: Mapping[str, object], view: Mapping[str, object]) -> None:
    if not path:
        return
    record = dict(metadata)
    record["bundle_hash"] = view["bundle_hash"]
    target = Path(str(path))
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _validate_response_metadata(metadata: Mapping[str, object]) -> None:
    for key in ("requested_model", "resolved_model", "fallback_model"):
        value = metadata.get(key)
        if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 128):
            raise _invalid_response(f"Orca Router returned invalid {key} metadata")
    request_id = metadata.get("request_id")
    if request_id is not None and (
        not isinstance(request_id, str) or not 1 <= len(request_id) <= 256
    ):
        raise _invalid_response("Orca Router returned invalid request_id metadata")
    fallback_level = metadata.get("fallback_level")
    if fallback_level is not None and (
        not isinstance(fallback_level, int) or not 0 <= fallback_level <= 4
    ):
        raise _invalid_response("Orca Router returned invalid fallback_level metadata")
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = metadata.get(key)
        if value is not None and (not isinstance(value, int) or value < 0):
            raise _invalid_response(f"Orca Router returned invalid {key} metadata")
    cost = metadata.get("cost_usd")
    if cost is not None and (not isinstance(cost, (int, float)) or cost < 0):
        raise _invalid_response("Orca Router returned invalid cost metadata")


def _invalid_response(message: str) -> OrcaRouterError:
    return OrcaRouterError(
        message,
        ProviderFailure(ProviderErrorClass.INVALID_RESPONSE, False, message),
    )


def _retryable_http_status(status_code: int) -> bool:
    return status_code in {408, 429} or 500 <= status_code <= 599


def _retry_after_seconds(headers: object, *, maximum: float) -> float:
    value = _header(headers, "retry-after", include_unprefixed=True)
    if value is None:
        return 0.0
    try:
        return min(max(float(value), 0.0), maximum)
    except (TypeError, ValueError):
        try:
            retry_at = parsedate_to_datetime(str(value))
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            delay = (retry_at - datetime.now(timezone.utc)).total_seconds()
            return min(max(delay, 0.0), maximum)
        except (TypeError, ValueError, OverflowError):
            return 0.0


def _header(
    headers: object, suffix: str, *, include_unprefixed: bool = False
) -> object | None:
    if not isinstance(headers, Mapping) and not hasattr(headers, "items"):
        return None
    normalized = {str(key).lower(): value for key, value in headers.items()}
    names = [f"x-orca-{suffix}", f"x-orcarouter-{suffix}"]
    if include_unprefixed:
        names.insert(0, suffix)
    for name in names:
        if name in normalized:
            return normalized[name]
    return None


def _optional_str(value: object) -> str | None:
    return str(value) if value is not None else None


def _int_or_none(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _float_or_none(value: object) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


__all__ = ["OrcaRouterError", "OrcaRouterExplanationGateway", "SYSTEM_PROMPT"]
