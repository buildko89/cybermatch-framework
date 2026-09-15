"""Pinned llama.cpp adapter for the Qwen2.5 model approved in LOCAL-1."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any, Callable, Mapping

from .ai import GatewayExplanation
from .policy import ProviderErrorClass, ProviderFailure
from .prompts import SYSTEM_PROMPT, build_explanation_prompt


MODEL_NAME = "qwen2.5-1.5b-instruct-q4_k_m.gguf"
MODEL_ID = "qwen2.5-1.5b-instruct-q4_k_m"
MODEL_SHA256 = "6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e"
MODEL_SIZE_BYTES = 1_117_320_736
MAX_RESPONSE_BYTES = 256 * 1024


class LocalQwenError(RuntimeError):
    def __init__(self, message: str, failure: ProviderFailure) -> None:
        super().__init__(message)
        self.failure = failure


class LocalQwenExplanationGateway:
    provider_id = "local-qwen"
    model_id = MODEL_ID

    def __init__(
        self,
        repository_root: str | Path,
        *,
        backend_factory: Callable[..., Any] | None = None,
        model_verifier: Callable[[Path], None] | None = None,
        n_ctx: int = 8192,
        max_tokens: int = 1024,
        temperature: float = 0.1,
    ) -> None:
        self.root = Path(repository_root).resolve()
        self.model_path = self.root / "models" / "local_llm" / MODEL_NAME
        (model_verifier or verify_local_qwen)(self.model_path)
        self._backend_factory = backend_factory
        self._backend: Any = None
        self.n_ctx = n_ctx
        self.max_tokens = max_tokens
        self.temperature = temperature

    def explain(self, result_view: Mapping[str, object]) -> GatewayExplanation:
        prompt = build_explanation_prompt(result_view)
        started = time.perf_counter()
        try:
            response = self._model().create_chat_completion(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"},
            )
            answer, usage = _parse_local_response(response)
        except LocalQwenError:
            raise
        except Exception as exc:
            failure = ProviderFailure(
                ProviderErrorClass.TRANSPORT,
                False,
                "Local Qwen inference failed",
            )
            raise LocalQwenError(failure.safe_message, failure) from exc
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return GatewayExplanation(
            answer=answer,
            metadata={
                "requested_model": self.model_id,
                "resolved_model": self.model_id,
                "request_id": None,
                "fallback_level": 0,
                "fallback_model": None,
                "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                "prompt_tokens": _nonnegative_int(usage.get("prompt_tokens")),
                "completion_tokens": _nonnegative_int(usage.get("completion_tokens")),
                "total_tokens": _nonnegative_int(usage.get("total_tokens")),
                "cost_usd": 0.0,
                "latency_ms": latency_ms,
            },
        )

    def _model(self) -> Any:
        if self._backend is not None:
            return self._backend
        factory = self._backend_factory
        if factory is None:
            try:
                from llama_cpp import Llama
            except ImportError as exc:
                failure = ProviderFailure(
                    ProviderErrorClass.CONFIGURATION,
                    False,
                    "llama-cpp-python is not installed",
                )
                raise LocalQwenError(failure.safe_message, failure) from exc
            factory = Llama
        self._backend = factory(
            model_path=str(self.model_path),
            n_ctx=self.n_ctx,
            n_threads=max(1, (os.cpu_count() or 2) - 1),
            seed=0,
            verbose=False,
        )
        return self._backend


def verify_local_qwen(path: Path) -> None:
    if not path.is_file() or path.stat().st_size != MODEL_SIZE_BYTES:
        raise LocalQwenError(
            "Pinned local Qwen model is missing or has the wrong size",
            ProviderFailure(
                ProviderErrorClass.CONFIGURATION,
                False,
                "Pinned local Qwen model is missing or invalid",
            ),
        )
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != MODEL_SHA256:
        raise LocalQwenError(
            "Pinned local Qwen model SHA-256 mismatch",
            ProviderFailure(
                ProviderErrorClass.CONFIGURATION,
                False,
                "Pinned local Qwen model is missing or invalid",
            ),
        )


def _parse_local_response(response: object) -> tuple[Mapping[str, object], Mapping[str, object]]:
    if not isinstance(response, Mapping):
        raise _invalid_response("Local Qwen response must be an object")
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise _invalid_response("Local Qwen returned no completion choices")
    choice = choices[0]
    if not isinstance(choice, Mapping) or not isinstance(choice.get("message"), Mapping):
        raise _invalid_response("Local Qwen returned an invalid completion choice")
    if choice.get("finish_reason") == "length":
        raise _invalid_response("Local Qwen response reached the token limit")
    content = choice["message"].get("content")
    if not isinstance(content, str) or not content.strip():
        raise _invalid_response("Local Qwen returned empty content")
    if len(content.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise _invalid_response("Local Qwen response exceeds the configured limit")
    try:
        answer = json.loads(content)
    except json.JSONDecodeError as exc:
        raise _invalid_response("Local Qwen content is not strict JSON") from exc
    if not isinstance(answer, Mapping):
        raise _invalid_response("Local Qwen content must be a JSON object")
    usage = response.get("usage")
    return answer, usage if isinstance(usage, Mapping) else {}


def _invalid_response(message: str) -> LocalQwenError:
    return LocalQwenError(
        message,
        ProviderFailure(ProviderErrorClass.INVALID_RESPONSE, False, message),
    )


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
    return parsed if parsed is None or parsed >= 0 else None


__all__ = [
    "LocalQwenError",
    "LocalQwenExplanationGateway",
    "MODEL_ID",
    "MODEL_NAME",
    "MODEL_SHA256",
    "MODEL_SIZE_BYTES",
    "verify_local_qwen",
]
