from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.cybermatch.pilot.ai import grounded_explanation
from src.cybermatch.pilot.local_qwen import LocalQwenExplanationGateway


pytestmark = [pytest.mark.phase3, pytest.mark.threat_hunting]


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
        "claims": [{"text": "F1 is 0.75.", "metric": "f1", "evidence_path": "hunting/metrics.json", "confidence": "measured"}],
        "limitations": ["Replay evidence is not live production evidence."],
        "limitation_codes": ["replay_not_live_production"],
        "recommended_human_decision": "Review the evidence.",
        "bundle_hash": "a" * 64,
    }


class FakeBackend:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def create_chat_completion(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        return self.response


def _gateway(tmp_path: Path, backend: FakeBackend) -> LocalQwenExplanationGateway:
    return LocalQwenExplanationGateway(
        tmp_path,
        backend_factory=lambda **kwargs: backend,
        model_verifier=lambda path: None,
    )


def test_local_qwen_returns_grounded_audited_answer(tmp_path: Path) -> None:
    backend = FakeBackend({
        "choices": [{"message": {"content": json.dumps(_answer())}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    })
    result = grounded_explanation(_view(), _gateway(tmp_path, backend))
    assert result["audit"]["provider_id"] == "local-qwen"
    assert result["audit"]["validation_status"] == "accepted"
    assert result["audit"]["cost_usd"] == 0.0
    assert result["audit"]["total_tokens"] == 30
    assert backend.calls[0]["response_format"] == {"type": "json_object"}


def test_local_qwen_malformed_answer_falls_back(tmp_path: Path) -> None:
    backend = FakeBackend({"choices": [{"message": {"content": "not-json"}}]})
    result = grounded_explanation(_view(), _gateway(tmp_path, backend))
    assert result["audit"]["validation_status"] == "fallback"
    assert result["audit"]["failure_class"] == "invalid_response"
