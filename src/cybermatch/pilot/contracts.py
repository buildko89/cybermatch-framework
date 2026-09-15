"""Versioned contracts for the human-approved pilot workflow."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Mapping

from jsonschema import Draft202012Validator


PILOT_CONTRACT_VERSION = "1.0"
AI_ANSWER_CONTRACT_VERSION = "1.1"
SCHEMAS = {
    "run_spec": "pilot-run-spec.schema.json",
    "result_view": "pilot-result-view.schema.json",
    "ai_answer": "pilot-ai-answer.schema.json",
    "llm_audit": "pilot-llm-audit.schema.json",
    "orcarouter_config": "pilot-orcarouter-config.schema.json",
}


def validate_contract(name: str, payload: object) -> None:
    if name not in SCHEMAS:
        raise ValueError(f"unknown pilot contract: {name}")
    schema = json.loads(files("src.cybermatch.schemas").joinpath(SCHEMAS[name]).read_text("utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda e: list(e.path))
    if errors:
        error = errors[0]
        location = ".".join(str(item) for item in error.path) or "<root>"
        raise ValueError(f"{name}.{location}: {error.message}")


def require_approved_run_spec(payload: Mapping[str, object]) -> None:
    validate_contract("run_spec", payload)
    approval = payload["human_approval"]
    assert isinstance(approval, Mapping)
    if approval.get("status") != "approved":
        raise ValueError("human approval is required before evaluation")


__all__ = [
    "AI_ANSWER_CONTRACT_VERSION",
    "PILOT_CONTRACT_VERSION",
    "require_approved_run_spec",
    "validate_contract",
]
