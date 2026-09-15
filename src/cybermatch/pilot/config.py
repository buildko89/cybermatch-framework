"""Repository-scoped operational configuration for pilot explanation gateways."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from .ai import LLMGateway, TemplateExplanationGateway
from .orcarouter import OrcaRouterExplanationGateway
from .policy import LLMPolicyError, validate_orcarouter_config


PILOT_LLM_CONFIG_ENV = "CYBERMATCH_PILOT_LLM_CONFIG"


def load_llm_config(
    repository_root: str | Path, config_path: str | Path
) -> Mapping[str, object]:
    """Load a validated config confined to the repository tree."""

    root = Path(repository_root).resolve()
    candidate = Path(config_path)
    if candidate.is_absolute():
        raise LLMPolicyError("pilot LLM config path must be repository-relative")
    target = (root / candidate).resolve()
    if not target.is_relative_to(root):
        raise LLMPolicyError("pilot LLM config path escapes the repository")
    try:
        payload = json.loads(
            target.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise LLMPolicyError("pilot LLM config could not be loaded") from exc
    if not isinstance(payload, Mapping):
        raise LLMPolicyError("pilot LLM config must be a JSON object")
    validate_orcarouter_config(payload)
    return payload


def build_explanation_gateway(
    repository_root: str | Path, *, config_path: str | Path | None = None
) -> LLMGateway:
    """Build the configured gateway, or the offline template when none is selected."""

    if config_path is None:
        return TemplateExplanationGateway()
    payload = load_llm_config(repository_root, config_path)
    return OrcaRouterExplanationGateway(payload, repository_root=repository_root)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise LLMPolicyError(f"pilot LLM config contains duplicate key: {key}")
        output[key] = value
    return output


__all__ = ["PILOT_LLM_CONFIG_ENV", "build_explanation_gateway", "load_llm_config"]
