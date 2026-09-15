from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.cybermatch.pilot.ai import TemplateExplanationGateway
from src.cybermatch.pilot.config import build_explanation_gateway, load_llm_config
from src.cybermatch.pilot.orcarouter import OrcaRouterExplanationGateway
from src.cybermatch.pilot.policy import LLMPolicyError
from src.cybermatch.pilot.service import PilotEvaluationService


pytestmark = [pytest.mark.phase3, pytest.mark.threat_hunting]
ROOT = Path(__file__).resolve().parents[1]


def test_gateway_factory_is_offline_by_default_and_loads_explicit_config() -> None:
    assert isinstance(build_explanation_gateway(ROOT), TemplateExplanationGateway)
    assert isinstance(
        build_explanation_gateway(ROOT, config_path="configs/pilot/orcarouter.example.json"),
        OrcaRouterExplanationGateway,
    )


def test_config_loader_rejects_paths_outside_repository() -> None:
    with pytest.raises(LLMPolicyError, match="repository-relative"):
        load_llm_config(ROOT, ROOT / "configs/pilot/orcarouter.example.json")
    with pytest.raises(LLMPolicyError, match="escapes"):
        load_llm_config(ROOT, "../outside.json")


def test_config_loader_rejects_duplicate_keys(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "duplicate.json").write_text(
        '{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8"
    )
    with pytest.raises(LLMPolicyError, match="duplicate key"):
        load_llm_config(root, "duplicate.json")


def test_service_receives_gateway_from_operational_config() -> None:
    service = PilotEvaluationService(
        ROOT, llm_config_path="configs/pilot/orcarouter.example.json"
    )
    assert isinstance(service.gateway, OrcaRouterExplanationGateway)


def test_service_rejects_ambiguous_gateway_configuration() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        PilotEvaluationService(
            ROOT,
            gateway=TemplateExplanationGateway(),
            llm_config_path="configs/pilot/orcarouter.example.json",
        )
