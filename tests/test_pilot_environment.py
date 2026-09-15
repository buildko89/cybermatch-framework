from __future__ import annotations

from pathlib import Path

import pytest

from src.cybermatch.pilot.environment import load_pilot_environment
from src.cybermatch.pilot.policy import LLMPolicyError


pytestmark = [pytest.mark.phase3, pytest.mark.threat_hunting]


def test_env_loader_reads_allowlisted_values_without_overriding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ORCAROUTER_API_KEY", "process-key")
    (tmp_path / ".env").write_text(
        "ORCAROUTER_API_KEY=file-key\n"
        "CYBERMATCH_PILOT_LLM_CONFIG=configs/pilot/orcarouter.example.json\n",
        encoding="utf-8",
    )
    loaded = load_pilot_environment(tmp_path)
    assert loaded == ("CYBERMATCH_PILOT_LLM_CONFIG",)
    assert __import__("os").environ["ORCAROUTER_API_KEY"] == "process-key"


def test_env_loader_rejects_unknown_or_duplicate_keys(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("UNAPPROVED=value\n", encoding="utf-8")
    with pytest.raises(LLMPolicyError, match="not allowed"):
        load_pilot_environment(tmp_path)

    (tmp_path / ".env").write_text(
        "ORCAROUTER_API_KEY=one\nORCAROUTER_API_KEY=two\n", encoding="utf-8"
    )
    with pytest.raises(LLMPolicyError, match="duplicate"):
        load_pilot_environment(tmp_path)
