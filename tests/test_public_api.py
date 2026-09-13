from pathlib import Path

import cybermatch_core
from cybermatch_core import contracts


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_stable_facade_exposes_version_and_contracts() -> None:
    assert cybermatch_core.__version__ == "1.0.1"
    assert contracts.RUN_CONTRACT_VERSION
    assert contracts.SchemaRegistry
    assert "EvaluationRun" in contracts.__all__


def test_public_api_policy_documents_compatibility_window() -> None:
    policy = (REPOSITORY_ROOT / "PUBLIC_API.md").read_text(encoding="utf-8")
    assert "cybermatch_core" in policy
    assert "no earlier than 2.0" in policy
    assert "RUN_CONTRACT_VERSION" in policy
