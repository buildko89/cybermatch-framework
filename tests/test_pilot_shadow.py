from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.cybermatch.pilot.ai import TemplateExplanationGateway
from src.cybermatch.pilot.shadow import run_shadow_evaluation, write_shadow_report


pytestmark = [pytest.mark.phase3, pytest.mark.threat_hunting]


def _view() -> dict[str, object]:
    return {
        "bundle_hash": "a" * 64,
        "metrics": {"f1": 0.75},
        "artifacts": [{"path": "hunting/metrics.json"}],
        "limitations": ["Replay evidence is not live production evidence."],
    }


def test_shadow_evaluation_runs_three_times_and_writes_internal_artifacts(tmp_path: Path) -> None:
    report = run_shadow_evaluation(
        _view(),
        {"template": TemplateExplanationGateway()},
        runs=3,
        unavailable={"orcarouter": "not_configured"},
    )
    json_path, markdown_path = write_shadow_report(report, tmp_path)
    assert len(report["runs"]) == 3
    assert report["candidate_summaries"][0]["run_count"] == 3
    assert report["candidate_summaries"][0]["schema_grounding_pass_rate"] == 1.0
    assert report["candidate_summaries"][0]["fallback_count"] == 0
    assert report["candidate_summaries"][0]["unique_output_count"] == 1
    assert report["unavailable_candidates"][0]["status"] == "not_run"
    assert json.loads(json_path.read_text("utf-8"))["blind_review_status"] == "pending"
    assert "Shadow Evaluation" in markdown_path.read_text("utf-8")
    blind = json.loads((tmp_path / "shadow_blind_review.json").read_text("utf-8"))
    key = json.loads((tmp_path / "shadow_blind_review_key.json").read_text("utf-8"))
    assert blind["items"][0]["candidate_label"] == "candidate-A"
    assert "provider_id" not in blind["items"][0]
    assert key["candidate_mapping"] == {"candidate-A": "template"}


@pytest.mark.parametrize("runs", [0, 2, 6])
def test_shadow_evaluation_enforces_three_to_five_runs(runs: int) -> None:
    with pytest.raises(ValueError, match="3 to 5"):
        run_shadow_evaluation(_view(), {"template": TemplateExplanationGateway()}, runs=runs)
