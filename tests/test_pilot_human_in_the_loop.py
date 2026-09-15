from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from src.cybermatch.contracts import canonical_sha256
from src.cybermatch.pilot.ai import TemplateExplanationGateway, grounded_explanation
from src.cybermatch.pilot.contracts import require_approved_run_spec
from src.cybermatch.pilot.grounding import validate_ai_answer
from src.cybermatch.pilot.service import PilotEvaluationService


pytestmark = [pytest.mark.phase3, pytest.mark.threat_hunting]
ROOT = Path(__file__).resolve().parents[1]


def _spec(status: str = "approved") -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "run_id": "pilot-test-001",
        "decision_question": "Can this replayed boundary escape be detected?",
        "evaluation_type": "external_replay",
        "scenario_id": "agentic-boundary-pressure-external",
        "evidence_class": "replay-backed",
        "source_id": "ocsf-boundary-escape-fixture-v1",
        "mapping_id": "ocsf_security_finding_v1",
        "recipe_id": "agentic_boundary_pressure_v1",
        "seed": 0,
        "human_approval": {
            "status": status,
            "approved_by": "pilot-tester",
            "approved_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def test_human_approval_is_mandatory() -> None:
    with pytest.raises(ValueError, match="human approval"):
        require_approved_run_spec(_spec("draft"))


def test_pilot_vertical_slice_and_human_decision(tmp_path: Path) -> None:
    service = PilotEvaluationService(ROOT, output_root=tmp_path / "pilot")
    result = service.execute(_spec())
    view = result["result_view"]
    answer = result["explanation"]["answer"]

    assert view["status"] == "succeeded"
    assert view["evidence_class"] == "replay-backed"
    assert "ground_truth" not in view
    assert validate_ai_answer(answer, view)
    decision = service.record_decision(
        "pilot-test-001",
        decision="additional_validation",
        rationale="A third-party replay is still required.",
        decided_by="pilot-tester",
    )
    assert decision.is_file()
    decision_payload = json.loads(decision.read_text(encoding="utf-8"))
    assert decision_payload["llm_audit_hash"] == canonical_sha256(
        result["explanation"]["audit"]
    )


def test_gateway_status_contains_only_non_secret_operational_identity(tmp_path: Path) -> None:
    service = PilotEvaluationService(ROOT, output_root=tmp_path / "pilot")

    assert service.gateway_status() == {
        "provider_id": "deterministic-template",
        "model_id": "pilot-fallback-v1",
        "mode": "offline-template",
    }


def test_gateway_choice_does_not_change_evaluation_or_evidence_bundle(
    tmp_path: Path,
) -> None:
    class AcceptedGateway:
        provider_id = "test-ai"
        model_id = "test-model"

        def explain(self, result_view: dict[str, object]) -> dict[str, object]:
            return TemplateExplanationGateway().explain(result_view)

    offline = PilotEvaluationService(ROOT, output_root=tmp_path / "offline").execute(
        _spec()
    )
    assisted = PilotEvaluationService(
        ROOT,
        output_root=tmp_path / "assisted",
        gateway=AcceptedGateway(),
    ).execute(_spec())

    assert offline["summary"] == assisted["summary"]
    assert offline["result_view"] == assisted["result_view"]
    assert offline["result_view"]["bundle_hash"] == assisted["result_view"]["bundle_hash"]
    assert offline["explanation"]["audit"]["validation_status"] == "fallback"
    assert assisted["explanation"]["audit"]["validation_status"] == "accepted"


def test_grounding_rejects_hallucinated_metric_and_artifact() -> None:
    view = {
        "bundle_hash": "a" * 64,
        "metrics": {"f1": 1.0},
        "artifacts": [{"path": "metrics.json"}],
        "limitations": ["replay only"],
    }
    answer = grounded_explanation(
        {**view, "artifacts": [{"path": "hunting/metrics.json"}]}
    )["answer"]
    answer["claims"][0]["metric"] = "invented_metric"
    with pytest.raises(ValueError, match="unknown metric"):
        validate_ai_answer(answer, view)


def test_human_decision_rejects_tampered_or_cross_run_audit(tmp_path: Path) -> None:
    service = PilotEvaluationService(ROOT, output_root=tmp_path / "pilot")
    service.execute(_spec())
    result_path = tmp_path / "pilot" / "pilot-test-001" / "pilot_result.json"
    stored = json.loads(result_path.read_text(encoding="utf-8"))
    stored["explanation"]["audit"]["result_view_hash"] = "0" * 64
    result_path.write_text(json.dumps(stored), encoding="utf-8")

    with pytest.raises(ValueError, match="result-view hash"):
        service.record_decision(
            "pilot-test-001",
            decision="reject",
            rationale="Audit does not belong to this verified view.",
            decided_by="pilot-tester",
        )
