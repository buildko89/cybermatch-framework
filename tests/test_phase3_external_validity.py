from __future__ import annotations

import json
from pathlib import Path

import pytest

from cybermatch_core.contracts import load_evidence_bundle
from cybermatch_core.external_sut import (
    ExternalSUTRequest,
    ExternalSUTResponse,
    run_external_replay_evaluation,
    validate_sut_response,
)
from cybermatch_core.threat_hunting import ExternalFieldMapping, HuntEvent, SCHEMA_VERSION
from scripts.run_external_replay import main as replay_main


pytestmark = [pytest.mark.phase3, pytest.mark.threat_hunting]
ROOT = Path(__file__).resolve().parents[1]


class _EmptyExternalAdapter:
    adapter_id = "pilot-external-sut"
    adapter_version = "1.0.0"

    def evaluate(self, request: ExternalSUTRequest) -> ExternalSUTResponse:
        return ExternalSUTResponse(
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            status="succeeded",
            findings=(),
        )


def _event(event_id: str = "event-1") -> HuntEvent:
    return HuntEvent(
        schema_version=SCHEMA_VERSION,
        event_id=event_id,
        step=0,
        campaign_id="campaign",
        scenario_id="scenario",
        seed=0,
        actor_id="actor",
        coalition_id=None,
        event_type="unintended_tool_probe",
        source_node=0,
        target_node=1,
        source_role=None,
        target_role=None,
        signal_class="telemetry",
    )


def _run(output: Path) -> dict[str, object]:
    return run_external_replay_evaluation(
        source_path=ROOT / "replays/anonymized/ocsf_boundary_escape_v1.jsonl",
        mapping_path=ROOT / "mappings/telemetry/ocsf_security_finding_v1.json",
        recipe_path=ROOT / "recipes/threat_hunting/agentic_boundary_pressure_v1.json",
        ground_truth_path=ROOT / "replays/anonymized/ocsf_boundary_escape_v1.ground_truth.json",
        synthetic_reference_path=ROOT / "replays/synthetic_reference/agentic_boundary_pressure_v1.json",
        output_dir=output,
        campaign_id="phase3-anonymized-replay",
        scenario_id="agentic-boundary-pressure-external",
        repository_root=ROOT,
    )


def test_external_sut_request_is_observation_only_and_validated() -> None:
    request = ExternalSUTRequest(
        run_id="run",
        events=(_event(),),
        evidence_class="replay-backed",
        detector_id="detector",
        detector_version="1.0",
    )
    payload = request.to_dict()
    assert set(payload) == {
        "contract_version", "run_id", "evidence_class", "detector_id", "detector_version", "events"
    }
    assert "ground_truth" not in json.dumps(payload)

    response = ExternalSUTResponse(
        adapter_id="test", adapter_version="1", status="succeeded", findings=()
    )
    validate_sut_response(request, response)
    with pytest.raises(ValueError, match="unsupported evidence_class"):
        ExternalSUTRequest(
            run_id="run",
            events=(_event(),),
            evidence_class="unknown",
            detector_id="detector",
            detector_version="1.0",
        )


def test_standard_mapping_assets_are_versioned_and_loadable() -> None:
    for path in sorted((ROOT / "mappings/telemetry").glob("*.json")):
        mapping = ExternalFieldMapping.from_dict(json.loads(path.read_text(encoding="utf-8")))
        assert mapping.mapping_version == "1.0.0"
        assert mapping.standard in {"cybermatch", "opentelemetry", "ocsf", "ecs"}
        assert len(mapping.mapping_hash) == 64


def test_anonymized_replay_runs_same_protocol_and_writes_verified_evidence(tmp_path: Path) -> None:
    output = tmp_path / "phase3-replay"
    result = _run(output)

    assert result["status"] == "succeeded"
    assert result["evidence_class"] == "replay-backed"
    assert result["event_count"] == 4
    assert result["finding_count"] == 1
    assert result["metrics"]["f1"] == 1.0
    assert result["domain_gap"]["event_type_js_divergence"] > 0
    manifest = json.loads((output / "replay_manifest.json").read_text(encoding="utf-8"))
    assert manifest["mapping"]["standard"] == "ocsf"
    assert manifest["source"]["sha256"]
    assert manifest["ground_truth"]["evaluator_only"] is True
    assert load_evidence_bundle(output).bundle_hash == result["evidence_bundle_hash"]
    report = (output / "PHASE3_EXTERNAL_VALIDITY_REPORT.md").read_text(encoding="utf-8")
    assert "Generalization boundary" in report
    assert "does not establish effectiveness for live production traffic" in report


def test_external_sut_evidence_cannot_use_reference_adapter(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="non-reference SUT adapter"):
        run_external_replay_evaluation(
            source_path=ROOT / "replays/anonymized/ocsf_boundary_escape_v1.jsonl",
            mapping_path=ROOT / "mappings/telemetry/ocsf_security_finding_v1.json",
            recipe_path=ROOT / "recipes/threat_hunting/agentic_boundary_pressure_v1.json",
            ground_truth_path=ROOT / "replays/anonymized/ocsf_boundary_escape_v1.ground_truth.json",
            synthetic_reference_path=ROOT / "replays/synthetic_reference/agentic_boundary_pressure_v1.json",
            output_dir=tmp_path / "external",
            campaign_id="phase3-anonymized-replay",
            scenario_id="scenario",
            evidence_class="external-sut-backed",
            repository_root=ROOT,
        )


def test_non_reference_adapter_can_emit_external_sut_backed_evidence(tmp_path: Path) -> None:
    output = tmp_path / "external-sut"
    result = run_external_replay_evaluation(
        source_path=ROOT / "replays/anonymized/ocsf_boundary_escape_v1.jsonl",
        mapping_path=ROOT / "mappings/telemetry/ocsf_security_finding_v1.json",
        recipe_path=ROOT / "recipes/threat_hunting/agentic_boundary_pressure_v1.json",
        ground_truth_path=ROOT / "replays/anonymized/ocsf_boundary_escape_v1.ground_truth.json",
        synthetic_reference_path=ROOT / "replays/synthetic_reference/agentic_boundary_pressure_v1.json",
        output_dir=output,
        campaign_id="phase3-anonymized-replay",
        scenario_id="scenario",
        evidence_class="external-sut-backed",
        sut_adapter=_EmptyExternalAdapter(),
        repository_root=ROOT,
    )
    assert result["evidence_class"] == "external-sut-backed"
    manifest = json.loads((output / "replay_manifest.json").read_text(encoding="utf-8"))
    assert manifest["sut"]["adapter_id"] == "pilot-external-sut"


def test_replay_cli_runs_and_refuses_overwrite(tmp_path: Path, capsys) -> None:
    output = tmp_path / "cli-output"
    arguments = [
        "--source", str(ROOT / "replays/anonymized/ocsf_boundary_escape_v1.jsonl"),
        "--mapping", str(ROOT / "mappings/telemetry/ocsf_security_finding_v1.json"),
        "--recipe", str(ROOT / "recipes/threat_hunting/agentic_boundary_pressure_v1.json"),
        "--ground-truth", str(ROOT / "replays/anonymized/ocsf_boundary_escape_v1.ground_truth.json"),
        "--synthetic-reference", str(ROOT / "replays/synthetic_reference/agentic_boundary_pressure_v1.json"),
        "--output", str(output),
        "--campaign-id", "phase3-anonymized-replay",
        "--scenario-id", "agentic-boundary-pressure-external",
    ]
    assert replay_main(arguments) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "succeeded"
    assert replay_main(arguments) == 2
    assert "already exists" in capsys.readouterr().err
