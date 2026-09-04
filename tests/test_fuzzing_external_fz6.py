from __future__ import annotations

import inspect
import json
import sys

import pytest

from src.cybermatch.fuzzing import (
    AllowlistedCommandTransport,
    ExecutionLimits,
    ExternalCodec,
    ExternalInfrastructureError,
    ExternalMappingError,
    ExternalSUTTarget,
    FuzzSpecError,
    load_campaign_spec,
    load_external_mapping,
)
from src.cybermatch.fuzzing.oracles import external_execution_health_oracle
from src.cybermatch.threat_hunting import Finding, HuntEvent, SCHEMA_VERSION


MAPPING_PATH = "fuzzing/mappings/vendor_neutral_v1.json"


def _events() -> tuple[HuntEvent, ...]:
    return (
        HuntEvent(
            schema_version=SCHEMA_VERSION,
            event_id="external-event-1",
            step=1,
            campaign_id="external-campaign",
            scenario_id="external-scenario",
            seed=9,
            actor_id="actor-日本語",
            coalition_id=None,
            event_type="critical_path_entry",
            source_node=0,
            target_node=4,
            source_role="workstation",
            target_role="critical_server",
            signal_class="derived_signal",
            attributes={"bytes": 256, "trusted": False, "note": "α,β"},
        ),
        HuntEvent(
            schema_version=SCHEMA_VERSION,
            event_id="external-event-2",
            step=2,
            campaign_id="external-campaign",
            scenario_id="external-scenario",
            seed=9,
            actor_id="actor-日本語",
            coalition_id=None,
            event_type="critical_path_near_target",
            source_node=1,
            target_node=4,
            source_role="server",
            target_role="critical_server",
            signal_class="derived_signal",
            attributes={"ratio": 0.125, "nullable": None},
        ),
    )


def _finding() -> Finding:
    return Finding(
        schema_version=SCHEMA_VERSION,
        finding_id="external-finding-1",
        recipe_id="external-detector",
        recipe_version="2.1",
        severity="high",
        score=0.875,
        campaign_id="external-campaign",
        actor_id="actor-日本語",
        start_step=1,
        end_step=2,
        title="External detection",
        reason="Mapped evidence",
        evidence_event_ids=("external-event-1", "external-event-2"),
        observed_value=2.0,
        baseline_value=None,
        threshold=1.0,
        attributes={"vendor_rule": "rule-7", "reviewed": False},
    )


@pytest.mark.parametrize("format_name", ["jsonl", "csv"])
def test_external_event_and_finding_round_trip_preserves_semantics(format_name):
    codec = ExternalCodec(load_external_mapping(MAPPING_PATH))

    events = codec.decode_events(codec.encode_events(_events(), format_name), format_name)
    findings = codec.decode_findings(
        codec.encode_findings((_finding(),), format_name),
        format_name,
        allowed_event_ids=frozenset(event.event_id for event in _events()),
    )

    assert [event.to_dict() for event in events] == [event.to_dict() for event in _events()]
    assert [finding.to_dict() for finding in findings] == [_finding().to_dict()]


def test_external_mapping_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / "duplicate-mapping.json"
    path.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")

    with pytest.raises(ExternalMappingError, match="duplicate key"):
        load_external_mapping(path)


def test_fz6_campaign_records_versioned_external_configuration():
    spec = load_campaign_spec("fuzzing/campaigns/threat_hunting_fz6_external_mock_v1.json")
    target = ExternalSUTTarget(
        spec.target.recipes,
        repository_root=".",
        configuration=spec.target.external,
    )
    configuration = target.manifest.to_dict()["configuration"]

    assert spec.target.adapter == "external_sut"
    assert configuration["mapping_id"] == "vendor_neutral_v1"
    assert configuration["mapping_version"] == "1.0.0"
    assert configuration["sut_id"] == "cybermatch_external_mock"
    assert configuration["transport"] == "mock"


def test_mock_external_target_normalizes_findings_and_provenance():
    spec = load_campaign_spec("fuzzing/campaigns/threat_hunting_fz6_external_mock_v1.json")
    target = ExternalSUTTarget(
        spec.target.recipes,
        repository_root=".",
        configuration=spec.target.external,
    )

    result = target.execute(_events(), ExecutionLimits())

    assert result.status == "completed"
    assert len(result.findings) == 1
    assert result.state_observations["encoded_event_count"] == 2
    assert result.state_observations["normalized_finding_count"] == 1
    assert result.state_observations["detection_verdict_eligible"] is True
    assert result.state_observations["mapping_version"] == "1.0.0"


class _FlakyTransport:
    def __init__(self, response: bytes, *, always_fail: bool = False):
        self.response = response
        self.always_fail = always_fail
        self.calls = 0

    def submit(self, payload, **kwargs):
        self.calls += 1
        if self.always_fail or self.calls == 1:
            raise ExternalInfrastructureError(
                "temporary_unavailable", "temporary external outage", retryable=True
            )
        return self.response


def test_external_target_retries_retryable_infrastructure_failure():
    spec = load_campaign_spec("fuzzing/campaigns/threat_hunting_fz6_external_mock_v1.json")
    codec = ExternalCodec(load_external_mapping(MAPPING_PATH))
    transport = _FlakyTransport(codec.encode_findings((), "jsonl"))
    target = ExternalSUTTarget(
        spec.target.recipes,
        repository_root=".",
        configuration=spec.target.external,
        transport=transport,
    )

    result = target.execute(_events(), ExecutionLimits())

    assert result.status == "completed"
    assert transport.calls == 2
    assert result.state_observations["attempt_count"] == 2
    assert result.state_observations["infrastructure_error_types"] == [
        "temporary_unavailable"
    ]


def test_infrastructure_failure_is_not_a_detection_failure():
    spec = load_campaign_spec("fuzzing/campaigns/threat_hunting_fz6_external_mock_v1.json")
    codec = ExternalCodec(load_external_mapping(MAPPING_PATH))
    transport = _FlakyTransport(codec.encode_findings((), "jsonl"), always_fail=True)
    target = ExternalSUTTarget(
        spec.target.recipes,
        repository_root=".",
        configuration=spec.target.external,
        transport=transport,
    )

    result = target.execute(_events(), ExecutionLimits())
    oracle = external_execution_health_oracle(result, target.manifest.target_id)

    assert result.status == "infrastructure_error"
    assert result.state_observations["detection_verdict_eligible"] is False
    assert result.state_observations["attempt_count"] == 3
    assert oracle.verdict == "inconclusive"


def test_external_finding_with_unknown_evidence_is_rejected():
    spec = load_campaign_spec("fuzzing/campaigns/threat_hunting_fz6_external_mock_v1.json")
    codec = ExternalCodec(load_external_mapping(MAPPING_PATH))
    bad = Finding.from_dict(
        {**_finding().to_dict(), "evidence_event_ids": ["not-an-input-event"]}
    )
    transport = _FlakyTransport(codec.encode_findings((bad,), "jsonl"))
    transport.calls = 1
    target = ExternalSUTTarget(
        spec.target.recipes,
        repository_root=".",
        configuration=spec.target.external,
        transport=transport,
    )

    result = target.execute(_events(), ExecutionLimits())

    assert result.status == "rejected"
    assert result.error_type == "external_finding_protocol"


def test_command_transport_requires_environment_opt_in(tmp_path, monkeypatch):
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "commands": [
                    {
                        "id": "test-command",
                        "executable": sys.executable,
                        "args": ["{input}", "{output}"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("CYBERMATCH_ALLOW_EXTERNAL_SUT", raising=False)
    transport = AllowlistedCommandTransport(
        repository_root=tmp_path,
        allowlist_path="allowlist.json",
        command_id="test-command",
        explicit_opt_in=True,
    )

    with pytest.raises(ExternalInfrastructureError) as caught:
        transport.submit(
            b"payload",
            input_format="jsonl",
            output_format="jsonl",
            timeout_seconds=1.0,
            limits=ExecutionLimits(),
        )

    assert caught.value.error_type == "external_execution_not_enabled"
    assert caught.value.retryable is False


def test_command_campaign_requires_all_explicit_fields(tmp_path):
    payload = json.loads(
        open(
            "fuzzing/campaigns/threat_hunting_fz6_external_mock_v1.json", encoding="utf-8"
        ).read()
    )
    payload["target"]["external"]["transport"] = "command"
    path = tmp_path / "unsafe-command.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(FuzzSpecError, match="requires command_id"):
        load_campaign_spec(path)


def test_external_target_interface_cannot_receive_ground_truth():
    parameters = tuple(inspect.signature(ExternalSUTTarget.execute).parameters)

    assert parameters == ("self", "events", "limits")
