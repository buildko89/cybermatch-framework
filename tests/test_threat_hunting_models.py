import json
from dataclasses import FrozenInstanceError

import pytest

from cybermatch_core.threat_hunting import (
    Finding,
    GroundTruthLabel,
    HuntEvent,
    ThreatHuntingRunConfig,
    canonical_json,
    stable_identifier,
)


def _event() -> HuntEvent:
    return HuntEvent(
        schema_version="1.0",
        event_id="event_001",
        step=3,
        campaign_id="campaign_seed_0",
        scenario_id="enterprise",
        seed=0,
        actor_id=None,
        coalition_id=None,
        event_type="credential_use",
        source_node=None,
        target_node=None,
        source_role=None,
        target_role=None,
        signal_class="telemetry",
        attributes={"source": "observable_events", "ordinal": 0},
    )


def test_hunt_event_round_trip_and_nested_immutability():
    event = _event()

    restored = HuntEvent.from_dict(json.loads(json.dumps(event.to_dict())))

    assert restored == event
    with pytest.raises(TypeError):
        event.attributes["ordinal"] = 1
    with pytest.raises(FrozenInstanceError):
        event.step = 4


def test_hunt_event_rejects_truth_bearing_signal_class():
    payload = _event().to_dict()
    payload["signal_class"] = "noise"

    with pytest.raises(ValueError, match="signal_class"):
        HuntEvent.from_dict(payload)


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), ["nested"], {"nested": True}])
def test_hunt_event_rejects_non_scalar_or_non_finite_attributes(invalid):
    payload = _event().to_dict()
    payload["attributes"] = {"invalid": invalid}

    with pytest.raises(ValueError, match="attribute"):
        HuntEvent.from_dict(payload)


def test_finding_round_trip_requires_unique_evidence():
    finding = Finding(
        schema_version="1.0",
        finding_id="finding_001",
        recipe_id="credential_sequence",
        recipe_version="1.0",
        severity="high",
        score=0.8,
        campaign_id="campaign_seed_0",
        actor_id=None,
        start_step=3,
        end_step=7,
        title="Credential sequence",
        reason="Three ordered events matched within five steps",
        evidence_event_ids=("event_001", "event_002", "event_003"),
        observed_value=3,
        threshold=3,
        attributes={"operator": "sequence"},
    )

    restored = Finding.from_dict(json.loads(json.dumps(finding.to_dict())))

    assert restored == finding
    duplicate_payload = finding.to_dict()
    duplicate_payload["evidence_event_ids"] = ["event_001", "event_001"]
    with pytest.raises(ValueError, match="duplicates"):
        Finding.from_dict(duplicate_payload)


@pytest.mark.parametrize("score", [-0.1, 1.1, float("nan")])
def test_finding_rejects_invalid_score(score):
    with pytest.raises(ValueError, match="score"):
        Finding(
            schema_version="1.0",
            finding_id="finding_001",
            recipe_id="recipe",
            recipe_version="1.0",
            severity="medium",
            score=score,
            campaign_id="campaign",
            actor_id=None,
            start_step=0,
            end_step=0,
            title="title",
            reason="reason",
            evidence_event_ids=("event_001",),
        )


def test_ground_truth_label_is_a_separate_round_trip_contract():
    label = GroundTruthLabel(
        label_id="truth_001",
        campaign_id="campaign_seed_0",
        label_type="critical_compromise",
        start_step=7,
        end_step=7,
        actor_id=None,
        target_node=4,
        severity="critical",
        attributes={"source": "simulator_truth"},
    )

    assert GroundTruthLabel.from_dict(label.to_dict()) == label
    assert not isinstance(label, HuntEvent)


def test_stable_identifier_is_independent_of_mapping_key_order():
    left = stable_identifier("event", {"step": 1, "type": "scan"})
    right = stable_identifier("event", {"type": "scan", "step": 1})

    assert left == right
    assert left.startswith("event_")
    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_threat_hunting_run_config_round_trip_and_limits():
    config = ThreatHuntingRunConfig(max_events=250, max_findings=25)

    assert ThreatHuntingRunConfig.from_dict(config.to_dict()) == config
    with pytest.raises(ValueError, match="max_events"):
        ThreatHuntingRunConfig(max_events=0)
    with pytest.raises(ValueError, match="max_groups"):
        ThreatHuntingRunConfig(max_groups=True)
