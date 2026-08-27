import json

from cybermatch_core.threat_hunting import (
    GROUND_TRUTH_HISTORY_KEYS,
    GroundTruthLabel,
    HistoryGroundTruthAdapter,
    HistoryObservationAdapter,
    HuntEvent,
)


PUBLIC_HUNT_EVENT_FIELDS = {
    "schema_version",
    "event_id",
    "step",
    "campaign_id",
    "scenario_id",
    "seed",
    "actor_id",
    "coalition_id",
    "event_type",
    "source_node",
    "target_node",
    "source_role",
    "target_role",
    "signal_class",
    "attributes",
}


def _observations(history):
    return [
        event.to_dict()
        for event in HistoryObservationAdapter().adapt(
            history,
            campaign_id="campaign",
            scenario_id="scenario",
            seed=0,
        )
    ]


def test_truth_only_changes_cannot_change_observation_output():
    observed = {
        "observable_events": ["scan", "credential_use|critical_path_entry"],
        "critical_path_events": ["", "critical_path_entry"],
    }
    history_a = {
        **observed,
        "attacker_success": [False, False],
        "attacker_detected": [False, False],
        "critical_compromise": [False, False],
        "attacker_critical_true_gain": [0.0, 0.0],
        "attacker_current_belief": [[0.99], [0.98]],
        "attacker_selection_score": [[999.0], [998.0]],
        "attacker_selected_target": [99, 98],
        "true_mission_history": ["secret-alpha", "secret-alpha"],
        "fake_signal_history": ["fake-secret-a", "fake-secret-b"],
        "noise_history": ["noise-secret-a", "noise-secret-b"],
    }
    history_b = {
        **observed,
        "attacker_success": [True, True],
        "attacker_detected": [True, True],
        "critical_compromise": [True, True],
        "attacker_critical_true_gain": [100.0, 200.0],
        "attacker_current_belief": [[0.01], [0.02]],
        "attacker_selection_score": [[-999.0], [-998.0]],
        "attacker_selected_target": [1, 2],
        "true_mission_history": ["secret-beta", "secret-gamma"],
        "fake_signal_history": ["fake-other-a", "fake-other-b"],
        "noise_history": ["noise-other-a", "noise-other-b"],
    }

    assert _observations(history_a) == _observations(history_b)


def test_public_observation_snapshot_contains_no_truth_fields_or_values():
    history = {
        "observable_events": ["scan|fake_critical_path_entry|noise_unknown"],
        "critical_path_events": [""],
        "true_mission_history": ["TOP_SECRET_MISSION"],
        "attacker_current_belief": [[0.123456789]],
        "attacker_selection_score": [[987654321.0]],
        "critical_compromise": [True],
        "fake_signal_history": ["TOP_SECRET_FAKE"],
        "noise_history": ["TOP_SECRET_NOISE"],
    }

    snapshots = _observations(history)
    serialized = json.dumps(snapshots, sort_keys=True)

    assert snapshots
    assert all(set(snapshot) == PUBLIC_HUNT_EVENT_FIELDS for snapshot in snapshots)
    assert all(set(snapshot["attributes"]) == {"source_history_keys", "ordinal"} for snapshot in snapshots)
    assert all(key not in serialized for key in GROUND_TRUTH_HISTORY_KEYS)
    assert "TOP_SECRET" not in serialized
    assert "0.123456789" not in serialized
    assert "987654321" not in serialized
    assert "fake_" not in serialized
    assert "noise_" not in serialized


def test_observation_and_truth_contracts_remain_separate():
    event = HistoryObservationAdapter().adapt(
        {"observable_events": ["scan"]},
        campaign_id="campaign",
        scenario_id="scenario",
    )[0]
    label = HistoryGroundTruthAdapter().adapt(
        {"critical_compromise": [True]},
        campaign_id="campaign",
    )[0]

    assert isinstance(event, HuntEvent)
    assert not isinstance(event, GroundTruthLabel)
    assert isinstance(label, GroundTruthLabel)
    assert not isinstance(label, HuntEvent)
    assert not issubclass(HuntEvent, GroundTruthLabel)
    assert not issubclass(GroundTruthLabel, HuntEvent)
