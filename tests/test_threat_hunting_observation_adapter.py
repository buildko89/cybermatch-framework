import numpy as np
import pytest

from cybermatch_core.threat_hunting import (
    HistoryAdapterError,
    HistoryObservationAdapter,
    ObservationPolicyViolation,
)


def _adapt(history):
    return HistoryObservationAdapter().adapt(
        history,
        campaign_id="campaign_seed_7",
        scenario_id="enterprise",
        seed=7,
    )


def test_observation_adapter_normalizes_deduplicates_and_sorts_events():
    history = {
        "observable_events": [
            " scan || noise_scan | fake_critical_path_entry | critical_path_entry ",
            "credential_noise|credential_use|fake_unknown|noise_unknown",
        ],
        "critical_path_events": ["critical_path_entry", ""],
        "critical_compromise": [False, True],
        "true_mission_history": ["profit", "persistence"],
    }

    events = _adapt(history)

    assert [(event.step, event.event_type) for event in events] == [
        (0, "critical_path_entry"),
        (0, "scan"),
        (1, "credential_use"),
    ]
    assert events[0].signal_class == "derived_signal"
    assert events[1].signal_class == "telemetry"
    assert events[0].attributes["source_history_keys"] == (
        "critical_path_events,observable_events"
    )
    assert all(event.actor_id is None for event in events)
    assert all(event.source_node is None and event.target_node is None for event in events)


def test_observation_adapter_stably_maps_known_internal_labels():
    history = {
        "observable_events": [
            "noise_recon|credential_noise|false_path|fake_critical_probe|"
            "fake_critical_path_progress|fake_critical_path_near_target|"
            "fake_objective_action"
        ]
    }

    event_types = [event.event_type for event in _adapt(history)]

    assert event_types == [
        "credential_use",
        "critical_path_near_target",
        "critical_path_progress",
        "critical_probe",
        "lateral_move",
        "objective_action",
        "scan",
    ]


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "attacker_critical_true_gain",
        "attacker_current_belief",
        "attacker_detected",
        "attacker_selection_score",
        "attacker_selected_target",
        "attacker_success",
        "critical_compromise",
        "fake_signal_history",
        "noise_history",
        "true_mission_history",
    ],
)
def test_observation_adapter_rejects_truth_only_history_keys(forbidden_key):
    with pytest.raises(ObservationPolicyViolation, match="unsupported observed history keys"):
        HistoryObservationAdapter(history_keys=("observable_events", forbidden_key))


def test_observation_adapter_rejects_inconsistent_observed_lengths():
    history = {
        "observable_events": ["scan", "credential_use"],
        "critical_path_events": ["critical_path_entry"],
    }

    with pytest.raises(HistoryAdapterError, match="inconsistent lengths"):
        _adapt(history)


def test_observation_adapter_rejects_non_string_allowlist_key():
    with pytest.raises(ObservationPolicyViolation, match="must be strings"):
        HistoryObservationAdapter(history_keys=("observable_events", 1))


def test_observation_adapter_reads_npz_without_pickle(tmp_path):
    history_path = tmp_path / "history.npz"
    np.savez(
        history_path,
        observable_events=np.asarray(["scan", "credential_use"], dtype="<U32"),
        critical_path_events=np.asarray(["", "critical_path_entry"], dtype="<U32"),
        critical_compromise=np.asarray([False, True], dtype=bool),
    )

    events = HistoryObservationAdapter().adapt(
        history_path,
        campaign_id="campaign",
        scenario_id="scenario",
        seed=0,
    )

    assert [(event.step, event.event_type) for event in events] == [
        (0, "scan"),
        (1, "credential_use"),
        (1, "critical_path_entry"),
    ]


def test_observation_adapter_requires_an_observed_field():
    with pytest.raises(HistoryAdapterError, match="no supported observed event fields"):
        _adapt({"attacker_success": [True]})


@pytest.mark.parametrize(
    ("history", "message"),
    [
        ({"observable_events": [42]}, "non-text event value"),
        ({"observable_events": "scan"}, "must be a sequence"),
    ],
)
def test_observation_adapter_rejects_malformed_event_history(history, message):
    with pytest.raises(HistoryAdapterError, match=message):
        _adapt(history)


@pytest.mark.parametrize(
    "metadata",
    [
        {"campaign_id": "", "scenario_id": "scenario", "seed": 0},
        {"campaign_id": "campaign", "scenario_id": " ", "seed": 0},
        {"campaign_id": "campaign", "scenario_id": "scenario", "seed": -1},
        {"campaign_id": "campaign", "scenario_id": "scenario", "seed": True},
    ],
)
def test_observation_adapter_validates_metadata(metadata):
    with pytest.raises(HistoryAdapterError):
        HistoryObservationAdapter().adapt({"observable_events": []}, **metadata)
