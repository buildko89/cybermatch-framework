import pytest

from cybermatch_core.threat_hunting import HistoryAdapterError, HistoryGroundTruthAdapter


def test_ground_truth_adapter_creates_evaluator_only_labels():
    history = {
        "critical_compromise": [False, False, True, True],
        "attacker_success": [False, True, False, True],
        "attacker_detected": [True, False, False, True],
        "attacker_selected_target": [0, 1, 2, 4],
        "attacker_critical_true_gain": [0.0, 1.25, 0.0, 2.5],
        "true_mission_history": ["profit", "profit", "persistence", "persistence"],
    }

    labels = HistoryGroundTruthAdapter().adapt(history, campaign_id="campaign_seed_7")

    by_type = {}
    for label in labels:
        by_type.setdefault(label.label_type, []).append(label)

    assert [(label.start_step, label.target_node) for label in by_type["attacker_success"]] == [
        (1, 1),
        (3, 4),
    ]
    assert [(label.start_step, label.target_node) for label in by_type["attacker_detected"]] == [
        (0, 0),
        (3, 4),
    ]
    assert len(by_type["critical_compromise"]) == 1
    assert by_type["critical_compromise"][0].start_step == 2
    assert by_type["critical_compromise"][0].target_node == 2
    assert [label.attributes["value"] for label in by_type["critical_true_gain"]] == [
        1.25,
        2.5,
    ]
    assert [
        (label.start_step, label.end_step, label.attributes["mission"])
        for label in by_type["true_mission"]
    ] == [(0, 1, "profit"), (2, 3, "persistence")]
    assert labels == sorted(
        labels,
        key=lambda label: (label.start_step, label.label_type, label.label_id),
    )


def test_ground_truth_adapter_is_deterministic():
    history = {
        "attacker_success": [True, False],
        "attacker_selected_target": [3, 2],
        "true_mission_history": ["profit", "profit"],
    }
    adapter = HistoryGroundTruthAdapter()

    first = [label.to_dict() for label in adapter.adapt(history, campaign_id="campaign")]
    second = [label.to_dict() for label in adapter.adapt(history, campaign_id="campaign")]

    assert first == second
    assert all(label["label_id"].startswith("truth_") for label in first)


@pytest.mark.parametrize("invalid", ["yes", 2, -1, 0.5, None])
def test_ground_truth_adapter_rejects_invalid_boolean_values(invalid):
    with pytest.raises(HistoryAdapterError, match="boolean values"):
        HistoryGroundTruthAdapter().adapt(
            {"attacker_success": [invalid]},
            campaign_id="campaign",
        )


def test_ground_truth_adapter_validates_values_after_first_compromise():
    with pytest.raises(HistoryAdapterError, match="boolean values"):
        HistoryGroundTruthAdapter().adapt(
            {"critical_compromise": [True, "invalid"]},
            campaign_id="campaign",
        )


@pytest.mark.parametrize("invalid", [True, "1.0", float("nan"), float("inf")])
def test_ground_truth_adapter_rejects_invalid_true_gain(invalid):
    with pytest.raises(HistoryAdapterError, match="finite numbers"):
        HistoryGroundTruthAdapter().adapt(
            {"attacker_critical_true_gain": [invalid]},
            campaign_id="campaign",
        )


def test_ground_truth_adapter_rejects_invalid_mission_history():
    with pytest.raises(HistoryAdapterError, match="must contain strings"):
        HistoryGroundTruthAdapter().adapt(
            {"true_mission_history": ["profit", ""]},
            campaign_id="campaign",
        )


def test_ground_truth_adapter_keeps_unknown_target_as_none():
    labels = HistoryGroundTruthAdapter().adapt(
        {
            "attacker_success": [True],
            "attacker_selected_target": [-1],
        },
        campaign_id="campaign",
    )

    assert labels[0].target_node is None
