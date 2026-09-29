"""T1開始時点の到着時刻・境界・真値分離を検証する。"""

import json
from pathlib import Path

import pytest

from cybermatch_core.threat_hunting import T0ObservationAdapter, T0ObservationAdapterError


ROOT = Path(__file__).resolve().parents[1]


def payload() -> dict[str, object]:
    return json.loads((ROOT / "configs/threat_hunting/observations/t0_synthetic_cti_observation.json").read_text(encoding="utf-8"))


def adapter() -> T0ObservationAdapter:
    return T0ObservationAdapter(run_id="t0-synthetic-run", tenant_id="tenant-example", scenario_id="t1-adapter-test")


def test_adapter_converts_only_arrived_observation_and_preserves_time_boundary():
    event = adapter().adapt(payload(), current_step=4)
    assert event.step == 2
    assert event.attributes["available_step"] == 4
    assert event.attributes["run_id"] == "t0-synthetic-run"
    assert event.attributes["tenant_id"] == "tenant-example"
    assert event.attributes["identity_ref"] == "identity-example"
    with pytest.raises(T0ObservationAdapterError, match="未到着"):
        adapter().adapt(payload(), current_step=3)


@pytest.mark.parametrize("field, value", [
    ("run_id", "another-run"),
    ("tenant_id", "another-tenant"),
    ("available_step", 1),
    ("available_step", True),
])
def test_adapter_rejects_boundary_and_invalid_time(field, value):
    item = payload()
    item[field] = value
    with pytest.raises(T0ObservationAdapterError):
        adapter().adapt(item, current_step=4)


def test_adapter_has_no_truth_input_and_rejects_unknown_pii_field():
    assert "truth" not in T0ObservationAdapter.adapt.__annotations__
    item = payload()
    item["observation"]["email"] = "person@example.invalid"
    with pytest.raises(T0ObservationAdapterError):
        adapter().adapt(item, current_step=4)


def test_adapter_snapshot_is_as_of_atomic_and_deterministically_sorted():
    later = payload()
    later["observation_id"] = "cti-obs-002"
    later["event_id"] = "hunt-event-cti-002"
    later["observed_step"] = 4
    later["available_step"] = 4
    events = adapter().adapt_snapshot((later, payload()), current_step=4)
    assert [event.event_id for event in events] == ["hunt-event-cti-001", "hunt-event-cti-002"]
    future = payload()
    future["observation_id"] = "cti-obs-003"
    future["event_id"] = "hunt-event-cti-003"
    future["available_step"] = 5
    with pytest.raises(T0ObservationAdapterError, match="未到着"):
        adapter().adapt_snapshot((payload(), future), current_step=4)
    duplicate = payload()
    with pytest.raises(T0ObservationAdapterError, match="重複"):
        adapter().adapt_snapshot((payload(), duplicate), current_step=4)
