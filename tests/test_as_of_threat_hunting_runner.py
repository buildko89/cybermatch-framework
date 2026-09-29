"""T2接続点が未到着観測・truthなしでrecipeを実行することを検証する。"""

import json
from pathlib import Path

import pytest

from cybermatch_core.threat_hunting import (
    AsOfThreatHuntingRunner,
    T0ObservationAdapter,
    T0ObservationAdapterError,
    ThreatHuntingRecipeLoader,
)


ROOT = Path(__file__).resolve().parents[1]


def observation(event_id: str, observed_step: int) -> dict[str, object]:
    item = json.loads((ROOT / "configs/threat_hunting/observations/t0_synthetic_cti_observation.json").read_text(encoding="utf-8"))
    item["observation_id"] = "cti-obs-" + event_id[-1]
    item["event_id"] = event_id
    item["observed_step"] = observed_step
    item["available_step"] = 4
    item["observation"]["event_type"] = "critical_path_progress"
    return item


def runner() -> AsOfThreatHuntingRunner:
    return AsOfThreatHuntingRunner(adapter=T0ObservationAdapter(run_id="t0-synthetic-run", tenant_id="tenant-example", scenario_id="as-of-runner"))


def test_runner_executes_recipe_only_over_arrived_snapshot():
    recipe = ThreatHuntingRecipeLoader(ROOT / "recipes/threat_hunting").load("critical_path_approach_v1.json")
    result = runner().run(recipe=recipe, payloads=(observation("hunt-event-cti-002", 3), observation("hunt-event-cti-001", 2)), current_step=4)
    assert [event.event_id for event in result.events] == ["hunt-event-cti-001", "hunt-event-cti-002"]
    assert len(result.findings) == 1
    assert result.findings[0].evidence_event_ids == ("hunt-event-cti-001", "hunt-event-cti-002")
    assert result.trace.event_ids == ("hunt-event-cti-001", "hunt-event-cti-002")
    assert result.trace.finding_ids == (result.findings[0].finding_id,)
    assert result.trace.recipe_hash == recipe.recipe_hash
    wire = result.to_dict()
    assert wire["trace"] == result.trace.to_dict()
    assert [event["event_id"] for event in wire["events"]] == ["hunt-event-cti-001", "hunt-event-cti-002"]


def test_runner_does_not_run_partial_snapshot_before_arrival():
    recipe = ThreatHuntingRecipeLoader(ROOT / "recipes/threat_hunting").load("critical_path_approach_v1.json")
    waiting = observation("hunt-event-cti-002", 3)
    waiting["available_step"] = 5
    with pytest.raises(T0ObservationAdapterError, match="未到着"):
        runner().run(recipe=recipe, payloads=(observation("hunt-event-cti-001", 2), waiting), current_step=4)
