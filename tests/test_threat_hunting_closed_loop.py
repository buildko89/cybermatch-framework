import inspect
import json
from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest

import src.cybermatch.threat_hunting.closed_loop_evaluation as evaluation_module
from scenario_loader import load_scenario
from src.cybermatch.attacker.attacker_model import AttackerModel
from src.cybermatch.config.simulation_config import SimulationConfig
from src.cybermatch.simulation.simulator import CyberDefenseSimulator
from src.cybermatch.threat_hunting.closed_loop_evaluation import (
    CLOSED_LOOP_REPORT_FILENAME,
    CLOSED_LOOP_SUMMARY_FILENAME,
    run_hunting_closed_loop_evaluation,
)


RECIPE = "recipes/threat_hunting/critical_path_approach_v1.json"


def _closed_loop_config(**overrides):
    values = {
        "T": 10,
        "seed": 0,
        "show_plot": False,
        "stochastic_detection": True,
        "stochastic_success": True,
        "attacker_enabled": True,
        "attacker_lateral_enabled": True,
        "attacker_mission": "critical_hunter",
        "mission_objectives_enabled": True,
        "perceived_utility_enabled": True,
        "frustration_enabled": True,
        "observable_events_enabled": True,
        "critical_path_events_enabled": True,
        "threat_hunting_enabled": True,
        "threat_hunting_typed_telemetry_enabled": True,
        "threat_hunting_feedback_enabled": True,
        "threat_hunting_recipe_paths": [RECIPE],
        "threat_hunting_campaign_id": "closed-loop-test",
        "threat_hunting_scenario_id": "closed-loop-test",
    }
    values.update(overrides)
    return SimulationConfig(**values)


def _assert_history_equal(first, second):
    assert first.keys() == second.keys()
    for key in first:
        left = np.asarray(first[key])
        right = np.asarray(second[key])
        if left.dtype.kind == "f" or right.dtype.kind == "f":
            np.testing.assert_allclose(left, right, equal_nan=True, err_msg=key)
        else:
            np.testing.assert_array_equal(left, right, err_msg=key)


def test_default_off_preserves_existing_simulation_history():
    control = SimulationConfig(T=4, seed=17, show_plot=False)
    explicit_off = replace(
        control,
        threat_hunting_enabled=False,
        threat_hunting_typed_telemetry_enabled=False,
        threat_hunting_feedback_enabled=False,
        threat_hunting_recipe_paths=[RECIPE],
        attacker_stealth_enabled=False,
        c2_jitter_ratio=1.0,
        dns_tunnel_chunk_size=32,
        process_masquerading=True,
        domain_homoglyph_enabled=True,
        hunting_awareness_threshold=0.0,
        sleep_or_slowdown_factor=4.0,
    )

    baseline_history = CyberDefenseSimulator(control).run()
    explicit_off_history = CyberDefenseSimulator(explicit_off).run()

    _assert_history_equal(baseline_history, explicit_off_history)
    assert "typed_telemetry" not in baseline_history
    assert "threat_hunting_feedback" not in baseline_history


def test_closed_loop_creates_future_actions_and_attacker_only_receives_consequences(monkeypatch):
    calls = []
    original = AttackerModel.observe_defender_consequence

    def checked(self, **kwargs):
        assert set(kwargs) == {
            "blocked",
            "delayed",
            "detected",
            "redirected",
            "confidence_decay",
            "frustration_increase",
        }
        assert all(isinstance(kwargs[key], bool) for key in ("blocked", "delayed", "detected", "redirected"))
        calls.append(dict(kwargs))
        return original(self, **kwargs)

    monkeypatch.setattr(AttackerModel, "observe_defender_consequence", checked)
    simulator = CyberDefenseSimulator(_closed_loop_config())
    history = simulator.run()

    assert simulator.threat_hunting_feedback_action_count > 0
    assert sum(history["threat_hunting_active_feedback_count"]) > 0
    assert any(json.loads(value)["created"] for value in history["threat_hunting_feedback"])
    assert any(any(call[key] for key in ("blocked", "delayed", "detected", "redirected")) for call in calls)
    assert "finding" not in inspect.signature(AttackerModel.observe_defender_consequence).parameters


def test_stealth_parameters_reduce_detection_probability_and_support_slowdown():
    neutral = AttackerModel(enabled=True)
    strong = AttackerModel(
        enabled=True,
        stealth_enabled=True,
        c2_jitter_ratio=1.0,
        dns_tunnel_chunk_size=32,
        process_masquerading=True,
        domain_homoglyph_enabled=True,
        hunting_awareness_threshold=0.5,
        sleep_or_slowdown_factor=3.0,
    )

    assert neutral.stealth_detection_multiplier() == 1.0
    assert 0.2 <= strong.stealth_detection_multiplier() < 1.0
    assert strong.should_slow_down(step=1, observed_hunting_pressure=0.7) is True
    assert strong.should_slow_down(step=3, observed_hunting_pressure=0.7) is False


def test_paired_runner_writes_seed_matched_sensitivity_and_separate_lifts(tmp_path, monkeypatch):
    scenario = load_scenario("scenarios/threat_hunting/threat_hunt_c2_jitter.json")
    scenario["evaluation"]["seeds"] = [3, 7]

    def fake_case(config):
        ratio = float(config.c2_jitter_ratio)
        closed = config.threat_hunting_feedback_enabled
        return {
            "steps": config.T,
            "detection_rate": 0.8 - 0.2 * ratio + (0.05 if closed else 0.0),
            "attacker_success_rate": 0.6 + 0.1 * ratio - (0.1 if closed else 0.0),
            "neutralization_score": 0.6 - 0.1 * ratio + (0.1 if closed else 0.0),
            "decision_neutralization_score": 0.2 + (0.3 if closed else 0.0),
            "critical_true_gain_total": 1.0,
            "attacker_retreated": False,
            "feedback_action_count": 2 if closed else 0,
            "feedback_active_steps": 2 if closed else 0,
            "attacker_slowdown_steps": 0,
        }

    monkeypatch.setattr(evaluation_module, "_run_case", fake_case)
    output = tmp_path / "closed-loop"
    rows = run_hunting_closed_loop_evaluation(scenario, output_dir=output)

    assert len(rows) == 2 * 4 * 2
    assert {row["seed"] for row in rows} == {3, 7}
    assert {row["loop_mode"] for row in rows} == {"open_loop", "closed_loop"}
    strong_closed = next(
        row
        for row in rows
        if row["seed"] == 3
        and row["stealth_profile"] == "strong"
        and row["loop_mode"] == "closed_loop"
    )
    assert strong_closed["stealth_neutralization_lift"] == pytest.approx(0.1)
    assert strong_closed["decision_neutralization_lift"] == pytest.approx(0.3)

    summary = json.loads((output / CLOSED_LOOP_SUMMARY_FILENAME).read_text(encoding="utf-8"))
    assert summary["paired_seed_comparison"] is True
    assert len(summary["sensitivity"]) == 8
    report = (output / CLOSED_LOOP_REPORT_FILENAME).read_text(encoding="utf-8")
    assert "stealth_neutralization_lift" in report
    assert "decision_neutralization_lift" in report


@pytest.mark.parametrize(
    "filename",
    [
        "threat_hunt_c2_jitter.json",
        "threat_hunt_dns_tunnel.json",
        "threat_hunt_pstree_lateral.json",
        "threat_hunt_baseline_zeroday.json",
    ],
)
def test_dedicated_h5_scenarios_validate(filename):
    scenario = load_scenario(str(Path("scenarios/threat_hunting") / filename))
    assert scenario["evaluation"]["runner"] == "hunting_closed_loop_evaluation"
    assert [profile["name"] for profile in scenario["hunting"]["stealth_sweep"]] == [
        "zero",
        "linear",
        "saturation",
        "strong",
    ]
