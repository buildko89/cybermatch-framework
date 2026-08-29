from __future__ import annotations

import json

import numpy as np

from cybermatch_core.threat_hunting import (
    load_threat_hunting_artifacts,
    load_threat_hunting_report,
    run_hunting_history_evaluation,
)
from src.cybermatch.threat_hunting.evaluation_cli import main


def _history(tmp_path):
    path = tmp_path / "history.npz"
    np.savez(
        path,
        observable_events=np.asarray(
            [
                "critical_path_entry",
                "critical_path_progress",
                "critical_path_near_target",
            ],
            dtype="<U64",
        ),
        critical_path_events=np.asarray(
            [
                "critical_path_entry",
                "critical_path_progress",
                "critical_path_near_target",
            ],
            dtype="<U64",
        ),
        critical_compromise=np.asarray([False, False, True], dtype=bool),
    )
    return path


def _arguments(history, output):
    return [
        "--history",
        str(history),
        "--recipe",
        "recipes/threat_hunting/critical_path_approach_v1.json",
        "--output",
        str(output),
        "--scenario-id",
        "gui-scenario",
        "--campaign-id",
        "gui-campaign",
        "--seed",
        "7",
        "--recipe-overrides",
        json.dumps({"window_size_steps": 4, "finding_threshold": 2}),
    ]


def test_evaluation_cli_records_overrides_and_writes_truth_separated_report(tmp_path):
    history = _history(tmp_path)
    output = tmp_path / "cli"

    assert main(_arguments(history, output)) == 0

    loaded = load_threat_hunting_artifacts(output)
    report = load_threat_hunting_report(output)
    assert loaded.manifest["recipe_overrides"] == {
        "finding_threshold": 2.0,
        "window_size_steps": 4,
    }
    assert report.evaluation.metrics["finding_count"] == 1


def test_gui_runner_and_evaluation_cli_generate_the_same_finding_id(tmp_path):
    history = _history(tmp_path)
    cli_output = tmp_path / "cli"
    direct_output = tmp_path / "gui"
    overrides = {"window_size_steps": 4, "finding_threshold": 2}

    assert main(_arguments(history, cli_output)) == 0
    run_hunting_history_evaluation(
        history_path=history,
        recipe_path="recipes/threat_hunting/critical_path_approach_v1.json",
        output_dir=direct_output,
        scenario_id="gui-scenario",
        campaign_id="gui-campaign",
        seed=7,
        recipe_overrides=overrides,
    )

    cli_findings = load_threat_hunting_artifacts(cli_output).findings
    gui_findings = load_threat_hunting_artifacts(direct_output).findings
    assert [value.finding_id for value in cli_findings] == [
        value.finding_id for value in gui_findings
    ]
