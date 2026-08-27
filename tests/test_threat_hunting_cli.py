import inspect
import json
import subprocess
import sys
from pathlib import Path

import numpy as np

import src.cybermatch.threat_hunting.cli as cli_module
from cybermatch_core.threat_hunting import load_threat_hunting_artifacts, threat_hunting_main


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_RECIPE = "recipes/threat_hunting/critical_path_approach_v1.json"


def _history_file(tmp_path):
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
        true_mission_history=np.asarray(["SECRET", "SECRET", "SECRET"], dtype="<U16"),
        critical_compromise=np.asarray([False, False, True], dtype=bool),
    )
    return path


def _arguments(history, output):
    return [
        "--history",
        str(history),
        "--recipe",
        SAMPLE_RECIPE,
        "--output",
        str(output),
        "--scenario-id",
        "scenario",
        "--campaign-id",
        "campaign",
        "--seed",
        "7",
    ]


def test_cli_runs_end_to_end_and_emits_reloadable_artifacts(tmp_path, capsys):
    history = _history_file(tmp_path)
    output = tmp_path / "artifacts"

    return_code = threat_hunting_main(_arguments(history, output))
    captured = capsys.readouterr()
    loaded = load_threat_hunting_artifacts(output)

    assert return_code == 0
    assert "success: true" in captured.out
    assert "findings: 1" in captured.out
    assert captured.err == ""
    assert len(loaded.events) == 3
    assert len(loaded.findings) == 1
    assert loaded.manifest["seed"] == 7
    assert "SECRET" not in json.dumps(loaded.manifest)


def test_cli_refuses_existing_directory_with_nonzero_and_clear_message(tmp_path, capsys):
    history = _history_file(tmp_path)
    output = tmp_path / "artifacts"
    output.mkdir()

    return_code = threat_hunting_main(_arguments(history, output))
    captured = capsys.readouterr()

    assert return_code == 2
    assert "failure:" in captured.err
    assert "already exists" in captured.err


def test_cli_invalid_recipe_returns_nonzero_without_creating_output(tmp_path, capsys):
    history = _history_file(tmp_path)
    output = tmp_path / "artifacts"
    arguments = _arguments(history, output)
    arguments[arguments.index(SAMPLE_RECIPE)] = "../outside.json"

    return_code = threat_hunting_main(arguments)
    captured = capsys.readouterr()

    assert return_code == 2
    assert "failure:" in captured.err
    assert not output.exists()


def test_cli_resource_error_returns_nonzero_without_partial_artifacts(tmp_path, capsys):
    history = _history_file(tmp_path)
    output = tmp_path / "artifacts"
    arguments = [*_arguments(history, output), "--max-events", "1"]

    return_code = threat_hunting_main(arguments)
    captured = capsys.readouterr()

    assert return_code == 2
    assert "max_events" in captured.err
    assert not output.exists()


def test_script_entry_point_runs_in_a_fresh_python_process(tmp_path):
    history = _history_file(tmp_path)
    output = tmp_path / "subprocess-artifacts"

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/run_threat_hunting.py",
            *_arguments(history, output),
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "success: true" in completed.stdout
    assert (output / "threat_hunting_manifest.json").is_file()


def test_h1_cli_has_no_ground_truth_dependency():
    source = inspect.getsource(cli_module)

    assert "GroundTruth" not in source
    assert "HistoryGroundTruthAdapter" not in source
