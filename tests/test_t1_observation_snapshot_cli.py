"""T1 as-of snapshot確認CLIの出力・拒否を検証する。"""

import json

from scripts.validate_t1_observation_snapshot import main


INPUT = "configs/threat_hunting/observations/t0_synthetic_cti_observation.json"


def test_cli_reports_arrived_synthetic_snapshot(capsys):
    assert main(["--input", INPUT, "--run-id", "t0-synthetic-run", "--tenant-id", "tenant-example", "--scenario-id", "cli-test", "--current-step", "4"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {"available_steps": [4], "event_count": 1, "event_ids": ["hunt-event-cti-001"], "observed_steps": [2]}


def test_cli_refuses_observation_before_arrival(capsys):
    assert main(["--input", INPUT, "--run-id", "t0-synthetic-run", "--tenant-id", "tenant-example", "--scenario-id", "cli-test", "--current-step", "3"]) == 2
    assert "検証できませんでした" in capsys.readouterr().err
