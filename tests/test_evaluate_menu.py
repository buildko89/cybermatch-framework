import json
from pathlib import Path

import pytest

from scripts import evaluate


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_presets_expand_to_known_lanes_without_duplicates() -> None:
    lanes = evaluate._resolve_lanes(["quickstart", "check", "hunting"])
    assert [lane.lane_id for lane in lanes] == ["check", "replay", "product", "hunting"]
    assert [lane.lane_id for lane in evaluate._resolve_lanes(["all"])] == list(evaluate.LANES)


def test_unknown_lane_is_rejected() -> None:
    with pytest.raises(SystemExit, match="unknown lane"):
        evaluate._resolve_lanes(["does-not-exist"])


def test_every_lane_writes_below_its_own_output_directory() -> None:
    for lane in evaluate.LANES.values():
        out = f"output/evaluations/test-run/{lane.lane_id}"
        commands = lane.build_commands(out)
        assert commands, lane.lane_id
        for command in commands:
            script = command[1]
            if script.startswith("scripts/"):
                assert (REPOSITORY_ROOT / script).is_file(), script
            if lane.uses_output_dir and script != "-c":
                assert any(part.startswith(out) for part in command), command


def test_referenced_input_assets_exist() -> None:
    for lane in evaluate.LANES.values():
        for command in lane.build_commands("output/evaluations/test-run/x"):
            for part in command[2:]:
                if part.endswith((".json", ".jsonl")) and not part.startswith("output/"):
                    assert (REPOSITORY_ROOT / part).is_file(), part


def test_dry_run_prints_commands_and_creates_nothing(capsys) -> None:
    run_id = "pytest-dry-run-menu"
    assert evaluate.main(["all", "--dry-run", "--run-id", run_id]) == 0
    output = capsys.readouterr().out
    assert "scripts/run_external_replay.py" in output
    assert not (REPOSITORY_ROOT / evaluate.DEFAULT_OUTPUT_ROOT / run_id).exists()


def test_invalid_run_id_is_rejected() -> None:
    with pytest.raises(SystemExit):
        evaluate.main(["check", "--run-id", "../escape"])


def test_summary_lists_status_and_reports(tmp_path) -> None:
    lane = evaluate.LANES["replay"]
    result = evaluate.LaneResult(
        lane=lane,
        status="succeeded",
        seconds=1.23,
        output_dir="output/evaluations/r1/replay",
        commands=["python scripts/run_external_replay.py"],
        evidence_bundle_hash="a" * 64,
    )
    summary_path = evaluate._write_summary(tmp_path, "r1", [result])
    text = summary_path.read_text(encoding="utf-8")
    assert "`replay`" in text
    assert "output/evaluations/r1/replay/PHASE3_EXTERNAL_VALIDITY_REPORT.md" in text
    data = json.loads((tmp_path / "evaluation_summary.json").read_text(encoding="utf-8"))
    assert data["lanes"][0]["evidence_bundle_hash"] == "a" * 64
