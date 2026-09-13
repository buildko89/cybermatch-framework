import sys

import numpy as np
import pytest

from src.cybermatch.application.process_control import launch_logged_process, terminate_process
from src.cybermatch.application.artifacts import discover_files, missing_artifacts
from src.cybermatch.simulation.probability import normalize_probability_vector


def test_probability_normalization_is_pure_and_has_uniform_fallback() -> None:
    source = np.array([-1.0, 1.0, 3.0])
    result = normalize_probability_vector(source, size=3)
    assert result.tolist() == pytest.approx([0.0, 0.25, 0.75])
    assert source.tolist() == [-1.0, 1.0, 3.0]
    assert normalize_probability_vector(np.zeros(4), size=4).tolist() == [0.25] * 4


def test_probability_normalization_rejects_ambiguous_shape() -> None:
    with pytest.raises(ValueError, match="shape"):
        normalize_probability_vector(np.zeros((2, 2)), size=4)


def test_process_control_runs_without_streamlit(tmp_path) -> None:
    log_path = tmp_path / "nested" / "run.log"
    process = launch_logged_process(
        [sys.executable, "-c", "print('service boundary')"],
        cwd=tmp_path,
        log_path=log_path,
    )
    assert process.wait(timeout=10) == 0
    terminate_process(process)
    assert log_path.read_text(encoding="utf-8").strip() == "service boundary"


def test_artifact_discovery_is_sorted_and_ui_independent(tmp_path) -> None:
    nested = tmp_path / "runs" / "one"
    nested.mkdir(parents=True)
    second = nested / "b.json"
    first = nested / "a.json"
    second.write_text("{}", encoding="utf-8")
    first.write_text("{}", encoding="utf-8")

    assert discover_files(tmp_path, "runs/**/*.json") == [first, second]
    absent = tmp_path / "missing.json"
    assert missing_artifacts({"present": first, "absent": absent}) == {"absent": absent}
    assert discover_files(tmp_path / "not-created", "*.json") == []
