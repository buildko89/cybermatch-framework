from pathlib import Path

from scripts.run_tests import FAST_TEST_PATTERNS, SMOKE_TIMEOUT_SECONDS, _fast_test_targets


def test_fast_lane_is_explicit_bounded_and_covers_current_flagship_domains():
    repository_root = Path(__file__).resolve().parents[1]
    targets = _fast_test_targets(repository_root)

    assert targets == sorted(set(targets))
    assert len(targets) < len(list((repository_root / "tests").glob("test_*.py")))
    assert any("agentic_security" in target for target in targets)
    assert any("threat_hunting" in target for target in targets)
    assert any("fuzzing" in target for target in targets)
    assert all("*" not in target for target in targets)
    assert FAST_TEST_PATTERNS
    assert SMOKE_TIMEOUT_SECONDS == 60
