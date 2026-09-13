import argparse
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import List, Mapping, Sequence


FAST_TEST_PATTERNS: Sequence[str] = (
    "tests/test_core_facade.py",
    "tests/test_evidence_contracts.py",
    "tests/test_evaluation_helpers.py",
    "tests/test_packaging.py",
    "tests/test_public_api.py",
    "tests/test_schema_registry.py",
    "tests/test_test_runner.py",
    "tests/test_agentic_security_*.py",
    "tests/test_agentic_resilience_*.py",
    "tests/test_architecture_seams.py",
    "tests/test_threat_intel_integrity.py",
    "tests/test_threat_hunting_*.py",
    "tests/test_fuzzing_*.py",
)
SMOKE_TIMEOUT_SECONDS = 60


def _run(
    command: List[str],
    *,
    env: Mapping[str, str] | None = None,
    timeout: int | None = None,
    cwd: Path | None = None,
) -> int:
    print("+ " + " ".join(command), flush=True)
    try:
        return subprocess.run(command, env=env, timeout=timeout, cwd=cwd).returncode
    except subprocess.TimeoutExpired:
        print(f"ERROR: command exceeded the {timeout}-second fast-lane SLO", file=sys.stderr)
        return 124


def _fast_test_targets(repository_root: Path) -> List[str]:
    targets: set[Path] = set()
    for pattern in FAST_TEST_PATTERNS:
        targets.update(repository_root.glob(pattern))
    if not targets:
        raise RuntimeError("fast test inventory is empty")
    return [str(path.relative_to(repository_root)) for path in sorted(targets)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CyberMatch test profiles.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--smoke", action="store_true", help="Run the curated fast lane (60-second SLO).")
    group.add_argument("--phase", choices=["phase1", "phase2", "phase3", "phase4", "phase5", "phase8", "phase83", "phase84", "phase85", "phase90", "phase91", "phase92", "phase93", "phase94", "phase95", "phase96", "phase97", "phase98", "phase99", "threat_hunting", "agentic_security"], help="Run one phase marker.")
    group.add_argument("--full", action="store_true", help="Run compile checks and the full pytest suite.")
    args = parser.parse_args()

    repository_root = Path(__file__).resolve().parents[1]
    compile_targets = ["cybermatch.py", "run_scenarios.py", "intent_inference.py", "behavior_profile.py", "feature_space.py", "feature_export.py", "archetype_analysis.py", "strategy_layer.py", "mission_taxonomy.py", "strategy_validation.py", "decision_graph.py", "scenario_loader.py", "benchmark_loader.py", "topology_loader.py", "src/cybermatch/application", "src/cybermatch/contracts", "src/cybermatch/evaluation", "src/cybermatch/simulation", "src/cybermatch/threat_hunting", "src/cybermatch/agentic", "cybermatch_core/threat_hunting.py", "cybermatch_core/agentic_security.py", "scripts/run_tests.py", "scripts/run_scenario.py", "scripts/run_agentic_resilience.py", "scripts/run_threat_hunting.py", "scripts/run_threat_hunting_evaluation.py", "scripts/validate_assets.py"]
    run_id = uuid.uuid4().hex[:12]
    run_root = repository_root / "output" / "pytest_tmp" / run_id
    run_root.mkdir(parents=True, exist_ok=False)
    run_env = os.environ.copy()
    run_env["PYTHONPYCACHEPREFIX"] = str(run_root / "pycache")
    run_env["MPLBACKEND"] = "Agg"

    compile_rc = _run(
        [sys.executable, "-m", "compileall", "-q", *compile_targets],
        env=run_env,
        cwd=repository_root,
    )
    if compile_rc != 0:
        return compile_rc

    profile_name = "smoke" if args.smoke else args.phase or "full"
    junit_path = repository_root / "output" / "test-results" / f"{profile_name}-{run_id}.xml"
    junit_path.parent.mkdir(parents=True, exist_ok=True)
    pytest_base = [
        sys.executable,
        "-m",
        "pytest",
        "--basetemp",
        str(run_root / "basetemp"),
        "-p",
        "no:cacheprovider",
        "--strict-markers",
        f"--junitxml={junit_path}",
    ]

    if args.smoke:
        return _run(
            [*pytest_base, *_fast_test_targets(repository_root), "-q"],
            env=run_env,
            timeout=SMOKE_TIMEOUT_SECONDS,
            cwd=repository_root,
        )
    if args.phase:
        return _run([*pytest_base, "-m", args.phase, "-q"], env=run_env, cwd=repository_root)
    return _run([*pytest_base, "-q"], env=run_env, cwd=repository_root)


if __name__ == "__main__":
    raise SystemExit(main())
