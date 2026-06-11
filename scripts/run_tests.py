import argparse
import os
import subprocess
import sys
import uuid
from typing import List


def _run(command: List[str]) -> int:
    print("+ " + " ".join(command), flush=True)
    return subprocess.run(command).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CyberMatch test profiles.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--smoke", action="store_true", help="Run compile checks and smoke/Phase5 tests.")
    group.add_argument("--phase", choices=["phase1", "phase2", "phase3", "phase4", "phase5"], help="Run one phase marker.")
    group.add_argument("--full", action="store_true", help="Run compile checks and the full pytest suite.")
    args = parser.parse_args()

    compile_targets = ["cybermatch.py", "run_scenarios.py", "scripts/run_tests.py"]
    compile_rc = _run([sys.executable, "-m", "compileall", *compile_targets])
    if compile_rc != 0:
        return compile_rc

    run_id = uuid.uuid4().hex[:12]
    os.makedirs("output/pytest_tmp", exist_ok=True)
    pytest_base = [
        sys.executable,
        "-m",
        "pytest",
        "--basetemp",
        f"output/pytest_tmp/{run_id}",
        "-p",
        "no:cacheprovider",
    ]

    if args.smoke:
        return _run([*pytest_base, "-m", "smoke or phase5", "-q"])
    if args.phase:
        return _run([*pytest_base, "-m", args.phase, "-q"])
    return _run([*pytest_base, "-q"])


if __name__ == "__main__":
    raise SystemExit(main())
