"""Run all CyberMatch publication evaluations."""

from __future__ import annotations

import argparse

from run_phase1 import main as run_phase1_main
from run_phase2 import main as run_phase2_main
from run_phase3 import main as run_phase3_main


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CyberMatch Phase1, Phase2, and Phase3-A evaluations.")
    parser.add_argument(
        "args",
        nargs="*",
        help="Arguments are intentionally handled by the phase scripts. Use run_phase1.py or run_phase2.py for options.",
    )
    parser.parse_args()

    run_phase1_main()
    run_phase2_main()
    run_phase3_main()


if __name__ == "__main__":
    main()
