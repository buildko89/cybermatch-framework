"""Run Phase3-A Adaptive Attacker Validation evaluations."""

from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from run_scenarios import (  # noqa: E402
    run_phase3_adaptive_attacker_evaluation,
    run_phase3_path_attacker_evaluation,
    run_phase3_planning_attacker_evaluation,
    run_phase3_preference_attacker_evaluation,
)


def _parse_seeds(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CyberMatch Phase3-A adaptive attacker evaluations.")
    parser.add_argument("--seeds", default="0", help="Comma-separated seed list. Default: 0")
    parser.add_argument("--output-dir", default=os.path.join("output", "phase3_publication"))
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    seeds = _parse_seeds(args.seeds)

    print("Running Phase3.1 adaptive memory attacker evaluation...")
    adaptive_rows = run_phase3_adaptive_attacker_evaluation(
        seeds=seeds,
        output_dir=os.path.join(args.output_dir, "phase3_adaptive_attacker"),
        config_path=args.config,
    )
    print(f"Phase3.1 rows: {len(adaptive_rows)}")

    print("Running Phase3.2 node preference attacker evaluation...")
    preference_rows = run_phase3_preference_attacker_evaluation(
        seeds=seeds,
        output_dir=os.path.join(args.output_dir, "phase3_preference_attacker"),
        config_path=args.config,
    )
    print(f"Phase3.2 rows: {len(preference_rows)}")

    print("Running Phase3.3 path preference attacker evaluation...")
    path_rows = run_phase3_path_attacker_evaluation(
        seeds=seeds,
        output_dir=os.path.join(args.output_dir, "phase3_path_attacker"),
        config_path=args.config,
    )
    print(f"Phase3.3 rows: {len(path_rows)}")

    print("Running Phase3.4 path planning attacker evaluation...")
    planning_rows = run_phase3_planning_attacker_evaluation(
        seeds=seeds,
        output_dir=os.path.join(args.output_dir, "phase3_planning_attacker"),
        config_path=args.config,
    )
    print(f"Phase3.4 rows: {len(planning_rows)}")
    print(f"Phase3-A outputs written below {args.output_dir}")


if __name__ == "__main__":
    main()
