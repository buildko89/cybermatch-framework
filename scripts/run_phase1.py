"""Run Phase1 Defense Neutralization evaluations.

This script is a thin publication entry point. Evaluation logic stays in
run_scenarios.py so Phase1 and Phase2 remain consistent.
"""

from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from run_scenarios import (  # noqa: E402
    CONDITIONAL_MTD_SCENARIO_NAMES,
    CREDENTIAL_AWARE_MTD_SCENARIO_NAMES,
    NEUTRALIZATION_SCENARIO_MAP,
    POLICY_SELECTION_SCENARIO_NAMES,
    SCENARIOS,
    run_neutralization_evaluation,
    run_scenarios_multi_seed,
)


def _parse_seeds(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def _phase1_scenarios() -> dict[str, dict[str, object]]:
    names = (
        set(NEUTRALIZATION_SCENARIO_MAP.values())
        | set(POLICY_SELECTION_SCENARIO_NAMES)
        | set(CONDITIONAL_MTD_SCENARIO_NAMES)
        | set(CREDENTIAL_AWARE_MTD_SCENARIO_NAMES)
    )
    return {name: SCENARIOS[name] for name in sorted(names) if name in SCENARIOS}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CyberMatch Phase1 Defense Neutralization evaluations.")
    parser.add_argument("--seeds", default="0", help="Comma-separated seed list. Default: 0")
    parser.add_argument("--output-dir", default=os.path.join("output", "phase1_publication"))
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    seeds = _parse_seeds(args.seeds)
    print("Running Phase1 neutralization evaluation...")
    neutralization_rows = run_neutralization_evaluation(
        output_dir=os.path.join(args.output_dir, "neutralization"),
        config_path=args.config,
    )
    print(f"Neutralization scenarios: {len(neutralization_rows)}")

    print("Running Phase1 policy and MTD evaluation...")
    stats_rows = run_scenarios_multi_seed(
        scenarios=_phase1_scenarios(),
        seeds=seeds,
        output_dir=os.path.join(args.output_dir, "policy_mtd"),
        config_path=args.config,
    )
    print(f"Phase1 policy/MTD scenarios: {len(stats_rows)}")
    print(f"Phase1 outputs written to {args.output_dir}")


if __name__ == "__main__":
    main()
