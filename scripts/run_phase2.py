"""Run Phase2 Decision Neutralization evaluations."""

from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from run_scenarios import (  # noqa: E402
    run_phase2_ai_cost_evaluation,
    run_phase2_ai_weight_sweep_evaluation,
    run_phase2_cognitive_neutralization_evaluation,
    run_phase2_cns_objective_evaluation,
    run_phase2_policy_selection_evaluation,
)


def _parse_seeds(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CyberMatch Phase2 Decision Neutralization evaluations.")
    parser.add_argument("--seeds", default="0", help="Comma-separated seed list. Default: 0")
    parser.add_argument("--output-dir", default=os.path.join("output", "phase2_publication"))
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    seeds = _parse_seeds(args.seeds)
    print("Running Phase2 AI cost evaluation...")
    ai_cost_rows = run_phase2_ai_cost_evaluation(
        seeds=seeds,
        output_dir=os.path.join(args.output_dir, "phase2_ai_cost"),
        config_path=args.config,
    )
    print(f"AI cost scenarios: {len(ai_cost_rows)}")

    print("Running Phase2 AI weight sweep...")
    ai_weight_rows = run_phase2_ai_weight_sweep_evaluation(
        seeds=seeds,
        output_dir=os.path.join(args.output_dir, "phase2_ai_weight_sweep"),
        config_path=args.config,
    )
    print(f"AI weight scenarios: {len(ai_weight_rows)}")

    print("Running Phase2 cognitive neutralization evaluation...")
    cognitive_rows = run_phase2_cognitive_neutralization_evaluation(
        seeds=seeds,
        output_dir=os.path.join(args.output_dir, "phase2_cognitive_neutralization"),
        config_path=args.config,
    )
    print(f"Cognitive scenarios: {len(cognitive_rows)}")

    print("Running Phase2 policy selection evaluation...")
    policy_rows = run_phase2_policy_selection_evaluation(
        seeds=seeds,
        output_dir=os.path.join(args.output_dir, "phase2_policy_selection"),
        config_path=args.config,
    )
    print(f"Policy scenarios: {len(policy_rows)}")

    print("Running Phase2 CNS objective evaluation...")
    objective_rows = run_phase2_cns_objective_evaluation(
        seeds=seeds,
        output_dir=os.path.join(args.output_dir, "phase2_cns_objective"),
        config_path=args.config,
    )
    print(f"CNS objective scenarios: {len(objective_rows)}")
    print(f"Phase2 outputs written below {args.output_dir}")


if __name__ == "__main__":
    main()
