"""Run Phase3-B Rational Attacker Validation evaluations."""

from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from run_scenarios import run_phase3_expected_utility_evaluation  # noqa: E402


def _parse_seeds(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CyberMatch Phase3-B rational attacker validation.")
    parser.add_argument("--seeds", default="0", help="Comma-separated seed list. Default: 0")
    parser.add_argument("--output-dir", default=os.path.join("output", "phase3_expected_utility"))
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    rows = run_phase3_expected_utility_evaluation(
        seeds=_parse_seeds(args.seeds),
        output_dir=args.output_dir,
        config_path=args.config,
    )
    print(f"Phase3.6 Expected Utility rows: {len(rows)}")
    print(f"Phase3-B outputs written below {args.output_dir}")


if __name__ == "__main__":
    main()
