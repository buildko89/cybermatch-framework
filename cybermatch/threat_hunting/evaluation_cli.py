"""Evaluation-mode CLI used by the H3 GUI parameter experiment."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from .scenario_runner import run_hunting_history_evaluation


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one truth-separated threat-hunting evaluation over history.npz."
    )
    parser.add_argument("--history", required=True)
    parser.add_argument("--recipe", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--product-profile", default=None)
    parser.add_argument(
        "--recipe-overrides",
        default="{}",
        help="JSON object with the audited recipe override fields.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        overrides = json.loads(args.recipe_overrides)
        if not isinstance(overrides, dict):
            raise ValueError("recipe overrides must be a JSON object")
        result = run_hunting_history_evaluation(
            history_path=args.history,
            recipe_path=args.recipe,
            output_dir=args.output,
            scenario_id=args.scenario_id,
            campaign_id=args.campaign_id,
            seed=args.seed,
            product_profile_path=args.product_profile,
            recipe_overrides=overrides,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"failure: {exc}", file=sys.stderr)
        return 2
    print(f"output dir: {result['output_dir']}")
    print(f"events: {result['event_count']}")
    print(f"findings: {result['finding_count']}")
    print(f"artifact hash: {result['artifact_hash']}")
    print("success: true")
    return 0


__all__ = ["build_parser", "main"]
