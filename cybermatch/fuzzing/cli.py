"""CLI for validating, running, and replaying fuzzing campaigns."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .corpus import REPOSITORY_ROOT
from .runner import replay_case, run_campaign
from .specs import load_campaign_spec


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run CyberMatch analysis-guided fuzzing.")
    parser.add_argument("campaign", nargs="?", help="Campaign JSON file.")
    parser.add_argument("--validate", metavar="CAMPAIGN", help="Validate without executing.")
    parser.add_argument("--replay", metavar="CASE_DIR", help="Replay a saved corpus case.")
    parser.add_argument("--output-dir", help="New output directory override.")
    parser.add_argument("--max-cases", type=int, help="Positive audited case-count override.")
    parser.add_argument("--no-minimize", action="store_true", help="Skip hard-failure minimization.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    selected = sum(bool(value) for value in (args.campaign, args.validate, args.replay))
    if selected != 1:
        parser.error("select exactly one campaign, --validate, or --replay")
    try:
        if args.validate:
            spec = load_campaign_spec(args.validate)
            print(f"campaign: {spec.campaign_id}")
            print(f"cases: {spec.limits.max_cases}")
            print("valid: true")
            return 0
        if args.replay:
            result = replay_case(args.replay, repository_root=REPOSITORY_ROOT)
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 0 if result["saved_result_match"] else 1
        result = run_campaign(
            args.campaign,
            repository_root=REPOSITORY_ROOT,
            output_dir=args.output_dir,
            max_cases=args.max_cases,
            minimize=not args.no_minimize,
        )
    except (OSError, ValueError) as exc:
        print(f"failure: {exc}", file=sys.stderr)
        return 2
    print(f"output dir: {result['output_dir']}")
    print(f"cases: {result['attempted_cases']}")
    print(f"interesting: {result['interesting_cases']}")
    print(f"artifact hash: {result['artifact_hash']}")
    print("success: true")
    return 0


__all__ = ["build_parser", "main"]
