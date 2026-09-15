"""Run an auditable Phase 3 external telemetry replay."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cybermatch_core.external_sut import run_external_replay_evaluation


ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--mapping", required=True)
    parser.add_argument("--recipe", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--synthetic-reference", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument(
        "--evidence-class", choices=["replay-backed", "external-sut-backed"], default="replay-backed"
    )
    parser.add_argument("--seed", type=int, default=0)
    return parser


def _path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_external_replay_evaluation(
            source_path=_path(args.source),
            mapping_path=_path(args.mapping),
            recipe_path=_path(args.recipe),
            ground_truth_path=_path(args.ground_truth),
            synthetic_reference_path=_path(args.synthetic_reference),
            output_dir=_path(args.output),
            campaign_id=args.campaign_id,
            scenario_id=args.scenario_id,
            evidence_class=args.evidence_class,
            seed=args.seed,
            repository_root=ROOT,
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"failure: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
