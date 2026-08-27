"""Command-line orchestration for offline defender-side threat hunting."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .adapters import HistoryObservationAdapter
from .artifacts import ThreatHuntingArtifactWriter
from .config import ThreatHuntingRunConfig
from .engine import ThreatHuntingEngine
from .recipes import ThreatHuntingRecipeLoader, default_recipe_root


def build_parser() -> argparse.ArgumentParser:
    defaults = ThreatHuntingRunConfig()
    parser = argparse.ArgumentParser(
        description="Run deterministic threat hunting over a CyberMatch history.npz file."
    )
    parser.add_argument("--history", required=True, help="Path to a CyberMatch history.npz file.")
    parser.add_argument(
        "--recipe",
        required=True,
        help="JSON recipe path below --recipe-root (repository-relative paths are accepted).",
    )
    parser.add_argument(
        "--recipe-root",
        default=str(default_recipe_root()),
        help="Trusted recipe root directory.",
    )
    parser.add_argument("--output", required=True, help="New artifact output directory.")
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--max-events", type=int, default=defaults.max_events)
    parser.add_argument("--max-window-steps", type=int, default=defaults.max_window_steps)
    parser.add_argument("--max-groups", type=int, default=defaults.max_groups)
    parser.add_argument("--max-sequence-length", type=int, default=defaults.max_sequence_length)
    parser.add_argument("--max-regex-length", type=int, default=defaults.max_regex_length)
    parser.add_argument("--max-findings", type=int, default=defaults.max_findings)
    return parser


def _recipe_relative_path(recipe_argument: str, recipe_root: Path) -> Path:
    requested = Path(recipe_argument)
    if requested.is_absolute():
        raise ValueError("recipe path must be relative")
    root = recipe_root.resolve()
    candidates = [
        (Path.cwd() / requested).resolve(),
        (root.parents[1] / requested).resolve() if len(root.parents) > 1 else root / requested,
    ]
    for candidate in candidates:
        if candidate.is_relative_to(root):
            return candidate.relative_to(root)
    return requested


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = ThreatHuntingRunConfig(
            max_events=args.max_events,
            max_window_steps=args.max_window_steps,
            max_groups=args.max_groups,
            max_sequence_length=args.max_sequence_length,
            max_regex_length=args.max_regex_length,
            max_findings=args.max_findings,
        )
        recipe_root = Path(args.recipe_root)
        loader = ThreatHuntingRecipeLoader(recipe_root)
        recipe = loader.load(_recipe_relative_path(args.recipe, recipe_root))
        history_path = Path(args.history)
        events = HistoryObservationAdapter().adapt(
            history_path,
            campaign_id=args.campaign_id,
            scenario_id=args.scenario_id,
            seed=args.seed,
        )
        findings = ThreatHuntingEngine(config).run(recipe, events)
        artifacts = ThreatHuntingArtifactWriter(args.output).write(
            events=events,
            findings=findings,
            recipe=recipe,
            config=config,
            source_history=history_path,
            campaign_id=args.campaign_id,
            scenario_id=args.scenario_id,
            seed=args.seed,
        )
    except (OSError, ValueError) as exc:
        print(f"failure: {exc}", file=sys.stderr)
        return 2

    print(f"output dir: {artifacts.output_dir}")
    print(f"events: {len(events)}")
    print(f"findings: {len(findings)}")
    print(f"artifact hash: {artifacts.artifact_hash}")
    print("success: true")
    return 0


__all__ = ["build_parser", "main"]
