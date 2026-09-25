from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cybermatch.loaders.scenario_loader import ScenarioValidationError, list_available_scenarios, load_scenario, run_scenario_from_file
from cybermatch.loaders.benchmark_loader import BenchmarkValidationError, load_benchmark


PHASE8_BENCHMARK_DEFAULTS = {
    "cybermatch_standard_v1": ("phase85_standard_benchmark", "output/phase85_standard_benchmark"),
}
PHASE83_DEFAULT = ("phase83_benchmark_suite", "output/phase83_benchmark_suite")


def _parse_seeds(value: str | None) -> list[int] | None:
    if value is None:
        return None
    seeds = [int(item.strip()) for item in value.split(",") if item.strip()]
    if not seeds:
        raise argparse.ArgumentTypeError("--seeds requires at least one integer")
    return seeds


def _phase8_baseline(target: str, seeds: list[int], baseline: str | None) -> tuple[str, bool]:
    """Return (baseline summary path, generated) for a Phase8.x benchmark.

    Without ``--baseline`` a fresh Phase6.3 baseline covering every product and
    mission is generated inside the benchmark output, so the result never
    depends on output/phase63_mission_products.
    """
    if baseline:
        return baseline, False
    from cybermatch.evaluation.runner import run_phase63_mission_aware_product_evaluation

    baseline_dir = Path(target) / "baseline"
    run_phase63_mission_aware_product_evaluation(seeds=seeds, output_dir=str(baseline_dir))
    return str(baseline_dir / "mission_product_summary.json"), True


def _phase8_seed_robustness(run, benchmark_path: str, target: str) -> None:
    """Re-run a Phase8.x suite once per baseline seed and summarize the spread."""
    from cybermatch.evaluation.runner import _report_product_label
    from cybermatch.evaluation.seed_robustness import summarize, write_phase63_per_seed_summaries, write_seed_robustness

    rows_by_seed = {}
    for seed, summary_path in write_phase63_per_seed_summaries(str(Path(target) / "baseline"), None).items():
        rows_by_seed[seed] = run(
            benchmark_path=benchmark_path,
            output_dir=str(Path(target) / "seeds" / f"seed_{seed}"),
            baseline_summary_path=summary_path,
        )
    summary = summarize(rows_by_seed, candidate_key="product_profile", score_key="benchmark_score", exclude_candidates=())
    write_seed_robustness(
        target,
        summary,
        title="seed 頑健性レポート(ベンチマーク横断比較)",
        score_label="横断比較スコア",
        group_label="比較範囲",
        label_candidate=_report_product_label,
        label_group=lambda group: "全条件" if group == "overall" else group,
    )


def _run_benchmark(
    path: str,
    output_dir: str | None,
    seeds: list[int] | None,
    baseline: str | None,
) -> tuple[str, str, int, list[int], list[str]]:
    """Dispatch a benchmark file.

    Returns (runner, output_dir, row_count, seeds, extra_input_paths).
    """

    benchmark = load_benchmark(path)
    metadata = benchmark.get("metadata", {})
    declared_seeds = [int(seed) for seed in benchmark.get("seeds", [0])]
    if metadata.get("type") == "agentic_security":
        from cybermatch.agentic import run_agentic_security_benchmark

        target = output_dir or "output/agentic_security/cybermatch_agentic_security_v1"
        rows = run_agentic_security_benchmark(benchmark_path=path, output_dir=target)
        return "agentic_security_evaluation", target, len(rows), declared_seeds, []
    if metadata.get("type") == "threat_hunting":
        from cybermatch.threat_hunting.benchmark_runner import run_hunting_benchmark

        target = output_dir or "output/threat_hunting/cybermatch_hunting_v1"
        rows = run_hunting_benchmark(benchmark_path=path, output_dir=target)
        return "hunting_recipe_evaluation", target, len(rows), declared_seeds, []

    from cybermatch.evaluation.runner import run_phase83_benchmark_suite, run_phase85_standard_benchmark

    runner_name, default_dir = PHASE8_BENCHMARK_DEFAULTS.get(str(metadata.get("name")), PHASE83_DEFAULT)
    run = run_phase85_standard_benchmark if runner_name == "phase85_standard_benchmark" else run_phase83_benchmark_suite
    target = output_dir or default_dir
    seed_values = seeds or declared_seeds
    baseline_path, generated = _phase8_baseline(target, seed_values, baseline)
    rows = run(benchmark_path=path, output_dir=target, baseline_summary_path=baseline_path)
    if generated and len(seed_values) >= 2:
        _phase8_seed_robustness(run, path, target)
    return runner_name, target, len(rows), seed_values, [] if generated else [baseline_path]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a CyberMatch JSON scenario.")
    parser.add_argument("scenario", nargs="?", help="Path to a CyberMatch scenario JSON file.")
    parser.add_argument("--list", action="store_true", help="List catalog scenarios.")
    parser.add_argument(
        "--output-dir",
        help="Override the output directory declared by the scenario or benchmark.",
    )
    parser.add_argument(
        "--seeds",
        type=_parse_seeds,
        help=(
            "Comma-separated seeds (e.g. 0,1,2,3,4) overriding the scenario. For the standard and "
            "product benchmarks they seed the generated Phase6.3 baseline. Two or more seeds add a "
            "seed-robustness report with 95%% confidence intervals."
        ),
    )
    parser.add_argument(
        "--baseline",
        help=(
            "Phase6.3 mission_product_summary.json used as the standard/product benchmark baseline. "
            "Default: generate a fresh baseline inside the output directory."
        ),
    )
    args = parser.parse_args()

    if args.list:
        for scenario_path in list_available_scenarios():
            scenario = load_scenario(str(scenario_path))
            metadata = scenario.get("metadata", {})
            print(f"{metadata.get('name')} [{metadata.get('industry', '')}] - {scenario_path}")
        return 0

    if not args.scenario:
        parser.error("scenario is required unless --list is used")

    try:
        config = json.loads(Path(args.scenario).read_text(encoding="utf-8"))
        is_benchmark = isinstance(config, dict) and "scenarios" in config and "evaluation" not in config
        if is_benchmark:
            name = config.get("metadata", {}).get("name")
            runner, output_dir, row_count, _, _ = _run_benchmark(
                args.scenario, args.output_dir, args.seeds, args.baseline
            )
            label = "benchmark name"
        else:
            if args.baseline:
                parser.error("--baseline applies only to the standard and product benchmarks")
            result = run_scenario_from_file(args.scenario, output_dir=args.output_dir, seeds=args.seeds)
            name, runner, output_dir, row_count = (
                result["scenario_name"], result["runner"], result["output_dir"], result["rows"]
            )
            label = "scenario name"
    except ScenarioValidationError as exc:
        print(f"failure: {exc}", file=sys.stderr)
        return 2
    except BenchmarkValidationError as exc:
        print(f"failure: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"failure: {exc}", file=sys.stderr)
        return 1

    print(f"{label}: {name}")
    print(f"runner: {runner}")
    print(f"output dir: {output_dir}")
    print(f"rows: {row_count}")
    print("success: true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
