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


def _phase8_baseline(target: str, seeds: list[int], baseline: str | None) -> str:
    """Return the baseline summary path for a Phase8.x benchmark.

    Without ``--baseline`` a fresh Phase6.3 baseline covering every product and
    mission is generated inside the benchmark output, so the result never
    depends on output/phase63_mission_products.
    """
    if baseline:
        return baseline
    from cybermatch.evaluation.runner import run_phase63_mission_aware_product_evaluation

    baseline_dir = Path(target) / "baseline"
    run_phase63_mission_aware_product_evaluation(seeds=seeds, output_dir=str(baseline_dir))
    return str(baseline_dir / "mission_product_summary.json")


def _run_benchmark(path: str, output_dir: str | None, baseline: str | None) -> tuple[str, str, int]:
    """Dispatch a benchmark file and return (runner, output_dir, row_count)."""

    benchmark = load_benchmark(path)
    metadata = benchmark.get("metadata", {})
    if metadata.get("type") == "agentic_security":
        from cybermatch.agentic import run_agentic_security_benchmark

        target = output_dir or "output/agentic_security/cybermatch_agentic_security_v1"
        rows = run_agentic_security_benchmark(benchmark_path=path, output_dir=target)
        return "agentic_security_evaluation", target, len(rows)
    if metadata.get("type") == "threat_hunting":
        from cybermatch.threat_hunting.benchmark_runner import run_hunting_benchmark

        target = output_dir or "output/threat_hunting/cybermatch_hunting_v1"
        rows = run_hunting_benchmark(benchmark_path=path, output_dir=target)
        return "hunting_recipe_evaluation", target, len(rows)

    from cybermatch.evaluation.runner import run_phase83_benchmark_suite, run_phase85_standard_benchmark

    runner_name, default_dir = PHASE8_BENCHMARK_DEFAULTS.get(str(metadata.get("name")), PHASE83_DEFAULT)
    run = run_phase85_standard_benchmark if runner_name == "phase85_standard_benchmark" else run_phase83_benchmark_suite
    target = output_dir or default_dir
    seeds = [int(seed) for seed in benchmark.get("seeds", [0])]
    baseline_path = _phase8_baseline(target, seeds, baseline)
    rows = run(benchmark_path=path, output_dir=target, baseline_summary_path=baseline_path)
    return runner_name, target, len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a CyberMatch JSON scenario.")
    parser.add_argument("scenario", nargs="?", help="Path to a CyberMatch scenario JSON file.")
    parser.add_argument("--list", action="store_true", help="List catalog scenarios.")
    parser.add_argument(
        "--output-dir",
        help="Override the output directory declared by the scenario or benchmark.",
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
        if isinstance(config, dict) and "scenarios" in config and "evaluation" not in config:
            runner, output_dir, row_count = _run_benchmark(args.scenario, args.output_dir, args.baseline)
            metadata = config.get("metadata", {})
            print(f"benchmark name: {metadata.get('name')}")
            print(f"runner: {runner}")
            print(f"output dir: {output_dir}")
            print(f"rows: {row_count}")
            print("success: true")
            return 0
        if args.baseline:
            parser.error("--baseline applies only to the standard and product benchmarks")
        result = run_scenario_from_file(args.scenario, output_dir=args.output_dir)
    except ScenarioValidationError as exc:
        print(f"failure: {exc}", file=sys.stderr)
        return 2
    except BenchmarkValidationError as exc:
        print(f"failure: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"failure: {exc}", file=sys.stderr)
        return 1

    print(f"scenario name: {result['scenario_name']}")
    print(f"runner: {result['runner']}")
    print(f"output dir: {result['output_dir']}")
    print(f"rows: {result['rows']}")
    print("success: true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
