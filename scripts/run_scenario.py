from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scenario_loader import ScenarioValidationError, list_available_scenarios, load_scenario, run_scenario_from_file
from benchmark_loader import BenchmarkValidationError, load_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a CyberMatch JSON scenario.")
    parser.add_argument("scenario", nargs="?", help="Path to a CyberMatch scenario JSON file.")
    parser.add_argument("--list", action="store_true", help="List catalog scenarios.")
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
            benchmark = load_benchmark(args.scenario)
            metadata = benchmark.get("metadata", {})
            if metadata.get("name") == "cybermatch_standard_v1":
                from run_scenarios import run_phase85_standard_benchmark

                rows = run_phase85_standard_benchmark(benchmark_path=args.scenario)
                print(f"benchmark name: {metadata.get('name')}")
                print("runner: phase85_standard_benchmark")
                print("output dir: output/phase85_standard_benchmark")
                print(f"rows: {len(rows)}")
                print("success: true")
                return 0
            from run_scenarios import run_phase83_benchmark_suite

            rows = run_phase83_benchmark_suite(benchmark_path=args.scenario)
            print(f"benchmark name: {metadata.get('name')}")
            print("runner: phase83_benchmark_suite")
            print("output dir: output/phase83_benchmark_suite")
            print(f"rows: {len(rows)}")
            print("success: true")
            return 0
        result = run_scenario_from_file(args.scenario)
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
