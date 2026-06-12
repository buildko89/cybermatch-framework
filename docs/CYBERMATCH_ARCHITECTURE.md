# CyberMatch Architecture

CyberMatch is a layered decision-evaluation framework. Phase8.6 adds a small module facade so v1.0 work can grow without forcing all callers to import directly from the historical monolithic files.

Phase8.6 does not change simulation logic, runner behavior, artifacts, benchmark scoring, attackers, defenders, RL, LLMs, or external API usage.

## Module Structure

```text
cybermatch-framework/
  cybermatch.py                 # simulation models and simulator implementation
  run_scenarios.py              # evaluation runners and artifact writers
  scenario_loader.py            # JSON scenario import
  topology_loader.py            # topology preset validation
  benchmark_loader.py           # benchmark validation
  cybermatch_core/
    products.py                 # ProductProfile and product loader facade
    scenarios.py                # scenario loader facade
    topologies.py               # topology loader facade
    benchmarks.py               # benchmark loader facade
    metrics.py                  # small shared metric helpers
    utils.py                    # repository path helpers
```

The top-level modules remain authoritative for backward compatibility. New code can prefer `cybermatch_core.*` imports where that improves readability.

## Dependency Overview

```text
profiles/products/*.json
        |
        v
cybermatch.py  <---- run_scenarios.py
        ^              |
        |              v
cybermatch_core.products

scenarios/*.json ---> scenario_loader.py ---> cybermatch_core.scenarios
topologies/*.json -> topology_loader.py ---> cybermatch_core.topologies
benchmarks/*.json -> benchmark_loader.py --> cybermatch_core.benchmarks
```

The facade modules import from existing implementation modules. Existing imports such as `from cybermatch import ProductProfile` remain valid.

## Runner Flow

```text
run_scenarios.py
  -> existing Phase runners
  -> CyberDefenseSimulator / ProductProfile
  -> CSV / JSON / PNG / Markdown artifacts under output/
```

Phase8.6 does not alter runner inputs, seeds, scoring, output paths, or artifact schemas.

## Scenario Flow

```text
scenario JSON
  -> load_scenario()
  -> validate_scenario()
  -> topology preset resolution
  -> existing Phase6.2 or Phase6.3 runner dispatch
```

Scenario import validates metadata, runner, missions, products, and topology presets. Products and topology presets are still controlled local JSON files.

## Benchmark Flow

```text
benchmark JSON
  -> load_benchmark()
  -> validate_benchmark()
  -> scenario / topology / mission / product matrix
  -> Phase8 benchmark summary artifacts
```

The standard benchmark uses:

```text
5 scenarios x 5 topologies x 4 missions x 5 products = 500 matrix cells
```

Benchmark interpretation remains benchmark-condition reporting, not product certification.

## Refactoring Boundary

Phase8.6 intentionally avoids large file moves. The immediate goal is a stable module boundary for future extraction:

- Product profile types and helpers can move behind `cybermatch_core.products`.
- Scenario import can move behind `cybermatch_core.scenarios`.
- Topology import can move behind `cybermatch_core.topologies`.
- Benchmark import can move behind `cybermatch_core.benchmarks`.
- Shared numeric/reporting helpers can move behind `cybermatch_core.metrics`.

This keeps v1.0 maintainability work incremental and testable.
