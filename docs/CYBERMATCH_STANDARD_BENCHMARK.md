# CyberMatch Standard Benchmark

Phase8.5 defines the CyberMatch Standard Benchmark Suite for v1.0.

The purpose is reproducible comparison under the same scenarios, topologies, missions, products, and seeds. It does not add attackers, defenders, simulation logic, RL, LLMs, external APIs, or real product integration.

## Purpose

The standard benchmark lets CyberMatch users evaluate controlled product profiles under identical conditions:

- same scenarios
- same topology presets
- same missions
- same product profiles
- same seeds

Results must be interpreted as benchmark-condition results, not product certification.

## Composition

Scenarios:

- `financial_enterprise`
- `hospital_enterprise`
- `cloud_native_startup`
- `ot_factory`
- `small_business`

Topologies:

- `enterprise`
- `hospital_network`
- `cloud_native`
- `ot_environment`
- `small_business`

Missions:

- `profit`
- `achievement`
- `persistence`
- `critical_hunter`

Products:

- `sample_ids`
- `sample_ips`
- `sample_honeypot`
- `sample_deception`
- `sample_xdr`

Seeds:

- `[0]`

## Matrix Size

```text
scenario_count x topology_count x mission_count x product_count
5 x 5 x 4 x 5 = 500
```

## Run Command

```bash
python scripts/run_scenario.py benchmarks/cybermatch_standard_v1.json
```

## Outputs

```text
output/phase85_standard_benchmark/
  standard_benchmark_summary.csv
  standard_benchmark_summary.json
  standard_product_ranking.png
  standard_scenario_heatmap.png
  standard_topology_heatmap.png
  standard_mission_heatmap.png
  PHASE85_STANDARD_BENCHMARK_REPORT.md
```

## Interpretation

The report includes:

- strongest overall
- strongest by mission
- strongest by scenario
- strongest by topology
- most consistent
- highest variance

These are results under the CyberMatch Standard Benchmark conditions. They are not a strongest-product certification.

## v1.0 Positioning

The standard benchmark is the reproducibility baseline for CyberMatch v1.0. Later benchmark suites can add richer topology templates, product sets, and scenario families while preserving this baseline for comparison.
