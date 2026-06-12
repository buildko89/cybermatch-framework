# CyberMatch Benchmarks

Phase8.3 introduces the Benchmark Suite foundation for reproducible product evaluation.

The goal is to move CyberMatch from single-run evaluation toward a repeatable comparison framework across Scenario x Mission x Product dimensions. The benchmark does not certify one strongest product and does not add simulation logic, attackers, defenders, RL, LLMs, external APIs, or real product integration.

## Benchmark Purpose

Benchmarks provide:

- A fixed set of catalog scenarios.
- A fixed mission list.
- A fixed product profile list.
- A reproducible seed list.
- Product-level summary metrics across scenario and mission contexts.

## Benchmark Schema

```json
{
  "metadata": {
    "name": "product_evaluation_benchmark",
    "version": "0.1"
  },
  "scenarios": [
    "scenarios/catalog/financial_enterprise.json",
    "scenarios/catalog/hospital_enterprise.json",
    "scenarios/catalog/cloud_native_startup.json",
    "scenarios/catalog/ot_factory.json",
    "scenarios/catalog/small_business.json"
  ],
  "missions": ["profit", "achievement", "persistence", "critical_hunter"],
  "products": [
    "profiles/products/sample_ids.json",
    "profiles/products/sample_ips.json",
    "profiles/products/sample_honeypot.json",
    "profiles/products/sample_deception.json",
    "profiles/products/sample_xdr.json"
  ],
  "seeds": [0]
}
```

## Product Evaluation Benchmark

The first benchmark is:

```text
benchmarks/product_evaluation_benchmark.json
```

It covers:

- 5 catalog scenarios
- 4 missions
- 5 product profiles
- seed `[0]`

## Run Command

```bash
python scripts/run_scenario.py benchmarks/product_evaluation_benchmark.json
```

The benchmark runner writes:

```text
output/phase83_benchmark_suite/
  benchmark_summary.csv
  benchmark_summary.json
  benchmark_product_ranking.png
  benchmark_scenario_heatmap.png
  benchmark_mission_heatmap.png
  benchmark_consistency.png
  PHASE83_BENCHMARK_SUITE_REPORT.md
```

## Metrics

Phase8.3 adds product-level benchmark metrics:

- `benchmark_name`
- `benchmark_score`
- `benchmark_rank`
- `scenario_coverage`
- `mission_coverage`
- `product_coverage`
- `consistency_score`

The report also provides interpretation helpers:

- strongest overall
- strongest by mission
- strongest by scenario
- most consistent
- highest variance

These are comparison aids, not product certification claims.
