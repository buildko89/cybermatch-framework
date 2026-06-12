# CyberMatch Scenario Import

Phase8.1 introduces the minimal Scenario Import foundation for CyberMatch v1.0.

The goal is to move the first product evaluation workflow from direct Python edits toward reusable JSON scenario files. Phase8.1 does not externalize all simulation settings and does not add simulation logic, attackers, defenders, RL, LLMs, external APIs, or real product integration.

## Purpose

Scenario Import provides a small, reproducible entry point for:

- Product Evaluation scenarios.
- Mission-Aware Product Evaluation scenarios.
- Built-in default enterprise topology selection.
- Existing product profiles under `profiles/products/`.
- Existing attacker missions: `profit`, `achievement`, `persistence`, and `critical_hunter`.

## Minimal Schema

```json
{
  "metadata": {
    "name": "mission_product_eval_basic",
    "description": "Mission-aware product evaluation using sample product profiles",
    "version": "0.1"
  },
  "evaluation": {
    "runner": "phase63_mission_aware_product",
    "output_dir": "output/phase63_mission_products",
    "seeds": [0]
  },
  "missions": ["profit", "achievement", "persistence", "critical_hunter"],
  "products": [
    "profiles/products/sample_ids.json",
    "profiles/products/sample_ips.json",
    "profiles/products/sample_honeypot.json",
    "profiles/products/sample_deception.json",
    "profiles/products/sample_xdr.json"
  ],
  "topology": {
    "preset": "default_enterprise"
  }
}
```

## Validation Rules

Required fields:

- `metadata.name`
- `evaluation.runner`
- `missions`
- `products`

Allowed runners:

- `phase62_product_profile`
- `phase63_mission_aware_product`

Allowed missions:

- `profit`
- `achievement`
- `persistence`
- `critical_hunter`

Product paths must exist and must be loadable JSON files.

Optional `evaluation.seeds` may be provided as a list of integers. The sample scenarios use `[0]` so command-line smoke runs remain lightweight. Omitting `seeds` preserves the existing runner default.

Allowed topology preset:

- `default_enterprise`

## Sample Scenarios

The repository includes:

- `scenarios/product_eval_basic.json`
- `scenarios/mission_product_eval_basic.json`

## Run Command

```bash
python scripts/run_scenario.py scenarios/mission_product_eval_basic.json
```

The script prints the scenario name, runner, output directory, row count, and success or failure status.

## v1.0 Positioning

Phase8.1 is the first step toward a reusable scenario catalog. It keeps the existing Phase6 runners intact and only dispatches to them after validating a JSON scenario.

In Phase8.1, `products` are validated but the existing runners still use their current built-in product profile set. This preserves the existing runner behavior while creating a stable import boundary.

## Future Extensions

Planned directions for later phases:

- Enterprise topology import and reusable topology presets.
- Product sets and scenario-specific product selection.
- Benchmark suites composed from multiple scenario files.
- GUI scenario execution integration.
- Scenario catalog metadata and reproducibility reports.
