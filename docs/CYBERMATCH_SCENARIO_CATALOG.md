# CyberMatch Scenario Catalog

Phase8.2 adds the Scenario Catalog foundation on top of Scenario Import.

The catalog lets users choose reusable scenario presets such as finance, hospital, cloud-native startup, factory, and small business contexts. Phase8.2 does not model detailed enterprise topology. It defines lightweight scenario characteristics that can be used to interpret existing Product Evaluation and Mission-Aware Product Evaluation results.

## Catalog Overview

Catalog scenarios live under:

```text
scenarios/catalog/
```

Current presets:

- `financial_enterprise.json`
- `hospital_enterprise.json`
- `cloud_native_startup.json`
- `ot_factory.json`
- `small_business.json`

## Scenario Characteristics

Each catalog scenario includes:

```json
{
  "characteristics": {
    "critical_asset_count": 3,
    "identity_dependency": "high",
    "operational_sensitivity": "high",
    "deception_effectiveness": "medium"
  }
}
```

Allowed values:

- `critical_asset_count`: integer from 1 to 5
- `identity_dependency`: `low`, `medium`, `high`
- `operational_sensitivity`: `low`, `medium`, `high`
- `deception_effectiveness`: `low`, `medium`, `high`

## Industry Assumptions

| scenario | industry | assumption |
|---|---|---|
| `financial_enterprise` | finance | high identity dependency, high operational sensitivity, many critical assets |
| `hospital_enterprise` | healthcare | high operational sensitivity, medium identity dependency |
| `cloud_native_startup` | technology | high identity dependency, high deception effectiveness, fewer critical assets |
| `ot_factory` | manufacturing | high operational sensitivity, many critical assets, lower deception effectiveness |
| `small_business` | small_business | fewer critical assets and lower operational complexity |

## Scenario Catalog Evaluation

Phase8.2 adds:

```python
run_phase82_scenario_catalog_evaluation()
```

The runner writes:

```text
output/phase82_scenario_catalog/
  scenario_catalog_summary.csv
  scenario_catalog_summary.json
  scenario_comparison_heatmap.png
  scenario_mission_matrix.png
  scenario_product_matrix.png
  PHASE82_SCENARIO_CATALOG_REPORT.md
```

The Phase8.2 runner uses catalog characteristics as a lightweight interpretation layer over existing Phase6.3 mission-aware product results. It does not add simulation logic, attackers, defenders, RL, LLMs, external APIs, or real product integration.

## CLI

List available catalog scenarios:

```bash
python scripts/run_scenario.py --list
```

Run one catalog scenario through the existing scenario import path:

```bash
python scripts/run_scenario.py scenarios/catalog/financial_enterprise.json
```

## Relationship to Future Topology

Phase8.2 focuses on reusable scenario presets, not detailed topology editing.

Future phases can connect these presets to:

- Enterprise topology templates
- Product sets
- Benchmark suites
- Scenario-specific product selection
- GUI scenario execution
