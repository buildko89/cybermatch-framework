# CyberMatch Enterprise Topology Library

Phase8.4 adds a lightweight Enterprise Topology Library foundation.

The goal is to let CyberMatch treat enterprise structure differences as an evaluation axis. This is not a network simulator and does not add simulation logic, attackers, defenders, RL, LLMs, external APIs, or real product integration.

## Topology Library Overview

Topology presets live under:

```text
topologies/
```

Current presets:

- `small_business.json`
- `enterprise.json`
- `cloud_native.json`
- `ot_environment.json`
- `hospital_network.json`

## Topology Schema

```json
{
  "metadata": {
    "name": "enterprise",
    "description": "Generic enterprise network"
  },
  "characteristics": {
    "critical_assets": 5,
    "identity_centralization": "high",
    "lateral_movement_complexity": "medium",
    "deception_surface": "medium",
    "operational_sensitivity": "medium"
  }
}
```

Allowed values:

- `critical_assets`: integer from 1 to 10
- `identity_centralization`: `low`, `medium`, `high`
- `lateral_movement_complexity`: `low`, `medium`, `high`
- `deception_surface`: `low`, `medium`, `high`
- `operational_sensitivity`: `low`, `medium`, `high`

## Topology Presets

| topology | description |
|---|---|
| `small_business` | limited critical assets and low identity centralization |
| `enterprise` | centralized identity and mixed lateral movement paths |
| `cloud_native` | centralized identity, elastic assets, broad deception surface |
| `ot_environment` | high critical asset concentration and high operational sensitivity |
| `hospital_network` | sensitive operations, centralized identity, moderate deception surface |

## Scenario Relationship

Scenario JSON can reference a topology preset:

```json
{
  "topology": {
    "preset": "enterprise"
  }
}
```

`default_enterprise` remains supported as a compatibility alias for `enterprise`.

## Topology Evaluation

Phase8.4 adds:

```python
run_phase84_topology_evaluation()
```

The runner writes:

```text
output/phase84_topology_library/
  topology_summary.csv
  topology_summary.json
  topology_comparison_heatmap.png
  topology_mission_matrix.png
  topology_product_matrix.png
  PHASE84_TOPOLOGY_LIBRARY_REPORT.md
```

The runner uses topology characteristics as a lightweight interpretation layer over existing Phase6.3 mission-aware product results.

## Future Enterprise Network Expansion

Later phases can connect these presets to:

- Enterprise topology templates
- Asset and subnet libraries
- Identity and trust graph layers
- Scenario-specific product sets
- Benchmark suites that vary topology and industry independently
