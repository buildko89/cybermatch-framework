# CyberMatch Refactoring Report

Phase8.6 evaluates whether CyberMatch can become easier to maintain without changing behavior.

## Current Analysis

### File Size

| file | lines |
|---|---:|
| `cybermatch.py` | 7111 |
| `run_scenarios.py` | 18909 |

### Largest Definitions

`cybermatch.py`:

| lines | kind | name |
|---:|---|---|
| 4997 | class | `CyberDefenseSimulator` |
| 1230 | function | `calculate_metrics` |
| 1019 | class | `SimulationConfig` |
| 813 | class | `AttackerModel` |
| 544 | function | `validate` |
| 482 | function | `run` |
| 268 | function | `reset` |

`run_scenarios.py`:

| lines | name |
|---:|---|
| 533 | `_build_multiseed_stats_row` |
| 248 | `plot_multiseed_summary` |
| 109 | `run_phase3_trust_attacker_evaluation` |
| 104 | `run_phase4_switch_benefit_evaluation` |
| 101 | `run_phase3_expected_utility_evaluation` |
| 90 | `run_phase3_planning_attacker_evaluation` |
| 89 | `run_phase63_mission_aware_product_evaluation` |
| 88 | `run_phase52_coordination_cost_evaluation` |
| 86 | `run_phase62_product_profile_evaluation` |

## Split Candidates

Low-risk candidates:

- Product profile types and JSON loading.
- Scenario import and validation.
- Topology import and validation.
- Benchmark import and validation.
- Shared numeric/reporting helpers.

Higher-risk candidates for later phases:

- `CyberDefenseSimulator` methods.
- `SimulationConfig.validate`.
- `calculate_metrics`.
- Multi-seed statistics and plotting.
- Phase-specific runner families in `run_scenarios.py`.

## Phase8.6 Extraction

Phase8.6 adds a compatibility package:

```text
cybermatch_core/
  products.py
  scenarios.py
  topologies.py
  benchmarks.py
  metrics.py
  utils.py
```

The package exposes stable imports while preserving the existing top-level modules. No runner behavior or artifact schema changed.

## Compatibility

Existing imports remain valid:

```python
from cybermatch import ProductProfile, load_product_profile
```

New code may use:

```python
from cybermatch_core.products import ProductProfile, load_product_profile
from cybermatch_core.scenarios import load_scenario
from cybermatch_core.topologies import load_topology
from cybermatch_core.benchmarks import load_standard_benchmark
```

## Behavior Check

Phase8.5 standard benchmark values were checked before and after Phase8.6.

Expected unchanged values:

- strongest overall: `sample_deception`
- most consistent: `sample_xdr`
- benchmark scores remain identical for each product profile

## Next Refactoring Steps

Recommended later work:

- Move product profile implementation into `cybermatch_core.products` and re-export from `cybermatch.py`.
- Split scenario, topology, and benchmark loaders into the package directly.
- Extract plotting utilities from `run_scenarios.py`.
- Split Phase6/Phase8 runners into dedicated modules.
- Add golden artifact checks for benchmark summaries.
