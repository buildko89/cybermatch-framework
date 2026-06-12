# CyberMatch Status

Status snapshot for **CyberMatch v1.0.0-rc1**.

## Completed

- Mission-Aware Attacker
- Adaptive Defender
- Counter-Deception
- Coalition
- Product Profiles
- Product Evaluation
- Scenario Import
- Scenario Catalog
- Topology Library
- Benchmark Suite
- Standard Benchmark
- GUI MVP
- Refactoring Foundation

## Release Candidate Scope

CyberMatch v1.0.0-rc1 is a reproducible research and evaluation framework. It supports controlled scenario, topology, mission, product profile, and benchmark evaluation without live product integrations or external runtime services.

## Reproducibility Baseline

The standard benchmark is:

```text
benchmarks/cybermatch_standard_v1.json
```

Matrix size:

```text
5 scenarios x 5 topologies x 4 missions x 5 products = 500
```

Expected benchmark completeness:

```text
1.0
```

## Future

- Human Layer
- Trust Layer
- AI Agent Evaluation
- Enterprise Topology Expansion

## Non-Goals for v1.0.0-rc1

- Real product integration
- Vendor certification
- External API dependency
- RL runtime
- LLM runtime
- Network simulation engine
