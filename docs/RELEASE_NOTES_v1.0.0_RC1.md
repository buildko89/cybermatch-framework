# CyberMatch v1.0.0-rc1 Release Notes

CyberMatch is a cyber decision-making simulator for evaluating whether defenses, deception, coalition behavior, product profiles, scenarios, topologies, and benchmarks change attacker mission outcomes.

This release candidate prepares CyberMatch for v1.0 publication. It focuses on reproducible evaluation rather than live product integration or external services.

## Major Capabilities

- Mission-aware attacker evaluation
- Adaptive defender evaluation
- Counter-deception and awareness evaluation
- Coalition, coordination cost, and hunting evaluation
- Product plugin interface and product profile import
- Mission-aware product evaluation
- Streamlit GUI MVP for product evaluation and result interpretation
- Scenario Import foundation
- Scenario Catalog foundation
- Enterprise Topology Library foundation
- Benchmark Suite foundation
- CyberMatch Standard Benchmark Suite
- Refactoring foundation with `cybermatch_core/` compatibility facade

## Phase4 Summary

Phase4 established intelligence-driven active defense, mission-aware defense, belief/state reasoning, virtual topology concepts, critical path intelligence, and campaign-level decision evaluation.

## Phase5 Summary

Phase5 added coalition behavior, coordination cost, counter-deception, attacker awareness, and hunting-oriented evaluation. These capabilities make deception evaluation more realistic under attacker adaptation.

## Phase6 Summary

Phase6 introduced product evaluation:

- Product categories: IDS, IPS, honeypot, deception, XDR
- Product profile JSON import
- Product effectiveness, operational cost, and false-positive scoring
- Mission-aware product x mission evaluation

## Phase7 Summary

Phase7 introduced the Streamlit GUI MVP and improved the Results page so users can interpret mission-aware product evaluation without reading raw CSV files first.

## Phase8 Summary

Phase8 prepared CyberMatch for v1.0 reproducibility:

- JSON scenario import
- Reusable scenario catalog
- Benchmark suite foundation
- Enterprise topology presets
- CyberMatch Standard Benchmark Suite
- Refactoring foundation

## Known Limitations

- CyberMatch does not connect to real security products.
- Product profiles are controlled JSON inputs, not vendor certifications.
- Topology presets are lightweight characteristics, not a network simulator.
- No RL, LLM, or external API runtime dependency is used.
- Human analyst behavior and trust-network layers remain future work.
- Benchmark results should be interpreted as benchmark-condition results, not universal product rankings.

## Roadmap

- Human behavior layer
- Trust network layer
- AI agent evaluation
- Enterprise topology expansion
- Scenario-specific product sets
- Extended benchmark suites and golden artifact checks
