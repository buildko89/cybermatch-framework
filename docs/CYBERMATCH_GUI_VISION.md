# CyberMatch GUI Vision

Phase7.1 defines the GUI direction for CyberMatch v1.0. This document is requirements and UX design only. It does not change simulation logic, attacker models, defender models, or evaluation behavior.

## Target Users

### SOC Analyst

SOC analysts need a fast way to compare whether a defense changes attacker mission success, detection exposure, campaign disruption, and deception outcomes.

Primary needs:

- Understand attacker decision pressure.
- Compare defensive strategies without reading raw CSV files.
- Explain why one result differs from another.

### CSIRT

CSIRT users need to evaluate response and containment options during campaign-level analysis.

Primary needs:

- Compare scenarios after incident reconstruction.
- Understand how attacker progress changes under different defensive assumptions.
- Export reproducible reports for internal communication.

### Security Product Vendor

Security product vendors need a neutral evaluation surface for product categories and product profiles.

Primary needs:

- Show where a product profile changes mission outcomes.
- Compare product behavior by mission rather than ranking a single universal winner.
- Separate product effectiveness from operational cost and false-positive penalty.

### Researcher

Researchers need reproducible experiment control and access to intermediate metrics.

Primary needs:

- Compare missions, beliefs, states, deception, coalition behavior, and product profiles.
- Reproduce outputs from fixed inputs.
- Export CSV, JSON, chart, and Markdown artifacts.

### Purple Team

Purple teams need to connect attacker behavior, defender action, and product evaluation into an exercise workflow.

Primary needs:

- Compare attacker missions and defensive assumptions.
- Present outcomes to both offensive and defensive stakeholders.
- Use heatmaps, timelines, and reports to guide discussion.

## User Goals

- Understand attacker decision-making.
- Compare defense strategies.
- Evaluate product categories and product profiles.
- Compare scenarios and mission outcomes.
- Produce reproducible evidence for discussion and publication.

## Design Principles

### Simple

The GUI should expose a small number of clear steps: select scenario, select attacker mission, select product profiles, run, inspect results.

### Explainable

Every chart should connect back to named metrics such as mission success, detection, diversion, disruption, and evaluation score.

### Reproducible

The GUI should make the selected scenario, product profiles, mission set, runner, and output directory visible.

### Mission-Aware

Results should be organized by attacker mission. Product evaluation should answer "effective against which mission?" before "best overall?"

### Product-Centric

Phase7.1 MVP should prioritize product evaluation workflows because Phase6.1-Phase6.3 established product categories, product profiles, and mission-aware product matrices.

## Future Vision

```text
v1.0 GUI
  -> Scenario Import
  -> Enterprise Topology
  -> Product Marketplace
  -> AI Agent Evaluation
```

AI Agent Evaluation is a future research direction only. It is not part of the Phase7.1 MVP and should not introduce LLM or RL dependencies into the current GUI design.
