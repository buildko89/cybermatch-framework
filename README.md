# CyberMatch Framework

**CyberMatch v1.0.0-rc1**

CyberMatch is a cyber decision-making simulator that reproduces attacker decision processes and enables comparative evaluation of defense strategies and security products.

It is designed for research and evaluation questions that are difficult to answer with technique replay alone:

- Did the defense change attacker mission success?
- Did deception alter attacker belief, confidence, trust, or path choice?
- Did coalition coordination cost reduce attacker effectiveness?
- Which product profile is effective against which attacker mission?

[日本語README](README_JP.md)

## What is CyberMatch?

CyberMatch evaluates attacker-defender interaction as a repeatable campaign. It does not only measure whether a detection fired or whether a known technique was replayed. It measures whether the defender changed what the attacker believed, chose, trusted, avoided, or abandoned.

Current scope reaches Phase6.3:

- Phase1: Defense Neutralization
- Phase2: Decision Neutralization
- Phase3: Adaptive and rational attacker validation
- Phase4: Intelligence-driven active defense
- Phase5: Coalition, counter-deception, awareness, and hunting
- Phase6: Product interface, product profiles, and mission-aware product evaluation

## Core Concepts

- **Mission**: attacker objective such as profit, achievement, persistence, or critical asset hunting.
- **Belief**: what the attacker or defender thinks is true about assets, paths, state, or mission.
- **State**: inferred campaign context used for policy selection and outcome analysis.
- **Trust**: whether attackers continue to rely on nodes, credentials, paths, or partners.
- **Deception**: decoys, fake assets, fake paths, intent masking, and misleading signals.
- **Coalition**: multiple attackers with handoff, coordination cost, information loss, and trust degradation.
- **Counter-Deception**: defender manipulation of attacker perception rather than passive filtering.
- **Awareness and Hunting**: attackers that recognize and actively search for deception.

## Product Evaluation

Phase6 turns CyberMatch toward a security product evaluation framework without connecting to real products, external APIs, RL, or LLMs.

Implemented product evaluation layers:

- **Phase6.1 Product Plugin Interface**: compares product categories such as IDS, IPS, honeypot, deception, and XDR.
- **Phase6.2 Product Profile Import**: loads lightweight JSON product profiles from `profiles/products/`.
- **Phase6.3 Mission-Aware Product Evaluation**: evaluates product profile effectiveness by attacker mission.

The goal is not to declare a single strongest product. The goal is to understand which defensive capability changes which attacker decision outcome under which mission.

Sample product profiles:

- `profiles/products/sample_ids.json`
- `profiles/products/sample_ips.json`
- `profiles/products/sample_honeypot.json`
- `profiles/products/sample_deception.json`
- `profiles/products/sample_xdr.json`

Representative Phase6 output directories:

- `output/phase61_product_interface/`
- `output/phase62_product_profiles/`
- `output/phase63_mission_products/`

`output/` is intentionally ignored by git; regenerate artifacts from the evaluation runners when needed.

## Documentation

Start here:

- [Documentation Index](docs/INDEX.md)
- [CyberMatch Vision](docs/CYBERMATCH_VISION.md)
- [CyberMatch Architecture](docs/CYBERMATCH_ARCHITECTURE.md)
- [CyberMatch Status](docs/CYBERMATCH_STATUS.md)
- [CyberMatch End-State Definition](docs/CYBERMATCH_END_STATE.md)
- [CyberMatch Use Cases](docs/CYBERMATCH_USE_CASES.md)
- [CyberMatch Roadmap](docs/CYBERMATCH_ROADMAP.md)
- [CyberMatch GUI Vision](docs/CYBERMATCH_GUI_VISION.md)
- [CyberMatch GUI UX](docs/CYBERMATCH_GUI_UX.md)
- [CyberMatch GUI MVP](docs/CYBERMATCH_GUI_MVP.md)
- [CyberMatch Scenario Import](docs/CYBERMATCH_SCENARIO_IMPORT.md)
- [CyberMatch Scenario Catalog](docs/CYBERMATCH_SCENARIO_CATALOG.md)
- [CyberMatch Benchmarks](docs/CYBERMATCH_BENCHMARKS.md)
- [CyberMatch Standard Benchmark](docs/CYBERMATCH_STANDARD_BENCHMARK.md)
- [CyberMatch Topologies](docs/CYBERMATCH_TOPOLOGIES.md)
- [CyberMatch v1.0.0-rc1 Release Notes](docs/RELEASE_NOTES_v1.0.0_RC1.md)
- [Reproducibility](docs/REPRODUCIBILITY.md)

Additional planning and release notes:

- [CyberMatch Evaluation Matrix](docs/CYBERMATCH_EVALUATION_MATRIX.md)
- [CyberMatch Gap Analysis](docs/CYBERMATCH_GAP_ANALYSIS.md)
- [GitHub Release Plan](docs/GITHUB_RELEASE_PLAN.md)
- [GitHub Release Notes](docs/GITHUB_RELEASE_NOTES.md)

## Quick Start

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the smoke test profile:

```bash
python scripts/run_tests.py --smoke
```

Run the Phase5 regression profile used by the recent Phase6 work:

```bash
python scripts/run_tests.py --phase phase5
```

Compile-check the main simulation modules:

```bash
python -m compileall cybermatch.py run_scenarios.py
```

Run all publication evaluations:

```bash
python scripts/run_all.py
```

Launch the Streamlit GUI MVP:

```bash
streamlit run apps/streamlit_app.py
```

The MVP dashboard supports Japanese and English from the sidebar language selector.

## Representative Experiments

Phase4 publication milestones:

```bash
python scripts/run_phase4.py --quick
```

Phase4 full publication workflow:

```bash
python scripts/run_phase4.py --publication
```

Legacy full scenario workflow:

```bash
python run_scenarios.py
```

Phase6 evaluation runners are exposed from the simulation framework:

- `run_phase61_product_interface_evaluation()`
- `run_phase62_product_profile_evaluation()`
- `run_phase63_mission_aware_product_evaluation()`

Phase7.2 adds a lightweight Streamlit dashboard for Product Evaluation:

```bash
streamlit run apps/streamlit_app.py
```

The dashboard UI can be switched between Japanese and English.

Phase7.3 adds an interpretation-focused dashboard for mission-aware product evaluation. The Results page now summarizes best products by mission, mission coverage gaps, mission variance, product detail metrics, existing heatmap artifacts, and CSV/JSON/Markdown downloads without changing simulation logic.

Phase8.1 adds the Scenario Import foundation for JSON-defined product evaluation scenarios:

```bash
python scripts/run_scenario.py scenarios/mission_product_eval_basic.json
```

Phase8.2 adds a reusable Scenario Catalog for finance, healthcare, cloud-native startup, factory, and small business presets:

```bash
python scripts/run_scenario.py --list
```

Phase8.3 adds a reproducible Benchmark Suite across Scenario x Mission x Product:

```bash
python scripts/run_scenario.py benchmarks/product_evaluation_benchmark.json
```

Phase8.4 adds a lightweight Enterprise Topology Library for evaluating topology preset differences:

```bash
python -c "from run_scenarios import run_phase84_topology_evaluation; run_phase84_topology_evaluation()"
```

Phase8.5 defines the CyberMatch Standard Benchmark Suite for reproducible v1.0 comparison:

```bash
python scripts/run_scenario.py benchmarks/cybermatch_standard_v1.json
```

## Repository Structure

```text
cybermatch-framework/
  README.md
  README_JP.md
  cybermatch.py
  run_scenarios.py
  scenario_loader.py
  benchmark_loader.py
  benchmarks/
  topology_loader.py
  topologies/
  scenarios/
  profiles/
    products/
  scripts/
  tests/
  docs/
    INDEX.md
    CYBERMATCH_ARCHITECTURE.md
    CYBERMATCH_STATUS.md
    phase1/
    phase2/
  output/              # generated locally, gitignored
```

## License

This project is licensed under the PolyForm Noncommercial License 1.0.0.

CyberMatch Framework is source-available for research, education, evaluation, and other noncommercial purposes. Commercial use is not permitted without separate permission from the repository owner.

See [LICENSE](LICENSE) for details.
