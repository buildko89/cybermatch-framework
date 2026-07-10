# CyberMatch Framework

**CyberMatch v1.0.1**

CyberMatch is a cyber decision-making simulator that reproduces attacker decision processes and enables comparative evaluation of defense strategies and security products.

It is designed for research and evaluation questions that are difficult to answer with technique replay alone:

- Did the defense change attacker mission success?
- Did deception alter attacker belief, confidence, trust, or path choice?
- Did coalition coordination cost reduce attacker effectiveness?
- Which product profile is effective against which attacker mission?

[日本語README](README_JP.md)

## What is CyberMatch?

CyberMatch evaluates attacker-defender interaction as a repeatable campaign. It does not only measure whether a detection fired or whether a known technique was replayed. It measures whether the defender changed what the attacker believed, chose, trusted, avoided, or abandoned.

Core capabilities:

- **Defense Neutralization & Decision Neutralization**
- **Adaptive and rational attacker validation**
- **Intelligence-driven active defense**
- **Coalition, counter-deception, awareness, and hunting**
- **Product interface, product profiles, and mission-aware product evaluation**
- **Scenario import, catalog, topology, and standard benchmark foundations**
- **Attacker decision model foundation from intent through decision graph**

## Core Concepts

- **Intent**: high-level attacker purpose such as financial gain, espionage, disruption, or long-term presence.
- **Mission**: attacker objective such as profit, achievement, persistence, or critical asset hunting.
- **Target**: asset or relationship class the attacker focuses on, such as identity infrastructure, cloud control plane, backup system, or trust relationship.
- **Strategy**: target-specific operational approach used to pursue the mission.
- **Belief**: what the attacker or defender thinks is true about assets, paths, state, or mission.
- **State**: inferred campaign context used for policy selection and outcome analysis.
- **Trust**: whether attackers continue to rely on nodes, credentials, paths, or partners.
- **Deception**: decoys, fake assets, fake paths, intent masking, and misleading signals.
- **Coalition**: multiple attackers with handoff, coordination cost, information loss, and trust degradation.
- **Counter-Deception**: defender manipulation of attacker perception rather than passive filtering.
- **Awareness and Hunting**: attackers that recognize and actively search for deception.

## CyberMatch Decision Model

CyberMatch organizes the attacker decision model as:

```text
Intent
  -> Mission
  -> Target
  -> Strategy
  -> Behavior
  -> Archetype
```

This model is analysis-only. It does not add runtime delegation, defense concept execution, RL, LLMs, external APIs, or new attacker/defender logic.

## Product Evaluation

CyberMatch serves as a security product evaluation framework without connecting to real products, external APIs, RL, or LLMs.

Implemented product evaluation layers:

- **Product Plugin Interface**: compares product categories such as IDS, IPS, honeypot, deception, and XDR.
- **Product Profile Import**: loads lightweight JSON product profiles from `profiles/products/`.
- **Mission-Aware Product Evaluation**: evaluates product profile effectiveness by attacker mission.

The goal is not to declare a single strongest product. The goal is to understand which defensive capability changes which attacker decision outcome under which mission.

Sample product profiles:

- `profiles/products/sample_ids.json`
- `profiles/products/sample_ips.json`
- `profiles/products/sample_honeypot.json`
- `profiles/products/sample_deception.json`
- `profiles/products/sample_xdr.json`

Representative output directories:

- `output/phase61_product_interface/`
- `output/phase62_product_profiles/`
- `output/phase63_mission_products/`

`output/` is intentionally ignored by git; regenerate artifacts from the evaluation runners when needed.

## Setup & GUI Dashboard (Quick Start)

CyberMatch consists of a Python-based simulation engine and a visual Streamlit GUI dashboard for comparing results.

### 1. Environment Setup

Install dependencies (Python 3.12 compatible environment recommended):

```bash
python -m venv .venv
# On Windows
.\.venv\Scripts\Activate.ps1
# On Linux / macOS
source .venv/bin/activate

python -m pip install -r requirements.txt
```

Run the smoke test to ensure your environment is set up correctly:

```bash
python scripts/run_tests.py --smoke
```

### 2. How to Start the GUI Dashboard

You can use the built-in Streamlit dashboard to run evaluations and visualize the results.

```bash
streamlit run apps/streamlit_app.py
```

Once running, your terminal will display a URL (usually `http://localhost:8501`). Open this URL in your web browser.

**Using the Dashboard:**
- Use the sidebar to switch between **English** and **Japanese**.
- **Scenario**: View and load evaluation conditions (JSON).
- **Products**: Inspect the defense product profiles to be compared.
- **Run**: Execute the simulations based on your selected scenario and products.
- **Results**: View detailed metrics, mission-aware effectiveness heatmaps, and download generated reports.

## Command-Line Execution (Representative Experiments)

> **Note**: During massive refactorings, core modules were moved into the `src/cybermatch/` directory. However, the root `cybermatch.py`, `run_scenarios.py`, and `strategy_layer.py` modules have been retained as aliases for backwards compatibility. Existing execution commands continue to work without changes.

### Active Defense Evaluation
Evaluate intelligence-driven active defense:
```bash
python scripts/run_phase4.py --quick
```

### Coalition & Counter-Deception Evaluation
Evaluate coalition, counter-deception, awareness, and hunting:
```bash
python scripts/run_tests.py --phase phase5
```

### Mission-Aware Product Evaluation
Evaluate product profile effectiveness by attacker mission from the CLI:
```bash
python scripts/run_scenarios.py
# Or with a specific scenario:
python scripts/run_scenario.py scenarios/mission_product_eval_basic.json
```

### Scenario Catalog & Benchmark Suite
Run cross-evaluations using reproducible JSON benchmarks (Scenario x Mission x Product).

List built-in scenarios:
```bash
python scripts/run_scenario.py --list
```
Run the standard CyberMatch benchmark suite:
```bash
python scripts/run_scenario.py benchmarks/cybermatch_standard_v1.json
```

### Topology Evaluation
Evaluate how different enterprise network topologies impact attacker choices:
```bash
python -c "from run_scenarios import run_phase84_topology_evaluation; run_phase84_topology_evaluation()"
```

## Repository Structure

```text
cybermatch-framework/
  README.md
  README_JP.md
  src/
    cybermatch/
      attacker/
      config/
      defense/
      evaluation/
      models/
      simulation/
      visualization/
  cybermatch.py        # Alias for backwards compatibility
  run_scenarios.py     # Alias for backwards compatibility
  strategy_layer.py    # Alias for backwards compatibility
  scenario_loader.py
  benchmark_loader.py
  benchmarks/
  topology_loader.py
  topologies/
  scenarios/
  profiles/
    products/
  apps/
    streamlit_app.py   # GUI Dashboard App
  scripts/
  tests/
  output/              # generated locally, gitignored
```

## License

This project is licensed under the PolyForm Noncommercial License 1.0.0.

CyberMatch Framework is source-available for research, education, evaluation, and other noncommercial purposes. Commercial use is not permitted without separate permission from the repository owner.

See [LICENSE](LICENSE) for details.
