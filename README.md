# CyberMatch Framework

Architecture and stability references: [ARCHITECTURE.md](ARCHITECTURE.md),
[PUBLIC_API.md](PUBLIC_API.md), and [DEPENDENCY_POLICY.md](DEPENDENCY_POLICY.md).

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
- **Auditable threat hunting with external telemetry and model plugins**
- **Agentic security evaluation with containment and threat-intelligence integrity checks**
- **Analysis-guided semantic fuzzing with deterministic replay and external SUT adapters**

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

Install the full local application in a Python 3.12 environment:

```bash
python -m venv .venv
# On Windows
.\.venv\Scripts\Activate.ps1
# On Linux / macOS
source .venv/bin/activate

python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e .
```

The default install (`python -m pip install -e .`) contains only the simulation
core. The `hunting` extra adds optional scikit-learn models, `ui` adds the
Streamlit dashboard, and `dev` adds test/build/lock tooling. Exact runtime
versions are available through `python -m pip install -r requirements.txt`.
See [DEPENDENCY_POLICY.md](DEPENDENCY_POLICY.md) for dependency and lock rules.

Run the curated fast lane to ensure your environment is set up correctly. It
has a 60-second timeout and covers core imports, Agentic Security, Threat
Hunting, and fuzzing contracts:

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
- **Threat Hunting**: Review the 18-case hunting benchmark, tune auditable recipe parameters, inspect evidence timelines, and export H1/H2 artifacts without feeding truth labels back into the detector.
  External CSV/JSONL telemetry can be mapped explicitly, and optional K-Means or Isolation Forest detectors preserve training IDs, feature/preprocessing hashes, seed, threshold, and model provenance.
  Opt-in closed-loop scenarios under `scenarios/threat_hunting/threat_hunt_*.json` compare open/closed feedback on identical seeds and report separate attacker-stealth and decision-neutralization lifts. Run one with `python scripts/run_scenario.py scenarios/threat_hunting/threat_hunt_c2_jitter.json`.
- **Agentic Security**: Replay synthetic autonomous boundary-escape timelines through auditable hunting recipes and next-step containment actions. A separate threat-intelligence integrity gate evaluates advisory provenance, corroboration, code-reference consistency, PoC reproduction, and correction latency without exposing ground-truth labels to the gate.

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

### Agentic Security Evaluation

Run the reproducible trust-boundary, open/closed containment, layered-defense failure, reward-hacking, and threat-intelligence integrity benchmark without connecting an external LLM:

```bash
python scripts/run_scenario.py benchmarks/cybermatch_agentic_security_v1.json
```

See `AGENTIC_SECURITY.md` for the topology, failure-domain, learning, event, action, and metric contracts.

Run the v2 flagship protocol with five paired seeds, six defense modes,
confidence intervals, paired effect sizes, sensitivity analysis, independence
checks, and a hash-verified Evidence Bundle:

```bash
cybermatch-agentic-benchmark --output-dir output/agentic-resilience-v2
```

The scenario hypotheses and falsification criteria are versioned in
`protocols/agentic/flagship_v2.json`. Results are synthetic evidence and must
not be interpreted as product certification.

### Analysis-Guided Fuzzing

CyberMatch uses missions, decision paths, observable `HuntEvent` telemetry, and threat-hunting evaluations to generate reproducible semantic fuzzing cases for detection and correlation logic. It does not generate real exploits or weaponized payloads.

Validate a campaign definition without executing it:

```bash
python scripts/run_fuzzing.py --validate fuzzing/campaigns/threat_hunting_mvp_v1.json
```

Run the 20-case MVP campaign:

```bash
python scripts/run_fuzzing.py fuzzing/campaigns/threat_hunting_mvp_v1.json
```

Run a short smoke campaign with an explicit output directory:

```bash
python scripts/run_fuzzing.py fuzzing/campaigns/threat_hunting_mvp_v1.json --max-cases 3 --output-dir output/fuzzing/mvp_smoke
```

Replay a saved corpus case:

```bash
python scripts/run_fuzzing.py --replay output/fuzzing/<campaign-id>/corpus/<case-id>
```

Inputs are restricted to repository-relative paths, and existing output directories are never overwritten. Only observable events are passed to the system under test (SUT); ground truth remains isolated in the oracle. Each mutant is compared with an unmodified control, so pre-existing false negatives or false positives are not reported as new regressions. Every case records its seed, mutation trace, target and oracle versions, and SHA-256 hashes. Minimized counterexamples and portable replay commands are referenced by a common `evidence_bundle.json`. The framework does not generate raw packets, low-level payloads, or real exploits.

The FZ5 closed-loop/topology campaign sends the same potential event sequence to open-loop and closed-loop targets while mutating feedback delay, topology paths, and defense failure domains:

```bash
python scripts/run_fuzzing.py --validate fuzzing/campaigns/threat_hunting_fz5_closed_loop_v1.json
python scripts/run_fuzzing.py fuzzing/campaigns/threat_hunting_fz5_closed_loop_v1.json
```

Feedback is not applied to the open-loop target. Only the closed-loop target applies future-effective defender actions derived from observed findings. Detection accuracy is evaluated on the open-loop target; forbidden boundary crossings, prevented event count, and post-alert blast radius are evaluated by closed-loop containment oracles. A metamorphic oracle verifies that both modes use matching input hashes, event counts, and mutation profiles.

The FZ6 external SUT adapter uses a versioned field mapping to serialize observable events as JSONL or CSV and normalize external findings into the CyberMatch format. The mock campaign exercises the complete adapter path without network access or external processes:

```bash
python scripts/run_fuzzing.py --validate fuzzing/campaigns/threat_hunting_fz6_external_mock_v1.json
python scripts/run_fuzzing.py fuzzing/campaigns/threat_hunting_fz6_external_mock_v1.json
```

The `command` transport for real processes is disabled by default. Enabling it requires all of the following: `allow_external_execution: true` in the campaign, a repository-local allowlist, an exact allowlisted command ID, an absolute executable path, and `CYBERMATCH_ALLOW_EXTERNAL_SUT=1` at runtime. It never invokes a shell and enforces timeout, rate, response-size, and retry limits. Do not store credentials or production endpoints in an allowlist. External environment failures are classified as `infrastructure_error` or `inconclusive`, not as product detection failures.

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
      agentic/
      attacker/
      config/
      defense/
      evaluation/
      fuzzing/
      models/
      simulation/
      threat_hunting/
      visualization/
  cybermatch_core/     # Stable import facade
  cybermatch.py        # Alias for backwards compatibility
  run_scenarios.py     # Alias for backwards compatibility
  strategy_layer.py    # Alias for backwards compatibility
  scenario_loader.py
  benchmark_loader.py
  benchmarks/
  fuzzing/
    allowlists/
    campaigns/
    corpus/
    mappings/
  topology_loader.py
  topologies/
  scenarios/
  recipes/
    threat_hunting/
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
