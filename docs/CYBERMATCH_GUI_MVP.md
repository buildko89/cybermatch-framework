# CyberMatch GUI MVP Definition

Phase7.1 defines the GUI MVP scope for CyberMatch v1.0. Implementation is planned for later phases.

## MVP Objective

The MVP should make Phase6 product evaluation usable without requiring the user to inspect raw scripts, CSV files, or output folders first.

The MVP should answer:

```text
Which product profile changes which attacker mission outcome?
```

## In Scope

### Scenario Selection

- Select a built-in product evaluation scenario.
- Select one mission or all MVP missions.
- Show the output destination before execution.

### Product Selection

- Select baseline.
- Select product profiles from `profiles/products/`.
- Compare IDS, IPS, honeypot, deception, and XDR profiles.
- Show profile attributes before running.

### Run

- Execute existing product evaluation runners.
- Show progress and completion status.
- Show generated artifact location.

### Results Display

- Show product comparison.
- Show mission-aware matrix.
- Show key metrics and deltas.
- Provide access to generated Markdown, CSV, JSON, and PNG artifacts.

## MVP Target

The MVP targets **Product Evaluation only**.

Primary runner alignment:

- Phase6.2 Product Profile Evaluation
- Phase6.3 Mission-Aware Product Evaluation

## Out of Scope

### Mission Editing

The MVP should not provide a mission editor. It should only select existing missions.

### Topology Editing

The MVP should not provide topology authoring or graph editing.

### Human Layer

The MVP should not model analyst behavior, fatigue, escalation, or human response workflows.

### Real Product Integration

The MVP should not connect to live products, vendor APIs, external APIs, RL systems, or LLM systems.

## MVP Success Criteria

- A user can select product profiles and missions.
- A user can run an existing evaluation.
- A user can view product x mission differences.
- A user can export or open reproducible reports.
- The GUI does not imply real-world product certification.

## Phase7.2 Implementation Status

Phase7.2 implements the MVP as a Streamlit application:

```bash
streamlit run apps/streamlit_app.py
```

Implemented sections:

- Home
- Scenario
- Products
- Run
- Results

Implemented language support:

- Japanese UI labels
- English UI labels
- Sidebar language selector

Implemented run control:

- Existing runners are launched as subprocesses from the GUI.
- The Run page provides a stop button for an active evaluation process.
- The app shows a lightweight run status and log preview.

Implemented result guidance:

- Results page includes bilingual explanations for the heatmap, mission variance, and Phase6.2 comparison views.
- Results page includes a metric guide for mission effectiveness, deltas, best mission, and worst mission.

Implemented runner integration:

- Primary: `run_phase63_mission_aware_product_evaluation()`
- Optional: `run_phase62_product_profile_evaluation()`

Displayed Phase6.3 artifacts:

- `output/phase63_mission_products/mission_product_summary.csv`
- `output/phase63_mission_products/mission_product_summary.json`
- `output/phase63_mission_products/mission_product_heatmap.png`
- `output/phase63_mission_products/mission_variance.png`
- `output/phase63_mission_products/phase63_vs_phase62.png`
- `output/phase63_mission_products/PHASE63_MISSION_PRODUCT_REPORT.md`

Current limitation:

- Mission and product selections are visible in the MVP UI, but the existing runners still execute their built-in evaluation sets.

## Non-Goals

- Build a complete cyber range.
- Replace ATT&CK replay.
- Build a product marketplace.
- Add new attacker or defender models.
- Add new simulation logic.
