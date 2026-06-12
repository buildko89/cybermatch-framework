# CyberMatch GUI Screen Definitions

This document defines the minimum screen set for a CyberMatch v1.0 GUI MVP. It is documentation only.

## Home

Purpose:

- Introduce CyberMatch as a decision-oriented cyber evaluation framework.
- Provide entry points to scenario selection, product evaluation, previous results, and documentation.

Primary content:

- CyberMatch summary
- Current evaluation mode
- Recent runs
- Links to documentation
- Start evaluation button

## Scenario Page

Purpose:

- Select the evaluation context before choosing products.

Controls:

- Scenario selection
- Mission selection
- Topology selection
- Evaluation phase selection
- Output directory preview

MVP scope:

- Built-in scenarios only.
- Mission selection from existing missions.
- Topology selection from existing presets or fixed defaults.

Out of scope:

- Scenario import
- Mission editing
- Topology editing

## Product Page

Purpose:

- Select product profiles and comparison targets.

Controls:

- Product profile selection
- Product category filter
- Baseline toggle
- Multi-select comparison list
- Profile detail panel

Profile detail fields:

- Product name
- Category
- Detection boost
- Interruption boost
- Diversion boost
- Confidence boost
- False-positive penalty
- Latency penalty
- Maintenance penalty

## Run Page

Purpose:

- Confirm inputs and execute an existing evaluation runner.

Controls and states:

- Run configuration summary
- Start run button
- Progress indicator
- Log preview
- Output path
- Success state
- Failure state with actionable error

MVP runner focus:

- Product profile evaluation
- Mission-aware product evaluation

## Results Page

Purpose:

- Explain product and mission outcomes from generated artifacts.

Required views:

- Mission results summary
- Product comparison
- Product x Mission heatmap
- Radar chart for selected product profile
- Campaign timeline
- Metric breakdown
- Markdown report download

Interpretation focus:

- Which mission was most affected?
- Which product profile had the strongest mission-specific effect?
- Where did operational cost reduce evaluation score?
- Did results show a single winner or mission-dependent tradeoffs?

## Report Download

Purpose:

- Export reproducible evidence for review and publication.

Supported artifacts:

- Markdown report
- CSV summary
- JSON summary
- PNG charts

The report should include scenario name, profile names, mission set, runner name, metric definitions, and generated timestamp.
