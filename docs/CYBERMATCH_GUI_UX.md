# CyberMatch GUI UX Flow

This document defines the Phase7.1 MVP user flow. It is design-only and does not implement the GUI.

## MVP UX

```text
Step 1: Scenario Selection
        |
        v
Step 2: Attacker Selection
        |
        v
Step 3: Product Selection
        |
        v
Step 4: Run Simulation
        |
        v
Step 5: Results Dashboard
```

## Step 1: Scenario Selection

The user selects a scenario preset or a built-in evaluation track.

Minimum fields:

- Scenario name
- Evaluation phase
- Mission set
- Topology preset
- Output directory preview

Phase7.1 MVP should expose product evaluation scenarios first. Scenario import is future work.

## Step 2: Attacker Selection

The user selects attacker mission focus rather than creating new attacker logic.

Minimum fields:

- Mission: profit, achievement, persistence, critical hunter
- Attacker model family: existing CyberMatch model only
- Mission comparison mode: single mission or all missions

No new attacker should be created as part of this GUI phase.

## Step 3: Product Selection

The user selects product profiles for comparison.

Minimum fields:

- Baseline
- IDS profile
- IPS profile
- Honeypot profile
- Deception profile
- XDR profile
- Optional multi-select comparison set

Profile details should show category, effectiveness parameters, false-positive penalty, latency penalty, and maintenance penalty.

## Step 4: Run Simulation

The user runs the selected evaluation using existing CyberMatch runners.

Minimum display:

- Selected scenario
- Selected missions
- Selected product profiles
- Runner name
- Progress indicator
- Output artifact location

The run page should not expose low-level implementation details unless the user opens an advanced panel.

## Step 5: Results Dashboard

The user inspects results through mission-aware views.

Required views:

- Summary cards
- Product ranking table
- Product x Mission heatmap
- Mission matrix
- Metric breakdown
- Campaign timeline
- Markdown report download

The dashboard should emphasize interpretation: which product profile changed which mission outcome and why.

## UX Guardrails

- Do not imply that CyberMatch certifies real products.
- Do not rank products without showing mission-specific context.
- Do not hide operational cost and false-positive penalties.
- Do not present generated outputs as live SOC telemetry.
- Keep all results tied to reproducible scenario and profile inputs.
