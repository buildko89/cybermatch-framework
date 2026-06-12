# CyberMatch GUI Wireframe

This document provides ASCII wireframes for the Phase7 GUI concept. It is design-only.

## Home

```text
+------------------------------------------------------+
| CyberMatch                                           |
| Decision-aware cyber defense evaluation              |
+------------------------------------------------------+
| [Scenario]  [Products]  [Run]  [Results]  [Docs]     |
+------------------------------------------------------+
| Current focus: Product Evaluation                    |
|                                                      |
| Recent Runs                                          |
| - phase63_mission_products                           |
| - phase62_product_profiles                           |
|                                                      |
| [Start Evaluation]                                   |
+------------------------------------------------------+
```

## Scenario

```text
+------------------------------------------------------+
| Scenario Selection                                   |
+------------------------------------------------------+
| Scenario        [Product Evaluation MVP        v]    |
| Mission Set     [All missions                 v]     |
| Topology        [Default enterprise topology   v]    |
| Phase           [Phase6.3 Mission Products     v]    |
| Output          output/phase63_mission_products/     |
|                                                      |
| [Back]                                      [Next]    |
+------------------------------------------------------+
```

## Products

```text
+------------------------------------------------------+
| Product Profiles                                     |
+------------------------------------------------------+
| [x] Baseline                                         |
| [x] Sample IDS          category: ids                |
| [x] Sample IPS          category: ips                |
| [x] Sample Honeypot     category: honeypot           |
| [x] Sample Deception    category: deception          |
| [x] Sample XDR          category: xdr                |
|                                                      |
| Profile Details                                      |
| detection_boost        0.30                          |
| false_positive_penalty 0.10                          |
| latency_penalty        0.00                          |
|                                                      |
| [Back]                                      [Next]    |
+------------------------------------------------------+
```

## Run

```text
+------------------------------------------------------+
| Run Simulation                                       |
+------------------------------------------------------+
| Scenario: Product Evaluation MVP                     |
| Missions: profit, achievement, persistence, critical |
| Products: baseline + 5 profiles                      |
| Runner: run_phase63_mission_aware_product_evaluation |
|                                                      |
| Progress                                             |
| [###############---------------] 50%                 |
|                                                      |
| Output: output/phase63_mission_products/             |
|                                                      |
| [Cancel]                                   [Run]     |
+------------------------------------------------------+
```

## Results

```text
+------------------------------------------------------+
| Results Dashboard                                    |
+------------------------------------------------------+
| Mission Success | Detection | Diversion | Disruption |
+------------------------------------------------------+
| Product x Mission Heatmap                           |
|                                                      |
|              Profit  Achieve  Persist  Critical     |
| IDS             0.42     0.31     0.28      0.37     |
| IPS             0.35     0.29     0.25      0.33     |
| Honeypot        0.30     0.27     0.34      0.45     |
| Deception       0.32     0.44     0.41      0.30     |
| XDR             0.38     0.33     0.30      0.36     |
|                                                      |
| [Heatmap] [Ranking] [Mission Matrix] [Timeline]      |
|                                                      |
| [Download Markdown Report] [CSV] [JSON] [PNG]        |
+------------------------------------------------------+
```

## Results Components

### Heatmap

Shows Product x Mission effectiveness.

### Ranking

Shows evaluation score with operational cost and false-positive penalty visible.

### Mission Matrix

Shows mission-specific deltas for success, disruption, detection, and diversion.

### Campaign Timeline

Shows campaign step outcomes for selected product profile and mission.
