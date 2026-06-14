# CyberMatch Phase9 Summary

Phase9 completes the attacker decision model foundation for CyberMatch.

The Phase9 decision model is:

```text
Intent
  -> Mission
  -> Target
  -> Strategy
  -> Behavior
  -> Archetype
```

Phase9 is an analysis and documentation milestone. It does not implement
Phase10 Defense Concept Evaluation, Runtime Delegation, RL, LLMs, external API
calls, or new attacker/defender runtime logic.

## Added Functions

### Mission Inference

Phase9.0 adds rule-based Mission Inference from observed CyberMatch histories
and metrics. It estimates mission labels, confidence, entropy, match rate, and
confusion metrics without relying only on ground-truth mission labels.

### Behavior Profiles

Phase9.1 adds Behavior Profiles as an intermediate layer between observed
events and mission inference. Profiles include utility-seeking,
stealth-seeking, disruption-seeking, critical-path-seeking, adaptive, and
opportunistic behavior.

### Feature Space

Phase9.2 defines and exports the CyberMatch behavior feature space. It measures
feature dominance, entropy, concentration, mission separability, profile
separability, and critical-path bias from existing simulation outputs.

### ProfileCore Integration

Phase9.3 connects CyberMatch behavior features to ProfileCore-oriented
analysis. The integration supports PCA-style feature analysis and archetype
candidate discovery while preserving CyberMatch simulation boundaries.

### Archetypes

Phase9.4 interprets discovered archetype candidates through feature signatures,
mission overlap, behavior profile overlap, centroid distance, stability, and
interpretability scoring.

### Strategy Layer

Phase9.5 introduces Strategy as an interpretation layer between Mission and
Behavior. Strategies describe operational approaches such as credential hunting,
critical asset hunting, persistence building, trust collapse, disruption, and
resource exhaustion.

### Taxonomy

Phase9.6 decomposes attacker labels into Intent, Mission, Target, Strategy,
Behavior, and Events. This makes Target explicit and prepares CyberMatch for
intent-aware analysis.

### Target-Specific Strategy

Phase9.7 adds target-specific strategy candidates for identity infrastructure,
cloud control planes, research systems, backup systems, industrial control
systems, and trust relationships.

### Strategy Validation

Phase9.8 validates target-specific strategy assignments with consistency,
stability, confidence, mission-strategy consistency, distinctiveness,
redundancy, and explainability metrics.

### Decision Graph

Phase9.9 integrates the Phase9 layers into a single Decision Graph. The graph
connects Intent, Mission, Target, Strategy, Behavior, and Archetype nodes,
counts observed transitions, enumerates paths, and reports graph-level metrics.

## Major Results

- Intent -> Mission -> Target -> Strategy is established.
- Target-Specific Strategy is established.
- Decision Graph is established.
- Phase10 Defense Concept Evaluation is ready to begin as a future phase.

## Phase10 Readiness

Phase9 provides the analysis vocabulary needed for Phase10, but does not
implement Phase10. Future Defense Concept Evaluation can map defensive concepts
to decision graph layers after this milestone is released.
