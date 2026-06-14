# CyberMatch ProfileCore Analysis

## Scope

Phase9.3 connects CyberMatch behavior features to ProfileCore for behavior
archetype discovery. The purpose is to inspect the latent structure of attacker
behavior, not to train or evaluate a mission classifier.

This phase does not change simulation logic, add attackers, add defenders, use
RL, use LLMs, or call external APIs.

## Feature Space

The analysis exports the existing CyberMatch behavior feature vector:

- attack_success_rate
- utility_activity
- expected_utility_activity
- deception_activity
- adaptation_activity
- ttp_change_activity
- coalition_activity
- critical_progress
- critical_focus
- critical_probe_activity
- stealth_activity
- trust_collapse_activity
- lateral_movement_activity
- mission_mutation_activity
- campaign_disruption_activity
- survival_activity
- objective_activity
- planned_critical_activity

These features are generated from existing run statistics through
`FeatureSpaceAnalyzer` and are passed to the Phase9.3 PCA bridge.

## PCA Result Interpretation

Phase9.3 writes PCA outputs under `output/phase93_profilecore/`:

- `pca_variance.png`
- `component_loadings.png`
- `feature_projection.png`
- `archetype_distribution.png`
- `profilecore_analysis.json`
- `PHASE93_PROFILECORE_REPORT.md`

`pca_explained_variance` shows how much behavior-feature variance is captured by
each principal component. `dominant_component` reports the strongest component
and its largest absolute loading dimension, such as `PC1:utility_activity`.

Component loadings are exploratory dimensions. A large positive or negative
loading indicates that the feature contributes strongly to that component; it is
not a mission label.

## Archetype Candidates

Rows are grouped in PCA space into deterministic exploratory labels:

- Archetype-1
- Archetype-2
- Archetype-3

The names are intentionally neutral. Phase9.3 does not automatically name
clusters as utility-driven, stealth-driven, critical-driven, deception-driven, or
adaptive-driven. Those interpretations must be made after inspecting component
loadings and projections.

The reported metrics are:

- `archetype_count`
- `archetype_distribution`
- `archetype_concentration`
- `archetype_entropy`

High concentration means one archetype dominates the projected rows. High
entropy means rows are more evenly spread across archetype candidates.

## Difference From Mission Analysis

Mission analysis asks whether a run aligns with a known mission such as profit,
achievement, persistence, or critical_hunter.

ProfileCore Phase9.3 asks a different question: whether the attacker behavior
feature space contains latent structure independent of those mission names. A
mission may correlate with an archetype, but the archetype is not trained as a
mission classifier and should not be interpreted as a predicted mission.

This distinction is the core Phase9.3 boundary: CyberMatch moves from
behavior-aware reporting toward behavior-understanding analysis.
