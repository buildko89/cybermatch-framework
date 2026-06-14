# CyberMatch Strategy Validation

Phase9.8 validates the Phase9.7 Target-Specific Strategy layer.

The goal is not to add new strategies. The goal is to check whether the
Target -> Strategy assignment is useful enough to carry into Phase10 defense
concept evaluation.

## Why Target-Specific Strategy Is Needed

Mission describes the broad attacker objective. Target describes what the
attacker focuses on. Strategy describes the approach used against that target.

Phase9.6 separated Intent, Mission, and Target. Phase9.7 then introduced
target-specific strategy candidates because a single generic strategy label was
not enough to describe target-dependent behavior.

Phase9.8 adds validation around that model:

- whether strategies are internally consistent
- whether strategies are stable across observed rows
- whether target-specific assignment confidence is high
- whether missions are explained by strategy distributions
- whether strategies are distinct or redundant

## Validation Method

The validation layer uses existing analysis rows only.

For each strategy, Phase9.8 builds a lightweight signature from:

- existing feature means
- observed target distribution
- observed mission distribution
- target taxonomy fallback for strategies with no observed rows

Pairwise distances are computed between all strategy signatures. This produces
the `strategy_distance_matrix` used for distinctiveness and redundancy checks.

## Metrics

`strategy_consistency` measures how consistently each strategy maps to a target.

`strategy_stability` measures whether feature patterns stay stable within each
strategy.

`target_strategy_confidence` is the mean confidence from the Phase9.7 strategy
inference layer.

`mission_strategy_consistency` measures whether missions have concentrated,
explainable strategy distributions.

`strategy_distinctiveness` is the mean pairwise distance between strategy
signatures.

`strategy_redundancy` is the share of near-duplicate strategy pairs.

`strategy_explainability` summarizes consistency, confidence,
distinctiveness, target specificity, and mission consistency.

## Interpretation

High distinctiveness and low redundancy indicate that the strategy labels are
not merely aliases.

High target specificity indicates that target-specific assignment is behaving
as designed.

Mission explainability is expected to be lower than target specificity when one
mission can reasonably operate against several targets.

## Scope Limits

Phase9.8 does not change simulation logic, attacker logic, defender logic,
ProfileCore internals, benchmarks, or previous phase outputs. It is an analysis
and quality-assurance layer for the Phase9.7 strategy taxonomy.
