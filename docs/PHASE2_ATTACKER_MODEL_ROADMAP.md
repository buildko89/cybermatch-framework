# CyberMatch Phase2 Attacker Model Roadmap

## Phase2.1 Perceived Utility

Phase2.1 separates actual utility from perceived utility. Actual utility is the objective outcome of the attack, while perceived utility is the attacker's subjective estimate of whether the operation is producing reliable value.

Confidence represents how much the attacker trusts observed success. Decoy hits, credential traps, and detections reduce confidence, which can make perceived utility fall even when actual utility remains positive.

In the `phase2_perceived_credential` evaluation, CyberMatch observed a case where actual utility was positive while perceived utility became negative enough to induce retreat. This established the first form of cognitive neutralization: the attacker may give up because the perceived payoff collapses, not because the real payoff is necessarily absent.

## Phase2.2 Human Frustration Model

Phase2.2 introduces frustration as an explicit attacker state. Frustration accumulates when the attacker hits decoys, triggers credential traps, gets detected, changes paths, or fails to make progress toward critical assets.

This model is useful for human attackers because it captures psychological cost that is not fully represented by utility. CyberMatch observed cases where utility remained positive but frustration exceeded the retreat threshold, causing the attacker to retreat.

The main limitation is that this model should not be applied directly to AI attackers. AI agents do not experience human frustration; they may continue operating as long as expected return remains favorable, even when a human operator would be discouraged.

## Phase2.3 AI Decision Cost Model

For AI attackers, frustration should be reframed as decision cost:

```text
frustration_decoy_hit       -> uncertainty_cost
frustration_path_change     -> replanning_cost
frustration_no_progress     -> search_cost
frustration_detection       -> operational_risk_cost
frustration_credential_trap -> trust_degradation_cost
```

The goal is not to make AI attackers emotional. The goal is to quantify when deception and moving-target defense increase the cost of planning, search, verification, and policy selection enough that another target or no action becomes preferable.

## Human vs AI Neutralization

Human neutralization:

- perceived utility collapse
- frustration accumulation
- retreat

AI neutralization:

- expected utility collapse
- planning cost increase
- search cost increase
- uncertainty increase
- policy gives up because expected return is below alternative target

## Phase2 Next Work

Priority:

1. Add AI decision cost metrics
2. Compare human frustration and AI cost on same scenarios
3. Define Cognitive Neutralization Score
4. Later: RL attacker / POMDP
