# CyberMatch Phase3-B Final Report

## Objective

Phase3-B introduces the Expected Utility Attacker and evaluates whether Decision Neutralization remains effective against a rational attacker.

Phase3-A validated adaptive behavior through memory, preference, path preference, planning, and trust-aware planning. Phase3-B adds a rational scoring layer that selects the action with the highest estimated return.

## Attacker Model

The Expected Utility Attacker estimates action value from:

- expected gain
- expected success probability
- trust
- detection risk
- search cost

The model does not introduce RL, PPO, or DQN. It uses a lightweight expected utility estimate and combines it with the existing planning score.

Simplified scoring:

```text
expected_utility =
    expected_gain_weight
    * expected_gain
    * expected_success_probability
    * trust
  - expected_detection_cost * detection_risk
  - expected_search_cost * search_cost
```

## Results

Mean Phase3-B comparison:

| Attacker | CNS | retreat_rate | critical_compromise_rate | target_switch_count |
|---|---:|---:|---:|---:|
| Trust-Aware Planning | 0.729 | 0.750 | 0.000 | 0.000 |
| Expected Utility | 0.691 | 0.750 | 0.250 | 8.500 |

Expected Utility reduced CNS by `0.038` compared with Trust-Aware Planning.

## Research Questions

1. CNS reduction:
   Expected Utility reduced CNS by `0.038` versus Trust-Aware Planning (`0.729` to `0.691`).

2. retreat maintenance:
   retreat_rate was maintained at `0.750`.

3. phase2_frustration_decoy status:
   The `phase2_frustration_decoy` lineage remained strongest. The best Phase3-B policy was `phase3_expected_frustration_decoy`.

4. target switch:
   target_switch occurred. Mean target_switch_count was `8.500`.

5. trust collapse:
   trust collapse remained observable. Mean trust_collapse_rate was `0.150`.

6. strongest attacker:
   Expected Utility is the strongest attacker model evaluated so far because it produced the largest CNS reduction in the Phase3 validation sequence.

7. critical asset movement:
   The attacker did not fully move away from critical assets. Expected Utility critical_compromise_rate was `0.250`, and planned critical path rate was `0.750`.

## Findings

Expected Utility attacker was the strongest Phase3 attacker.

It reduced CNS more than Trust-Aware Planning and produced target switching behavior. However, Decision Neutralization still held: retreat behavior remained stable, the strongest defense policy remained the frustration-decoy lineage, and trust collapse stayed observable as a useful signal.

## Conclusion

Phase3-B completes rational attacker validation for the current CyberMatch decision-neutralization sequence.

Decision Neutralization remains effective against the Expected Utility Attacker. The project is ready to move to Phase4 Adaptive Defense.
