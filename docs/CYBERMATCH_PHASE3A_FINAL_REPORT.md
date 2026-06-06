# CyberMatch Phase3-A Final Report

## 1. Objective

Phase3-A evaluates whether Decision Neutralization remains effective against adaptive attacker models.

Phase1 measured defense neutralization. Phase2 introduced Cognitive Neutralization Score (CNS) and attacker decision cost. Phase3-A keeps the defense policies fixed and varies the attacker model from static targeting through memory, node preference, path preference, and lightweight path planning.

The objective is validation, not reinforcement learning. Phase3-A does not introduce DQN, PPO, or other RL attackers.

## 2. Phase3.1 Adaptive Memory

Phase3.1 adds a memory attacker that updates behavior from observed success, decoy hits, and detection.

Result summary:

- mean static CNS: `0.690`
- mean adaptive memory CNS: `0.704`
- CNS delta adaptive vs static: `+0.014`
- retreat occurred in adaptive evaluations: `True`
- max retreat_rate: `1.000`

The memory attacker did not break Decision Neutralization. The strongest adaptive-memory policy remained the `phase3_adaptive_frustration_decoy` lineage.

## 3. Phase3.2 Node Preference

Phase3.2 adds node-level success reinforcement. The attacker can form a preferred node based on success, critical reward, decoy penalty, and detection penalty.

Result summary:

- mean memory CNS: `0.704`
- mean node-preference CNS: `0.703`
- CNS delta preference vs memory: `-0.001`
- preference retreat_rate mean: `0.750`
- preferred node critical-path concentration: `0.325`

Node preference created visible preference scores, especially in reference and gated-count scenarios, but CNS did not materially collapse.

## 4. Phase3.3 Path Preference

Phase3.3 adds path-level preference. The attacker reinforces path sequences rather than only individual nodes.

Result summary:

- mean node-preference CNS: `0.703`
- mean path-preference CNS: `0.703`
- CNS delta path vs preference: `0.000`
- path retreat_rate mean: `0.750`
- preferred path formed: `True`
- preferred path critical concentration: `0.250`
- path-aware decoy effective against path learner: `True`

Path preference formed critical-path bias in some scenarios, but the evaluated defenses retained their neutralization effect.

## 5. Phase3.4 Path Planning

Phase3.4 adds a lightweight k-step path planning attacker. The planner evaluates future path value using:

```text
success_reward + critical_reward - decoy_penalty - detection_penalty
```

The implementation uses a small lookahead depth and does not train an RL policy.

Result summary:

- mean path-preference CNS: `0.703`
- mean planning CNS: `0.690`
- CNS reduction planning vs path learner: `0.014`
- planning retreat_rate mean: `0.750`
- planning critical path concentration: `0.900`
- planning attacker stronger than path learner: `True`
- path-aware decoy effective against planning attacker: `True`

The planning attacker concentrated much more strongly on critical paths, but did not cause a large CNS collapse.

## 6. Cross Comparison

Mean values across the Phase3.4 comparison set:

| Attacker model | CNS | retreat_rate | effectiveness | critical_compromise_rate |
|---|---:|---:|---:|---:|
| Static | 0.690 | 0.750 | 0.749 | 0.000 |
| Adaptive Memory | 0.704 | 0.750 | 0.777 | 0.000 |
| Adaptive Preference | 0.703 | 0.750 | 0.776 | 0.000 |
| Adaptive Path Preference | 0.703 | 0.750 | 0.776 | 0.000 |
| Adaptive Planning | 0.690 | 0.750 | 0.749 | 0.000 |

Scenario-level Phase3.4 planning rows:

| Scenario | CNS | retreat_rate | effectiveness | planned_path | planned critical rate |
|---|---:|---:|---:|---|---:|
| phase3_planning_ai_balanced | 0.788 | 1.000 | 0.891 | 0->1 | 1.000 |
| phase3_planning_frustration_decoy | 0.829 | 1.000 | 0.909 | 1->3->4 | 1.000 |
| phase3_planning_gated_count2 | 0.628 | 1.000 | 0.745 | 0->1 | 0.800 |
| phase3_planning_reference | 0.514 | 0.000 | 0.452 | 1->3->4 | 0.800 |

## 7. Findings

1. Adaptive attacker impact on CNS:
   The strongest observed reduction was the planning attacker versus path learner: CNS decreased by `0.014`. This is a small reduction, not a collapse.

2. Retreat maintenance:
   retreat_rate was maintained at `0.750` for memory, preference, path preference, and planning comparisons.

3. phase2_frustration_decoy status:
   The `phase2_frustration_decoy` lineage remained strongest across Phase3.1 through Phase3.4.

4. Path-aware decoy against planning:
   Path-aware decoy remained effective against the planning attacker. Phase3.4 reports `path_aware_decoy_effective=True`.

## 8. Conclusion

Decision Neutralization did not materially break under the evaluated adaptive attacker sequence:

```text
Memory -> Node Preference -> Path Preference -> Path Planning
```

The path planning attacker concentrated on critical paths more strongly than earlier attackers, but CNS and retreat behavior remained stable in the evaluated scenarios. CyberMatch therefore preserves the Phase2 Decision Neutralization finding through the Phase3-A adaptive attacker validation set.
