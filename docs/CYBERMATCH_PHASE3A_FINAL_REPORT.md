# CyberMatch Phase3-A Final Report

## 1. Objective

Phase3-A evaluates whether Decision Neutralization remains effective against adaptive attacker models.

The research question is:

```text
Can Decision Neutralization remain effective against an Adaptive Attacker?
```

Phase3-A keeps defense policies fixed and changes the attacker model across Phase3.1 to Phase3.5. This is an Adaptive Attacker Validation phase, not a new feature expansion phase and not an RL/DQN/PPO attacker implementation.

## 2. Phase3.1 Memory Attacker

The memory attacker updates target behavior from prior success, decoy hits, and detection events.

Results:

- mean static CNS: `0.690`
- mean memory CNS: `0.704`
- CNS delta memory vs static: `+0.014`
- retreat observed: `True`
- max retreat_rate: `1.000`
- best memory policy: `phase3_adaptive_frustration_decoy`
- effectiveness for best memory policy: `0.909`

The memory attacker did not degrade Decision Neutralization. CNS improved slightly relative to the static baseline in this comparison set.

## 3. Phase3.2 Node Preference Attacker

The node preference attacker reinforces node choices using success reward, critical reward, decoy penalty, and detection penalty.

Results:

- mean memory CNS: `0.704`
- mean node-preference CNS: `0.703`
- CNS delta preference vs memory: `-0.001`
- preference retreat_rate mean: `0.750`
- preferred node: no single stable exported node across all policies
- preferred node critical-path concentration: `0.325`
- best preference policy: `phase3_preference_frustration_decoy`

Node preference formed measurable critical-path bias, but it did not cause a material CNS collapse.

## 4. Phase3.3 Path Preference Attacker

The path preference attacker reinforces path sequences rather than only individual nodes.

Results:

- mean node-preference CNS: `0.703`
- mean path-preference CNS: `0.703`
- CNS delta path preference vs node preference: `0.000`
- path retreat_rate mean: `0.750`
- preferred path formed: `True`
- preferred path examples: `0->1->3->4`, `0->1`
- critical path concentration: `0.250`
- path-aware decoy effective: `True`
- best path policy: `phase3_path_frustration_decoy`

Path preference created visible path bias in gated-count and reference scenarios, but Decision Neutralization remained stable.

## 5. Phase3.4 Planning Attacker

The planning attacker uses a lightweight lookahead planner. It scores candidate future paths with:

```text
success_reward + critical_reward - decoy_penalty - detection_penalty
```

Results:

- mean path-preference CNS: `0.703`
- mean planning CNS: `0.690`
- CNS reduction planning vs path preference: `0.014`
- planning retreat_rate mean: `0.750`
- planning score max examples: `6.000` for reference, `1.581` for gated count, `0.674` for frustration decoy
- planned critical path rate: `0.900`
- planning attacker stronger than path learner: `True`
- path-aware decoy effective against planning: `True`
- best planning policy: `phase3_planning_frustration_decoy`

The planning attacker was the strongest attacker in Phase3.1 to Phase3.4 because it concentrated heavily on critical paths. Even so, the mean CNS reduction was small.

## 6. Phase3.5 Trust-Aware Planning Attacker

The trust-aware planning attacker extends planning with attacker trust estimates. Trust decreases after decoys, credential traps, and detection, and can recover after successful actions.

Results:

- mean planning CNS within Phase3.5 set: `0.729`
- mean trust-aware planning CNS: `0.729`
- CNS delta trust-aware vs planning: `0.000`
- trust collapse observed: `True`
- mean trust collapse rate: `0.150`
- trust-aware retreat_rate mean: `0.750`
- planning retreat_rate mean: `0.750`
- trust collapse / retreat correlation: `1.000`
- trust-aware attacker stronger than planning attacker: `False`
- best trust-aware policy: `phase3_trust_frustration_decoy`

Trust collapse was observable. It correlated with retreat in this evaluation set and is therefore a useful monitoring variable for Phase3.6.

## 7. Cross Phase Comparison

Mean values across the Phase3-A validation outputs:

| Attacker | CNS | retreat_rate | effectiveness | critical_compromise_rate |
|---|---:|---:|---:|---:|
| Static | 0.690 | 0.750 | 0.749 | 0.000 |
| Memory | 0.704 | 0.750 | 0.777 | 0.050 |
| Preference | 0.703 | 0.750 | 0.776 | 0.075 |
| Path Preference | 0.703 | 0.750 | 0.776 | 0.075 |
| Planning | 0.690 | 0.750 | 0.749 | 0.150 |
| Trust-Aware Planning | 0.729 | 0.750 | 0.808 | 0.000 |

The Trust-Aware Planning row uses the Phase3.5 comparison set. In that set, static CNS was `0.689`, planning CNS was `0.729`, and trust-aware planning CNS was `0.729`.

## 8. Key Findings

1. Adaptive attacker CNS degradation:
   The largest observed CNS degradation was from path preference to planning: `0.014`. This is a small degradation, not a collapse.

2. Retreat maintenance:
   retreat_rate remained `0.750` for memory, node preference, path preference, planning, and trust-aware planning evaluations.

3. phase2_frustration_decoy status:
   The `phase2_frustration_decoy` lineage remained the strongest Decision Neutralization policy across all Phase3-A attacker models.

4. Planning attacker strength:
   The planning attacker was the strongest Phase3.1 to Phase3.4 attacker because it increased critical path concentration to `0.900`.

5. Trust collapse observation:
   Trust collapse was observed with mean collapse rate `0.150`.

6. Trust collapse and retreat correlation:
   Trust collapse and retreat showed correlation `1.000` in the Phase3.5 comparison set.

## 9. Conclusion

Decision Neutralization did not materially break under:

- Memory
- Preference
- Path Preference
- Planning
- Trust-Aware Planning

The strongest adaptive pressure came from the planning attacker, but CNS decreased only `0.014` versus the path-preference attacker. Trust-aware planning exposed useful trust-collapse telemetry, but did not outperform planning in CNS degradation.

## 10. Phase3.6 Direction

Phase3.6 should extend the attacker model to an Expected Utility Attacker.

The next attacker should choose actions by explicitly estimating expected utility from:

- expected critical asset gain
- expected success probability
- expected decoy or credential-trap penalty
- expected detection penalty
- expected future trust degradation
- expected retreat or re-planning cost

This is the appropriate next step because Phase3-A showed that simple memory, preference, path preference, planning, and trust-aware planning attackers do not break Decision Neutralization.

## Research Questions Summary

Q1: Adaptive attacker CNS degradation rate

- The largest observed CNS degradation was `0.014` CNS points, from path preference (`0.703`) to planning (`0.690`).

Q2: Strongest attacker

- The planning attacker was strongest because it produced the largest CNS reduction and reached planned critical path concentration `0.900`.

Q3: Strongest defense policy

- `phase2_frustration_decoy` remained the strongest Decision Neutralization policy lineage.

Q4: Is trust collapse an effective observation?

- Yes. Trust collapse occurred, had mean collapse rate `0.150`, and correlated with retreat at `1.000` in Phase3.5.

Q5: Is Phase3.6 worth doing?

- Yes. Phase3.6 should test an Expected Utility Attacker because Phase3-A did not materially break Decision Neutralization with simpler adaptive attacker models.
