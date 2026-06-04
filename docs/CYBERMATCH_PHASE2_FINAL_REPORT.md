# CyberMatch Phase2 Final Report

## 1. Objective

Phase2 extends CyberMatch from asset-protection evaluation to Decision Neutralization. The goal is to quantify whether a defense policy changes the attacker's decision process enough to reduce progress, confidence, utility, and willingness to continue.

Phase1 measured neutralization mainly through critical protection, utility suppression, delay, deception, and retreat. Phase2 keeps those measures, but adds attacker-side cognitive metrics so that CyberMatch can compare defenses against both Human and AI attacker models.

## 2. Phase2.1 Perceived Utility

Phase2.1 separates actual utility from perceived utility.

- actual utility measures the environment's realized reward and compromise value.
- perceived utility measures what the attacker believes the attack is worth.
- confidence measures how strongly the attacker trusts its belief.

Result summary: perceived utility and confidence make deception visible even when direct compromise metrics do not fully explain attacker behavior. Decoy and credential-based scenarios can reduce perceived utility and confidence before they fully change critical compromise outcomes.

## 3. Phase2.2 Human Frustration

The Human Frustration model was introduced to represent decision fatigue and discouragement from repeated traps, path changes, detection, and lack of progress.

The model keeps the existing attacker behavior lightweight. It adds frustration accumulation, decay, and retreat pressure without replacing the attacker class.

Main result: frustration scenarios expose a defense effect that is not captured by critical compromise rate alone. Decoy hits, credential traps, path changes, detection, and no-progress events can increase retreat pressure and reduce attacker persistence.

## 4. Phase2.3 AI Decision Cost

AI Decision Cost separates AI attacker cost from Human Frustration. The two models share source events but use different weights:

- uncertainty_cost from decoy hits
- replanning_cost from path changes
- search_cost from no progress
- operational_risk_cost from detection
- trust_degradation_cost from credential traps

The weighted AI cost emphasizes uncertainty and trust degradation more strongly than human path-change frustration. This reflects the Phase2 hypothesis that an AI attacker tolerates replanning but is more sensitive to unreliable observations and poisoned trust.

Main result: Human frustration and AI decision cost do not have to rank defenses identically. Credential traps and decoys affect both models, but their relative impact changes once AI-specific weights are applied.

## 5. Cognitive Neutralization Score

Cognitive Neutralization Score (CNS) combines Phase2 attacker-side signals into a 0-1 score where higher is better for the defender.

Human score uses:

- perceived_utility_final
- confidence_final
- frustration_final
- retreat

AI score uses:

- ai_weighted_cost
- confidence_final
- perceived_utility_final
- retreat

Combined CNS uses:

- critical_protection_score
- cognitive_human_score
- cognitive_ai_score

CNS is an evaluation metric, not a new defense mechanism. It lets CyberMatch compare whether policies neutralize attacker decision-making, not only whether they block compromise.

## 6. Policy Selection

Phase2.5 and Phase2.6 compare existing scenarios and policies without adding new defensive logic.

Comparison targets include:

- phase2_frustration_decoy
- phase2_frustration_credential
- phase2_ai_balanced
- phase2_ai_high_trust_degradation
- gated_edge_pressure_count_2
- gated_edge_pressure_duration_2
- credential_aware_mtd_window5

Best policy results:

- Phase1 Best: phase2_ai_balanced
- CNS Best: phase2_frustration_decoy
- Effectiveness Best: phase2_frustration_decoy
- CNS Objective Best: phase2_frustration_decoy

The rankings show that Phase1 neutralization and cognitive neutralization are related but not identical.

## 7. Main Findings

- Phase1 Best = phase2_ai_balanced
- CNS Best = phase2_frustration_decoy
- Human Best = phase2_frustration_decoy
- AI Best = phase2_frustration_decoy
- Recommended Policy = phase2_frustration_decoy

The main Phase2 finding is that decision neutralization changes policy ranking. The strongest Phase1 policy is not necessarily the strongest cognitive policy. Under the CNS objective, decoy-driven frustration is the most consistent decision neutralization policy in the current evaluation set.

The Phase2.6 sensitivity sweep found phase2_frustration_decoy as best in 7 of 9 tested human/AI weight settings, with phase2_ai_balanced best in the remaining 2 settings.

## 8. Limitations

- oracle assumptions: several evaluations still rely on model-internal knowledge and simplified scenario definitions.
- simplified attacker: the attacker is rule-based and lightweight.
- no RL attacker: Phase2 does not train an adaptive reinforcement-learning attacker.
- no POMDP: attacker belief and defender response are not modeled as a full partially observable decision process.
- no real network logs: calibration is synthetic and does not use production telemetry or real incident logs.

## 9. Phase3 Direction

Phase3 should focus on model realism and adaptive policy learning. Candidate directions:

- RL attacker
- adaptive policy
- POMDP
- attacker model calibration

No Phase3 implementation is included in this finalization task.
