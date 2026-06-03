# Neutralization Evaluation Report

## 1. 無力化の定義
本評価では CyberMatch の最終目標を攻撃の無力化とし、重要資産防護、攻撃者 utility 抑制、欺瞞による浪費誘導、攻撃進行の摩擦、撤退誘導の5軸で 0.0 から 1.0 に正規化して評価する。1.0 に近いほど無力化成功を意味する。

## 2. 各subscoreの意味
- `critical_protection_score`: critical compromise の未発生、または発生遅延を評価する。
- `utility_suppression_score`: final utility と utility が負である時間割合を評価する。
- `deception_waste_score`: decoy attack、credential trigger、MTD event、post-decoy real attack 抑制を評価する。
- `friction_score`: critical 到達遅延、lateral failure、blocked edge、critical path 削減を評価する。
- `retreat_score`: attacker retreat の有無と早さを評価する。

## 3. 現状のbest policy
現状の best policy は `credential_aware_mtd` (`credential_aware_mtd_edge_pressure`) で、neutralization_score は `0.742`。

## 4. 重要資産防護は達成できているか
critical compromise が発生しなかった評価対象は 1/7 件。best policy の critical_protection_score は `1.000`。

## 5. 攻撃者の浪費誘導はできているか
deception_waste_score が最大の policy は `gated_edge_pressure_count_2` で、score は `0.441`。decoy/credential/MTD は浪費誘導の測定対象として機能しているが、post-decoy real attack の残存量も併せて見る必要がある。

## 6. 撤退誘導はまだ弱いか
attacker_retreated が true になった評価対象は 3/7 件。retreat_score は総合スコア中の補助軸であり、現状では重要資産防護や utility 抑制に比べて弱い可能性がある。

## 7. Phase1完了条件
Phase1 は、neutralization_score と5つの subscore が全評価対象で出力され、ランキング、breakdown、CSV/JSON、Markdown レポートが再生成可能になった時点で完了とする。

## 8. Phase2で必要なこと
Phase2 では、複数 seed の neutralization 平均/分散、攻撃者 belief 更新の perceived 化、defender-visible logs ベースの観測、撤退誘導を強化する policy を検討する必要がある。

## Ranking

| rank | label | scenario | neutralization_score | critical | utility | deception | friction | retreat |
|---:|---|---|---:|---:|---:|---:|---:|---:|
| 1 | credential_aware_mtd | credential_aware_mtd_edge_pressure | 0.742 | 1.000 | 1.000 | 0.335 | 0.613 | 0.000 |
| 2 | gated_edge_pressure_duration_2 | gated_edge_pressure_duration_2 | 0.456 | 0.073 | 1.000 | 0.431 | 0.459 | 0.469 |
| 3 | gated_edge_pressure_count_2 | gated_edge_pressure_count_2 | 0.454 | 0.073 | 1.000 | 0.441 | 0.448 | 0.449 |
| 4 | current_best_policy | policy_gated_edge_mtd_edge_pressure | 0.453 | 0.073 | 1.000 | 0.431 | 0.439 | 0.469 |
| 5 | path_aware_decoy | lateral_decoy_on_chokepoint | 0.077 | 0.086 | 0.056 | 0.066 | 0.155 | 0.000 |
| 6 | baseline | lateral_baseline | 0.055 | 0.031 | 0.008 | 0.200 | 0.081 | 0.000 |
| 7 | naive_decoy | lateral_decoy | 0.053 | 0.031 | 0.008 | 0.183 | 0.086 | 0.000 |
