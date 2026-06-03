# CyberMatch Phase1 Final Report

作成日: 2026-06-03  
参照データ:

- `output/neutralization/neutralization_summary.csv`
- `output/neutralization/NEUTRALIZATION_REPORT.md`
- `output/scenarios/summary.csv`
- `output/scenarios_multiseed/summary_stats.csv`
- `output/scenarios_multiseed/best_policy.json`

---

## 1. Executive Summary

CyberMatch は、サイバー防御を単なる「検知率」や「攻撃成功率」ではなく、攻撃者の意思決定、攻撃進行、utility、欺瞞への反応、撤退まで含めて評価するためのシミュレーション研究基盤である。

Phase1 の中心目的は、攻撃者を単に検知することではなく、攻撃者の期待利得を下げ、重要資産への到達を遅延または阻止し、デコイ・MTD・credential honeypot によって攻撃行動を浪費させる「攻撃の無力化」を定量評価できる状態にすることだった。

Phase1 では、MPC defender、matching-based defense、attacker utility、belief learning、decoy、post-decoy aware defense、Bayesian estimation、lateral movement、critical path analysis、edge-level MTD、credential-aware MTD までを統合し、最終的に `neutralization_score` と5つの subscore による評価基盤を実装した。

現在の targeted neutralization evaluation では、Best Policy は `credential_aware_mtd` (`credential_aware_mtd_edge_pressure`) である。Neutralization Score は `0.742` で、critical protection と utility suppression は `1.000` に到達した。一方で retreat score は `0.000` であり、撤退誘導は Phase2 の主要課題として残っている。

既存の multi-seed policy selection では、`best_policy.json` 上の Best Policy は `gated_edge_pressure_count_2` であり、`defense_objective_score_mean = 506.990`、`critical_compromise_rate = 0.500`、`post_decoy_compromised_mean = 153.990` だった。これは従来の defense objective に基づく最良であり、neutralization score に基づく最良とは評価軸が異なる。

---

## 2. Problem Statement

従来の防御評価は、主に以下のような局所指標に寄りがちだった。

- 検知率
- 攻撃成功率
- 防御リソース消費
- 最終リスク量

これらは重要だが、攻撃者が防御に反応して行動を変える問題を十分に表現できない。例えば、検知率が高くても攻撃者が重要資産に到達していれば防御は失敗に近い。逆に、検知できなくても攻撃者がデコイや低価値経路に誘導され、utility が負になり、critical asset が守られていれば、防御目的はかなり達成されている。

CyberMatch が扱う問題は、攻撃者を状態遷移の外乱として扱うだけではなく、限定合理的な意思決定主体として扱い、その主体をどう変調・遅延・浪費・撤退させるかを評価することである。

CyberMatch の評価対象は以下である。

- 攻撃者がどのノードを狙うか
- 攻撃者 belief がどのように変化するか
- デコイが攻撃者の行動を変えるか
- MTD が critical path 到達を遅らせるか
- credential honeypot が攻撃者を誘導できるか
- 攻撃者 utility を負に抑えられるか
- 最終的に攻撃者を撤退に追い込めるか

Phase1 の結論として、CyberMatch は「防御が効いたか」を単一イベントではなく、攻撃者行動全体の変化として測る基盤を構築できた。

---

## 3. Definition of Neutralization

Phase1 の最終定義では、攻撃の無力化を以下の5軸で評価する。

| Axis | Metric | Meaning |
|---|---|---|
| Critical Asset Protection | `critical_protection_score` | critical compromise を防ぐ、または遅らせる |
| Attacker Utility Suppression | `utility_suppression_score` | attacker utility を低く、できれば負に保つ |
| Deception / Waste Induction | `deception_waste_score` | decoy、credential、MTD により攻撃を浪費させる |
| Attack Progress Friction | `friction_score` | lateral movement や critical path 到達を遅らせる |
| Retreat Induction | `retreat_score` | attacker retreat を誘導する |

### Overall Score

現在の総合スコアは以下で定義している。

```text
neutralization_score =
    0.35 * critical_protection_score
  + 0.25 * utility_suppression_score
  + 0.15 * deception_waste_score
  + 0.15 * friction_score
  + 0.10 * retreat_score
```

重みは、Phase1 では critical asset protection と utility suppression を最重要視している。

| Subscore | Weight |
|---|---:|
| `critical_protection_score` | 0.35 |
| `utility_suppression_score` | 0.25 |
| `deception_waste_score` | 0.15 |
| `friction_score` | 0.15 |
| `retreat_score` | 0.10 |

### Subscore Formulas

実装上の概略式は以下である。すべて `0.0` から `1.0` に正規化される。

```text
critical_protection_score =
    1.0                                  if critical_compromise == False
    clip(0.3 * critical_compromise_step / (T - 1), 0, 1)
                                          otherwise
```

```text
utility_suppression_score =
    0.6 * final_utility_score
  + 0.4 * negative_utility_rate

final_utility_score =
    1.0                                  if attacker_utility_final <= 0
    clip(1 - attacker_utility_final / utility_scale, 0, 1)
                                          otherwise
```

```text
deception_waste_score =
    0.35 * decoy_attack_rate
  + 0.25 * credential_trigger_rate
  + 0.20 * mtd_event_rate
  + 0.20 * post_decoy_real_suppression
```

```text
friction_score =
    0.35 * compromise_delay_score
  + 0.25 * lateral_failure_score
  + 0.20 * edge_block_activity_score
  + 0.20 * max(active_path_reduction, edge_block_event_score)
```

```text
retreat_score =
    clip(1 - attacker_retreat_step / (T - 1), 0, 1)   if attacker_retreated
    0.0                                               otherwise
```

この定義により、単なる成功/失敗ではなく、攻撃の遅延、浪費、utility 抑制、撤退までを同一スケールで比較できるようになった。

---

## 4. Architecture Evolution

### MPC Defender

目的は、防御リソース配分を単純な固定割当ではなく、将来リスクを見越した最適化問題として扱うことだった。

実装では MPC によってリソース量を最適化し、solver 失敗時には greedy fallback を使う。得られた知見は、MPC は防御基盤として有効だが、それだけでは攻撃者の行動変化や欺瞞効果を十分に評価できないという点である。

### Matching-based Defense

目的は、防御リソースをどのノードに割り当てるかを制約付き matching として扱うことだった。

実装では ILP matching により node-resource の割当を決め、capacity 制約と fallback を持たせた。これにより、防御対象の選定を明示的に記録できるようになったが、matching 単独では攻撃者誘導の評価には不十分だった。

### Attacker Utility Model

目的は、攻撃者を単なるランダム外乱ではなく、利得とコストに反応する主体として扱うことだった。

実装では compromised value、attack cost、defense cost、detection penalty から attacker utility を計算する。Phase1 の重要な知見は、utility が負になる policy は「検知できた」以上に強い無力化の証拠になり得るという点である。

### Attacker Belief

目的は、攻撃者が真の asset value を完全には知らず、belief に基づいて標的を選ぶ状況を表現することだった。

実装では attacker belief を target selection に組み込み、asset value と belief のズレを作れるようにした。これにより、デコイや honeypot が「見かけ上価値がある」対象として機能する余地が生まれた。

### Decoy

目的は、攻撃者を実資産から逸らし、攻撃コストと時間を浪費させることだった。

実装では node type として `decoy` を導入し、true gain と perceived gain を分離した。Phase1 では、naive decoy は必ずしも有効ではなく、critical path や attacker belief と整合した配置が重要であることが分かった。

### Stochastic Detection

目的は、検知を決定論的な yes/no ではなく、確率的イベントとして扱うことだった。

実装では base detection probability、defense strength、decoy detection probability、MTD bonus などを組み合わせて検知確率を計算する。これにより、低検知環境やデコイ高検知環境の比較が可能になった。

### Stochastic Success

目的は、攻撃成功も確率的に扱い、防御強度やデコイによる成功率低下を評価することだった。

実装では base success probability、defense success decay、decoy success probability、MTD success decay bonus を導入した。これにより、攻撃成功率そのものよりも、成功確率を下げた結果として utility や retreat にどう影響するかを見る基盤ができた。

### Multi-seed Evaluation

目的は、確率的シミュレーションの単一 seed 依存を避けることだった。

実装では `summary_runs.csv/json` と `summary_stats.csv/json` を出力し、平均、標準偏差、critical compromise rate、retreat rate などを評価できるようにした。Phase1 では、multi-seed の policy selection により `gated_edge_pressure_count_2` が従来 objective 上の best policy と判定された。

### Belief Learning

目的は、攻撃者が攻撃結果に応じて belief を更新し、同じデコイに固定され続けない状況を表現することだった。

実装では success / failure / detection / decoy に基づく belief update を導入した。得られた知見は、belief learning が入ると naive decoy の効果は弱まり、post-decoy の再誘導や防御強化が必要になるという点である。

### Post-Decoy Analysis

目的は、デコイ攻撃後に攻撃者が実資産へ戻るのか、デコイへ滞留するのかを測ることだった。

実装では `post_decoy_real_attack_count`、`post_decoy_compromised_value`、`post_decoy_utility`、post-decoy target counts を追加した。これにより、デコイが「一度踏ませるだけ」なのか、「その後も攻撃を歪める」のかを分離して評価できるようになった。

### Post-Decoy Aware Defense

目的は、デコイ発火後に防御重みや matching / MPC の対象を変え、攻撃者の次の行動に備えることだった。

実装では post-decoy defense weight、top-k、belief source、injection mode を導入した。知見として、デコイ単独よりも、デコイ後に real target への移行を抑える防御が重要であることが分かった。

### Estimated Defender Belief

目的は、防御側が攻撃者 belief を直接知らない前提で、観測から推定することだった。

実装では target frequency、selection score、visible log、hybrid visible の観測モードを導入した。Phase1 では、推定 belief を使った防御が可能になった一方、selection score 直接観測には oracle 性が残るため Phase2 の改善対象である。

### Bayesian Estimation

目的は、防御側 belief 推定を逐次的な Bayesian update として扱うことだった。

実装では prior strength、success likelihood、detected likelihood、decoy likelihood、critical path likelihood、decay を導入した。知見として、Bayesian 推定精度の向上が必ずしも defense performance に直結しないことが確認された。推定精度と防御目的の間には policy design の層が必要である。

### Lateral Movement

目的は、攻撃者が単一ノードを独立に攻撃するのではなく、ネットワーク上を移動して critical asset に近づく状況を表現することだった。

実装では adjacency matrix、entry nodes、current node、visited / compromised nodes、lateral success probability を導入した。これにより、critical compromise step や critical path 到達遅延を評価できるようになった。

### Critical Path Analysis

目的は、entry node から critical node までの攻撃経路を明示し、どこを守るべきかを分析することだった。

実装では critical paths、node path frequency、edge path frequency を算出する。これにより、単純な高リスクノード防御ではなく、critical path 上の構造的要所を防御する視点が得られた。

### Chokepoint Analysis

目的は、複数の critical path に共通して現れる防御優先点を抽出することだった。

実装では chokepoint nodes と critical edges を計算する。得られた知見は、デコイや MTD は任意配置では弱く、chokepoint や critical edge に絡めることで効果が増すという点である。

### Edge-level MTD

目的は、ノード防御だけでなく、critical path 上の edge を動的に遮断・変化させることで lateral movement を遅らせることだった。

実装では edge block count、duration、active steps、blocked edges、risk gating を導入した。結果として、edge MTD 単独は万能ではないが、path-aware decoy や credential-aware trigger と組み合わせることで friction を高められることが分かった。

### Credential Honeypot

目的は、攻撃者が credential を価値あるアクセス手段として認識する状況を利用し、偽 credential で誘導・検知することだった。

実装では credential node IDs、credential attraction bonus、credential detection bonus、reuse decay を導入した。これにより、ノードの asset value とは別に、攻撃者の perceived gain を増やす欺瞞チャネルを作れた。

### Credential-aware MTD

目的は、credential honeypot が発火したタイミングで MTD を強化し、攻撃者の次の lateral movement を妨害することだった。

実装では credential trigger window、block count、block duration、force MTD、risk bonus を導入した。targeted neutralization evaluation では、`credential_aware_mtd` が最高の `neutralization_score = 0.742` を達成し、Phase1 の最良無力化 policy となった。

### Neutralization Evaluation

目的は、Phase1 全体の成果を「攻撃の無力化」という最終目標に統合して評価することだった。

実装では `neutralization_score` と5つの subscore を metrics に追加し、`output/neutralization/` に summary、ranking、breakdown、Markdown report を生成した。これにより、個別機能の良し悪しではなく、攻撃者無力化という統一目標で policy を比較できるようになった。

---

## 5. Experimental Results

Targeted neutralization evaluation の主要結果は以下である。

| Label | Scenario | Neutralization | Critical | Utility | Deception | Friction | Retreat | Critical Compromise | Step | Utility Final |
|---|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| baseline | `lateral_baseline` | 0.055 | 0.031 | 0.008 | 0.200 | 0.081 | 0.000 | True | 5 | 1165.699 |
| path_aware_decoy | `lateral_decoy_on_chokepoint` | 0.077 | 0.086 | 0.056 | 0.066 | 0.155 | 0.000 | True | 14 | 393.696 |
| gated_edge_pressure_count_2 | `gated_edge_pressure_count_2` | 0.454 | 0.073 | 1.000 | 0.441 | 0.448 | 0.449 | True | 12 | -50.712 |
| gated_edge_pressure_duration_2 | `gated_edge_pressure_duration_2` | 0.456 | 0.073 | 1.000 | 0.431 | 0.459 | 0.469 | True | 12 | -51.813 |
| credential_aware_mtd | `credential_aware_mtd_edge_pressure` | 0.742 | 1.000 | 1.000 | 0.335 | 0.613 | 0.000 | False | N/A | -27.283 |
| current_best_policy | `policy_gated_edge_mtd_edge_pressure` | 0.453 | 0.073 | 1.000 | 0.431 | 0.439 | 0.469 | True | 12 | -51.813 |

補足として、targeted neutralization では `credential_aware_mtd` が最良だった。一方で、multi-seed defense objective に基づく `best_policy.json` では `gated_edge_pressure_count_2` が best policy として選ばれている。

| Source | Best Policy | Score / Objective | Critical Rate | Post-decoy Compromised |
|---|---|---:|---:|---:|
| neutralization targeted evaluation | `credential_aware_mtd_edge_pressure` | neutralization `0.742` | 0.000 in targeted run | 43 post-decoy real attacks |
| multi-seed defense objective | `gated_edge_pressure_count_2` | objective mean `506.990` | `0.500` | `153.990` |

この差は矛盾ではない。従来 objective は critical compromise rate と post-decoy compromised value を重視する一方、neutralization score は utility suppression、deception waste、friction、retreat も含む統合指標である。

---

## 6. Key Findings

### Finding 1: Naive decoy はほぼ効果なし

`naive_decoy` (`lateral_decoy`) の neutralization score は `0.053` で、baseline の `0.055` とほぼ同等だった。critical compromise step も baseline と同じ `5` であり、単に decoy node を置くだけでは攻撃者無力化には不十分である。

### Finding 2: Path-aware decoy で改善するが単独では足りない

`path_aware_decoy` (`lateral_decoy_on_chokepoint`) は neutralization score `0.077` と baseline より改善した。critical compromise step は `5` から `14` に遅延した。ただし utility はまだ大きく正であり、critical compromise も発生しているため、単独では無力化達成とは言えない。

### Finding 3: Edge MTD 単独は弱いが、utility suppression には効く

`gated_edge_pressure_count_2` と `gated_edge_pressure_duration_2` はどちらも utility suppression score `1.000` を達成した。attacker utility final も負になっている。一方で critical compromise は step `12` で発生しており、critical protection は弱い。

### Finding 4: Path-aware decoy + Edge MTD は friction を増やす

Gated edge pressure 系 policy は baseline / naive decoy より friction score が大幅に高い。edge block と risk gating により、攻撃者の進行に摩擦を加えることはできている。ただし、critical asset protection の完全達成には至らないケースがある。

### Finding 5: Bayesian 推定精度向上と防御性能は一致しない

Bayesian estimation は defender belief の推定基盤として有効だが、推定誤差が小さいことと、post-decoy compromised value や critical compromise rate が低いことは同一ではない。Phase1 では、推定モデルと policy selection の間に追加設計が必要であることが分かった。

### Finding 6: Credential-aware MTD が最も高い Neutralization Score を達成

`credential_aware_mtd` は targeted neutralization evaluation で score `0.742` を達成した。critical compromise は発生せず、utility suppression も最大評価になった。これは、credential honeypot による誘導と MTD の発火を組み合わせることで、攻撃者の進行を実質的に無力化できることを示している。

---

## 7. Best Policy Analysis

現時点の neutralization best policy は以下である。

```text
label:    credential_aware_mtd
scenario: credential_aware_mtd_edge_pressure
score:    0.7422
```

| Subscore | Value |
|---|---:|
| `critical_protection_score` | 1.000 |
| `utility_suppression_score` | 1.000 |
| `deception_waste_score` | 0.335 |
| `friction_score` | 0.613 |
| `retreat_score` | 0.000 |

### Why It Is Strong

`credential_aware_mtd` が強い理由は、credential honeypot と MTD が連動している点にある。攻撃者は credential を価値あるアクセス手段として認識し、それが発火すると MTD が critical edge pressure に応じて作動する。これにより、攻撃者は real asset に向かう経路上で摩擦を受け、critical compromise まで到達できなかった。

また、attacker utility final は `-27.283` であり、utility suppression score は `1.000` である。これは、攻撃者が得た成果よりも、攻撃コスト、検知・防御・欺瞞による負担の方が大きかったことを示す。

### Remaining Weakness

最大の弱点は retreat induction である。`credential_aware_mtd` の `retreat_score` は `0.000` で、attacker_retreated は false だった。つまり、この policy は攻撃者を実質的に不利にし、critical asset を守ることには成功しているが、攻撃者自身が撤退を選ぶモデル上の条件までは満たしていない。

また、deception_waste_score は `0.335` であり、gated edge pressure 系の `0.431` から `0.441` より低い。credential trigger rate は高いが、post-decoy real attack count が `43` と残っているため、浪費誘導はまだ改善余地がある。

---

## 8. Limitations

Phase1 には以下の限界がある。

- Attacker behavior simplification: 攻撃者は greedy / utility / adaptive の範囲に限定され、長期計画や戦略的撤退は単純化されている。
- Static topology baseline: MTD による active topology はあるが、基底ネットワーク自体は小規模・固定である。
- Simplified credential model: credential は抽象的な trigger / perceived gain として扱われ、credential graph や権限階層は未実装である。
- Heuristic policy selection: best policy は objective や neutralization score に基づく比較であり、online adaptive optimization ではない。
- Limited attacker adaptation: 攻撃者 belief learning はあるが、defender policy を学習・回避する高度な attacker adaptation は未実装である。
- Defender observation oracle risk: 一部の推定モードには selection score 直接観測のような oracle 性が残る。
- Retreat model is weak: attacker retreat は utility threshold と patience に依存しており、frustration、risk perception、goal abandonment は未分離である。
- Neutralization is single-seed in final targeted output: `neutralization_summary.csv` は targeted run の結果であり、Phase2 では multi-seed neutralization score の平均・分散が必要である。

---

## 9. Phase1 Completion Assessment

| Item | Status | Assessment |
|---|---|---|
| Neutralization 定義 | Achieved | 5軸 subscore と総合 score を定義済み |
| Neutralization 評価基盤 | Achieved | metrics と `output/neutralization/` 出力を実装済み |
| Multi-seed 評価 | Achieved | `summary_stats.csv` と `best_policy.json` を生成済み |
| Policy Ranking | Achieved | defense objective ranking と neutralization ranking の両方を出力可能 |
| Best Policy Selection | Achieved | neutralization では `credential_aware_mtd`、multi-seed objective では `gated_edge_pressure_count_2` を選定 |
| Critical Asset Protection 評価 | Achieved | `critical_compromise`, `critical_compromise_step`, `critical_protection_score` を出力 |
| Deception 評価 | Achieved | decoy attack、credential trigger、post-decoy real attack、deception waste を出力 |
| MTD 評価 | Achieved | MTD event、edge block、risk gate、friction score を出力 |

Phase1 Status: **COMPLETED**

ただし、Phase1 completed は「研究基盤としての完了」を意味する。攻撃者撤退モデル、perceived utility、online policy selection、実ログ統合は Phase2 の課題である。

---

## 10. Phase2 Roadmap

### High Priority

| Topic | Reason |
|---|---|
| Perceived Utility | true gain ではなく、攻撃者が認識する utility で belief update / retreat を統一する必要がある |
| Attacker Frustration Model | utility が負でも撤退しないケースを説明する心理・運用上の摩擦モデルが必要 |
| Dynamic Retreat Model | threshold / patience だけでなく、損失累積、検知リスク、成果停滞に応じた撤退が必要 |
| Multi-seed Neutralization Score | final neutralization ranking を seed 平均・分散で評価する必要がある |
| Defender-visible Observation | selection score oracle を排除し、visible logs に基づく推定へ移行する必要がある |

### Medium Priority

| Topic | Reason |
|---|---|
| Credential Graph | credential の権限範囲、再利用、横展開可能性を構造化する |
| Online Adaptive Policy Selection | fixed scenario ではなく、観測に応じて policy を切り替える |
| POMDP Defender | defender が不完全観測下で belief と action を同時最適化する |
| RL Attacker | attacker が defender policy に適応する状況を評価する |

### Low Priority

| Topic | Reason |
|---|---|
| Real-world Log Integration | 現実ログとの接続は重要だが、先に観測モデルの整理が必要 |
| Larger Topology Benchmark | 小規模 topology で指標を安定化した後に拡張する |
| Visualization Dashboard | 研究評価が固まった後に可視化を強化する |

---

## Phase1 Final Conclusion

CyberMatch Phase1 が証明できたことは、サイバー防御の成果を「攻撃を検知したか」や「攻撃が成功したか」だけで測るのでは不十分であり、攻撃者の utility、belief、経路選択、デコイへの反応、MTD による遅延、credential honeypot への誘導を統合して評価することで、攻撃の無力化を定量化できるということである。

特に、Phase1 は以下を示した。

- naive decoy はほぼ無力化に寄与しない。
- path-aware decoy は critical compromise を遅らせるが、単独では不十分である。
- edge-level MTD は utility suppression と friction に効くが、critical protection を常に保証するわけではない。
- credential honeypot と MTD を連動させると、critical compromise を防ぎ、attacker utility を負に抑えられる。
- neutralization score によって、critical protection、utility suppression、deception、friction、retreat を同一スケールで比較できる。

研究者向けに最も重要な結論は、CyberMatch が「攻撃者無力化」を実験可能な評価対象に変換したことである。Phase1 の段階ではまだ攻撃者モデルと撤退モデルは単純化されているが、防御 policy が攻撃者の行動と utility をどう変えるかを、再現可能な simulation / metrics / scenarios として評価できるようになった。

したがって、Phase1 の成果は、完成した防御アルゴリズムそのものではなく、攻撃者無力化を研究するための測定器を構築した点にある。この測定器により、Phase2 では perceived utility、frustration、dynamic retreat、adaptive attacker、POMDP defender、real-world logs へ進むための土台が整った。
