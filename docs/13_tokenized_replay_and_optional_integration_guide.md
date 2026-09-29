# Token化replay・任意接続ガイド（T4a／T4b）

## 1. 対象範囲

T4aは、信頼境界の外で事前token化されたCTI、ASM、inventory binding、内部telemetryをread-onlyで再生し、既存recipeへの検知適合性を確認します。反実仮想の対処効果、本番有効性、商用CTIとの同等性は主張しません。

T4bは任意接続です。攻撃者モデルへの観測可能な結果通知、仮説選択のshadow Pilot、独立UI rendererを提供します。Pilotの提案から対処を自動実行しません。

## 2. T4aの入力境界

source manifestでは次の項目を必須とします。

- evidence class `replay-backed`
- source ref一覧
- identity正規化versionとHMAC key version
- 保持日数
- snapshot形式（JSONLまたはCSV）
- 制約事項

snapshotはJSONLでは`record_type`と`payload`、CSVでは`record_type`と`payload_json`だけを許可します。未対応field、平文identity形式、credential値、tenant/run不一致はdata quality不合格として明示します。HMAC鍵やraw入力はBundleへ保存しません。

```powershell
python scripts/run_tokenized_cti_asm_replay.py `
  --spec configs/active_defense/runs/t4a_tokenized_replay_v1.json `
  --output output/active_defense/t4a-tokenized-replay-v1
```

パッケージ導入後は`cybermatch-tokenized-cti-asm-replay`でも実行できます。

主な成果物は`data_quality_report.json`、`matches.jsonl`、`hypotheses.jsonl`、`finding_trace.jsonl`、`tokenized_replay_result.json`、日本語`report.md`、`evidence_bundle.json`です。

## 3. T4b attacker接続

`AttackerConsequenceAdapter`は既存`AttackerModel.observe_defender_consequence`と同じinterfaceへ、次のbooleanだけを渡します。

- blocked
- delayed
- detected
- redirected

Finding、CTI source、defender score、truth、identityは渡しません。これにより撤退・迂回・継続は攻撃者が観測できる結果に基づいて発生します。

## 4. T4b hypothesis Pilot

Pilot viewは検証済みEvidence Bundleと`hypotheses.jsonl`から作ります。候補ごとに仮説ID、template ID、scope、観測参照、recipe ID/hash、priorityだけを含めます。

proposalは候補に含まれる仮説ID、観測参照、scope、recipe ID/hashとの完全一致が必要です。自由predicate、新規operator、閾値変更、allowlist外recipeは契約上表現できません。gateway例外、schema不正、grounding不一致の場合は実行候補を空にしてabstainします。

```powershell
python scripts/run_active_defense_hypothesis_pilot_shadow.py `
  --evaluation-output output/active_defense/t4a-tokenized-replay-v1 `
  --output output/active_defense/t4b-hypothesis-shadow-v1
```

パッケージ導入後は`cybermatch-active-defense-pilot-shadow`でも実行できます。

`apps/active_defense_pilot_view.py`はrunnerから独立し、CLIと同じsanitized view／shadow proposalだけを表示します。`execution_authorized`は常にfalseです。

## 5. 制約

- 同梱fixtureはtoken化済み形式の動作確認用で、実組織データではありません。
- 実データの取得、token化、所有権確認、利用規約確認は信頼境界内の別工程です。
- T4aは検知適合性だけを評価し、対処による防止率を出しません。
- T4b Pilotはshadow限定で、人手承認後であっても本実装から対処を実行しません。
- 独立UI rendererは表示層だけであり、runnerやprivate policyへアクセスしません。
