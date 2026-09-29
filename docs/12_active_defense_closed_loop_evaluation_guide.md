# 能動防御・閉ループ評価ガイド（T3）

## 1. 目的

T3は、T2で生成した文脈付き仮説とFindingを、対象限定の模擬対処へ接続します。評価対象は合成世界だけです。実identityの失効、実SIEMへのルール登録、外部CTIの取得は行いません。

| モード | 調査順 | 対処 |
|---|---|---|
| B0 `internal_open` | 内部観測scopeの固定順 | なし |
| B1 `context_open` | CTI/ASMの相関・priority順 | なし |
| B2 `internal_closed` | B0と同じ | identity限定失効 |
| B3 `context_closed` | B1と同じ | identity限定失効 |

同じseedでは潜在操作graphを共有します。closed-loopで対処が適用された後は世界状態が変わるため、後続の実観測がopenモードと異なることを許容します。

## 2. 実装配置

用途が名前から分かるよう、T3固有処理を次のファイルへ分離しています。

- `logging_hygiene.py`: family別のdrop、field除去、遅延、保持期限
- `stateful_mock_world.py`: sessionと操作依存関係を持つ合成世界
- `response_action_sink.py`: 対象限定actionの検証、適用、期限終了、receipt
- `active_defense_evaluation_runner.py`: B0〜B3のstep実行
- `closed_loop_evaluation.py`: paired bootstrap比較
- `active_defense_evaluation_report.py`: 日本語reportとEvidence Bundle
- `scripts/run_active_defense_closed_loop_evaluation.py`: T3専用CLI

T2 runnerや旧`ThreatHuntingFeedback`へ暗黙に処理を追加していません。

## 3. 実行方法

```powershell
python scripts/run_active_defense_closed_loop_evaluation.py `
  --spec configs/active_defense/runs/t3_synthetic_closed_loop_evaluation_v1.json `
  --output output/active_defense/t3-synthetic-closed-loop-v1
```

パッケージを導入済みの場合は、同じ引数を`cybermatch-active-defense-evaluation`へ渡して実行できます。

出力先は新規directoryでなければなりません。既存成果物は上書きしません。

| ファイル | 内容 |
|---|---|
| `mode_profile_results.jsonl` | mode・profile・seed別のscalar結果 |
| `actions.jsonl` | 対処要求。要求だけでは適用済みを意味しない |
| `receipts.jsonl` | `applied`、`rejected`、`expired`の追記型結果 |
| `paired_comparisons.json` | 2,000回paired bootstrapの95%区間 |
| `evaluator_only_world_outcomes.jsonl` | evaluator専用の操作結果。検知器入力には使わない |
| `active_defense_evaluation_result.json` | wall-clockを含まない決定論的結果 |
| `report.md` | 日本語の比較レポート |
| `evidence_bundle.json` | 成果物hashを含む共通Bundle |

## 4. 対処とsessionの意味

identity失効は`effective_step >= requested_step + 1`で適用され、半開区間`[effective_step, expires_step)`だけ有効です。対象identity以外へ効果を広げません。同じaction IDの再送は新しい効果やreceiptを増やしません。

この模擬世界では、identity失効は新規認証を拒否しますが、既に確立されたsessionを直ちに終了しません。sessionは宣言済みの期限まで継続します。この区別により、「対処したので攻撃者は必ず即時撤退する」という前提を置かず、継続、阻止、期限後の再開を別々に観測できます。

## 5. ログ健全性profile

既定profileは完全、command-line除去、20% drop、3 step遅延、保持5 stepです。dropのdrawは`seed`、潜在event ID、固定namespace、profile IDから独立に導出します。検知成否やmodeはdraw keyへ含めません。

ログ変換は防御側へ渡す観測のコピーだけを変更します。潜在graph、世界状態、evaluator専用labelは変更しません。到着予定が保持期限以上になった観測は、遅延観測ではなく期限切れとして別集計します。

## 6. 解釈上の制約

- 結果は宣言した合成世界と対処モデル内の比較です。実環境での防御効果を保証しません。
- 20% dropは実環境から推定した値ではありません。
- CTI matchだけでは対処しません。到着済み内部観測から生成されたFindingを必要とします。
- evaluator専用graphとlabelを相関器、recipe、対処policyへ渡しません。
- seed 0〜29は同じscenario templateから生成されるため、信頼区間は現実の攻撃多様性を表しません。
