# CyberMatch OR-4 引継ぎメモリ

**更新日:** 2026-09-15

**対象revision:** 本文書を含むcommit

**Stage状態:** OR-0〜OR-3完了、LOCAL-1完了、OR-4技術評価完了・blind human review待ち

**次のStage:** OR-4 human gate完了後、OR-5 Internal HITL pilot

## 1. 現在地

CyberMatch FrameworkへPhase 3 external validity replayと、Human-in-the-Loop LLM PilotのOR-0〜OR-4実装を統合した。

| Stage | 状態 | 主な成果 |
|---|---|---|
| Phase 3 external replay | 完了 | CSV／JSONL mapping、Ground Truth分離、domain gap、Evidence Bundle |
| OR-0 Contract／Policy | 完了 | RunSpec、ResultView、AIAnswer、LLM audit、Orca config schema |
| OR-1 Orca adapter | 完了 | free-only route、bounded retry、allowlist、safe fallback、usage audit |
| LOCAL-1 | 完了 | pinned Qwen2.5-1.5B Q4_K_M、size／SHA-256検証、offline setup |
| OR-2 Service／UI | 完了 | runtime injection、表示分離、human decisionとaudit hash結合 |
| OR-3 Security／resilience | 完了 | injection、leak、cross-run、provider failure matrix |
| OR-4 Shadow evaluation | 90% | 3候補×3 runの技術評価完了、blind human review待ち |

## 2. OR-4最終技術結果

同一ResultViewでtemplate、local Qwen、Orca Routerを各3回評価した。

| Candidate | Schema／grounding | Fallback | Mean latency | Unique outputs | Automated flags |
|---|---:|---:|---:|---:|---:|
| Deterministic template | 3/3 | 0 | n/a | 1 | 0 |
| Local Qwen2.5 1.5B | 3/3 | 0 | 22,357.78 ms | 3 | 2 |
| Orca Router | 3/3 | 0 | 5,558.23 ms | 3 | 0 |

Orca resolved modelは`deepseek/deepseek-v4-flash-free`だった。providerからcost metadataは返らなかったため、測定値を0として補完していない。

生成artifactは`output/pilot/shadow/or4-three-candidate-final/`にあるが、`output/`はGit管理外である。必要な場合は組織の内部artifact storageからhash付きで受け渡す。

## 3. Orca response contract修正

当初のOrca runは3件とも`invalid_response`へfallbackした。原因はnamed router応答の標準`model`にprovider内部名が入り、公開canonical model IDが`X-Orca-Resolved-Model`へ入る仕様を、両者の不一致として拒否していたことだった。

修正内容:

- named routerでは`X-Orca-Resolved-Model`をcanonical IDとしてallowlist検証する。
- direct model呼出ではresponse／headerの真正な不一致を引き続き拒否する。
- `response_format: {"type":"json_object"}`を固定送信する。
- sanitized `failure_detail`をLLM auditへ記録する。
- free-tier 429は`Retry-After`がある場合だけ再試行する。
- provider previewと実送信bodyを同じbuilderから生成する。
- provider本文、prompt本文、API keyはfailure auditへ保存しない。

## 4. 検証結果

| Test | Result |
|---|---|
| Curated fast lane | 350 passed、既知のjoblib CPU検出warning 1件 |
| OR-4／Orca／security targeted | 66 passed |
| Phase 3 marker | 85 passed, 581 deselected |
| OR-4 integrated live shadow | template、local、Orcaすべて3/3 accepted相当、fallback 0 |
| Evidence Bundle loader | 既存bundleのhash／artifact検証成功 |
| Provider preview | `contains_api_key=false`、JSON modeを確認 |

## 5. 外部利用者向け文書

| 文書 | 用途 |
|---|---|
| `CYBERMATCH_EVALUATION_EXECUTION_GUIDE.md` | 取得、環境構築、同梱／独自replay、HITL、LLM比較、Evidence提出 |
| `OR4_BLIND_HUMAN_REVIEW_PROCEDURE_20260915.md` | OR-4のblind採点、unblind、集計、gate判断 |
| `README_JP.md` | 上記文書への入口と代表command |
| `pilots/phase3/PILOT_INTAKE_TEMPLATE.md` | 外部pilotの受付・承認記録 |

## 6. 秘密・生成物の取扱い

- `.env`はGit管理外。許可keyは`ORCAROUTER_API_KEY`と`CYBERMATCH_PILOT_LLM_CONFIG`だけ。
- `models/local_llm/*.gguf`と`.part`はGit管理外。
- `output/`はGit管理外。
- `.env.example`、Orca config、手順書には実credentialを含めない。
- 外部providerを使う前に`provider_send_preview.json`を人間が確認する。

## 7. 再開手順

1. `OR4_BLIND_HUMAN_REVIEW_PROCEDURE_20260915.md`に従い、`shadow_blind_review.json`の9回答を人間reviewerが採点する。
2. completed packetのSHA-256を固定してからmapping keyを開示する。
3. clarity、Evidence traceability、material overclaimを候補別に集計する。
4. leakage 0、架空根拠0、schema pass率95%以上、limitation保持率100%を確認する。
5. OR-4 gate decisionと採用候補を記録する。
6. 合格時は内部利用者1〜3名に限定したOR-5へ進む。

## 8. 再開時の検証command

```powershell
python scripts\run_tests.py --smoke
python scripts\run_tests.py --phase phase3
python -m pytest tests/test_pilot_orcarouter_gateway.py tests/test_pilot_orcarouter_policy.py tests/test_pilot_shadow.py tests/test_pilot_or3_security.py tests/test_pilot_human_in_the_loop.py -q -p no:cacheprovider
```

## 9. 現在の制約

- Pilot UIのcatalogは同梱OCSF replayへ固定されている。
- 独自CSV／JSONLは`run_external_replay.py`のCLIで評価する。
- 標準CLIのreference adapterでは`external-sut-backed`を名乗れない。
- Local Qwenは現在shadow runner用で、Pilot UIのruntime config backendではない。
- Llama系local modelは対象外のまま保留する。
- OR-4完了は外部公開readyを意味しない。OR-5とOR-6が必要である。
