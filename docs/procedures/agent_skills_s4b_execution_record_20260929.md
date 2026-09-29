# Agent Skills S4b Linux・No-Egress実行記録（2026-09-29）

## 1. 実行識別子

| 項目 | 値 |
|---|---|
| GitHub Actions run | `36561904646` |
| S4b job ID | `109384520381` |
| branch | `codex/agent-skills-s4b-20260929` |
| code revision | `9f04bb86d3f9a0a11f48e6b4a3d0f0c4591684f4` |
| external source revision | `54a798831d2266a3ca61ce68a7acb80b81160d57` |
| runner | GitHub-hosted Ubuntu、Linux `6.17.0-1022-azure` |
| Python | `3.12.14` |
| 非特権UID | `65532` |

実行URL: `https://github.com/buildko89/cybermatch-framework/actions/runs/36561904646`

## 2. 結果

専用job `Agent Skills Linux / S4b No-Egress`は51秒で成功しました。

| 検証 | 結果 |
|---|---|
| native Agent Skills試験・評価 | 成功 |
| 固定外部source取得・revision照合 | 成功 |
| 代表8 packageのsnapshot/LICENSE照合 | 成功 |
| container network拒否 | `egress_blocked=true` |
| repository書込拒否 | `repository_write_blocked=true` |
| 外部source書込拒否 | `external_source_write_blocked=true` |
| cloud credential非注入 | `cloud_credentials_present=false` |
| 外部script実行 | 0件 |
| sandbox総合判定 | `passed=true` |

native result hashは`52755c3101bc266c182c9a2527418854046bcb095ab37fa4f1e8f1bcc904a655`、外部審査result hashは`9bb8e9535b37edd381bdfb5f8109e1ad57d78288342513fff4c42a45e3eb9455`です。

## 3. 外部package判定

- `reviewed_not_bound`: 5件
- `excluded`: 3件
- external binding: 0件
- external script execution: 0件

全8件で対象revisionのApache-2.0 LICENSE hashが一致しました。ただし、licenseとhashの一致は内容の安全性・recipeとの同値性を示しません。外部API、credential検証、外部command、未固定model、Tor／hidden service等のrisk signalを記録し、自動承認しませんでした。

## 4. 証跡

GitHub Actions artifact `agent-skills-linux-s4b`に、次を保存しました。

- `linux_execution_record.json`
- `s4b-sandbox/sandbox_probe.json`
- `s4b-review/external_skill_review.json`
- `s4b-review/report.md`
- `s4b-review/evidence_bundle.json`
- native評価のmetrics、trace、report、Evidence Bundle

ローカルにも`output/agent_skills/github_run_36561904646/`へ同artifactを取得し、JSON内容を再確認しました。
