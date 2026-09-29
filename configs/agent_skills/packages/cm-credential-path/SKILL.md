---
name: cm-credential-path
description: 合成認証観測からcredential経由の重要経路接近を確認するための読み取り専用手順。
---

# 認証情報から重要経路までの確認

## 目的

認証成功、credentialの利用、重要資産への接近を観測済みイベントだけで相関する。未観測のcredential値、利用者の意図、真値labelを推定しない。

## 必要な観測

`attributes.auth_result` と `attributes.credential_present` が到着済みであること。tenantとrunが対象の調査範囲と一致すること。

## 手順

1. `available_step`以前の観測だけをsnapshotに含める。
2. `credential_to_critical_path_v1` の必須fieldを満たすか確認する。不足時は `not_evaluable:missing_fields` とする。
3. recipeのFindingと証拠event IDを確認し、実行結果をtraceに保存する。
4. 対処が必要な場合は別policyがC0 actionを作る。SOP本文は対処権限を持たない。

## 制限

これは合成評価用の候補であり、現時点では承認・実行対象ではない。パスワード、token、平文emailを要求・保存しない。
