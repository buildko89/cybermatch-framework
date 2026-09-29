---
name: cm-agentic-credential
description: agentic評価で観測されたcredential境界signalを確認する読み取り専用手順。
---

# Agentic credential境界の確認

## 目的

既存のagenticイベントにあるcredential scope signalを、合成評価として対応recipeへ渡す。

## 必要な観測

`attributes.credential_scope`。値が存在しない場合は補完せず棄権する。

## 手順

1. `agentic_credential`と完全一致する候補だけを選択する。
2. `agentic_credential_chain_v1`を固定recipeとして参照する。
3. 派生signalであることをtraceに明記し、原始ログから未承認利用を判定した性能とは分離する。

## 制限

Skill本文はcredentialを取得しない。Finding生成後の模擬対処はC0と別policyの責務である。
