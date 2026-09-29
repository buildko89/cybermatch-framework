---
name: cm-agentic-boundary
description: agentic評価における境界圧力signalを確認する読み取り専用手順。
---

# Agentic境界圧力の確認

## 目的

共有資源や権限境界へ向かう観測済みsignalを確認し、合成実験のFindingを再現する。

## 必要な観測

`attributes.boundary`。run、tenant、到着時刻が評価範囲と一致すること。

## 手順

1. `agentic_boundary`候補と必要fieldを固定順で照合する。
2. `agentic_boundary_pressure_v1`を実行候補としてtrace化する。
3. policyが対処を要求しても、C0 receiptが`applied`になるまでは阻止成功と数えない。

## 制限

これは実OSや実クラウドの隔離試験ではない。任意scriptや外部APIを実行しない。
