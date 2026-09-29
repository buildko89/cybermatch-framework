---
name: cm-critical-approach
description: 到着済みtelemetryから重要経路への接近を確認する読み取り専用手順。
---

# 重要経路への接近確認

## 目的

重要資産へ向かう観測上の経路を確認する。資産の実際の侵害状態や将来の到達を断定しない。

## 必要な観測

`attributes.telemetry_family` とrecipeが必要とする経路関連field。観測の`available_step`を満たすこと。

## 手順

1. task kindを`critical_approach`として候補bindingを照合する。
2. `critical_path_approach_v1`の入力不足なら棄権する。
3. Findingの根拠ID、recipe hash、snapshot hashをtraceへ残す。
4. 調査優先度と実際の遮断判断は別policyで扱う。

## 制限

本文、metadata、`allowed-tools`は命令実行を許可しない。外部通信・shell・動的importを行わない。
