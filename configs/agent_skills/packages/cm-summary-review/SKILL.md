---
name: cm-summary-review
description: 合成要約中の明示的な隠蔽要求を確認するための読み取り専用手順。
---

# 合成要約の明示的隠蔽要求確認

## 目的

合成要約に現れる明示的な隠蔽要求を、観測可能な原記録参照と照合する。モデルの意図や内部状態を推定しない。

## 必要な観測

`attributes.summary_text`と可視record参照。必要情報が不足する場合は`abstain`とする。

## 手順

1. task kind `summary_review`に対応する候補を選ぶ。
2. 将来作成する`summary_suppression_v1`では肯定例だけでなく、否定、引用、短縮、原記録不足を評価する。
3. truth labelは検査器に渡さず、evaluatorだけが選択・Findingを採点する。

## 制限

このbindingは新規recipe未作成のため、現在は実行不可である。候補manifestの承認前に自動実行しない。
