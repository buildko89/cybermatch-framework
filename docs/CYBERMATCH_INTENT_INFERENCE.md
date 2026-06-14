# CyberMatch Intent Inference

## Intent Inferenceとは何か

Intent Inferenceは、観測された攻撃行動から攻撃者のMissionを推定するPhase9.0の基盤です。

Phase9.0の目的はAI攻撃者を作ることではありません。既存のCyberMatchが持つMission、Belief、Campaign、Strategy、Mutation、Coalition、Deceptionの履歴を使い、Ground Truth Missionを見るだけの評価から、観測行動に基づくMission推定へ進むことです。

## Mission推定の考え方

初期実装はAI、RL、LLM、外部APIを使わないルールベースです。

推定対象は次の4クラスです。

- `profit`
- `achievement`
- `persistence`
- `critical_hunter`

ヒューリスティックは以下の読み方をします。

- Profit: utility activity、attack success、expected utilityを重視する。
- Achievement: objective activity、critical progress、successを重視する。
- Persistence: trust collapse、stealth/adaptation、survival、deception interactionを重視する。
- Critical Hunter: critical path progress、critical focus、critical probesを重視する。

出力は`inferred_mission`、`mission_confidence`、`mission_entropy`、`mission_match`、`mission_confusion_score`、`mission_inference_accuracy`です。

## 利用する特徴量

Phase9.0は新しいシミュレーションロジックを追加せず、既存履歴と既存metricsから特徴量を抽出します。

- `attack_success_rate`
- `utility_activity`
- `expected_utility_activity`
- `critical_progress`
- `critical_focus`
- `critical_probe_activity`
- `trust_collapse_activity`
- `stealth_activity`
- `survival_activity`
- `deception_activity`
- `lateral_movement_activity`
- `objective_activity`
- `planned_critical_activity`
- `mission_signal_profit`
- `mission_signal_achievement`
- `mission_signal_persistence`
- `mission_signal_critical_hunter`

利用元の例は、`mission_history`、`strategy_history`、`deception_history`、`coalition_role_history`、`adaptation_history`、`attack_success_prob`、`critical_path_events`、`trust_score`、`actual_utility`、`expected_utility`、`observable_events`です。

`mission_history`とmission weightは、Phase9.0の初期ベースラインでは弱いmission signalとして扱います。`true_mission_history`は評価時の比較に使います。

## Artifact

Phase9.0 runnerは`output/phase90_intent_inference/`に次を生成します。

- `intent_inference_summary.csv`
- `intent_inference_summary.json`
- `mission_confusion_matrix.png`
- `mission_accuracy.png`
- `mission_confidence_distribution.png`
- `PHASE90_INTENT_INFERENCE_REPORT.md`

`history.npz`には`inferred_mission_history`と`mission_confidence_history`を保存します。

## Future Phase: ProfileCore連携構想

Phase9.0ではProfileCore連携は実装しません。

将来Phaseでは次の流れを想定します。

Behavior Features

↓

Feature Extraction

↓

PCA / ProfileCore

↓

Intent Inference

この段階では、手作りヒューリスティックをベースラインとして保持し、ProfileCore由来の行動特徴がMission推定の精度、安定性、説明可能性を改善するかを比較します。
