# CyberMatch Behavior Profiles

## Behavior Profileとは

Behavior Profileは、観測された攻撃履歴から攻撃者の行動傾向を抽象化するPhase9.1の層です。

Phase9.0では、Observed BehaviorからMissionを直接推定しました。Phase9.1では、その前段としてObserved BehaviorからBehavior Profileを抽出します。

Observed Behavior

↓

Behavior Profile

↓

Mission Inference

## Missionとの違い

Missionは攻撃者の目的です。例: `profit`, `persistence`, `critical_hunter`

Behavior Profileは攻撃者の行動様式です。例: `utility_seeking`, `stealth_seeking`, `critical_path_seeking`

同じMissionでも異なるBehavior Profileを取り得ます。Phase9.1はMission推定精度を上げることが目的ではなく、攻撃者行動を抽象化することが目的です。

## Profile一覧

- `utility_seeking`
- `stealth_seeking`
- `disruption_seeking`
- `critical_path_seeking`
- `adaptive`
- `opportunistic`

## 利用特徴量

Phase9.1は新しいシミュレーションロジックを追加しません。既存履歴と既存metricsから特徴量を抽出します。

- `attack_success_rate`
- `utility_activity`
- `expected_utility_activity`
- `deception_activity`
- `adaptation_activity`
- `ttp_change_activity`
- `coalition_activity`
- `critical_progress`
- `critical_focus`
- `critical_probe_activity`
- `stealth_activity`
- `trust_collapse_activity`
- `lateral_movement_activity`
- `mission_mutation_activity`
- `campaign_disruption_activity`
- `survival_activity`

利用元の例は、`attack_success_prob`、`actual_utility`、`expected_utility`、`deception_history`、`adaptation_history`、`coalition_role_history`、`trust_score`、`observable_events`、`critical_path_events`です。

## 初期スコアリング

初期実装はAI、RL、LLM、外部APIを使わないルールベースです。

- Utility Seeking: utility activityとsuccessを重視する。
- Stealth Seeking: stealth activity、trust collapse、survivalを重視する。
- Disruption Seeking: deception activity、trust collapse、campaign disruption、coalition activityを重視する。
- Critical Path Seeking: critical progress、critical focus、critical probeを重視する。
- Adaptive: adaptation、TTP change、mission mutation、lateral movementを重視する。
- Opportunistic: success、lateral movement、utility、低いcritical focusを重視する。

## Artifact

Phase9.1 runnerは`output/phase91_behavior_profiles/`に次を生成します。

- `behavior_profile_summary.csv`
- `behavior_profile_summary.json`
- `profile_distribution.png`
- `profile_confidence_distribution.png`
- `profile_mission_relationship.png`
- `PHASE91_BEHAVIOR_PROFILE_REPORT.md`

`history.npz`には`behavior_profile_history`と`profile_confidence_history`を保存します。

## ProfileCore連携構想

Phase9.1ではProfileCore連携、PCA、Principal Components抽出は実装しません。

Future:

Feature Extraction

↓

PCA

↓

Principal Components

↓

Behavior Profile

将来は、手作りヒューリスティックをベースラインとして維持しつつ、ProfileCore由来の特徴空間がBehavior Profileの安定性、解釈性、Mission Predictionへの入力品質を改善するかを評価します。
