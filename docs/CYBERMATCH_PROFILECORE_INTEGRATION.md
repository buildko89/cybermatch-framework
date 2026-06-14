# CyberMatch ProfileCore Integration Design

## 目的

ProfileCore連携の目的は、CyberMatchの攻撃行動特徴量を外部の特徴空間分析・プロファイル分析基盤へ渡し、Behavior ProfileとMission Predictionの説明可能性を高めることです。

Phase9.2ではProfileCoreを実装しません。submodule追加も行いません。
Phase9.3で、この設計を前提に`external/profilecore`を連携対象として扱い、
CyberMatchのFeature VectorをProfileCore分析へ接続します。

## CyberMatch Feature Vector

Phase9.2では、CyberMatch内で次の特徴量ベクトルを定義します。

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
- `objective_activity`
- `planned_critical_activity`

将来はこのFeature VectorをProfileCoreへ渡し、ProfileCore側で特徴量管理、次元削減、Profile解釈を行う構成を想定します。

## PCA / Principal Component Interpretation

Phase9.2の目的はPCAではありません。

PCAを導入する前に、CyberMatch内部で以下を確認します。

- dominant feature
- feature entropy
- feature concentration
- mission feature separability
- profile feature separability
- critical path bias score

将来PCAを導入する場合は、principal componentを「どの攻撃行動特徴量の組み合わせか」として解釈し、Behavior Profileの説明に使います。

## submodule構成

Phase9.3でProfileCore連携が必要になったため、次の構成を採用します。

```bash
git submodule add https://github.com/buildko89/profilecore.git external/profilecore
git submodule update --init --recursive
```

Phase9.2では実行しません。Phase9.3以降の分析で使用します。

想定ディレクトリ:

```text
external/
  profilecore/
```

CyberMatch側は`feature_space.py`で生成したFeature VectorをProfileCore adapterへ渡します。adapterは将来追加し、Phase9.2では作成しません。

## Future Flow

Feature Extraction

↓

PCA

↓

Principal Components

↓

Behavior Profile

↓

Mission Prediction
