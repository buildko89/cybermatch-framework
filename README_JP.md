# CyberMatch Framework

**CyberMatch v1.0.1**

CyberMatchは、攻撃者の意思決定プロセスを再現し、防御戦略やセキュリティ製品の比較評価を可能にするサイバー意思決定シミュレータです。

単なる手法のリプレイ（technique replay）だけでは答えるのが難しい、以下のような研究・評価上の疑問に答えるために設計されています：

- その防御策は、攻撃者の目的（mission）達成をどの程度阻止できたか？
- Deception（欺瞞）は、攻撃者の信念（belief）、確信度（confidence）、信頼（trust）、経路選択（path choice）を変化させたか？
- 防御側の連携（coalition）コストは攻撃者の有効性を低下させたか？
- どの製品プロファイルが、どの攻撃目的（mission）に対して効果的か？

[English README](README.md)

## CyberMatchとは (What is CyberMatch?)

CyberMatchは、攻撃者と防御者の相互作用を反復可能なキャンペーンとして評価します。単に「検知が発火したか」「既知のテクニックが再生されたか」を測定するだけではなく、防御策が「攻撃者の考え、選択、信頼、回避、放棄」をどのように変化させたかを測定します。

主な機能（Core capabilities）:

- **Defense Neutralization & Decision Neutralization** (防御の無効化と意思決定の無効化)
- **Adaptive and rational attacker validation** (適応的かつ合理的な攻撃者の検証)
- **Intelligence-driven active defense** (インテリジェンス主導の積極的防御)
- **Coalition, counter-deception, awareness, and hunting** (複数組織の連携、カウンター・ディセプション、認知、ハンティング)
- **Product interface, product profiles, and mission-aware product evaluation** (製品インターフェース、製品プロファイル、目的に応じた製品評価)
- **Scenario import, catalog, topology, and standard benchmark foundations** (シナリオのインポート、カタログ、トポロジ、標準ベンチマーク基盤)
- **Attacker decision model foundation from intent through decision graph** (意図から意思決定グラフに至る攻撃者意思決定モデル基盤)

## コアコンセプト (Core Concepts)

- **Intent**: 金銭目的、スパイ活動、破壊活動、長期潜伏など、攻撃者の上位の目的。
- **Mission**: 利益獲得、実績、永続化、重要資産の探索など、攻撃者の具体的な目的。
- **Target**: アイデンティティ基盤、クラウドのコントロールプレーン、バックアップシステム、信頼関係など、攻撃者が標的とする資産や関係性。
- **Strategy**: 目的を達成するために使用される、標的に特化した作戦上のアプローチ。
- **Belief**: 資産、経路、状態、目的について、攻撃者や防御側が「真である」と信じていること。
- **State**: ポリシー選択や結果分析に使用される、推論されたキャンペーンのコンテキスト（状態）。
- **Trust**: 攻撃者がノード、認証情報、経路、パートナーに依存し続けているかどうか。
- **Deception**: デコイ、偽の資産、偽の経路、意図の隠蔽、誤解を招くシグナル。
- **Coalition**: 引き継ぎ、調整コスト、情報損失、信頼の低下を伴う複数の攻撃者による連携。
- **Counter-Deception**: 受動的なフィルタリングではなく、防御側による攻撃者の認識の能動的な操作。
- **Awareness and Hunting**: Deception（欺瞞）を認識し、積極的に探索する攻撃者。

## CyberMatch意思決定モデル (CyberMatch Decision Model)

CyberMatchでは、攻撃者の意思決定モデルを以下のように整理しています：

```text
Intent
  -> Mission
  -> Target
  -> Strategy
  -> Behavior
  -> Archetype
```

このモデルは分析専用のレイヤーです。Runtime Delegation（実行時の委譲）、防御コンセプトの実処理、強化学習（RL）、LLM、外部API、新しい攻撃者・防御者ロジックなどを追加するものではありません。

## 製品評価 (Product Evaluation)

CyberMatchは、実際の製品、外部API、強化学習、LLMなどに接続することなく、セキュリティ製品の評価フレームワークとして機能します。

実装されている製品評価レイヤー：

- **Product Plugin Interface**: IDS、IPS、ハニーポット、Deception、XDRなどの製品カテゴリを比較します。
- **Product Profile Import**: `profiles/products/` から軽量なJSON形式の製品プロファイルを読み込みます。
- **Mission-Aware Product Evaluation**: 攻撃者の目的（mission）ごとに、製品プロファイルの有効性を評価します。

目標は「最強の製品を1つ決めること」ではありません。「どの防御機能が、どの目的に対して、攻撃者の意思決定をどう変化させるか」を理解することです。

サンプルの製品プロファイル：

- `profiles/products/sample_ids.json`
- `profiles/products/sample_ips.json`
- `profiles/products/sample_honeypot.json`
- `profiles/products/sample_deception.json`
- `profiles/products/sample_xdr.json`

代表的な出力ディレクトリ：

- `output/phase61_product_interface/`
- `output/phase62_product_profiles/`
- `output/phase63_mission_products/`

※ `output/` は意図的にgitの追跡対象から外されています。必要に応じて評価用スクリプトを実行して結果を再生成してください。

## 環境構築とGUIダッシュボード (Quick Start)

CyberMatchは、Pythonベースのシミュレーションエンジンと、結果を比較するための視覚的なStreamlit GUIダッシュボードで構成されています。

### 1. 動作環境のセットアップ

依存パッケージをインストールします（Python 3.12 互換環境を推奨）：

```bash
python -m venv .venv
# Windowsの場合
.\.venv\Scripts\Activate.ps1
# Linux / macOSの場合
source .venv/bin/activate

python -m pip install -r requirements.txt
```

環境が正しく構築できたか確認するために、スモークテストを実行してください：

```bash
python scripts/run_tests.py --smoke
```

### 2. GUIダッシュボードの起動方法

組み込みのStreamlitダッシュボードを使用して、評価の実行と結果の可視化を行うことができます。

```bash
streamlit run apps/streamlit_app.py
```

起動すると、ターミナルにURL（通常は `http://localhost:8501`）が表示されます。ブラウザでこのURLを開いてください。

**ダッシュボードの使い方:**
- サイドバーから言語（**English** または **日本語**）を切り替えることができます。
- **Scenario**: 評価条件ファイル（JSON）の確認と読み込み。
- **Products**: 比較対象となる各防御策（製品）プロファイルの確認。
- **Run**: 選択したシナリオと防御策に基づいてシミュレーションを実行。
- **Results**: 詳細な指標、目的に応じた有効性のヒートマップ表示、生成されたレポートのダウンロード。

## コマンドラインでの実行 (Representative Experiments)

> **Note**: これまでの大規模リファクタリングにより主要なコードは `src/cybermatch/` 配下に移動しましたが、ルートの `cybermatch.py`、`run_scenarios.py`、`strategy_layer.py` は後方互換性のためのエイリアスとして残されています。既存の実行コマンドは変更なくそのまま動作します。

### Active Defense Evaluation (アクティブディフェンス評価)
インテリジェンス主導の積極的防御のシミュレーションを評価します：
```bash
python scripts/run_phase4.py --quick
```

### Coalition & Counter-Deception Evaluation (連携とカウンター・ディセプション評価)
複数攻撃者の連携、カウンター・ディセプション、認知、ハンティングを評価します：
```bash
python scripts/run_tests.py --phase phase5
```

### Mission-Aware Product Evaluation (防御策の比較評価)
CLIから、攻撃者の目的ごとに製品プロファイルの有効性を評価します：
```bash
python scripts/run_scenarios.py
# または特定のシナリオを指定する場合：
python scripts/run_scenario.py scenarios/mission_product_eval_basic.json
```

### Scenario Catalog & Benchmark Suite (シナリオカタログとベンチマークスイート)
再現可能なJSONベンチマーク（Scenario x Mission x Product）を使用して横断的な評価を実行します。

組み込みシナリオの一覧表示：
```bash
python scripts/run_scenario.py --list
```
CyberMatch標準ベンチマークスイートの実行：
```bash
python scripts/run_scenario.py benchmarks/cybermatch_standard_v1.json
```

### Topology Evaluation (トポロジ評価)
企業ネットワークのトポロジ（構成）の違いが攻撃者の選択にどのように影響するかを評価します：
```bash
python -c "from run_scenarios import run_phase84_topology_evaluation; run_phase84_topology_evaluation()"
```

## リポジトリ構成

```text
cybermatch-framework/
  README.md
  README_JP.md
  src/
    cybermatch/
      attacker/
      config/
      defense/
      evaluation/
      models/
      simulation/
      visualization/
  cybermatch.py        # 後方互換性用エイリアス
  run_scenarios.py     # 後方互換性用エイリアス
  strategy_layer.py    # 後方互換性用エイリアス
  scenario_loader.py
  benchmark_loader.py
  benchmarks/
  topology_loader.py
  topologies/
  scenarios/
  profiles/
    products/
  apps/
    streamlit_app.py   # GUIダッシュボードアプリケーション
  scripts/
  tests/
  output/              # ローカルで生成されるファイル群 (gitignored)
```

## ライセンス

本プロジェクトは PolyForm Noncommercial License 1.0.0 の下でライセンスされています。

CyberMatch Frameworkは、研究、教育、評価などの非営利目的でのみソースコードを利用できます。リポジトリ所有者からの別途の許可がない限り、商用利用は認められません。

詳細は [LICENSE](LICENSE) をご参照ください。
