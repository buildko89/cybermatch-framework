# CyberMatchとは

**CyberMatch v1.0.1**

CyberMatch は、「攻撃者の意思決定を再現し、防御戦略やセキュリティ製品を比較評価できるサイバー意思決定シミュレータ」です。

CyberMatch は、単に ATT&CK technique を再生したり、検知が発火したかを確認したりするためのツールではありません。防御が攻撃者の mission success、belief、state、trust、confidence、path choice、coalition behavior にどのような影響を与えたかを評価します。

[English README](README.md)

## 解決したい課題

- ATT&CK replay だけでは、攻撃者の判断変化や mission outcome まで評価しにくい。
- 検知有無だけでは、防御が攻撃者の意思決定を変えたか分からない。
- Deception、counter-deception、coalition、hunting を含む campaign-level evaluation が必要。
- IDS、IPS、honeypot、deception platform、XDR などを、共通の評価軸で比較したい。

## 主な特徴

- **Intent**: financial gain、espionage、disruption、long-term presence などの高位目的を扱う。
- **Mission**: profit、achievement、persistence、critical hunter などの攻撃目的を扱う。
- **Target**: identity infrastructure、cloud control plane、backup system、trust relationship などの攻撃対象を扱う。
- **Strategy**: target-specific な攻撃アプローチを扱う。
- **Belief**: 攻撃者や防御側が何を真だと考えているかを扱う。
- **State**: campaign phase や defender policy selection に使う状態を扱う。
- **Trust**: node、credential、path、coalition partner への信頼を評価する。
- **Deception**: decoy、fake asset、fake path、intent masking を扱う。
- **Coalition**: 複数攻撃者、handover、coordination cost、information loss を扱う。
- **Counter-Deception**: 防御側が攻撃者の認識を能動的に操作する。
- **Awareness**: 攻撃者が deception に気づく条件を扱う。
- **Hunting**: 攻撃者が deception を探索・検証する行動を扱う。
- **Product Evaluation**: 製品カテゴリ、製品プロファイル、mission-aware evaluation を扱う。

## CyberMatch Decision Model

攻撃者意思決定モデルを次の階層として整理しています。

```text
Intent
  -> Mission
  -> Target
  -> Strategy
  -> Behavior
  -> Archetype
```

このモデルは分析層です。Runtime Delegation、Defense Concept実行、RL、LLM、外部API、新しい攻撃者・防御者ロジックは追加していません。

## ユースケース

- **SOC**: 防御施策が攻撃者の mission success をどれだけ下げるかを評価する。
- **CSIRT**: incident response や deception 戦略の効果を campaign 視点で比較する。
- **Purple Team**: ATT&CK replay の結果に加えて、攻撃者意思決定への影響を測る。
- **Security Product Evaluation**: IDS、IPS、honeypot、deception、XDR を共通指標で比較する。
- **Research Platform**: attacker-defender co-evolution、counter-deception、coalition を再現可能に研究する。

## CyberMatch Architecture

```text
Scenario / Configuration / Product Profiles
                |
                v
+------------------------------------------+
| Layer 1: Attacker Modeling               |
| adaptive, rational, coalition, hunting   |
+------------------------------------------+
                |
                v
+------------------------------------------+
| Layer 2: Mission / Belief / State        |
| mission objective, confidence, trust     |
+------------------------------------------+
                |
                v
+------------------------------------------+
| Layer 3: Defense Campaign                |
| adaptive defense, intelligence, topology |
+------------------------------------------+
                |
                v
+------------------------------------------+
| Layer 4: Counter-Deception               |
| intent deception, awareness, hunting     |
+------------------------------------------+
                |
                v
+------------------------------------------+
| Layer 5: Product Evaluation              |
| categories, profiles, mission matrix     |
+------------------------------------------+
                |
                v
Artifacts: CSV / JSON / PNG / Markdown reports
```

## 環境構築とGUIの起動方法 (Quick Start)

CyberMatch は、Pythonベースのシミュレータエンジンと、評価結果をブラウザ上で確認できる Streamlit のGUIダッシュボードを備えています。

### 1. 動作環境のセットアップ

Python 3.12 互換環境を推奨します。

#### Windowsの場合
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

#### WSL2 / Linuxの場合
```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

#### 動作確認テスト (Smoke Test)
環境が正しく構築できたか確認するために、以下のテストを実行してください。
```bash
python scripts/run_tests.py --smoke
```

### 2. GUI（ダッシュボード）の起動方法

評価の実行や結果の確認は、Streamlit を用いたダッシュボードからブラウザ上で視覚的に行えます。以下のコマンドを実行してください。

```bash
streamlit run apps/streamlit_app.py
```

実行すると、ターミナルに以下のようなURLが表示されます。
```text
  Local URL: http://localhost:8501
  Network URL: http://192.168.x.x:8501
```
お使いのブラウザで `http://localhost:8501` にアクセスすると、CyberMatch の GUIダッシュボードが表示されます。画面左のサイドバーから「日本語」と「English」の表示言語を切り替えることができます。

#### GUIダッシュボードでできること
- **Scenario**: 評価条件ファイル（JSON）の確認と読み込み
- **Products**: 比較対象となる各防御策（製品）プロファイルの確認
- **Run**: シミュレーションの実行（評価条件の適用や手動実行）
- **Results**: シミュレーション結果の確認（目的に応じた最適な防御策の比較やヒートマップ表示、レポートのダウンロード）

## 代表実験とCLIでの実行

GUIだけでなく、コマンドライン（CLI）から直接各種評価シミュレーションを実行することも可能です。以下は代表的なシミュレーションの実行例です。

> **Note**: これまでの大規模リファクタリングにより主要なコードは `src/` 配下に移動しましたが、ルートの `cybermatch.py` および `run_scenarios.py` は後方互換性のためのエイリアスとして残されています。そのため、既存の実行コマンドや使い方は変更なくそのまま動作します。

### Active Defense 評価
Intelligence-driven active defense のシミュレーションを評価します。
```bash
python scripts/run_phase4.py --quick
```

### Coalition & Counter-Deception 評価
複数攻撃者(Coalition)、counter-deception、awareness、hunting を評価します。
```bash
python scripts/run_tests.py --phase phase5
```

### Mission-Aware Product Evaluation (防御策の比較評価)
製品プロファイルを読み込み、攻撃者の目的（Mission）ごとにどの防御策が有効かを評価します。（※この評価はGUIの「Run」画面からも実行可能です）
```bash
python scripts/run_scenarios.py
# または特定のシナリオを指定する場合
python scripts/run_scenario.py scenarios/mission_product_eval_basic.json
```

### Scenario Catalog & Benchmark Suite
金融、医療、クラウドネイティブ、工場など、複数のシナリオプリセットを用いた横断的なベンチマーク評価を行います。

シナリオカタログの確認:
```bash
python scripts/run_scenario.py --list
```
標準ベンチマークスイートの実行:
```bash
python scripts/run_scenario.py benchmarks/cybermatch_standard_v1.json
```

### Topology Evaluation
企業ネットワークの構成（Topology）の違いによる影響を評価します。
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
      attacker/          # 攻撃者モデル
      config/            # シミュレーション設定
      defense/           # 防御戦略や最適化エンジン
      evaluation/        # シナリオ実行・評価エンジン
      models/            # データモデル (ProductProfileなど)
      simulation/        # シミュレータ本体
      visualization/     # 可視化モジュール
  cybermatch.py          # 後方互換性用エイリアス
  run_scenarios.py       # 後方互換性用エイリアス
  strategy_layer.py      # 後方互換性用エイリアス
  scenario_loader.py
  benchmark_loader.py
  benchmarks/            # ベンチマーク設定
  topologies/            # ネットワーク構成設定
  scenarios/             # シナリオ設定
  profiles/              # 防御策などのプロファイル定義
  apps/
    streamlit_app.py     # GUIダッシュボードのメインアプリケーション
  scripts/               # CLI用の実行スクリプト群
  tests/                 # テストコード
  output/                # 実行結果出力先 (gitignored)
```

## 今後のロードマップ

v1.0 に向けた主な方向性:

- Scenario import と reusable scenario catalog
- Enterprise topology library
- Trust network layer
- Human behavior layer
- Product plugin integration
- Scenario-specific product evaluation
- Reproducible benchmark suite
