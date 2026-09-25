# CyberMatch Framework

**CyberMatch v2.0.0** ・ [English README](README.md) ・ [ドキュメント案内](docs/README.md)

CyberMatch は、**攻撃者の意思決定プロセスを再現**し、防御戦略やセキュリティ製品を比較評価するためのサイバー意思決定シミュレータです。
「検知が発火したか」だけでなく、防御によって攻撃者が**何を信じ、何を選び、何を諦めたか**が変わったかを測ります。

## 3ステップで試す

```powershell
# 1. 環境構築(Python 3.12 以上)
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # Linux / macOS: source .venv/bin/activate
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e .

# 2. 評価を実行(環境確認 + ログのリプレイ評価 + 製品比較デモ、約2分)
python scripts/evaluate.py quickstart

# 3. 表示された EVALUATION_SUMMARY.md を開く
```

詳しくは [docs/01 クイックスタート](docs/01_quickstart.md) を参照してください。

## CyberMatch で答えられる問い

| 問い | 評価レーン |
|---|---|
| 攻撃者の目的(mission)によって、有効な防御製品は変わるか? | `product` / `standard` |
| Deception(欺瞞)は、攻撃者の信念・確信度・経路選択を変えたか? | `product`(Deception デモ) |
| 検知レシピは、攻撃を早く・少ない誤検知で捉えられるか? | `hunting` / `replay` |
| 検知結果を防御に反映する閉ループは、攻撃の成功を下げるか? | `hunting` / `resilience` |
| 自律 AI エージェントの境界逸脱を封じ込められるか? | `agentic` / `resilience` |
| 検知ロジックは、入力の揺らぎに対して頑健か? | `fuzzing` |

`python scripts/evaluate.py --list` で全レーンを表示できます。各レーンの詳細と結果の読み方は [docs/02 評価メニュー](docs/02_evaluation_menu.md) にあります。

## 全体像

```mermaid
flowchart LR
    subgraph Inputs[評価条件 JSON]
        SC[シナリオ<br/>業種・攻撃者]
        TP[トポロジ]
        PR[製品プロファイル]
        RC[検知レシピ]
        TL[記録済みログ<br/>OCSF / ECS / OTel]
    end
    subgraph Engine[CyberMatch]
        SIM[攻撃・防御<br/>シミュレータ]
        HUNT[脅威ハンティング<br/>評価器]
        AG[Agentic Security<br/>封じ込め]
        FZ[分析駆動<br/>ファジング]
    end
    subgraph Outputs[成果物]
        REP[日本語レポート<br/>比較表・ヒートマップ]
        EB[Evidence Bundle<br/>ハッシュ検証可能な証跡]
    end
    SC & TP & PR --> SIM
    RC & TL --> HUNT
    SC --> AG
    RC --> FZ
    SIM & HUNT & AG & FZ --> REP
    HUNT & AG & FZ --> EB
    REP --> GUI[Streamlit GUI]
    EB --> HITL[人間による最終判断<br/>HITL pilot]
```

## 攻撃者の意思決定モデル

```mermaid
flowchart LR
    I[Intent<br/>意図] --> M[Mission<br/>目的] --> T[Target<br/>標的] --> S[Strategy<br/>戦略] --> B[Behavior<br/>行動] --> A[Archetype<br/>類型]
```

| 概念 | 意味 |
|---|---|
| Mission | 攻撃者の目的。金銭獲得 (`profit`)、目標達成 (`achievement`)、継続的な潜伏 (`persistence`)、重要資産の探索 (`critical_hunter`) |
| Belief / Trust | 攻撃者が真だと考えていること / ノード・認証情報・経路を頼り続けるか |
| Deception | デコイ、偽の資産・経路、誤誘導シグナル |
| Coalition | 複数攻撃者の連携(調整コスト・情報損失を伴う) |
| Counter-Deception | 攻撃者の認識そのものを操作する防御 |

用語の一覧は [docs/08 用語集](docs/08_glossary.md) を参照してください。

## 主な機能

| 領域 | 内容 |
|---|---|
| 製品評価 | IDS / IPS / Honeypot / Deception / XDR などの製品プロファイルを、攻撃者の目的別に比較。「最強の製品」を決めるのではなく、**どの防御がどの目的の攻撃者の意思決定をどう変えるか**を理解する |
| シナリオ・ベンチマーク | 業種別シナリオ(金融・病院・クラウド・OT・中小企業)、トポロジ、標準ベンチマーク(500パターン) |
| 脅威ハンティング | 監査可能な検知レシピ、外部テレメトリ(CSV/JSONL)の取り込み、任意の ML 検知器、閉ループ評価 |
| Agentic Security | 自律エージェントの境界逸脱、脅威情報の汚染、共通原因故障、報酬ハックの評価([docs/04](docs/04_agentic_security.md)) |
| ファジング | 攻撃者の目的・意思決定経路に基づく意味的ファジング。決定的な再生と外部SUTアダプタ付き |
| 外部妥当性 | OCSF / ECS / OpenTelemetry 形式の記録ログを同じ評価器で再生し、合成評価との差を測定 |
| HITL pilot | 人間の事前承認 → 評価 → 説明(既定はオフラインのテンプレート、任意でローカル/外部 LLM) → 人間の最終判断 |

実製品・外部API・LLM への接続は必須ではありません。既定の評価はすべてオフラインで完結します。

## GUI ダッシュボード

```powershell
streamlit run apps/streamlit_app.py      # 評価・結果閲覧(サイドバーで日本語を選択)
streamlit run apps/pilot_web.py          # HITL pilot(人間の承認と最終判断を記録)
```

デモの実演手順は [scenarios/demos/README.md](scenarios/demos/README.md)、pilot の運用は [docs/03 外部評価実行手順書](docs/03_external_evaluation_guide.md) を参照してください。

## ドキュメント

| 目的 | 文書 |
|---|---|
| まず動かす | [01 クイックスタート](docs/01_quickstart.md) |
| 評価項目を選ぶ・結果を読む | [02 評価メニュー](docs/02_evaluation_menu.md) |
| 自組織のデータで評価する・LLM 説明を比較する | [03 外部評価実行手順書](docs/03_external_evaluation_guide.md) |
| AI エージェントの安全性評価 | [04 Agentic Security](docs/04_agentic_security.md) |
| 仕組み・連携 | [05 アーキテクチャ](docs/05_architecture.md) / [06 公開API方針](docs/06_public_api.md) / [07 依存関係方針](docs/07_dependency_policy.md) |
| 用語 | [08 用語集](docs/08_glossary.md) |

## リポジトリ構成

```text
cybermatch-framework/
├── README.md / README_JP.md   概要(英語 / 日本語)
├── docs/                      ドキュメント(番号順に読む)
├── scripts/                   CLI(evaluate.py = 評価メニューの入口)
├── apps/                      Streamlit GUI、HITL pilot UI
├── cybermatch_core/           安定した公開 API(外部連携はここを使う)
├── src/cybermatch/            実装本体(ローダー・意思決定モデルを含む)
├── scenarios/ benchmarks/ topologies/ profiles/ recipes/
│   mappings/ replays/ fuzzing/ protocols/ configs/   評価条件(JSON)
├── pilots/ models/            pilot 受付テンプレート、ローカル LLM 配置場所
├── tests/                     pytest
└── output/                    生成物(Git 管理外)
```

直下には設定ファイル(`pyproject.toml`、lock、`pytest.ini` など)だけを置いています。各ファイルの役割は [docs/05 アーキテクチャ](docs/05_architecture.md#リポジトリ直下のファイル) を参照してください。

> **v2.0.0 の変更:** 直下にあった Python モジュール(`scenario_loader.py`、`run_scenarios.py`、`cybermatch.py` など)は `src/cybermatch/` 配下へ移動しました。旧名で import しているコードは [docs/06 公開API方針 3章](docs/06_public_api.md#3-1x-からの移行200-の破壊的変更) の対応表に従って書き換えてください。

## ライセンス

本プロジェクトは **PolyForm Noncommercial License 1.0.0** で提供されます。

研究・教育・評価などの**非商用目的**で利用できます。商用利用には、リポジトリ所有者の別途許諾が必要です。
詳細は [LICENSE](LICENSE) を参照してください。
