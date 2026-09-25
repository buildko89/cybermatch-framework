# 05. アーキテクチャ

## 1. 基本方針

CyberMatch は、グラフやシミュレーション履歴だけでなく、**監査可能な証跡 (auditable evidence)** を主な成果物とする評価ワークベンチです。
依存の向きは上位から下位への一方向です。

```mermaid
flowchart TD
    UI["CLI / Streamlit<br/>scripts/, apps/"] --> APP["アプリケーションサービス<br/>src.cybermatch.application"]
    APP --> WF["評価ワークフロー<br/>evaluation / agentic / threat_hunting / fuzzing / pilot"]
    WF --> DOM["シミュレーションとドメインモデル<br/>simulation / attacker / defense / models<br/>decision_model / loaders"]
    DOM --> CON["版管理された契約とスキーマ<br/>contracts / schemas"]
    FAC["cybermatch_core<br/>(2.x 安定ファサード)"] -.再エクスポート.-> WF
    FAC -.再エクスポート.-> CON
    EXT["外部利用者・連携システム"] --> FAC
```

- `cybermatch_core` パッケージが **2.x 系の安定ファサード**です。実装はすべて `src.cybermatch` 配下にあります。
- 2.0.0 でリポジトリ直下の Python モジュールを廃止し、直下は設定ファイルとドキュメントだけになりました。旧名からの移行表は [06 公開API方針 3章](06_public_api.md#3-1x-からの移行200-の破壊的変更) を参照してください。

## 2. ディレクトリと責務

```text
cybermatch-framework/
├── cybermatch_core/        安定ファサード(外部連携はここだけを使う)
├── src/cybermatch/
│   ├── contracts/          canonical JSON・SHA-256・EvaluationRun・Evidence Bundle・スキーマレジストリ
│   ├── schemas/            版管理された JSON Schema(資産・pilot・mapping 等)
│   ├── simulation/         攻撃・防御シミュレータ本体と純粋な確率演算
│   ├── attacker/ defense/  攻撃者モデル、防御戦略(ILP/MPC)
│   ├── models/ config/     製品プロファイル、シミュレーション設定
│   ├── decision_model/     攻撃者の意思決定モデル(意図推定・行動プロファイル・特徴空間・類型・分類体系・戦略検証・意思決定グラフ)
│   ├── loaders/            シナリオ・ベンチマーク・トポロジ JSON のローダー
│   ├── evaluation/         Phase 別評価ランナー、統計・成果物 I/O ヘルパー
│   ├── threat_hunting/     防御側ハンティング(レシピ・評価器・外部テレメトリ・閉ループ)
│   ├── agentic/            Agentic Security(封じ込め・学習・完全性ゲート・統計プロトコル)
│   ├── fuzzing/            分析駆動ファジング(変異・オラクル・ターゲット・外部SUT)
│   ├── pilot/              HITL pilot(承認・ResultView・LLM説明・shadow比較)
│   ├── application/        GUI から使うプロセス制御・結果探索
│   ├── visualization/      グラフ描画
│   └── external_sut.py     外部SUT契約とリプレイ評価
├── apps/                   Streamlit GUI(streamlit_app.py)、HITL pilot UI(pilot_web.py)
├── scripts/                CLI エントリポイント(evaluate.py が評価メニューの入口)
├── scenarios/ benchmarks/ topologies/ profiles/ recipes/
│   mappings/ replays/ fuzzing/ protocols/ configs/   … 評価条件(JSON 資産)
├── tests/                  pytest(マーカーで機能別に実行可能)
└── output/                 生成物(Git 管理外)
```

### リポジトリ直下のファイル

2.0 以降、直下には Python モジュールを置かず、ツールが直下にあることを前提とする設定ファイルだけを置きます。

| ファイル | 役割 | 直下に置く理由 |
|---|---|---|
| `pyproject.toml` | パッケージ定義・依存範囲・CLI エントリポイント | Python パッケージングの規格上、直下が必須 |
| `requirements.lock` | 実行時依存の固定版 | Evidence Bundle が依存 lock のハッシュを記録する際にこの位置を参照 |
| `requirements-dev.lock` | 開発・テスト用依存の固定版 | CI のインストールとキャッシュキーがこの位置を参照 |
| `requirements.txt` | `-r requirements.lock` だけを含む互換入口 | 旧来の `pip install -r requirements.txt` 手順との互換 |
| `pytest.ini` | テストマーカーと探索除外の設定 | pytest がルートディレクトリの設定として読み込む |
| `.env.example` | pilot 用環境変数のひな形(実際の `.env` は Git 管理外) | pilot のローダーが直下の `.env` を読む |
| `.gitignore` / `.gitmodules` | Git の設定 | Git の規約 |
| `LICENSE` / `README.md` / `README_JP.md` | ライセンス・概要 | GitHub が直下を表示 |

`__pycache__/`、`build/`、`dist/`、`*.egg-info/`、`.venv*/`、`output/` はローカルで生成されるもので、Git 管理外です。不要になったら削除して構いません。

## 3. Phase 1 で設けた境界(構造分離の第一段階)

| モジュール | 役割 |
|---|---|
| `src.cybermatch.contracts` | canonical JSON、ハッシュ、実行マニフェスト、指標、Evidence Bundle、スキーマレジストリ |
| `src.cybermatch.evaluation.statistics` / `artifact_io` | 巨大な評価ランナーから切り出した、純粋関数/副作用を限定したヘルパー |
| `src.cybermatch.simulation.probability` | シミュレータから最初に切り出した純粋な状態演算 |
| `src.cybermatch.application.process_control` / `artifacts` | Streamlit 層がプロセスのライフサイクル管理と結果探索を委譲する先 |
| `scripts/validate_assets.py` | 登録済みの全 JSON 資産を検証する CI・運用者向けの入口 |

以降の分割は、これらテスト済みの継ぎ目 (seam) の内側で進めます。
`runner.py`(約2.1万行)や `simulator.py`(約5千行)の全面書き換えは、振る舞いの変更と構造の変更が混ざるため Phase 1 の対象外としています。

## 4. 版管理されたデータの流れ

すべての評価は最終的に `EvaluationRun` と `EvidenceBundle` に集約されることを目指しています。

```mermaid
flowchart LR
    IN["入力 JSON<br/>scenario / benchmark / recipe / mapping"] -->|SchemaRegistry で検証| RUN[評価ワークフロー]
    SEED[seed 集合] --> RUN
    RUN --> ART["ドメイン固有の成果物<br/>summary.json / report.md / csv"]
    ART --> EB["EvidenceBundle<br/>契約バージョン + canonical SHA-256"]
    META["コード revision<br/>依存 lock のハッシュ<br/>入力ハッシュ<br/>再生手順"] --> EB
    EB --> V["load_evidence_bundle()<br/>ハッシュ・サイズを再検証"]
```

- 入力は `SchemaRegistry` で検査されます。
- 出力は契約バージョンと canonical SHA-256 ハッシュを持ちます。
- ドメイン固有の成果物は残してよいですが、マニフェストは**ハッシュを変えずに**共通の証跡レコードを参照できる必要があります。

### Evidence Bundle の検証

```powershell
python -c "from cybermatch_core.contracts import load_evidence_bundle; print(load_evidence_bundle('output/evaluations/<run-id>/replay').bundle_hash)"
```

`scripts/evaluate.py` は、Evidence Bundle を出すレーン(`replay` / `resilience` / `fuzzing`)でこの検証を自動実行します。

## 5. Phase 2: フラッグシップ・プロトコル

```mermaid
flowchart LR
    S["同一 seed の実現値"] --> M1[no_defense]
    S --> M2[static_defense]
    S --> M3[hunting_only]
    S --> M4[containment_only]
    S --> M5[closed_loop]
    S --> M6[active_deception]
    M1 & M2 & M3 & M4 & M5 & M6 --> P["agentic.protocol<br/>分布・95%信頼区間・対応効果量<br/>感度分析・失敗領域"]
    IC["独立性チェック"] --> P
    P --> EB[Evidence Bundle]
```

| 要素 | 内容 |
|---|---|
| `agentic.mode_runner` | 潜在/実際のイベントを検知器のテレメトリと分離し、同一 seed の実現値を6つの防御モードで評価 |
| `agentic.protocol` | 分布、95%信頼区間、対応ランク双列相関による効果量、標準の感度軸、再現された失敗領域を報告 |
| 独立性チェック | オラクル用フィールド、未来の証拠、ラベルを含むID、観測されていないイベントを引用する Finding を実行時に拒否 |

Agentic ベンチマークの成果物とファジングの反例は、共通の Evidence Bundle を使います。
Bundle には、コード revision、依存 lock のハッシュ、入力ハッシュ、seed 集合、再生手順、各成果物のハッシュが記録されます。

## 6. 現在の制約

| 制約 | 状況 |
|---|---|
| 共通 Evidence Bundle への移行 | 既存ワークフローのすべてがまだ出力しているわけではない(`product` / `standard` / `hunting` / `agentic` は未対応)。契約と移行境界は用意済みで、段階的に適用する |
| `src` 名前空間 | 実装パッケージ名は `src.cybermatch` のまま。`cybermatch` への改名は今後のメジャーバージョンで扱う |
| 標準ベンチマークの基準値 | `output/phase63_mission_products/` の既存結果を読み込む。`evaluate.py` は毎回再生成して回避([02 評価メニュー 3.4](02_evaluation_menu.md#34-standard--標準ベンチマーク)) |
| OS 検証 | Ubuntu での動作は push 後の GitHub Actions で検証。ローカル検証は Windows |
