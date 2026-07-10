# CyberMatch デモシナリオ

このディレクトリのJSONは、GUIの「デモシナリオ」からワンクリックで評価条件へ適用できる固定デモである。各デモはPhase6.3の選択評価を実行し、5分以内に結論を説明するための最小構成に絞る。

| ファイル | 伝える結論 | 評価条件 |
| --- | --- | --- |
| `demo_vendor_comparison.json` | missionにより適した製品プロファイルは変化する | enterprise、profit / achievement、IDS / IPS / XDR |
| `demo_deception_value.json` | Deceptionは攻撃者の迂回・無駄行動・撤退を変え得る | cloud_native、persistence / critical_hunter、Honeypot / Deception / XDR |
| `demo_ot_factory_defense.json` | 資産とトポロジにより防御優先順位は変化する | ot_environment、achievement / critical_hunter、IPS / Deception / XDR |

## 起動前の準備

以下のコマンドは、リポジトリのルートディレクトリで実行する。

```powershell
Set-Location <CyberMatchのリポジトリルート>
python --version
python -c "import streamlit; print(streamlit.__version__)"
```

`streamlit` が利用できない場合は、プロジェクトで使用するPython環境を有効化してから依存関係を導入する。

```powershell
python -m pip install -r requirements.txt
```

> `requirements.txt` には開発環境固有の依存関係が含まれる場合がある。既存の仮想環境がある場合は、その環境を使用する。

## GUIから起動する手順

### 1. Streamlitを起動する

リポジトリルートで次を実行する。

```powershell
python -m streamlit run apps/streamlit_app.py
```

起動後、ターミナルに表示されるLocal URLをブラウザで開く。通常はブラウザが自動的に開く。

### 2. 表示言語を選ぶ

画面左のサイドバーにある表示言語から、日本語またはEnglishを選択する。デモ説明は日本語表示を推奨する。

### 3. デモ条件を一括適用する

1. 左のナビゲーションから **実行** を開く。
2. 画面上部の **デモシナリオ** を開く。
3. 実施したいデモの説明と「デモで伝える結論」を確認する。
4. **このデモ条件を適用** を押す。
5. `適用中のデモ` が表示され、以下の条件が自動設定されたことを確認する。
   - topology
   - mission
   - product profile
   - seed

適用後も、表示されたmission、製品、topologyは手動で確認・変更できる。デモの再現性を保つため、説明時は適用直後の条件を変更しない。

### 4. 評価を実行する

1. 実行ページの **Phase6.3 Mission-Aware Product Evaluation を実行** を押す。
2. `Evaluation is running.` が表示されることを確認する。
3. 実行中のログは **Run log** を展開して確認する。
4. 完了メッセージが表示されたら、左のナビゲーションから **結果** を開く。

各固定デモはseedを`0`に固定している。実行時間はマシン性能に依存するが、デモで扱うmissionと製品を絞っているため、通常は5分以内の完走を想定する。

### 5. 結果を説明する

結果ページでは、次の順番で説明する。

1. **結論**: 選択条件での推奨候補とmission別候補を示す。
2. **理由**: mission success、campaign disruption、検知確率、攻撃者の迂回・無駄行動のうち、主な変化要因を示す。
3. **比較**: Product x Mission表とヒートマップで候補間の差を確認する。
4. **前提・制約**: `run_manifest.json` の入力条件と、モデル比較であることを説明する。

デモ中は、製品の「最強」や実環境効果の保証を主張しない。必ず「この条件では」「このmissionでは」という表現を使う。

## デモ別の説明ポイント

### `demo_vendor_comparison.json`

1. enterprise topology、`profit` / `achievement`、IDS / IPS / XDR が適用されていることを確認する。
2. mission別の推奨候補が同一か異なるかを結果ページで確認する。
3. 「一律な製品順位ではなく、攻撃者の目的に応じて比較する」と説明する。

### `demo_deception_value.json`

1. cloud-native topology、`persistence` / `critical_hunter`、Honeypot / Deception / XDR が適用されていることを確認する。
2. 理由セクションで、攻撃者の迂回・無駄行動またはcampaign disruptionへの影響を確認する。
3. 「Deceptionは成功率だけではなく、攻撃者の行動変容として価値を評価できる」と説明する。

### `demo_ot_factory_defense.json`

1. OT topology、`achievement` / `critical_hunter`、IPS / Deception / XDR が適用されていることを確認する。
2. Product x Mission比較で、重要資産・トポロジの前提に対する候補差を確認する。
3. 「業種・守る資産の条件が変われば、防御の優先順位も変わる」と説明する。

## CLIで実行する場合

GUIを使わずに、固定デモJSONをScenario Loader経由で実行できる。

```powershell
python scripts/run_scenario.py scenarios/demos/demo_vendor_comparison.json
python scripts/run_scenario.py scenarios/demos/demo_deception_value.json
python scripts/run_scenario.py scenarios/demos/demo_ot_factory_defense.json
```

選択済みのmission、製品、topology、seedだけを評価し、出力先は各JSONで指定された `output/phase63_mission_products/` になる。

個別に条件を指定する場合は、Phase6.3用CLIを使う。

```powershell
python scripts/run_phase63.py --mission profit --mission achievement --product profiles/products/sample_ids.json --product profiles/products/sample_ips.json --product profiles/products/sample_xdr.json --topology enterprise --seed 0
```

## 出力と再現方法

評価結果は既定で次のディレクトリへ生成される。

```text
output/phase63_mission_products/
```

特に確認するファイルは次のとおり。

| ファイル | 用途 |
| --- | --- |
| `run_manifest.json` | mission、製品、topology、seedなど実行条件の記録 |
| `mission_product_summary.csv` | Product x Missionの集計値 |
| `mission_product_summary.json` | 集計値と分析結果 |
| `PHASE63_MISSION_PRODUCT_REPORT.md` | Markdown形式の評価レポート |

同じ出力先で次の評価を実行すると、既存の集計ファイルは更新される。デモ結果を保存する場合は、実行後に出力ディレクトリを別の場所へコピーするか、ダウンロード機能でCSV、JSON、Markdown、manifestを保存する。

## トラブルシュート

| 状況 | 確認・対応 |
| --- | --- |
| `No module named streamlit` | 正しいPython環境を有効化し、`python -m pip install -r requirements.txt` を実行する。 |
| ブラウザが開かない | ターミナルに表示されたLocal URLを手動で開く。 |
| 実行ボタンが押せない | 実行中の評価がないか確認し、必要に応じて **実行を停止** を使う。 |
| 結果が表示されない | 実行ページのRun logでエラーを確認し、`output/phase63_mission_products/` にsummaryファイルが生成されているか確認する。 |
| 選択条件が不明 | 結果ページの **前提・制約** にある `run_manifest.json` を確認する。 |
| デモの結論が変わった | manifest、seed、mission、製品、topologyがデモ定義と一致しているか確認する。 |

## 注意事項

- 結果は記録された条件とモデル仮定に基づく比較評価であり、実製品の認証ではない。
- デモの結論は説明すべき論点であり、特定製品の優劣を断定するものではない。
