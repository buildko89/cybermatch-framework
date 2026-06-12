# CyberMatchとは

CyberMatch は、「攻撃者の意思決定を再現し、防御戦略やセキュリティ製品を比較評価できるサイバー意思決定シミュレータ」です。

CyberMatch は、単に ATT&CK technique を再生したり、検知が発火したかを確認したりするためのツールではありません。防御が攻撃者の mission success、belief、state、trust、confidence、path choice、coalition behavior にどのような影響を与えたかを評価します。

[English README](README.md)

## 解決したい課題

- ATT&CK replay だけでは、攻撃者の判断変化や mission outcome まで評価しにくい。
- 検知有無だけでは、防御が攻撃者の意思決定を変えたか分からない。
- Deception、counter-deception、coalition、hunting を含む campaign-level evaluation が必要。
- IDS、IPS、honeypot、deception platform、XDR などを、共通の評価軸で比較したい。

## 主な特徴

- **Mission**: profit、achievement、persistence、critical hunter などの攻撃目的を扱う。
- **Belief**: 攻撃者や防御側が何を真だと考えているかを扱う。
- **State**: campaign phase や defender policy selection に使う状態を扱う。
- **Trust**: node、credential、path、coalition partner への信頼を評価する。
- **Deception**: decoy、fake asset、fake path、intent masking を扱う。
- **Coalition**: 複数攻撃者、handover、coordination cost、information loss を扱う。
- **Counter-Deception**: 防御側が攻撃者の認識を能動的に操作する。
- **Awareness**: 攻撃者が deception に気づく条件を扱う。
- **Hunting**: 攻撃者が deception を探索・検証する行動を扱う。
- **Product Evaluation**: 製品カテゴリ、製品プロファイル、mission-aware evaluation を扱う。

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

詳細は [CyberMatch Architecture](docs/CYBERMATCH_ARCHITECTURE.md) を参照してください。

## Quick Start

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python scripts/run_tests.py --smoke
```

### WSL2

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/run_tests.py --smoke
```

### Python

Python 3.12 互換環境を推奨します。主要依存関係は `requirements.txt` に定義されています。

### pytest

通常の開発では smoke または phase-specific profile を使います。

```bash
python scripts/run_tests.py --smoke
python scripts/run_tests.py --phase phase5
python -m pytest
```

## 代表実験

### Phase4

Intelligence-driven active defense を評価します。

```bash
python scripts/run_phase4.py --quick
```

### Phase5

Coalition、counter-deception、awareness、hunting を評価します。

```bash
python scripts/run_tests.py --phase phase5
```

### Phase6

Product Interface、Product Profile、Mission-Aware Product Evaluation を評価します。

代表的な出力先:

- `output/phase61_product_interface/`
- `output/phase62_product_profiles/`
- `output/phase63_mission_products/`

## ドキュメント

- [Documentation Index](docs/INDEX.md)
- [Vision](docs/CYBERMATCH_VISION.md)
- [Architecture](docs/CYBERMATCH_ARCHITECTURE.md)
- [Status](docs/CYBERMATCH_STATUS.md)
- [End State](docs/CYBERMATCH_END_STATE.md)
- [Use Cases](docs/CYBERMATCH_USE_CASES.md)
- [Roadmap](docs/CYBERMATCH_ROADMAP.md)
- [Reproducibility](docs/REPRODUCIBILITY.md)

## 今後のロードマップ

v1.0 に向けた主な方向性:

- Scenario import と reusable scenario catalog
- Enterprise topology library
- Trust network layer
- Human behavior layer
- Product plugin integration
- Scenario-specific product evaluation
- Reproducible benchmark suite

CyberMatch の到達点と制約は [CyberMatch Status](docs/CYBERMATCH_STATUS.md) にまとめています。
