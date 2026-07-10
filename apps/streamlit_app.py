"""Streamlit MVP for CyberMatch product evaluation artifacts.

This app is intentionally thin: it calls existing Phase6 runners and reads
existing artifact files. It does not add simulation logic.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import streamlit as st


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PRODUCT_PROFILE_DIR = ROOT / "profiles" / "products"
SCENARIO_DIR = ROOT / "scenarios"
SCENARIO_CATALOG_DIR = SCENARIO_DIR / "catalog"
DEMO_SCENARIO_DIR = SCENARIO_DIR / "demos"
BENCHMARK_DIR = ROOT / "benchmarks"
TOPOLOGY_DIR = ROOT / "topologies"
PHASE63_OUTPUT_DIR = ROOT / "output" / "phase63_mission_products"
PHASE62_OUTPUT_DIR = ROOT / "output" / "phase62_product_profiles"
PHASE83_OUTPUT_DIR = ROOT / "output" / "phase83_benchmark_suite"
PHASE85_OUTPUT_DIR = ROOT / "output" / "phase85_standard_benchmark"
PHASE90_OUTPUT_DIR = ROOT / "output" / "phase90_intent_inference"
PHASE91_OUTPUT_DIR = ROOT / "output" / "phase91_behavior_profiles"
PHASE92_OUTPUT_DIR = ROOT / "output" / "phase92_feature_space"
PHASE93_OUTPUT_DIR = ROOT / "output" / "phase93_profilecore"
PHASE94_OUTPUT_DIR = ROOT / "output" / "phase94_archetype_interpretation"
PHASE95_OUTPUT_DIR = ROOT / "output" / "phase95_strategy_layer"
PHASE96_OUTPUT_DIR = ROOT / "output" / "phase96_taxonomy"
PHASE97_OUTPUT_DIR = ROOT / "output" / "phase97_target_strategy"
PHASE98_OUTPUT_DIR = ROOT / "output" / "phase98_strategy_validation"
PHASE99_OUTPUT_DIR = ROOT / "output" / "phase99_decision_graph"
PHASE63_LOG_PATH = PHASE63_OUTPUT_DIR / "streamlit_phase63_run.log"
PHASE62_LOG_PATH = PHASE62_OUTPUT_DIR / "streamlit_phase62_run.log"
PHASE83_LOG_PATH = PHASE83_OUTPUT_DIR / "streamlit_phase83_run.log"
PHASE85_LOG_PATH = PHASE85_OUTPUT_DIR / "streamlit_phase85_run.log"

PHASE63_ARTIFACTS = {
    "summary_csv": PHASE63_OUTPUT_DIR / "mission_product_summary.csv",
    "summary_json": PHASE63_OUTPUT_DIR / "mission_product_summary.json",
    "manifest": PHASE63_OUTPUT_DIR / "run_manifest.json",
    "heatmap": PHASE63_OUTPUT_DIR / "mission_product_heatmap.png",
    "variance": PHASE63_OUTPUT_DIR / "mission_variance.png",
    "phase62_comparison": PHASE63_OUTPUT_DIR / "phase63_vs_phase62.png",
    "report": PHASE63_OUTPUT_DIR / "PHASE63_MISSION_PRODUCT_REPORT.md",
}

PHASE83_ARTIFACTS = {
    "summary_csv": PHASE83_OUTPUT_DIR / "benchmark_summary.csv",
    "summary_json": PHASE83_OUTPUT_DIR / "benchmark_summary.json",
    "ranking": PHASE83_OUTPUT_DIR / "benchmark_product_ranking.png",
    "scenario_heatmap": PHASE83_OUTPUT_DIR / "benchmark_scenario_heatmap.png",
    "mission_heatmap": PHASE83_OUTPUT_DIR / "benchmark_mission_heatmap.png",
    "consistency": PHASE83_OUTPUT_DIR / "benchmark_consistency.png",
    "report": PHASE83_OUTPUT_DIR / "PHASE83_BENCHMARK_SUITE_REPORT.md",
}

PHASE85_ARTIFACTS = {
    "summary_csv": PHASE85_OUTPUT_DIR / "standard_benchmark_summary.csv",
    "summary_json": PHASE85_OUTPUT_DIR / "standard_benchmark_summary.json",
    "ranking": PHASE85_OUTPUT_DIR / "standard_product_ranking.png",
    "scenario_heatmap": PHASE85_OUTPUT_DIR / "standard_scenario_heatmap.png",
    "topology_heatmap": PHASE85_OUTPUT_DIR / "standard_topology_heatmap.png",
    "mission_heatmap": PHASE85_OUTPUT_DIR / "standard_mission_heatmap.png",
    "report": PHASE85_OUTPUT_DIR / "PHASE85_STANDARD_BENCHMARK_REPORT.md",
}

PHASE90_ARTIFACTS = {
    "summary_csv": PHASE90_OUTPUT_DIR / "intent_inference_summary.csv",
    "summary_json": PHASE90_OUTPUT_DIR / "intent_inference_summary.json",
    "confusion_matrix": PHASE90_OUTPUT_DIR / "mission_confusion_matrix.png",
    "accuracy": PHASE90_OUTPUT_DIR / "mission_accuracy.png",
    "confidence": PHASE90_OUTPUT_DIR / "mission_confidence_distribution.png",
    "report": PHASE90_OUTPUT_DIR / "PHASE90_INTENT_INFERENCE_REPORT.md",
}

PHASE91_ARTIFACTS = {
    "summary_csv": PHASE91_OUTPUT_DIR / "behavior_profile_summary.csv",
    "summary_json": PHASE91_OUTPUT_DIR / "behavior_profile_summary.json",
    "distribution": PHASE91_OUTPUT_DIR / "profile_distribution.png",
    "confidence": PHASE91_OUTPUT_DIR / "profile_confidence_distribution.png",
    "relationship": PHASE91_OUTPUT_DIR / "profile_mission_relationship.png",
    "report": PHASE91_OUTPUT_DIR / "PHASE91_BEHAVIOR_PROFILE_REPORT.md",
}

PHASE92_ARTIFACTS = {
    "summary_csv": PHASE92_OUTPUT_DIR / "feature_space_summary.csv",
    "summary_json": PHASE92_OUTPUT_DIR / "feature_space_summary.json",
    "dominance": PHASE92_OUTPUT_DIR / "feature_dominance.png",
    "mission_heatmap": PHASE92_OUTPUT_DIR / "mission_feature_heatmap.png",
    "profile_heatmap": PHASE92_OUTPUT_DIR / "profile_feature_heatmap.png",
    "critical_path_bias": PHASE92_OUTPUT_DIR / "critical_path_bias.png",
    "report": PHASE92_OUTPUT_DIR / "PHASE92_FEATURE_SPACE_REPORT.md",
}

PHASE93_ARTIFACTS = {
    "summary_csv": PHASE93_OUTPUT_DIR / "profilecore_feature_projection.csv",
    "summary_json": PHASE93_OUTPUT_DIR / "profilecore_analysis.json",
    "pca_variance": PHASE93_OUTPUT_DIR / "pca_variance.png",
    "component_loadings": PHASE93_OUTPUT_DIR / "component_loadings.png",
    "feature_projection": PHASE93_OUTPUT_DIR / "feature_projection.png",
    "archetype_distribution": PHASE93_OUTPUT_DIR / "archetype_distribution.png",
    "report": PHASE93_OUTPUT_DIR / "PHASE93_PROFILECORE_REPORT.md",
}
PHASE94_ARTIFACTS = {
    "summary_csv": PHASE94_OUTPUT_DIR / "archetype_summary.csv",
    "summary_json": PHASE94_OUTPUT_DIR / "archetype_summary.json",
    "feature_comparison": PHASE94_OUTPUT_DIR / "archetype_feature_comparison.png",
    "mission_distribution": PHASE94_OUTPUT_DIR / "archetype_mission_distribution.png",
    "profile_distribution": PHASE94_OUTPUT_DIR / "archetype_profile_distribution.png",
    "distance_matrix": PHASE94_OUTPUT_DIR / "archetype_distance_matrix.png",
    "report": PHASE94_OUTPUT_DIR / "PHASE94_ARCHETYPE_INTERPRETATION_REPORT.md",
}
PHASE95_ARTIFACTS = {
    "summary_csv": PHASE95_OUTPUT_DIR / "strategy_summary.csv",
    "summary_json": PHASE95_OUTPUT_DIR / "strategy_summary.json",
    "strategy_distribution": PHASE95_OUTPUT_DIR / "strategy_distribution.png",
    "mission_strategy_matrix": PHASE95_OUTPUT_DIR / "mission_strategy_matrix.png",
    "strategy_archetype_matrix": PHASE95_OUTPUT_DIR / "strategy_archetype_matrix.png",
    "strategy_profile_matrix": PHASE95_OUTPUT_DIR / "strategy_profile_matrix.png",
    "report": PHASE95_OUTPUT_DIR / "PHASE95_STRATEGY_LAYER_REPORT.md",
}
PHASE96_ARTIFACTS = {
    "summary_csv": PHASE96_OUTPUT_DIR / "taxonomy_summary.csv",
    "summary_json": PHASE96_OUTPUT_DIR / "taxonomy_summary.json",
    "intent_mission_matrix": PHASE96_OUTPUT_DIR / "intent_mission_matrix.png",
    "mission_target_matrix": PHASE96_OUTPUT_DIR / "mission_target_matrix.png",
    "target_strategy_matrix": PHASE96_OUTPUT_DIR / "target_strategy_matrix.png",
    "report": PHASE96_OUTPUT_DIR / "PHASE96_TAXONOMY_REPORT.md",
}
PHASE97_ARTIFACTS = {
    "summary_json": PHASE97_OUTPUT_DIR / "target_strategy_summary.json",
    "target_strategy_matrix": PHASE97_OUTPUT_DIR / "target_strategy_matrix.png",
    "strategy_distribution": PHASE97_OUTPUT_DIR / "strategy_distribution.png",
    "strategy_diversity": PHASE97_OUTPUT_DIR / "strategy_diversity.png",
    "target_specificity": PHASE97_OUTPUT_DIR / "target_specificity.png",
    "strategy_alignment": PHASE97_OUTPUT_DIR / "strategy_alignment.png",
    "report": PHASE97_OUTPUT_DIR / "PHASE97_TARGET_STRATEGY_REPORT.md",
}
PHASE98_ARTIFACTS = {
    "summary_csv": PHASE98_OUTPUT_DIR / "strategy_validation_summary.csv",
    "summary_json": PHASE98_OUTPUT_DIR / "strategy_validation_summary.json",
    "distance_matrix": PHASE98_OUTPUT_DIR / "strategy_distance_matrix.png",
    "distinctiveness": PHASE98_OUTPUT_DIR / "strategy_distinctiveness.png",
    "redundancy": PHASE98_OUTPUT_DIR / "strategy_redundancy.png",
    "target_validation": PHASE98_OUTPUT_DIR / "target_strategy_validation.png",
    "mission_explainability": PHASE98_OUTPUT_DIR / "mission_strategy_explainability.png",
    "report": PHASE98_OUTPUT_DIR / "PHASE98_STRATEGY_VALIDATION_REPORT.md",
}
PHASE99_ARTIFACTS = {
    "summary_csv": PHASE99_OUTPUT_DIR / "decision_graph_summary.csv",
    "summary_json": PHASE99_OUTPUT_DIR / "decision_graph_summary.json",
    "decision_graph": PHASE99_OUTPUT_DIR / "decision_graph.png",
    "intent_mission": PHASE99_OUTPUT_DIR / "intent_mission_graph.png",
    "mission_target": PHASE99_OUTPUT_DIR / "mission_target_graph.png",
    "target_strategy": PHASE99_OUTPUT_DIR / "target_strategy_graph.png",
    "strategy_behavior": PHASE99_OUTPUT_DIR / "strategy_behavior_graph.png",
    "report": PHASE99_OUTPUT_DIR / "PHASE99_DECISION_GRAPH_REPORT.md",
}

PROFILE_COLUMNS = [
    "name",
    "category",
    "detection_boost",
    "interruption_boost",
    "diversion_boost",
    "confidence_boost",
    "false_positive_penalty",
    "latency_penalty",
    "maintenance_penalty",
]

MISSION_OPTIONS = ["profit", "achievement", "persistence", "critical_hunter"]
MISSION_LABELS = {
    "profit": "金銭獲得",
    "achievement": "目標達成",
    "persistence": "継続的な潜伏",
    "critical_hunter": "重要資産の探索",
}
PRODUCT_CATEGORY_LABELS = {
    "ids": "IDS（侵入検知）",
    "ips": "IPS（侵入防御）",
    "honeypot": "ハニーポット",
    "deception": "デセプション",
    "xdr": "XDR（統合検知・対応）",
}
TOPOLOGY_LABELS = {
    "cloud_native": "クラウドネイティブ企業",
    "enterprise": "一般的な企業ネットワーク",
    "hospital_network": "病院ネットワーク",
    "ot_environment": "OT・工場環境",
    "small_business": "小規模事業者環境",
}
TOPOLOGY_DESCRIPTIONS = {
    "cloud_native": "ID基盤への依存が高く、資産構成が変化しやすいクラウド中心の環境です。",
    "enterprise": "集中したID基盤と複数の業務資産を持つ、一般的な企業環境です。",
    "hospital_network": "業務停止への影響が大きく、医療関連の重要資産を持つ環境です。",
    "ot_environment": "工場設備などの重要資産が集中し、業務停止への影響が高い環境です。",
    "small_business": "重要資産と構成の複雑さが比較的小さい事業者環境です。",
}
SCENARIO_LABELS = {
    "financial_enterprise": "金融企業",
    "hospital_enterprise": "病院・医療機関",
    "cloud_native_startup": "クラウドネイティブ企業",
    "ot_factory": "OT・工場",
    "small_business": "小規模事業者",
}
SCENARIO_DESCRIPTIONS = {
    "financial_enterprise": "ID基盤への依存と業務停止への敏感さが高い金融企業を想定します。",
    "hospital_enterprise": "医療業務への影響が大きく、運用停止を避ける必要がある病院を想定します。",
    "cloud_native_startup": "ID基盤への依存とデコイの活用余地が高いクラウド中心の企業を想定します。",
    "ot_factory": "重要な制御設備があり、業務停止への影響が高い工場を想定します。",
    "small_business": "資産数と構成の複雑さが比較的小さい事業者を想定します。",
}
JAPANESE_REPORT_INFO = {
    "PHASE90_INTENT_INFERENCE_REPORT.md": ("攻撃者の目的を推定する分析レポート", "観測された攻撃者行動から、設定した攻撃者の目的をどの程度推定できたかを確認します。"),
    "PHASE91_BEHAVIOR_PROFILE_REPORT.md": ("攻撃者行動の傾向分析レポート", "攻撃者の行動を傾向別に分類し、攻撃者の目的との関係を確認します。"),
    "PHASE92_FEATURE_SPACE_REPORT.md": ("評価特徴量の分析レポート", "どの特徴が分析結果に強く影響しているかを確認します。"),
    "PHASE93_PROFILECORE_REPORT.md": ("行動プロファイル統合分析レポート", "攻撃者行動の特徴から、行動タイプの候補を確認します。"),
    "PHASE94_ARCHETYPE_INTERPRETATION_REPORT.md": ("攻撃者タイプの解釈レポート", "抽出された攻撃者タイプの特徴と、目的・行動傾向との関係を確認します。"),
    "PHASE95_STRATEGY_LAYER_REPORT.md": ("攻撃戦略の分析レポート", "攻撃者の目的と行動の間にある攻撃戦略の傾向を確認します。"),
    "PHASE96_TAXONOMY_REPORT.md": ("攻撃者目的・対象の関係分析レポート", "攻撃の意図、目的、対象、戦略の関係を確認します。"),
    "PHASE97_TARGET_STRATEGY_REPORT.md": ("対象別の攻撃戦略分析レポート", "攻撃対象によって、どの攻撃戦略が選ばれやすいかを確認します。"),
    "PHASE98_STRATEGY_VALIDATION_REPORT.md": ("攻撃戦略モデルの検証レポート", "攻撃対象と戦略の関係モデルが、既存データとどの程度整合するかを確認します。"),
    "PHASE99_DECISION_GRAPH_REPORT.md": ("攻撃者の意思決定経路レポート", "攻撃の意図から行動傾向までの意思決定経路を確認します。"),
}
JAPANESE_REPORT_SECTIONS = {
    "Summary": "結果の要約",
    "Method": "分析の前提",
    "Confusion Matrix": "推定結果の対応表",
    "Rows": "分析対象の詳細",
    "Profile Distribution": "行動傾向の分布",
    "Mission Relationship": "攻撃者目的との関係",
    "Dominant Feature Ranking": "影響の大きい特徴",
    "Archetype Candidates": "攻撃者タイプ候補",
    "Principal Components": "主な分析軸",
    "Archetype Summary": "攻撃者タイプの要約",
    "Feature Distance": "タイプ間の特徴差",
    "Mission Distribution": "攻撃者目的の分布",
    "Strategy Distribution": "攻撃戦略の分布",
    "Future Integration": "今後の拡張",
    "Intents": "攻撃の意図",
    "Missions": "攻撃者の目的",
    "Targets": "攻撃対象",
    "Taxonomy Edges": "意図・目的・対象・戦略の関係",
    "Target Strategy Mapping": "対象と攻撃戦略の対応",
    "Observed Rows": "観測結果の詳細",
    "Validation Metrics": "検証指標",
    "Strategy Summary": "攻撃戦略の要約",
    "Graph Structure": "意思決定経路の構造",
    "Metrics": "指標",
    "Node Explorer": "構成要素",
}
JAPANESE_REPORT_TERMS = {
    "critical_hunter": "重要資産の探索",
    "persistence": "継続的な潜伏",
    "achievement": "目標達成",
    "profit": "金銭獲得",
    "financial_gain": "金銭獲得",
    "long_term_presence": "長期潜伏",
    "credential_theft": "認証情報の窃取",
    "data_exfiltration": "情報の持ち出し",
    "service_disruption": "サービス妨害",
    "infrastructure_takeover": "基盤の乗っ取り",
    "long_term_persistence": "長期的な潜伏",
    "supply_chain_compromise": "サプライチェーン侵害",
    "identity_infrastructure": "ID基盤",
    "critical_database": "重要データベース",
    "business_application": "業務アプリケーション",
    "cloud_control_plane": "クラウド管理基盤",
    "backup_system": "バックアップシステム",
    "research_system": "研究システム",
    "industrial_control_system": "産業制御システム",
    "trust_relationship": "信頼関係",
    "critical_asset_hunter": "重要資産探索型",
    "credential_hunter": "認証情報探索型",
    "persistence_builder": "潜伏基盤構築型",
    "process_manipulator": "プロセス操作型",
    "research_explorer": "研究資産探索型",
    "secret_hunter": "機密情報探索型",
    "trust_abuser": "信頼関係悪用型",
    "resource_exhaustion": "リソース枯渇型",
    "utility_seeking": "効用重視型",
    "stealth_seeking": "隠密行動重視型",
    "disruption_seeking": "妨害重視型",
    "critical_path_seeking": "重要資産経路重視型",
    "opportunistic": "機会追随型",
    "Mission inference accuracy": "目的推定の一致率",
    "Mean mission confidence": "目的推定の平均確信度",
    "Mean mission entropy": "目的推定の曖昧さ",
    "Profile differences observed": "行動傾向の違いが観測されたか",
    "Profiles observed": "観測された行動傾向数",
    "Profile concentration": "行動傾向の集中度",
    "Mean profile confidence": "行動傾向推定の平均確信度",
    "Dominant feature": "最も影響が大きい特徴",
    "normalized weight": "正規化した重み",
    "strategy": "攻撃戦略",
    "mission": "攻撃者目的",
    "target": "攻撃対象",
    "confidence": "確信度",
    "accuracy": "一致率",
    "true": "設定値",
    "inferred": "推定値",
    "feature": "特徴",
    "profile": "行動傾向",
    "archetype": "攻撃者タイプ",
    "intent": "攻撃の意図",
    "rows": "件数",
    "count": "件数",
    "value": "値",
    "metric": "評価項目",
}

TEXT = {
    "日本語": {
        "nav": ["ホーム", "シナリオ", "製品", "実行", "結果", "ベンチマーク"],
        "nav_to_key": {
            "ホーム": "home",
            "シナリオ": "scenario",
            "製品": "products",
            "実行": "run",
            "結果": "results",
            "ベンチマーク": "benchmark",
        },
        "language": "表示言語",
        "report_locale": "ja",
        "scope": "防御策の比較評価",
        "home_subtitle": "防御策比較ダッシュボード",
        "definition": (
            "CyberMatch は、システムを狙う攻撃者の思考や行動をシミュレーションし、"
            "どのセキュリティ対策（防御戦略や製品）が最も効果的かを比較・評価できるツールです。"
        ),
        "mvp_scope": (
            "このダッシュボードでは、「想定される環境」と「攻撃者の狙い」に対して、"
            "複数のセキュリティ対策を簡単に比較・評価できます。"
        ),
        "cert_warning": (
            "※ 本ツールは「どの環境でも最強の製品」を保証するものではありません。"
            "攻撃者の目的に応じて対策の効果がどう変わるかを比較・分析するための参考情報としてご利用ください。"
        ),
        "current_focus": """
        **このツールの主な機能**

        - 「どんな環境で」「どんな目的の攻撃者に」「どの対策を使うか」を選択
        - 選んだ対策の効果を比較し、「なぜその対策が効くのか」という理由を確認
        - 実行したシミュレーション条件と結果のレポートを保存
        """,
        "home_how_to": """
        **使い方（3ステップで簡単にはじめられます）**

        1. **実行** ページを開き、**デモシナリオ**から試したい業種や環境を選びます。
        2. **このデモ条件を適用** ボタンを押すと、攻撃者の目的や防御策が自動でセットされます。
        3. **防御策の比較を実行** ボタンを押し、完了したら **結果** ページでどの対策が最も有効だったかを確認します。

        CyberMatchを使えば、「自社の環境や想定される攻撃に対して、どのセキュリティ製品から検討すべきか」の当たりをつけることができます。
        """,
        "scenario_title": "シナリオ",
        "scenario_import": "評価条件ファイルを確認",
        "scenario_catalog": "業種別の想定シナリオ",
        "demo_scenarios": "デモシナリオ",
        "apply_demo": "このデモ条件を適用",
        "demo_conclusion": "デモで伝える結論",
        "demo_applied": "適用中のデモ",
        "no_demo_scenarios": "scenarios/demos/ 配下にデモシナリオが見つかりません。",
        "scenario_name": "シナリオ名",
        "scenario_industry": "想定業種",
        "scenario_description": "このシナリオで想定する状況",
        "scenario_page_guide": "「シナリオ」とは、どのような組織（業種）や攻撃目的を想定して対策を比較するかを決める設定のことです。JSONファイルは、評価の前提条件を記録した単なる設定ファイルです。",
        "scenario_catalog_guide": "業種ごとの代表的なシナリオ一覧です。金融、病院、クラウド企業、工場など、よくある前提条件を確認できます。実際にシミュレーションを回す際の条件は「実行」ページで設定します。",
        "scenario_file_guide": "評価条件ファイルには、想定環境・攻撃者の目的・比較する対策などの情報が保存されています。通常は変更する必要はありませんが、詳細を確認したい場合のみ開いてください。",
        "json_detail": "設定ファイルの詳細（JSON）",
        "benchmark_suite": "全体傾向の確認（ベンチマーク）",
        "benchmark_guide": "「ベンチマーク」は、複数のシナリオや環境をまとめてシミュレーションし、防御策の全体的な傾向をつかむための機能です。特定の案件の結論というより、広い視点での傾向分析に役立ちます。",
        "benchmark_name": "ベンチマーク名",
        "scenario_count": "シナリオ数",
        "mission_count": "攻撃者目的数",
        "product_count": "比較する防御策数",
        "topology_count": "想定環境数",
        "matrix_size": "比較パターン数",
        "benchmark_json": "ベンチマーク設定ファイル",
        "no_benchmarks": "benchmarks/ 配下にベンチマーク設定ファイルが見つかりません。",
        "topology_library": "想定ネットワーク（Topology）",
        "topology_guide": "「想定環境」は、守るべき重要資産の数やネットワークの構造、業務停止による影響の大きさなどをモデル化したものです。実際の複雑なネットワーク構成をそのまま読み込むものではありません。",
        "topology_name": "想定環境名",
        "topology_description": "想定環境の説明",
        "topology_characteristics": "比較に使う環境特性",
        "topology_json": "想定環境の設定ファイル",
        "no_topologies": "topologies/ 配下に想定環境の設定ファイルが見つかりません。",
        "scenario_json": "評価条件ファイル",
        "selected_scenario_path": "選択中の設定ファイル",
        "no_scenarios": "scenarios/ 配下に評価条件ファイルが見つかりません。",
        "scenario_selector": "評価の種類",
        "mission_selection": "攻撃者の目的",
        "mission_caption": "チェックを入れた攻撃目的について、それぞれの防御策がどれだけ効くかをシミュレーションします。複数選ぶと「目的ごとにどの対策が向いているか」を比較できます。",
        "products_title": "比較する防御策",
        "no_profiles": "profiles/products/ 配下に防御策の設定ファイルが見つかりません。",
        "comparison_targets": "比較する防御策",
        "product_caption": "比較したい対策にチェックを入れてください。※これらは特定の製品そのものではなく、「IDS」「IPS」「XDR」といった一般的な製品特性をモデル化したものです。",
        "run_title": "実行",
        "run_guide": "初心者の方は、まず **デモシナリオ** から「このデモ条件を適用」ボタンを押して条件を自動セットすることをおすすめします。手動で設定する場合は、想定環境、攻撃者の目的、比較する防御策をそれぞれ選んでください。",
        "scenario_import_hook": "評価条件ファイルを選ぶ",
        "primary_runner": "実行する評価:",
        "output": "出力先:",
        "run_phase63": "防御策の比較を実行",
        "run_phase83": "横断ベンチマーク比較を実行",
        "run_standard_benchmark": "標準条件で横断比較を実行",
        "stop_run": "実行を停止",
        "running_phase63": "防御策の比較を実行中...",
        "runner_failed": "Runner が失敗しました",
        "runner_running": "Evaluation is running.",
        "runner_stopped": "Evaluation を停止しました。",
        "runner_exit_code": "終了コード",
        "runner_not_running": "実行中のrunnerはありません。",
        "phase63_done": "防御策の比較が完了しました。",
        "phase83_done": "横断ベンチマーク比較が完了しました。",
        "phase85_done": "標準条件での横断比較が完了しました。",
        "phase62_done": "防御策プロファイルの基礎比較が完了しました。",
        "artifacts_written": "結果の保存先:",
        "optional_phase62": "防御策プロファイルの基礎比較（詳細）",
        "run_phase62": "防御策プロファイルの基礎比較を実行",
        "running_phase62": "防御策プロファイルの基礎比較を実行中...",
        "results_title": "結果",
        "decision_conclusion": "結論",
        "decision_conclusion_intro": "選択した条件での推奨候補と、攻撃者の目的別の最適候補です。",
        "decision_reason": "理由",
        "decision_reason_intro": "各攻撃者目的の推奨候補について、最も大きく変化した攻撃者行動を示します。",
        "decision_primary_driver": "主な変化",
        "decision_driver_success": "攻撃者目的の達成率低下",
        "decision_driver_disruption": "攻撃活動の妨害増加",
        "decision_driver_detection": "検知確率の増加",
        "decision_driver_diversion": "攻撃者の迂回・無駄行動の増加",
        "decision_comparison": "比較",
        "decision_comparison_intro": "防御策と攻撃者目的の組合せごとの効果差を比較します。数値は選択した前提条件におけるモデル評価です。",
        "decision_constraints": "前提・制約",
        "decision_constraints_text": "本結果は、設定した条件に基づくシミュレーション上の比較評価であり、実際の環境での効果を完全に保証するものではありません。",
        "advanced_analysis": "分析詳細",
        "run_summary_title": "今回の評価のまとめ",
        "run_summary_intro": "選択した条件でのシミュレーション結果です。まずはこの概要から確認してください。",
        "summary_environment": "想定環境",
        "summary_missions": "攻撃者の目的",
        "summary_products": "比較した防御策",
        "summary_result": "主な結果",
        "summary_seed": "再現用seed",
        "summary_recommendation": "今回の条件では、総合的に見て「 `{product}` 」が最も高い効果を示しました。ただし、攻撃の目的によっては別の対策が最適な場合もあります。",
        "run_conditions": "実行条件の詳細",
        "run_manifest": "実行条件（JSON）",
        "select_topology_error": "評価前に想定環境を1つ選択してください。",
        "select_mission_error": "評価前に攻撃者の目的を1つ以上選択してください。",
        "select_product_error": "評価前に比較する防御策を1つ以上選択してください。",
        "results_missing": "結果が見つかりません。先に「実行」ページで比較を実行してください。",
        "go_to_run": "実行ページで「防御策の比較を実行」を押してください。",
        "expected_output_path": "結果の保存先",
        "missing_files": "不足している結果ファイル",
        "results_intro": (
            "この画面では、シミュレーション結果（どの防御策が一番効果的だったか）を確認できます。"
            "表示される数値は実環境での確実な効果を保証するものではなく、設定した条件に基づく比較・参考値です。"
        ),
        "interpretation_notice": (
            "CyberMatchは「どの環境でも最強の製品」を決めるものではありません。"
            "攻撃者が何を狙っているか（目的）によって、防御策の効果がどう変わるかを比較・分析するためのツールです。"
        ),
        "summary_cards": "比較結果の要点",
        "best_product_overall": "総合的に高い候補",
        "best_product_per_mission": "目的別の有力候補数",
        "worst_mission_coverage": "平均効果が低い目的",
        "highest_mission_variance": "目的による差が大きい候補",
        "single_winner_exists": "全目的で同じ候補か",
        "product_mission_table": "防御策と攻撃者目的の比較表",
        "product_mission_chart": "防御策と攻撃者目的の比較ヒートマップ",
        "winner_explanation": "目的別の有力候補の説明",
        "product_detail": "選択した防御策の詳細",
        "product_selector": "確認する防御策",
        "detail_metric": "評価項目",
        "detail_value": "値",
        "per_mission_detail": "目的ごとの詳細",
        "summary_table": "全比較結果（詳細）",
        "heatmap": "防御策と攻撃者目的のヒートマップ",
        "heatmap_help": "縦軸は比較する防御策、横軸は攻撃者の目的です。色が濃いほど、その組合せで防御策の比較スコアが高いことを示します。",
        "variance": "攻撃者の目的による効果のばらつき",
        "variance_help": "同じ防御策でも、攻撃者の目的によって効果がどの程度変わるかを表します。値が大きいほど、目的による効果差が大きいことを示します。",
        "phase62_comparison": "基礎比較と目的別比較の違い",
        "phase62_help": "防御策そのものの基礎比較と、攻撃者の目的を考慮した比較の違いを示します。目的別比較では、単一の順位ではなく、どの目的に適するかを確認します。",
        "markdown_report": "評価レポート（Markdown）",
        "json_summary": "結果データ（JSON）",
        "downloads": "結果ファイルをダウンロード",
        "benchmark_artifacts": "横断ベンチマーク比較の結果",
        "phase90_intent_inference": "攻撃者の目的を推定する分析（研究用）",
        "phase90_missing": "攻撃者目的の推定結果が見つかりません。",
        "phase90_help": "実際に設定した攻撃者目的と推定された目的がどの程度一致するかを示します。",
        "phase91_behavior_profiles": "攻撃者行動の傾向分析（研究用）",
        "phase91_missing": "攻撃者行動の傾向分析結果が見つかりません。",
        "phase91_help": "攻撃者行動の傾向、推定の確からしさ、目的との関係を示します。",
        "phase92_feature_space": "評価特徴量の分析（研究用）",
        "phase92_missing": "評価特徴量の分析結果が見つかりません。",
        "phase92_help": "評価に効いている特徴と、攻撃者目的との関係を示します。",
        "phase93_profilecore": "行動プロファイルの統合分析（研究用）",
        "phase93_missing": "行動プロファイルの統合分析結果が見つかりません。",
        "phase93_help": "PCA variance、Dominant Component、Archetype Distributionを表示します。",
        "phase94_archetype": "攻撃者タイプの解釈（研究用）",
        "phase94_missing": "攻撃者タイプの解釈結果が見つかりません。",
        "phase94_help": "Archetype Summary、Signature、Feature Comparison、Mission/Profileとの関係を表示します。",
        "archetype_summary": "Archetype Summary",
        "archetype_signature": "Archetype Signature",
        "feature_comparison": "Feature Comparison",
        "mission_relationship": "Mission Relationship",
        "phase95_strategy": "攻撃戦略の分析（研究用）",
        "phase95_missing": "攻撃戦略の分析結果が見つかりません。",
        "phase95_help": "Strategy、Strategy Confidence、Mission/Archetype/Profileとの関係を表示します。",
        "strategy": "Strategy",
        "strategy_confidence": "Strategy Confidence",
        "archetype_relationship": "Archetype Relationship",
        "phase96_taxonomy": "攻撃者目的・対象の関係分析（研究用）",
        "phase96_missing": "攻撃者目的・対象の関係分析結果が見つかりません。",
        "phase96_help": "Intent → Mission → Target と Target → Strategy の関係を表示します。",
        "taxonomy_explorer": "Taxonomy Explorer",
        "target_relationship": "Target Relationship",
        "phase97_target_strategy": "対象別の攻撃戦略分析（研究用）",
        "phase97_missing": "対象別の攻撃戦略分析結果が見つかりません。",
        "phase97_help": "Target、Strategy、Target-Strategy Mapping、Alignment Scoreを表示します。",
        "target_strategy_mapping": "Target-Strategy Mapping",
        "alignment_score": "Alignment Score",
        "phase98_strategy_validation": "攻撃戦略モデルの検証（研究用）",
        "phase98_missing": "攻撃戦略モデルの検証結果が見つかりません。",
        "phase98_help": "Strategy Validation、Distinctiveness、Redundancy、Explainabilityを表示します。",
        "distinctiveness": "Distinctiveness",
        "redundancy": "Redundancy",
        "explainability": "Explainability",
        "phase99_decision_graph": "攻撃者の意思決定経路（研究用）",
        "phase99_missing": "攻撃者の意思決定経路の結果が見つかりません。",
        "phase99_help": "Decision Graph、Decision Path Explorer、Node Explorerを表示します。",
        "decision_path_explorer": "Decision Path Explorer",
        "node_explorer": "Node Explorer",
        "true_mission": "設定した攻撃者の目的",
        "inferred_mission": "推定された攻撃者の目的",
        "behavior_profile": "攻撃者行動の傾向",
        "profile_confidence": "プロファイル推定の確からしさ",
        "dominant_feature": "主な特徴",
        "critical_path_bias": "重要資産を優先する傾向",
        "accuracy": "一致率",
        "benchmark_results_missing": "横断ベンチマーク比較の結果が見つかりません。先に比較を実行してください。",
        "metric_guide": "評価指標の読み方",
        "metric_guide_text": """
        - `mission_effectiveness`: 総合評価（攻撃者の目的を防ぐ効果の高さ）
        - `mission_success_delta`: 攻撃の成功をどれだけ防げたか（低下した成功率）
        - `mission_disruption_delta`: 攻撃者の活動をどれだけ妨害できたか（増加した妨害率）
        - `mission_detection_delta`: 攻撃をどれだけ検知しやすくなったか（増加した検知率）
        - `diversion_delta`: 攻撃者にどれだけ無駄な行動や迂回を強要できたか
        - `best_mission` / `worst_mission`: この対策が最も有効な攻撃目的 / 最も効果が薄い攻撃目的
        """,
        "mission_interpretation": "目的別の読み方",
        "mission_interpretation_help": (
            "攻撃者の目的ごとに、最も評価スコアが高かった対策を抽出しています。"
            "「絶対的な最強製品」を決めるものではなく、目的によって効きやすい対策が変わることを確認するための表示です。"
        ),
        "download_csv": "CSVをダウンロード",
        "download_json": "JSONをダウンロード",
        "download_md": "Markdownをダウンロード",
        "missing": "Missing",
        "not_found": "not found.",
    },
    "English": {
        "nav": ["Home", "Scenario", "Products", "Run", "Results", "Benchmark"],
        "nav_to_key": {
            "Home": "home",
            "Scenario": "scenario",
            "Products": "products",
            "Run": "run",
            "Results": "results",
            "Benchmark": "benchmark",
        },
        "language": "Display language",
        "report_locale": "en",
        "scope": "Product Evaluation only",
        "home_subtitle": "Product Evaluation Dashboard MVP",
        "definition": (
            "CyberMatch is a cyber decision-making simulator that reproduces attacker "
            "decision processes and enables comparative evaluation of defense strategies "
            "and security products."
        ),
        "mvp_scope": (
            "MVP scope: Product Evaluation only. The app uses existing runners and generated artifacts."
        ),
        "cert_warning": (
            "CyberMatch is not real product certification. It is a reproducible scenario "
            "evaluation framework for comparing controlled product profiles."
        ),
        "current_focus": """
        **Current MVP focus**

        - Product profile inspection
        - Mission-aware product evaluation
        - Existing artifact viewing
        - CSV, JSON, PNG, and Markdown report access
        """,
        "home_how_to": """
        **Start here (three quick steps)**

        1. Open **Run** and choose a purpose-driven demo from **Demo scenarios**.
        2. Click **Apply these demo conditions** to set missions, products, and topology.
        3. Run **Mission-Aware Product Evaluation**, then open **Results** to review the conclusion.

        CyberMatch compares which defense options should be validated first for a given attacker mission and environment.
        """,
        "scenario_title": "Scenario",
        "scenario_import": "Scenario import",
        "scenario_catalog": "Scenario catalog",
        "demo_scenarios": "Demo scenarios",
        "apply_demo": "Apply these demo conditions",
        "demo_conclusion": "Demo conclusion",
        "demo_applied": "Applied demo",
        "no_demo_scenarios": "No demo scenarios found under scenarios/demos/.",
        "scenario_name": "Scenario Name",
        "scenario_industry": "Industry",
        "scenario_description": "Description",
        "benchmark_suite": "Benchmark suite",
        "benchmark_name": "Benchmark name",
        "scenario_count": "Scenario count",
        "mission_count": "Mission count",
        "product_count": "Product count",
        "topology_count": "Topology count",
        "matrix_size": "Matrix size",
        "benchmark_json": "Benchmark JSON",
        "no_benchmarks": "No benchmark JSON files found under benchmarks/.",
        "topology_library": "Topology library",
        "topology_name": "Topology name",
        "topology_description": "Topology description",
        "topology_characteristics": "Topology characteristics",
        "topology_json": "Topology JSON",
        "no_topologies": "No topology JSON files found under topologies/.",
        "scenario_json": "Scenario JSON",
        "selected_scenario_path": "Selected scenario path",
        "no_scenarios": "No scenario JSON files found under scenarios/.",
        "scenario_selector": "Built-in scenario",
        "mission_selection": "Mission selection",
        "mission_caption": "Only selected missions are evaluated; select multiple missions to compare them.",
        "products_title": "Products",
        "no_profiles": "No product profiles found under profiles/products/.",
        "comparison_targets": "Comparison targets",
        "product_caption": "Only selected product profiles are compared.",
        "run_title": "Run",
        "run_guide": "For a demo, apply conditions from **Demo scenarios** first. For manual setup, choose topology (environment assumptions), missions (attacker objectives), and product profiles to compare. Normal GUI runs use seed `0` for fast, reproducible results.",
        "scenario_import_hook": "Scenario import hook",
        "primary_runner": "Primary runner:",
        "output": "Output:",
        "run_phase63": "Run Mission-Aware Product Evaluation",
        "run_phase83": "Run Benchmark Suite",
        "run_standard_benchmark": "Run CyberMatch Standard Benchmark",
        "stop_run": "Stop run",
        "running_phase63": "Running evaluation...",
        "runner_failed": "Runner failed",
        "runner_running": "Evaluation is running.",
        "runner_stopped": "Evaluation stopped.",
        "runner_exit_code": "Exit code",
        "runner_not_running": "No runner is currently active.",
        "phase63_done": "Evaluation completed.",
        "phase83_done": "Benchmark suite completed.",
        "phase85_done": "Standard benchmark completed.",
        "artifacts_written": "Artifacts written to",
        "optional_phase62": "Optional runner",
        "run_phase62": "Run Product Profile Evaluation",
        "running_phase62": "Running evaluation...",
        "phase62_done": "Evaluation completed.",
        "results_title": "Results",
        "decision_conclusion": "Conclusion",
        "decision_conclusion_intro": "Recommended candidates and the best fit for each selected mission.",
        "decision_reason": "Why",
        "decision_reason_intro": "For each recommended candidate, the largest change in attacker outcome is shown.",
        "decision_primary_driver": "Primary change",
        "decision_driver_success": "reduced mission success",
        "decision_driver_disruption": "increased campaign disruption",
        "decision_driver_detection": "increased detection probability",
        "decision_driver_diversion": "increased attacker diversion and wasted activity",
        "decision_comparison": "Comparison",
        "decision_comparison_intro": "Compare effectiveness differences by product and mission. Values are model evaluations under the selected conditions.",
        "decision_constraints": "Assumptions and limitations",
        "decision_constraints_text": "CyberMatch results are comparative model evaluations under the recorded inputs and assumptions. They do not certify products or prove real-world effectiveness.",
        "advanced_analysis": "Detailed analysis",
        "run_conditions": "Run conditions",
        "run_manifest": "Run manifest",
        "select_topology_error": "Select a topology before running the evaluation.",
        "select_mission_error": "Select at least one mission before running the evaluation.",
        "select_product_error": "Select at least one product profile before running the evaluation.",
        "results_missing": "Results not found. Run the evaluation first.",
        "go_to_run": "Open the Run page and execute the evaluation.",
        "expected_output_path": "Expected output path",
        "missing_files": "Missing files",
        "results_intro": (
            "This page displays generated artifacts. Chart labels come from "
            "the existing runner output; use the explanations below to interpret each view."
        ),
        "interpretation_notice": (
            "CyberMatch does not certify one universally strongest product. It is an "
            "evaluation dashboard for comparing effectiveness differences by attacker mission."
        ),
        "summary_cards": "Summary cards",
        "best_product_overall": "Best product overall",
        "best_product_per_mission": "Best product per mission",
        "worst_mission_coverage": "Worst mission coverage",
        "highest_mission_variance": "Highest mission variance",
        "single_winner_exists": "Single winner exists",
        "product_mission_table": "Product x Mission table",
        "product_mission_chart": "Product x Mission table heatmap",
        "winner_explanation": "Mission winner explanation",
        "product_detail": "Product detail",
        "product_selector": "Product profile",
        "detail_metric": "Metric",
        "detail_value": "Value",
        "per_mission_detail": "Per-mission detail",
        "summary_table": "Summary table",
        "heatmap": "Product x Mission heatmap",
        "heatmap_help": (
            "The heatmap shows mission_effectiveness for each product profile and attacker mission. "
            "Rows are products/profiles, columns are missions, and stronger color means stronger "
            "mission-specific effectiveness."
        ),
        "variance": "Mission variance",
        "variance_help": (
            "Mission variance shows how differently the same product profile performs across missions. "
            "A larger value means the effect is more mission-dependent."
        ),
        "phase62_comparison": "Base vs Mission-Aware Comparison",
        "phase62_help": (
            "This view contrasts profile-level evaluation with mission-aware evaluation. "
            "It should be read as mission suitability, not a single ranking."
        ),
        "markdown_report": "Markdown report",
        "json_summary": "JSON summary",
        "downloads": "Downloads",
        "benchmark_artifacts": "Benchmark artifacts",
        "phase90_intent_inference": "Intent Inference",
        "phase90_missing": "Intent inference artifacts not found.",
        "phase90_help": "Displays True Mission, Inferred Mission, Confidence, Accuracy, and Confusion Matrix.",
        "phase91_behavior_profiles": "Behavior Profiles",
        "phase91_missing": "Behavior profile artifacts not found.",
        "phase91_help": "Displays Behavior Profile, Profile Confidence, Profile Distribution, and Mission Relationship.",
        "phase92_feature_space": "Feature Space",
        "phase92_missing": "Feature space artifacts not found.",
        "phase92_help": "Displays Dominant Feature, Critical Path Bias, Feature Dominance, and Mission Feature Heatmap.",
        "phase93_profilecore": "ProfileCore",
        "phase93_missing": "ProfileCore artifacts not found.",
        "phase93_help": "Displays PCA variance, Dominant Component, and Archetype Distribution.",
        "phase94_archetype": "Archetype Interpretation",
        "phase94_missing": "Archetype interpretation artifacts not found.",
        "phase94_help": "Displays Archetype Summary, Signature, Feature Comparison, and Mission/Profile relationships.",
        "archetype_summary": "Archetype Summary",
        "archetype_signature": "Archetype Signature",
        "feature_comparison": "Feature Comparison",
        "mission_relationship": "Mission Relationship",
        "phase95_strategy": "Strategy Layer",
        "phase95_missing": "Strategy layer artifacts not found.",
        "phase95_help": "Displays Strategy, Strategy Confidence, and Mission/Archetype/Profile relationships.",
        "strategy": "Strategy",
        "strategy_confidence": "Strategy Confidence",
        "archetype_relationship": "Archetype Relationship",
        "phase96_taxonomy": "Taxonomy Explorer",
        "phase96_missing": "Taxonomy artifacts not found.",
        "phase96_help": "Displays Intent -> Mission -> Target and Target -> Strategy relationships.",
        "taxonomy_explorer": "Taxonomy Explorer",
        "target_relationship": "Target Relationship",
        "phase97_target_strategy": "Target-Specific Strategy",
        "phase97_missing": "Target strategy artifacts not found.",
        "phase97_help": "Displays Target, Strategy, Target-Strategy Mapping, and Alignment Score.",
        "target_strategy_mapping": "Target-Strategy Mapping",
        "alignment_score": "Alignment Score",
        "phase98_strategy_validation": "Strategy Validation",
        "phase98_missing": "Strategy validation artifacts not found.",
        "phase98_help": "Displays Strategy Validation, Distinctiveness, Redundancy, and Explainability.",
        "distinctiveness": "Distinctiveness",
        "redundancy": "Redundancy",
        "explainability": "Explainability",
        "phase99_decision_graph": "Decision Graph",
        "phase99_missing": "Decision graph artifacts not found.",
        "phase99_help": "Displays the Decision Graph, Decision Path Explorer, and Node Explorer.",
        "decision_path_explorer": "Decision Path Explorer",
        "node_explorer": "Node Explorer",
        "true_mission": "True Mission",
        "inferred_mission": "Inferred Mission",
        "behavior_profile": "Behavior Profile",
        "profile_confidence": "Profile Confidence",
        "dominant_feature": "Dominant Feature",
        "critical_path_bias": "Critical Path Bias",
        "accuracy": "Accuracy",
        "benchmark_results_missing": "Benchmark results not found. Run the benchmark suite first.",
        "metric_guide": "Metric guide",
        "metric_guide_text": """
        - `mission_effectiveness`: product profile effect for a specific mission.
        - `mission_success_delta`: reduction in mission success compared with baseline.
        - `mission_disruption_delta`: increase in campaign disruption.
        - `mission_detection_delta`: increase in detection probability.
        - `diversion_delta`: increase in attacker diversion.
        - `best_mission` / `worst_mission`: mission where a profile is strongest / weakest.
        """,
        "mission_interpretation": "Mission interpretation",
        "mission_interpretation_help": (
            "This table extracts the profile with the highest mission_effectiveness for each mission "
            "from the summary CSV. It is a reading aid, not product certification or a universal ranking."
        ),
        "download_csv": "Download CSV",
        "download_json": "Download JSON",
        "download_md": "Download Markdown",
        "missing": "Missing",
        "not_found": "not found.",
    },
}


def canonical_repo_path(path_value: str | Path) -> str:
    return Path(path_value).as_posix()


def normalized_option_selection(values: Any, options: List[str], *, path_values: bool = False) -> List[str]:
    if values is None:
        return list(options)
    if not isinstance(values, list):
        return []
    normalize = canonical_repo_path if path_values else str
    option_set = set(options)
    return list(dict.fromkeys(normalize(value) for value in values if normalize(value) in option_set))


def load_product_profiles() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path in sorted(PRODUCT_PROFILE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            rows.append({"name": path.stem, "category": "invalid", "error": str(exc), "file": str(path)})
            continue
        row = {column: data.get(column, 0.0) for column in PROFILE_COLUMNS}
        row["file"] = canonical_repo_path(path.relative_to(ROOT))
        rows.append(row)
    return rows


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def localize_report_markdown(report: str, report_name: str, locale: str) -> str:
    if locale != "ja" or not report or report.startswith("# 防御策の比較評価レポート") or report.startswith("# CyberMatch 標準ベンチマーク比較レポート"):
        return report

    title, purpose = JAPANESE_REPORT_INFO.get(
        report_name,
        ("CyberMatch 分析レポート", "この分析結果は、攻撃者行動と防御策評価に関する研究用の詳細情報です。"),
    )
    lines = [f"# {title}", "", "## このレポートで分かること", purpose, ""]
    skip_method_body = False
    for source_line in report.splitlines():
        if source_line.startswith("# "):
            continue
        if source_line.startswith("## "):
            section = source_line[3:].strip()
            skip_method_body = section == "Method"
            translated_section = JAPANESE_REPORT_SECTIONS.get(section, "分析の詳細")
            lines.extend([f"## {translated_section}", ""])
            if skip_method_body:
                lines.extend(["この分析は、既に生成された攻撃者行動データを整理・解釈する研究用の分析です。新たな攻撃や防御を実行するものではありません。", ""])
            continue
        if skip_method_body:
            continue
        if source_line and not source_line.startswith(("|", "- ", "`")) and any(character.isalpha() for character in source_line):
            continue
        translated_line = source_line
        for source, target in sorted(JAPANESE_REPORT_TERMS.items(), key=lambda item: len(item[0]), reverse=True):
            translated_line = translated_line.replace(source, target)
        translated_line = translated_line.replace("True", "はい").replace("False", "いいえ")
        lines.append(translated_line)
    return "\n".join(lines).rstrip() + "\n"


def render_generated_report(path: Path, text: Dict[str, Any]) -> None:
    report = read_text(path)
    if report:
        st.markdown(localize_report_markdown(report, path.name, str(text.get("report_locale", "en"))))


def list_scenario_files() -> List[Path]:
    if not SCENARIO_DIR.exists():
        return []
    return sorted(SCENARIO_DIR.glob("*.json"))


def list_catalog_scenario_files() -> List[Path]:
    if not SCENARIO_CATALOG_DIR.exists():
        return []
    return sorted(SCENARIO_CATALOG_DIR.glob("*.json"))


def list_demo_scenario_files() -> List[Path]:
    if not DEMO_SCENARIO_DIR.exists():
        return []
    return sorted(DEMO_SCENARIO_DIR.glob("*.json"))


def demo_selection_values(path: Path) -> Dict[str, Any]:
    scenario = read_json(path)
    if not isinstance(scenario, dict):
        raise ValueError(f"Demo scenario is invalid: {path}")
    missions = scenario.get("missions")
    products = scenario.get("products")
    topology = scenario.get("topology", {})
    evaluation = scenario.get("evaluation", {})
    if not isinstance(missions, list) or not all(mission in MISSION_OPTIONS for mission in missions):
        raise ValueError(f"Demo scenario has invalid missions: {path}")
    if not isinstance(products, list) or not all(isinstance(product, str) for product in products):
        raise ValueError(f"Demo scenario has invalid products: {path}")
    if not isinstance(topology, dict) or not isinstance(topology.get("preset"), str):
        raise ValueError(f"Demo scenario has invalid topology: {path}")
    seeds = evaluation.get("seeds") if isinstance(evaluation, dict) else None
    if seeds is not None and (not isinstance(seeds, list) or not all(isinstance(seed, int) for seed in seeds)):
        raise ValueError(f"Demo scenario has invalid seeds: {path}")
    return {
        "missions": missions,
        "products": products,
        "topology_preset": topology["preset"],
        "seeds": seeds,
    }


def apply_demo_scenario(path: Path) -> None:
    values = demo_selection_values(path)
    topology_path = TOPOLOGY_DIR / f"{values['topology_preset']}.json"
    if not topology_path.is_file():
        raise ValueError(f"Demo scenario topology not found: {values['topology_preset']}")
    st.session_state["selected_missions"] = values["missions"]
    st.session_state["selected_product_paths"] = [canonical_repo_path(product) for product in values["products"]]
    st.session_state["selected_topology_path"] = str(topology_path.relative_to(ROOT))
    st.session_state["selected_demo_scenario_path"] = str(path.relative_to(ROOT))
    st.session_state["selected_demo_seeds"] = values["seeds"]


def list_benchmark_files() -> List[Path]:
    if not BENCHMARK_DIR.exists():
        return []
    return sorted(BENCHMARK_DIR.glob("*.json"))


def list_topology_files() -> List[Path]:
    if not TOPOLOGY_DIR.exists():
        return []
    return sorted(TOPOLOGY_DIR.glob("*.json"))


def render_scenario_metadata(path: Path, text: Dict[str, Any]) -> None:
    scenario_data = read_json(path)
    if not isinstance(scenario_data, dict):
        return
    metadata = scenario_data.get("metadata", {})
    if not isinstance(metadata, dict):
        return
    col1, col2 = st.columns(2)
    with col1:
        st.write(text["scenario_name"])
        st.write(display_scenario_name(str(metadata.get("name", ""))))
    with col2:
        st.write(text["scenario_industry"])
        st.code(str(metadata.get("industry", "")), language="text")
    st.write(text["scenario_description"])
    scenario_name = str(metadata.get("name", ""))
    st.write(SCENARIO_DESCRIPTIONS.get(scenario_name, str(metadata.get("description", ""))))


def render_benchmark_metadata(path: Path, text: Dict[str, Any]) -> None:
    benchmark_data = read_json(path)
    if not isinstance(benchmark_data, dict):
        return
    metadata = benchmark_data.get("metadata", {})
    if not isinstance(metadata, dict):
        return
    scenario_count = len(benchmark_data.get("scenarios", []))
    topology_count = len(benchmark_data.get("topologies", []))
    mission_count = len(benchmark_data.get("missions", []))
    product_count = len(benchmark_data.get("products", []))
    matrix_size = scenario_count * (topology_count or 1) * mission_count * product_count
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1:
        st.metric(text["benchmark_name"], str(metadata.get("name", "")))
    with col2:
        st.metric("設定ファイルの版", str(metadata.get("version", "")))
    with col3:
        st.metric(text["scenario_count"], scenario_count)
    with col4:
        st.metric(text["topology_count"], topology_count)
    with col5:
        st.metric(text["mission_count"], mission_count)
    with col6:
        st.metric(text["product_count"], product_count)
    st.metric(text["matrix_size"], matrix_size)


def render_topology_metadata(path: Path, text: Dict[str, Any]) -> None:
    topology_data = read_json(path)
    if not isinstance(topology_data, dict):
        return
    metadata = topology_data.get("metadata", {})
    characteristics = topology_data.get("characteristics", {})
    if not isinstance(metadata, dict):
        return
    col1, col2 = st.columns(2)
    with col1:
        st.write(text["topology_name"])
        st.write(display_topology_name(str(metadata.get("name", ""))))
    with col2:
        st.write(text["topology_description"])
        topology_name = str(metadata.get("name", ""))
        st.write(TOPOLOGY_DESCRIPTIONS.get(topology_name, str(metadata.get("description", ""))))
    st.write(text["topology_characteristics"])
    if isinstance(characteristics, dict):
        labels = {
            "critical_assets": "重要資産の数",
            "identity_centralization": "ID基盤の集中度",
            "lateral_movement_complexity": "横移動の複雑さ",
            "deception_surface": "デコイを置ける範囲",
            "operational_sensitivity": "業務停止への敏感さ",
        }
        st.dataframe(
            [{"環境特性": labels.get(key, key), "設定値": value} for key, value in characteristics.items()],
            use_container_width=True,
            hide_index=True,
        )


def to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def non_baseline_rows(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    return [row for row in rows if row.get("profile_id") != "baseline"]


def product_label(row: Dict[str, str]) -> str:
    return row.get("product_profile_name") or row.get("profile_id") or ""


def mean(values: List[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def round_metric(value: Any) -> float:
    return round(to_float(value), 4)


def display_mission_name(mission: str) -> str:
    return MISSION_LABELS.get(mission, mission)


def display_product_name(row: Dict[str, Any]) -> str:
    category = PRODUCT_CATEGORY_LABELS.get(str(row.get("product_category", "")), str(row.get("product_category", "")))
    name = str(row.get("product_profile_name", ""))
    return f"{category}（{name}）" if category and name else name or category


def display_topology_name(topology_name: str) -> str:
    return TOPOLOGY_LABELS.get(topology_name, topology_name)


def display_scenario_name(scenario_name: str) -> str:
    return SCENARIO_LABELS.get(scenario_name, scenario_name)


def build_product_mission_pivot(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    products: Dict[str, Dict[str, Any]] = {}
    missions: Set[str] = set()
    for row in non_baseline_rows(rows):
        profile_id = row.get("profile_id", "")
        if not profile_id:
            continue
        mission = row.get("mission_name", "")
        if not mission:
            continue
        missions.add(mission)
        product_row = products.setdefault(
            profile_id,
            {
                "profile_id": profile_id,
                "product_profile_name": product_label(row),
                "category": row.get("product_category", ""),
            },
        )
        product_row[mission] = round_metric(row.get("mission_effectiveness"))
    ordered_missions = sorted(missions)
    return [
        {**product_row, **{mission: product_row.get(mission, 0.0) for mission in ordered_missions}}
        for _, product_row in sorted(products.items())
    ]


def build_summary_cards(rows: List[Dict[str, str]], summary_json: Any) -> Dict[str, Any]:
    active_rows = non_baseline_rows(rows)
    by_product: Dict[str, List[Dict[str, str]]] = {}
    by_mission: Dict[str, List[Dict[str, str]]] = {}
    for row in active_rows:
        by_product.setdefault(row.get("profile_id", ""), []).append(row)
        by_mission.setdefault(row.get("mission_name", ""), []).append(row)

    product_scores = {
        product_id: mean([to_float(row.get("mission_effectiveness")) for row in product_rows])
        for product_id, product_rows in by_product.items()
    }
    best_product_id = max(product_scores, key=product_scores.get) if product_scores else ""
    best_product_row = by_product.get(best_product_id, [{}])[0]

    best_by_mission: Dict[str, str] = {}
    best_by_mission_scores: Dict[str, float] = {}
    for mission, mission_rows in by_mission.items():
        best_row = max(mission_rows, key=lambda row: to_float(row.get("mission_effectiveness")))
        best_by_mission[mission] = best_row.get("profile_id", "")
        best_by_mission_scores[mission] = to_float(best_row.get("mission_effectiveness"))

    mission_coverage = {
        mission: mean([to_float(row.get("mission_effectiveness")) for row in mission_rows])
        for mission, mission_rows in by_mission.items()
    }
    worst_mission = min(mission_coverage, key=mission_coverage.get) if mission_coverage else ""

    variance_by_product = {
        product_id: to_float(product_rows[0].get("mission_variance_score"))
        for product_id, product_rows in by_product.items()
    }
    highest_variance_product = max(variance_by_product, key=variance_by_product.get) if variance_by_product else ""
    highest_variance_row = by_product.get(highest_variance_product, [{}])[0]

    analysis = summary_json.get("analysis", {}) if isinstance(summary_json, dict) else {}
    single_winner = analysis.get("single_strongest_product_exists")
    if single_winner is None and best_by_mission:
        single_winner = len(set(best_by_mission.values())) == 1

    return {
        "best_product_overall": {
            "profile_id": best_product_id,
            "name": product_label(best_product_row),
            "score": product_scores.get(best_product_id, 0.0),
        },
        "best_product_per_mission": best_by_mission,
        "best_product_per_mission_scores": best_by_mission_scores,
        "worst_mission_coverage": {
            "mission": worst_mission,
            "score": mission_coverage.get(worst_mission, 0.0),
        },
        "highest_mission_variance": {
            "profile_id": highest_variance_product,
            "name": product_label(highest_variance_row),
            "score": variance_by_product.get(highest_variance_product, 0.0),
        },
        "single_winner_exists": bool(single_winner),
    }


def build_user_run_summary(manifest: Any, summary_cards: Dict[str, Any]) -> Dict[str, Any]:
    inputs = manifest.get("inputs", {}) if isinstance(manifest, dict) else {}
    product_profiles = inputs.get("product_profiles", {}) if isinstance(inputs, dict) else {}
    product_ids = list(product_profiles) if isinstance(product_profiles, dict) else []
    missions = inputs.get("missions", []) if isinstance(inputs, dict) else []
    seeds = inputs.get("seeds", "") if isinstance(inputs, dict) else ""
    best_product = summary_cards.get("best_product_overall", {})
    return {
        "topology": str(inputs.get("topology", "未記録")) if isinstance(inputs, dict) else "未記録",
        "missions": [str(mission) for mission in missions] if isinstance(missions, list) else [],
        "product_ids": product_ids,
        "seeds": ", ".join(str(seed) for seed in seeds) if isinstance(seeds, list) else str(seeds),
        "best_product_id": str(best_product.get("profile_id", "")),
        "best_product_name": str(best_product.get("name", "")),
        "best_product_score": float(best_product.get("score", 0.0)),
    }


def build_mission_interpretation(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    best_by_mission: Dict[str, Dict[str, str]] = {}
    for row in rows:
        if row.get("profile_id") == "baseline":
            continue
        mission = str(row.get("mission_name") or "")
        if not mission:
            continue
        current = best_by_mission.get(mission)
        if current is None or to_float(row.get("mission_effectiveness")) > to_float(current.get("mission_effectiveness")):
            best_by_mission[mission] = row
    return [
        {
            "mission_name": mission,
            "profile_id": row.get("profile_id", ""),
            "product_profile_name": row.get("product_profile_name", ""),
            "product_category": row.get("product_category", ""),
            "mission_effectiveness": round(to_float(row.get("mission_effectiveness")), 4),
            "best_mission_for_profile": row.get("best_mission", ""),
            "worst_mission_for_profile": row.get("worst_mission", ""),
        }
        for mission, row in sorted(best_by_mission.items())
    ]


def build_winner_explanations(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    winners = build_mission_interpretation(rows)
    return [
        {
            "mission": row["mission_name"],
            "winner": row["profile_id"],
            "explanation": (
                f"{row['mission_name']} winner is {row['profile_id']} "
                f"({row['product_category']}) with mission_effectiveness "
                f"{row['mission_effectiveness']}."
            ),
        }
        for row in winners
    ]


def build_decision_recommendations(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    drivers = (
        ("success", "mission_success_delta"),
        ("disruption", "mission_disruption_delta"),
        ("detection", "mission_detection_delta"),
        ("diversion", "diversion_delta"),
    )
    recommendations: List[Dict[str, Any]] = []
    for winner in build_mission_interpretation(rows):
        source_row = next(
            (
                row
                for row in non_baseline_rows(rows)
                if row.get("profile_id") == winner["profile_id"]
                and row.get("mission_name") == winner["mission_name"]
            ),
            {},
        )
        driver_key, metric_key = max(drivers, key=lambda item: abs(to_float(source_row.get(item[1]))))
        recommendations.append(
            {
                "mission_name": winner["mission_name"],
                "profile_id": winner["profile_id"],
                "product_profile_name": winner["product_profile_name"],
                "mission_effectiveness": winner["mission_effectiveness"],
                "driver_key": driver_key,
                "driver_value": round_metric(source_row.get(metric_key)),
            }
        )
    return recommendations


def build_product_detail(rows: List[Dict[str, str]], profile_id: str) -> Dict[str, Any]:
    product_rows = [row for row in non_baseline_rows(rows) if row.get("profile_id") == profile_id]
    if not product_rows:
        return {}
    first = product_rows[0]
    return {
        "category": first.get("product_category", ""),
        "evaluation_score": round_metric(first.get("evaluation_score")),
        "best_mission": first.get("best_mission", ""),
        "worst_mission": first.get("worst_mission", ""),
        "mission_variance_score": round_metric(first.get("mission_variance_score")),
        "mission_success_delta": round(mean([to_float(row.get("mission_success_delta")) for row in product_rows]), 4),
        "mission_disruption_delta": round(mean([to_float(row.get("mission_disruption_delta")) for row in product_rows]), 4),
        "mission_detection_delta": round(mean([to_float(row.get("mission_detection_delta")) for row in product_rows]), 4),
    }


def build_product_mission_detail(rows: List[Dict[str, str]], profile_id: str) -> List[Dict[str, Any]]:
    product_rows = [row for row in non_baseline_rows(rows) if row.get("profile_id") == profile_id]
    return [
        {
            "mission_name": row.get("mission_name", ""),
            "mission_effectiveness": round_metric(row.get("mission_effectiveness")),
            "mission_success_delta": round_metric(row.get("mission_success_delta")),
            "mission_disruption_delta": round_metric(row.get("mission_disruption_delta")),
            "mission_detection_delta": round_metric(row.get("mission_detection_delta")),
        }
        for row in sorted(product_rows, key=lambda row: row.get("mission_name", ""))
    ]


def get_runner_process() -> Optional[subprocess.Popen[Any]]:
    process = st.session_state.get("runner_process")
    if isinstance(process, subprocess.Popen):
        return process
    return None


def runner_is_active() -> bool:
    process = get_runner_process()
    return process is not None and process.poll() is None


def build_phase63_command(
    topology_path: Path,
    missions: List[str],
    product_paths: List[str],
    seeds: Optional[List[int]] = None,
) -> List[str]:
    command = [
        sys.executable,
        str(ROOT / "scripts" / "run_phase63.py"),
        "--topology",
        canonical_repo_path(topology_path.relative_to(ROOT)),
        "--output-dir",
        canonical_repo_path(PHASE63_OUTPUT_DIR.relative_to(ROOT)),
    ]
    for mission in missions:
        command.extend(["--mission", mission])
    for profile_path in product_paths:
        command.extend(["--product", canonical_repo_path(profile_path)])
    for seed in seeds if seeds else [0]:
        command.extend(["--seed", str(seed)])
    return command


def start_runner(command: List[str], log_path: Path, success_key: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            command,
            cwd=str(ROOT),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
    st.session_state["runner_process"] = process
    st.session_state["runner_log_path"] = str(log_path)
    st.session_state["runner_success_key"] = success_key
    st.session_state["runner_stopped"] = False


def stop_runner() -> bool:
    process = get_runner_process()
    if process is None or process.poll() is not None:
        return False
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    st.session_state["runner_stopped"] = True
    return True


def render_runner_status(text: Dict[str, Any]) -> None:
    process = get_runner_process()
    log_path_value = st.session_state.get("runner_log_path")
    log_path = Path(str(log_path_value)) if log_path_value else None
    if process is None:
        st.caption(text["runner_not_running"])
    elif process.poll() is None:
        st.info(text["runner_running"])
    elif st.session_state.get("runner_stopped"):
        st.warning(text["runner_stopped"])
    elif process.returncode == 0:
        st.success(text.get(str(st.session_state.get("runner_success_key")), text["phase63_done"]))
    else:
        st.error(f"{text['runner_failed']}. {text['runner_exit_code']}: {process.returncode}")

    if log_path is not None and log_path.is_file():
        log_text = read_text(log_path)
        if log_text.strip():
            with st.expander("実行ログ"):
                st.code(log_text[-6000:], language="text")

    if process is not None and process.poll() is None:
        time.sleep(1)
        st.rerun()


def render_download(path: Path, label: str, mime: str, text: Dict[str, Any]) -> None:
    if not path.exists():
        st.caption(f"{text['missing']}: {path.relative_to(ROOT)}")
        return
    st.download_button(
        label=label,
        data=path.read_bytes(),
        file_name=path.name,
        mime=mime,
        use_container_width=True,
    )


def render_home(text: Dict[str, Any]) -> None:
    st.title("CyberMatch")
    st.subheader(text["home_subtitle"])
    st.write(text["definition"])
    st.info(text["mvp_scope"])
    st.warning(text["cert_warning"])
    st.info(text["home_how_to"])
    st.markdown(text["current_focus"])


def render_scenario(text: Dict[str, Any]) -> None:
    st.title(text["scenario_title"])
    st.info(text["scenario_page_guide"])
    topology_files = list_topology_files()
    st.subheader(text["topology_library"])
    st.caption(text["topology_guide"])
    if topology_files:
        selected_topology = st.selectbox(text["topology_json"], topology_files, format_func=lambda path: display_topology_name(path.stem))
        st.session_state["selected_topology_path"] = str(selected_topology.relative_to(ROOT))
        render_topology_metadata(selected_topology, text)
        st.code(str(selected_topology.relative_to(ROOT)), language="text")
    else:
        st.warning(text["no_topologies"])

    benchmark_files = list_benchmark_files()
    st.subheader(text["benchmark_suite"])
    if benchmark_files:
        selected_benchmark = st.selectbox(text["benchmark_json"], benchmark_files, format_func=lambda path: path.name)
        st.session_state["selected_benchmark_path"] = str(selected_benchmark.relative_to(ROOT))
        render_benchmark_metadata(selected_benchmark, text)
        st.write(text["selected_scenario_path"])
        st.code(str(selected_benchmark.relative_to(ROOT)), language="text")
    else:
        st.warning(text["no_benchmarks"])

    catalog_files = list_catalog_scenario_files()
    st.subheader(text["scenario_catalog"])
    st.caption(text["scenario_catalog_guide"])
    if catalog_files:
        selected_catalog = st.selectbox(text["scenario_catalog"], catalog_files, format_func=lambda path: display_scenario_name(path.stem))
        st.session_state["selected_catalog_scenario_path"] = str(selected_catalog.relative_to(ROOT))
        render_scenario_metadata(selected_catalog, text)
        st.write(text["selected_scenario_path"])
        st.code(str(selected_catalog.relative_to(ROOT)), language="text")
    else:
        st.warning(text["no_scenarios"])

    scenario_files = list_scenario_files()
    st.subheader(text["scenario_import"])
    st.caption(text["scenario_file_guide"])
    if scenario_files:
        selected = st.selectbox(text["scenario_json"], scenario_files, format_func=lambda path: path.name)
        st.session_state["selected_scenario_path"] = str(selected.relative_to(ROOT))
        st.write(text["selected_scenario_path"])
        st.code(str(selected.relative_to(ROOT)), language="text")
        scenario_data = read_json(selected)
        if scenario_data is not None:
            with st.expander(text["json_detail"]):
                st.json(scenario_data)
    else:
        st.warning(text["no_scenarios"])

    selected_mission = st.selectbox(
        text["scenario_selector"],
        ["攻撃者の目的別に防御策を比較", "防御策プロファイルの基礎比較"],
        index=0,
    )
    st.session_state["selected_runner"] = selected_mission
    selected_mission = st.selectbox(text["mission_selection"], MISSION_OPTIONS, index=0, key="scenario_mission")
    st.session_state["selected_missions"] = [selected_mission]
    st.caption(text["mission_caption"])
    st.code(str(PHASE63_OUTPUT_DIR.relative_to(ROOT)), language="text")


def render_products(text: Dict[str, Any]) -> None:
    st.title(text["products_title"])
    profiles = load_product_profiles()
    if not profiles:
        st.warning(text["no_profiles"])
        return

    profile_paths = [str(row.get("file", "")) for row in profiles]
    profile_names = {str(row.get("file", "")): str(row.get("name", "")) for row in profiles}
    selected_product_defaults = normalized_option_selection(
        st.session_state.get("selected_product_paths"),
        profile_paths,
        path_values=True,
    )
    st.session_state["selected_product_paths"] = selected_product_defaults
    selected_profile_paths = st.multiselect(
        text["comparison_targets"],
        profile_paths,
        default=selected_product_defaults,
        format_func=lambda path: profile_names.get(path, path),
        key="selected_product_paths",
    )
    st.caption(text["product_caption"])
    st.dataframe(profiles, use_container_width=True, hide_index=True)


def render_run(text: Dict[str, Any]) -> None:
    st.title(text["run_title"])
    st.info(text["run_guide"])
    demo_files = list_demo_scenario_files()
    with st.expander(text["demo_scenarios"], expanded=True):
        if demo_files:
            for demo_path in demo_files:
                demo_data = read_json(demo_path)
                metadata = demo_data.get("metadata", {}) if isinstance(demo_data, dict) else {}
                demo = demo_data.get("demo", {}) if isinstance(demo_data, dict) else {}
                st.write(f"**{metadata.get('name', demo_path.stem)}**")
                st.caption(str(metadata.get("description", "")))
                if isinstance(demo, dict) and demo.get("conclusion"):
                    st.write(f"{text['demo_conclusion']}: {demo['conclusion']}")
                st.button(
                    text["apply_demo"],
                    key=f"apply_demo_{demo_path.stem}",
                    on_click=apply_demo_scenario,
                    args=(demo_path,),
                )
            selected_demo_path = st.session_state.get("selected_demo_scenario_path")
            if selected_demo_path:
                st.success(f"{text['demo_applied']}: `{selected_demo_path}`")
        else:
            st.warning(text["no_demo_scenarios"])

    topology_files = list_topology_files()
    selected_topology: Optional[Path] = None
    with st.expander(text["topology_library"], expanded=True):
        st.caption(text["topology_guide"])
        if topology_files:
            default_topology_path = st.session_state.get("selected_topology_path")
            default_topology_index = 0
            if default_topology_path:
                for index, path in enumerate(topology_files):
                    if str(path.relative_to(ROOT)) == default_topology_path:
                        default_topology_index = index
                        break
            selected_topology = st.selectbox(
                text["topology_json"],
                topology_files,
                index=default_topology_index,
                format_func=lambda path: display_topology_name(path.stem),
            )
            st.session_state["selected_topology_path"] = str(selected_topology.relative_to(ROOT))
            render_topology_metadata(selected_topology, text)
            st.code(str(selected_topology.relative_to(ROOT)), language="text")
        else:
            st.warning(text["no_topologies"])

    benchmark_files = list_benchmark_files()
    with st.expander(text["benchmark_suite"], expanded=True):
        if benchmark_files:
            default_benchmark_path = st.session_state.get("selected_benchmark_path")
            default_benchmark_index = 0
            if default_benchmark_path:
                for index, path in enumerate(benchmark_files):
                    if str(path.relative_to(ROOT)) == default_benchmark_path:
                        default_benchmark_index = index
                        break
            selected_benchmark = st.selectbox(
                text["benchmark_json"],
                benchmark_files,
                index=default_benchmark_index,
                format_func=lambda path: path.name,
            )
            st.session_state["selected_benchmark_path"] = str(selected_benchmark.relative_to(ROOT))
            render_benchmark_metadata(selected_benchmark, text)
            st.code(str(selected_benchmark.relative_to(ROOT)), language="text")
            if st.button(text["run_phase83"], disabled=runner_is_active()):
                start_runner(
                    [
                        sys.executable,
                        "-c",
                        "from run_scenarios import run_phase83_benchmark_suite; run_phase83_benchmark_suite()",
                    ],
                    PHASE83_LOG_PATH,
                    "phase83_done",
                )
                st.rerun()
        else:
            st.warning(text["no_benchmarks"])

    catalog_files = list_catalog_scenario_files()
    with st.expander(text["scenario_catalog"], expanded=True):
        if catalog_files:
            default_catalog_path = st.session_state.get("selected_catalog_scenario_path")
            default_catalog_index = 0
            if default_catalog_path:
                for index, path in enumerate(catalog_files):
                    if str(path.relative_to(ROOT)) == default_catalog_path:
                        default_catalog_index = index
                        break
            selected_catalog = st.selectbox(
                text["scenario_catalog"],
                catalog_files,
                index=default_catalog_index,
                format_func=lambda path: display_scenario_name(path.stem),
            )
            st.session_state["selected_catalog_scenario_path"] = str(selected_catalog.relative_to(ROOT))
            render_scenario_metadata(selected_catalog, text)
            st.write(text["selected_scenario_path"])
            st.code(str(selected_catalog.relative_to(ROOT)), language="text")
        else:
            st.warning(text["no_scenarios"])

    scenario_files = list_scenario_files()
    with st.expander(text["scenario_import_hook"], expanded=True):
        if scenario_files:
            default_path = st.session_state.get("selected_scenario_path")
            default_index = 0
            if default_path:
                for index, path in enumerate(scenario_files):
                    if str(path.relative_to(ROOT)) == default_path:
                        default_index = index
                        break
            selected = st.selectbox(text["scenario_json"], scenario_files, index=default_index, format_func=lambda path: path.name)
            st.session_state["selected_scenario_path"] = str(selected.relative_to(ROOT))
            st.write(text["selected_scenario_path"])
            st.code(str(selected.relative_to(ROOT)), language="text")
        else:
            st.warning(text["no_scenarios"])

    profiles = load_product_profiles()
    profile_paths = [str(row.get("file", "")) for row in profiles]
    profile_names = {str(row.get("file", "")): str(row.get("name", "")) for row in profiles}
    default_product_paths = normalized_option_selection(
        st.session_state.get("selected_product_paths"),
        profile_paths,
        path_values=True,
    )
    selected_mission_defaults = normalized_option_selection(st.session_state.get("selected_missions"), MISSION_OPTIONS)
    st.session_state["selected_product_paths"] = default_product_paths
    st.session_state["selected_missions"] = selected_mission_defaults
    selected_product_paths = st.multiselect(
        text["comparison_targets"],
        profile_paths,
        default=default_product_paths,
        format_func=lambda path: profile_names.get(path, path),
        key="selected_product_paths",
    )
    selected_missions = st.multiselect(
        text["mission_selection"],
        MISSION_OPTIONS,
        default=selected_mission_defaults,
        key="selected_missions",
    )
    st.caption(text["mission_caption"])

    st.write(text["primary_runner"])
    st.code("scripts/run_phase63.py", language="text")
    st.write(text["output"])
    st.code(str(PHASE63_OUTPUT_DIR.relative_to(ROOT)), language="text")

    run_col, stop_col = st.columns(2)
    with run_col:
        if st.button(text["run_phase63"], type="primary", disabled=runner_is_active()):
            if selected_topology is None:
                st.error(text["select_topology_error"])
                return
            if not selected_missions:
                st.error(text["select_mission_error"])
                return
            if not selected_product_paths:
                st.error(text["select_product_error"])
                return
            selected_demo_seeds = st.session_state.get("selected_demo_seeds")
            command = build_phase63_command(
                selected_topology,
                selected_missions,
                selected_product_paths,
                selected_demo_seeds if isinstance(selected_demo_seeds, list) else None,
            )
            start_runner(
                command,
                PHASE63_LOG_PATH,
                "phase63_done",
            )
            st.rerun()
    with stop_col:
        if st.button(text["stop_run"], disabled=not runner_is_active()):
            stop_runner()
            st.rerun()

    render_runner_status(text)
    if get_runner_process() is not None and not runner_is_active() and not st.session_state.get("runner_stopped"):
        st.write(f"{text['artifacts_written']} `{PHASE63_OUTPUT_DIR.relative_to(ROOT)}`.")

    with st.expander(text["optional_phase62"]):
        st.code("run_phase62_product_profile_evaluation()", language="python")
        st.write(f"{text['output']} `{PHASE62_OUTPUT_DIR.relative_to(ROOT)}`")
        if st.button(text["run_phase62"], disabled=runner_is_active()):
            start_runner(
                [
                    sys.executable,
                    "-c",
                    "from run_scenarios import run_phase62_product_profile_evaluation; run_phase62_product_profile_evaluation()",
                ],
                PHASE62_LOG_PATH,
                "phase62_done",
            )
            st.rerun()


def render_results(text: Dict[str, Any]) -> None:
    st.title(text["results_title"])
    missing_artifacts = [path for path in PHASE63_ARTIFACTS.values() if not path.exists()]
    if not PHASE63_ARTIFACTS["summary_csv"].exists():
        st.warning(text["results_missing"])
        st.info(text["go_to_run"])
        st.write(text["expected_output_path"])
        st.code(str(PHASE63_OUTPUT_DIR.relative_to(ROOT)), language="text")
        st.write(text["missing_files"])
        st.dataframe(
            [{"missing_file": str(path.relative_to(ROOT))} for path in missing_artifacts],
            use_container_width=True,
            hide_index=True,
        )
        return
    if missing_artifacts:
        with st.expander(text["missing_files"]):
            st.dataframe(
                [{"missing_file": str(path.relative_to(ROOT))} for path in missing_artifacts],
                use_container_width=True,
                hide_index=True,
            )

    rows = read_csv_rows(PHASE63_ARTIFACTS["summary_csv"])
    summary_json = read_json(PHASE63_ARTIFACTS["summary_json"])
    summary_cards = build_summary_cards(rows, summary_json)
    manifest = read_json(PHASE63_ARTIFACTS["manifest"])
    run_summary = build_user_run_summary(manifest, summary_cards)
    rows_by_profile = {
        str(row.get("profile_id", "")): row
        for row in non_baseline_rows(rows)
        if row.get("profile_id")
    }

    st.subheader(text["run_summary_title"])
    st.caption(text["run_summary_intro"])
    condition_col, arrow_one, target_col, arrow_two, result_col = st.columns([4, 1, 4, 1, 4])
    with condition_col:
        st.info(
            f"**{text['summary_environment']}**\n\n{run_summary['topology']}\n\n"
            f"**{text['summary_missions']}**\n\n"
            f"{'、'.join(display_mission_name(mission) for mission in run_summary['missions']) or '未記録'}"
        )
    with arrow_one:
        st.markdown("### →")
    with target_col:
        product_labels = [display_product_name(rows_by_profile[profile_id]) for profile_id in run_summary["product_ids"] if profile_id in rows_by_profile]
        st.info(
            f"**{text['summary_products']}**\n\n"
            f"{'、'.join(product_labels) or '未記録'}\n\n"
            f"**{text['summary_seed']}**\n\n{run_summary['seeds'] or '未記録'}"
        )
    with arrow_two:
        st.markdown("### →")
    with result_col:
        best_row = rows_by_profile.get(run_summary["best_product_id"], {})
        st.success(
            f"**{text['summary_result']}**\n\n"
            f"{display_product_name(best_row) or run_summary['best_product_id'] or '該当なし'}\n\n"
            f"比較スコア: {run_summary['best_product_score']:.4f}"
        )
    if run_summary["best_product_id"]:
        st.info(
            text["summary_recommendation"].format(
                product=display_product_name(rows_by_profile.get(run_summary["best_product_id"], {}))
                or run_summary["best_product_id"]
            )
        )

    st.subheader(text["decision_conclusion"])
    st.caption(text["decision_conclusion_intro"])
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        best = summary_cards["best_product_overall"]
        st.metric(text["best_product_overall"], best["profile_id"], f"{best['score']:.4f}")
        st.caption(best["name"])
    with col2:
        best_by_mission = summary_cards["best_product_per_mission"]
        st.metric(text["best_product_per_mission"], str(len(set(best_by_mission.values()))))
        st.caption(", ".join(f"{display_mission_name(mission)}: {product}" for mission, product in sorted(best_by_mission.items())))
    with col3:
        worst = summary_cards["worst_mission_coverage"]
        st.metric(text["worst_mission_coverage"], worst["mission"], f"{worst['score']:.4f}")
    with col4:
        variance = summary_cards["highest_mission_variance"]
        st.metric(text["highest_mission_variance"], variance["profile_id"], f"{variance['score']:.4f}")
        st.caption(variance["name"])
    with col5:
        st.metric(text["single_winner_exists"], str(summary_cards["single_winner_exists"]).lower())
    st.dataframe(
        [
            {
                "攻撃者の目的": display_mission_name(mission),
                "有力候補": display_product_name(rows_by_profile.get(product, {})) or product,
                "比較スコア": round_metric(
                    summary_cards["best_product_per_mission_scores"].get(mission, 0.0)
                ),
            }
            for mission, product in sorted(summary_cards["best_product_per_mission"].items())
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.subheader(text["decision_reason"])
    st.caption(text["decision_reason_intro"])
    for recommendation in build_decision_recommendations(rows):
        driver_label = text[f"decision_driver_{recommendation['driver_key']}"]
        st.write(
            f"**{display_mission_name(recommendation['mission_name'])}**: "
            f"{display_product_name(rows_by_profile.get(recommendation['profile_id'], {}))} — "
            f"比較スコア `{recommendation['mission_effectiveness']:.4f}`、"
            f"{text['decision_primary_driver']}: {driver_label} "
            f"(`{recommendation['driver_value']:+.4f}`)"
        )

    st.subheader(text["decision_comparison"])
    st.caption(text["decision_comparison_intro"])
    pivot_rows = build_product_mission_pivot(rows)
    st.dataframe(pivot_rows, use_container_width=True, hide_index=True)

    with st.expander(text["product_mission_chart"], expanded=False):
        st.caption(text["heatmap_help"])
        if PHASE63_ARTIFACTS["heatmap"].exists():
            st.image(str(PHASE63_ARTIFACTS["heatmap"]))
        else:
            st.warning(f"mission_product_heatmap.png {text['not_found']}")

    st.subheader(text["decision_constraints"])
    st.warning(text["decision_constraints_text"])
    st.info(text["interpretation_notice"])
    if isinstance(manifest, dict):
        st.caption(text["run_conditions"])
        st.dataframe(
            [
                {"項目": text["summary_environment"], "設定内容": run_summary["topology"]},
                {"項目": text["summary_missions"], "設定内容": "、".join(display_mission_name(mission) for mission in run_summary["missions"])},
                {"項目": text["summary_products"], "設定内容": "、".join(run_summary["product_ids"])},
                {"項目": text["summary_seed"], "設定内容": run_summary["seeds"]},
            ],
            use_container_width=True,
            hide_index=True,
        )

    st.subheader(text["advanced_analysis"])
    st.info(text["results_intro"])
    st.subheader(text["product_detail"])
    product_ids = sorted({row.get("profile_id", "") for row in non_baseline_rows(rows) if row.get("profile_id")})
    if product_ids:
        labels_by_product = {
            profile_id: product_label(next(row for row in non_baseline_rows(rows) if row.get("profile_id") == profile_id))
            for profile_id in product_ids
        }
        selected_product_label = st.selectbox(
            text["product_selector"],
            [f"{profile_id} - {labels_by_product[profile_id]}" for profile_id in product_ids],
        )
        selected_product = selected_product_label.split(" - ", 1)[0]
        detail = build_product_detail(rows, selected_product)
        st.dataframe(
            [{text["detail_metric"]: key, text["detail_value"]: value} for key, value in detail.items()],
            use_container_width=True,
            hide_index=True,
        )
        st.caption(text["per_mission_detail"])
        st.dataframe(build_product_mission_detail(rows, selected_product), use_container_width=True, hide_index=True)

    st.subheader(text["summary_table"])
    st.dataframe(rows, use_container_width=True, hide_index=True)

    with st.expander(text["metric_guide"], expanded=True):
        st.markdown(text["metric_guide_text"])

    st.subheader(text["mission_interpretation"])
    st.caption(text["mission_interpretation_help"])
    st.dataframe(build_mission_interpretation(rows), use_container_width=True, hide_index=True)

    st.subheader(text["variance"])
    st.caption(text["variance_help"])
    if PHASE63_ARTIFACTS["variance"].exists():
        st.image(str(PHASE63_ARTIFACTS["variance"]))
    else:
        st.warning(f"mission_variance.png {text['not_found']}")

    st.subheader(text["phase62_comparison"])
    st.caption(text["phase62_help"])
    if PHASE63_ARTIFACTS["phase62_comparison"].exists():
        st.image(str(PHASE63_ARTIFACTS["phase62_comparison"]))
    else:
        st.warning(f"phase63_vs_phase62.png {text['not_found']}")

    st.subheader(text["markdown_report"])
    report = read_text(PHASE63_ARTIFACTS["report"])
    if report:
        st.markdown(localize_report_markdown(report, PHASE63_ARTIFACTS["report"].name, text["report_locale"]))
    else:
        st.warning(f"PHASE63_MISSION_PRODUCT_REPORT.md {text['not_found']}")

    with st.expander(text["json_summary"]):
        if summary_json is None:
            st.warning(f"mission_product_summary.json {text['not_found']}")
        else:
            st.json(summary_json)

    st.subheader(text["downloads"])
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        render_download(PHASE63_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
    with col2:
        render_download(PHASE63_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
    with col3:
        render_download(PHASE63_ARTIFACTS["report"], text["download_md"], "text/markdown", text)
    with col4:
        render_download(PHASE63_ARTIFACTS["manifest"], text["run_manifest"], "application/json", text)

    st.subheader(text["phase90_intent_inference"])
    st.caption(text["phase90_help"])
    if not PHASE90_ARTIFACTS["summary_csv"].exists():
        st.warning(text["phase90_missing"])
        st.code(str(PHASE90_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase90_rows = read_csv_rows(PHASE90_ARTIFACTS["summary_csv"])
        phase90_json = read_json(PHASE90_ARTIFACTS["summary_json"])
        phase90_analysis = phase90_json.get("analysis", {}) if isinstance(phase90_json, dict) else {}
        first_row = phase90_rows[0] if phase90_rows else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(text["true_mission"], str(first_row.get("true_mission", "")))
        with col2:
            st.metric(text["inferred_mission"], str(first_row.get("inferred_mission", "")))
        with col3:
            st.metric("推定の確からしさ", str(first_row.get("mission_confidence", "")))
        with col4:
            st.metric(text["accuracy"], str(phase90_analysis.get("mission_inference_accuracy", "")))
        st.dataframe(phase90_rows, use_container_width=True, hide_index=True)
        for key in ("confusion_matrix", "accuracy", "confidence"):
            if PHASE90_ARTIFACTS[key].exists():
                st.image(str(PHASE90_ARTIFACTS[key]))
        phase90_report = read_text(PHASE90_ARTIFACTS["report"])
        if phase90_report:
            st.markdown(localize_report_markdown(phase90_report, PHASE90_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE90_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE90_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE90_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase91_behavior_profiles"])
    st.caption(text["phase91_help"])
    if not PHASE91_ARTIFACTS["summary_csv"].exists():
        st.warning(text["phase91_missing"])
        st.code(str(PHASE91_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase91_rows = read_csv_rows(PHASE91_ARTIFACTS["summary_csv"])
        phase91_json = read_json(PHASE91_ARTIFACTS["summary_json"])
        phase91_analysis = phase91_json.get("analysis", {}) if isinstance(phase91_json, dict) else {}
        first_row = phase91_rows[0] if phase91_rows else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(text["true_mission"], str(first_row.get("true_mission", "")))
        with col2:
            st.metric(text["behavior_profile"], str(first_row.get("behavior_profile", "")))
        with col3:
            st.metric(text["profile_confidence"], str(first_row.get("profile_confidence", "")))
        with col4:
            st.metric("行動傾向のばらつき", str(phase91_analysis.get("mean_profile_entropy", "")))
        st.dataframe(phase91_rows, use_container_width=True, hide_index=True)
        for key in ("distribution", "confidence", "relationship"):
            if PHASE91_ARTIFACTS[key].exists():
                st.image(str(PHASE91_ARTIFACTS[key]))
        phase91_report = read_text(PHASE91_ARTIFACTS["report"])
        if phase91_report:
            st.markdown(localize_report_markdown(phase91_report, PHASE91_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE91_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE91_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE91_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase92_feature_space"])
    st.caption(text["phase92_help"])
    if not PHASE92_ARTIFACTS["summary_csv"].exists():
        st.warning(text["phase92_missing"])
        st.code(str(PHASE92_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase92_rows = read_csv_rows(PHASE92_ARTIFACTS["summary_csv"])
        phase92_json = read_json(PHASE92_ARTIFACTS["summary_json"])
        phase92_analysis = phase92_json.get("analysis", {}) if isinstance(phase92_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(text["dominant_feature"], str(phase92_analysis.get("dominant_feature", "")))
        with col2:
            st.metric(text["critical_path_bias"], str(phase92_analysis.get("critical_path_bias_score", "")))
        with col3:
            st.metric("目的ごとの特徴の分かれやすさ", str(phase92_analysis.get("mission_feature_separability", "")))
        with col4:
            st.metric("行動傾向ごとの分かれやすさ", str(phase92_analysis.get("profile_feature_separability", "")))
        st.dataframe(phase92_rows, use_container_width=True, hide_index=True)
        for key in ("dominance", "mission_heatmap", "critical_path_bias"):
            if PHASE92_ARTIFACTS[key].exists():
                st.image(str(PHASE92_ARTIFACTS[key]))
        phase92_report = read_text(PHASE92_ARTIFACTS["report"])
        if phase92_report:
            st.markdown(localize_report_markdown(phase92_report, PHASE92_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE92_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE92_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE92_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase93_profilecore"])
    st.caption(text["phase93_help"])
    if not PHASE93_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase93_missing"])
        st.code(str(PHASE93_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase93_rows = read_csv_rows(PHASE93_ARTIFACTS["summary_csv"])
        phase93_json = read_json(PHASE93_ARTIFACTS["summary_json"])
        phase93_analysis = phase93_json.get("analysis", {}) if isinstance(phase93_json, dict) else {}
        distribution = phase93_analysis.get("archetype_distribution", {})
        variance = phase93_analysis.get("pca_explained_variance", [])
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("主な分析軸", str(phase93_analysis.get("dominant_component", "")))
        with col2:
            st.metric("攻撃者タイプ数", str(phase93_analysis.get("archetype_count", "")))
        with col3:
            st.metric("攻撃者タイプのばらつき", str(phase93_analysis.get("archetype_entropy", "")))
        with col4:
            first_variance = variance[0] if isinstance(variance, list) and variance else ""
            st.metric("主な分析軸の説明力", str(first_variance))
        if isinstance(distribution, dict):
            st.dataframe(
                [{"archetype": key, "rows": value} for key, value in sorted(distribution.items())],
                use_container_width=True,
                hide_index=True,
            )
        st.dataframe(phase93_rows, use_container_width=True, hide_index=True)
        for key in ("pca_variance", "component_loadings", "feature_projection", "archetype_distribution"):
            if PHASE93_ARTIFACTS[key].exists():
                st.image(str(PHASE93_ARTIFACTS[key]))
        phase93_report = read_text(PHASE93_ARTIFACTS["report"])
        if phase93_report:
            st.markdown(localize_report_markdown(phase93_report, PHASE93_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE93_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE93_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE93_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase94_archetype"])
    st.caption(text["phase94_help"])
    if not PHASE94_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase94_missing"])
        st.code(str(PHASE94_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase94_rows = read_csv_rows(PHASE94_ARTIFACTS["summary_csv"])
        phase94_json = read_json(PHASE94_ARTIFACTS["summary_json"])
        phase94_analysis = phase94_json.get("analysis", {}) if isinstance(phase94_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        distance = phase94_analysis.get("archetype_feature_distance", {})
        distance_values = []
        if isinstance(distance, dict):
            for left, row in distance.items():
                if isinstance(row, dict):
                    for right, value in row.items():
                        if str(left) < str(right):
                            try:
                                distance_values.append(float(value))
                            except (TypeError, ValueError):
                                pass
        mean_distance = sum(distance_values) / len(distance_values) if distance_values else 0.0
        with col1:
            st.metric("攻撃者タイプ数", str(phase94_analysis.get("archetype_count", "")))
        with col2:
            st.metric("タイプ間の特徴差", f"{mean_distance:.3f}")
        with col3:
            st.metric("目的の重なり", str(phase94_analysis.get("archetype_mission_overlap", "")))
        with col4:
            st.metric("解釈しやすさ", str(phase94_analysis.get("archetype_interpretability_score", "")))
        st.markdown(f"**{text['archetype_summary']}**" if "archetype_summary" in text else "**Archetype Summary**")
        st.dataframe(phase94_rows, use_container_width=True, hide_index=True)
        signature = phase94_analysis.get("archetype_signature", {})
        if isinstance(signature, dict):
            st.markdown(f"**{text['archetype_signature']}**")
            st.dataframe(
                [{"archetype": key, "signature": "; ".join(value) if isinstance(value, list) else str(value)} for key, value in sorted(signature.items())],
                use_container_width=True,
                hide_index=True,
            )
        st.markdown(f"**{text['feature_comparison']}**")
        for key in ("feature_comparison", "distance_matrix"):
            if PHASE94_ARTIFACTS[key].exists():
                st.image(str(PHASE94_ARTIFACTS[key]))
        st.markdown(f"**{text['mission_relationship']}**")
        for key in ("mission_distribution", "profile_distribution"):
            if PHASE94_ARTIFACTS[key].exists():
                st.image(str(PHASE94_ARTIFACTS[key]))
        phase94_report = read_text(PHASE94_ARTIFACTS["report"])
        if phase94_report:
            st.markdown(localize_report_markdown(phase94_report, PHASE94_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE94_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE94_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE94_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase95_strategy"])
    st.caption(text["phase95_help"])
    if not PHASE95_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase95_missing"])
        st.code(str(PHASE95_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase95_rows = read_csv_rows(PHASE95_ARTIFACTS["summary_csv"])
        phase95_json = read_json(PHASE95_ARTIFACTS["summary_json"])
        phase95_analysis = phase95_json.get("analysis", {}) if isinstance(phase95_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(text["strategy"], str(phase95_analysis.get("strategy_distribution", ""))[:80])
        with col2:
            confidence_values = []
            for row in phase95_rows:
                try:
                    confidence_values.append(float(row.get("strategy_confidence", 0.0)))
                except (TypeError, ValueError):
                    pass
            mean_confidence = sum(confidence_values) / len(confidence_values) if confidence_values else 0.0
            st.metric(text["strategy_confidence"], f"{mean_confidence:.3f}")
        with col3:
            st.metric("戦略のばらつき", str(phase95_analysis.get("strategy_entropy", "")))
        with col4:
            st.metric("戦略の一致率", str(phase95_analysis.get("strategy_match_rate", "")))
        st.dataframe(phase95_rows, use_container_width=True, hide_index=True)
        if PHASE95_ARTIFACTS["strategy_distribution"].exists():
            st.image(str(PHASE95_ARTIFACTS["strategy_distribution"]))
        st.markdown(f"**{text['mission_relationship']}**")
        if PHASE95_ARTIFACTS["mission_strategy_matrix"].exists():
            st.image(str(PHASE95_ARTIFACTS["mission_strategy_matrix"]))
        st.markdown(f"**{text['archetype_relationship']}**")
        for key in ("strategy_archetype_matrix", "strategy_profile_matrix"):
            if PHASE95_ARTIFACTS[key].exists():
                st.image(str(PHASE95_ARTIFACTS[key]))
        phase95_report = read_text(PHASE95_ARTIFACTS["report"])
        if phase95_report:
            st.markdown(localize_report_markdown(phase95_report, PHASE95_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE95_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE95_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE95_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase96_taxonomy"])
    st.caption(text["phase96_help"])
    if not PHASE96_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase96_missing"])
        st.code(str(PHASE96_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase96_rows = read_csv_rows(PHASE96_ARTIFACTS["summary_csv"])
        phase96_json = read_json(PHASE96_ARTIFACTS["summary_json"])
        phase96_analysis = phase96_json.get("analysis", {}) if isinstance(phase96_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("意図の種類数", str(phase96_analysis.get("intent_count", "")))
        with col2:
            st.metric("攻撃者目的数", str(phase96_analysis.get("mission_count", "")))
        with col3:
            st.metric("攻撃対象数", str(phase96_analysis.get("target_count", "")))
        with col4:
            st.metric("関係定義の充足度", str(phase96_analysis.get("taxonomy_completeness", "")))
        st.markdown(f"**{text['taxonomy_explorer']}**")
        st.dataframe(phase96_rows, use_container_width=True, hide_index=True)
        st.markdown(f"**{text['mission_relationship']}**")
        for key in ("intent_mission_matrix", "mission_target_matrix"):
            if PHASE96_ARTIFACTS[key].exists():
                st.image(str(PHASE96_ARTIFACTS[key]))
        st.markdown(f"**{text['target_relationship']}**")
        if PHASE96_ARTIFACTS["target_strategy_matrix"].exists():
            st.image(str(PHASE96_ARTIFACTS["target_strategy_matrix"]))
        phase96_report = read_text(PHASE96_ARTIFACTS["report"])
        if phase96_report:
            st.markdown(localize_report_markdown(phase96_report, PHASE96_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE96_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE96_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE96_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase97_target_strategy"])
    st.caption(text["phase97_help"])
    if not PHASE97_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase97_missing"])
        st.code(str(PHASE97_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase97_json = read_json(PHASE97_ARTIFACTS["summary_json"])
        phase97_rows = phase97_json.get("rows", []) if isinstance(phase97_json, dict) else []
        phase97_analysis = phase97_json.get("analysis", {}) if isinstance(phase97_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(text["strategy"], str(phase97_analysis.get("strategy_distribution", ""))[:80])
        with col2:
            st.metric("戦略の多様性", str(phase97_analysis.get("strategy_diversity", "")))
        with col3:
            st.metric("対象への特化度", str(phase97_analysis.get("target_specificity_score", "")))
        with col4:
            st.metric(text["alignment_score"], str(phase97_analysis.get("strategy_target_alignment", "")))
        st.dataframe(phase97_rows, use_container_width=True, hide_index=True)
        st.markdown(f"**{text['target_strategy_mapping']}**")
        for key in ("target_strategy_matrix", "strategy_distribution", "strategy_diversity", "target_specificity", "strategy_alignment"):
            if PHASE97_ARTIFACTS[key].exists():
                st.image(str(PHASE97_ARTIFACTS[key]))
        phase97_report = read_text(PHASE97_ARTIFACTS["report"])
        if phase97_report:
            st.markdown(localize_report_markdown(phase97_report, PHASE97_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2 = st.columns(2)
        with col1:
            render_download(PHASE97_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col2:
            render_download(PHASE97_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase98_strategy_validation"])
    st.caption(text["phase98_help"])
    if not PHASE98_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase98_missing"])
        st.code(str(PHASE98_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase98_json = read_json(PHASE98_ARTIFACTS["summary_json"])
        phase98_summary = phase98_json.get("strategy_summary", []) if isinstance(phase98_json, dict) else []
        phase98_analysis = phase98_json.get("analysis", {}) if isinstance(phase98_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("検証結果", str(phase98_analysis.get("strategy_validation_pass", "")))
        with col2:
            st.metric(text["distinctiveness"], str(phase98_analysis.get("strategy_distinctiveness", "")))
        with col3:
            st.metric(text["redundancy"], str(phase98_analysis.get("strategy_redundancy", "")))
        with col4:
            st.metric(text["explainability"], str(phase98_analysis.get("strategy_explainability", "")))
        st.dataframe(phase98_summary, use_container_width=True, hide_index=True)
        for key in ("distance_matrix", "distinctiveness", "redundancy", "target_validation", "mission_explainability"):
            if PHASE98_ARTIFACTS[key].exists():
                st.image(str(PHASE98_ARTIFACTS[key]))
        phase98_report = read_text(PHASE98_ARTIFACTS["report"])
        if phase98_report:
            st.markdown(localize_report_markdown(phase98_report, PHASE98_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE98_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE98_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE98_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["phase99_decision_graph"])
    st.caption(text["phase99_help"])
    if not PHASE99_ARTIFACTS["summary_json"].exists():
        st.warning(text["phase99_missing"])
        st.code(str(PHASE99_OUTPUT_DIR.relative_to(ROOT)), language="text")
    else:
        phase99_json = read_json(PHASE99_ARTIFACTS["summary_json"])
        phase99_rows = phase99_json.get("rows", []) if isinstance(phase99_json, dict) else []
        phase99_analysis = phase99_json.get("analysis", {}) if isinstance(phase99_json, dict) else {}
        phase99_nodes = phase99_json.get("nodes", {}) if isinstance(phase99_json, dict) else {}
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("経路モデルの検証結果", str(phase99_analysis.get("graph_valid", "")))
        with col2:
            st.metric("判断要素数", str(phase99_analysis.get("decision_graph_nodes", "")))
        with col3:
            st.metric("関係数", str(phase99_analysis.get("decision_graph_edges", "")))
        with col4:
            st.metric("経路数", str(phase99_analysis.get("decision_path_count", "")))
        if PHASE99_ARTIFACTS["decision_graph"].exists():
            st.image(str(PHASE99_ARTIFACTS["decision_graph"]))
        st.markdown(f"**{text['decision_path_explorer']}**")
        st.dataframe(phase99_rows, use_container_width=True, hide_index=True)
        st.markdown(f"**{text['node_explorer']}**")
        node_rows = [{"layer": layer, "nodes": ", ".join(nodes) if isinstance(nodes, list) else str(nodes)} for layer, nodes in phase99_nodes.items()]
        st.dataframe(node_rows, use_container_width=True, hide_index=True)
        for key in ("intent_mission", "mission_target", "target_strategy", "strategy_behavior"):
            if PHASE99_ARTIFACTS[key].exists():
                st.image(str(PHASE99_ARTIFACTS[key]))
        phase99_report = read_text(PHASE99_ARTIFACTS["report"])
        if phase99_report:
            st.markdown(localize_report_markdown(phase99_report, PHASE99_ARTIFACTS["report"].name, text["report_locale"]))
        col1, col2, col3 = st.columns(3)
        with col1:
            render_download(PHASE99_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
        with col2:
            render_download(PHASE99_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
        with col3:
            render_download(PHASE99_ARTIFACTS["report"], text["download_md"], "text/markdown", text)

    st.subheader(text["benchmark_artifacts"])
    if not PHASE83_ARTIFACTS["summary_csv"].exists():
        st.warning(text["benchmark_results_missing"])
        st.code(str(PHASE83_OUTPUT_DIR.relative_to(ROOT)), language="text")
        return
    benchmark_rows = read_csv_rows(PHASE83_ARTIFACTS["summary_csv"])
    st.dataframe(benchmark_rows, use_container_width=True, hide_index=True)
    for key in ("ranking", "scenario_heatmap", "mission_heatmap", "consistency"):
        if PHASE83_ARTIFACTS[key].exists():
            st.image(str(PHASE83_ARTIFACTS[key]))
    benchmark_report = read_text(PHASE83_ARTIFACTS["report"])
    if benchmark_report:
        st.markdown(localize_report_markdown(benchmark_report, PHASE83_ARTIFACTS["report"].name, text["report_locale"]))
    col1, col2, col3 = st.columns(3)
    with col1:
        render_download(PHASE83_ARTIFACTS["summary_csv"], text["download_csv"], "text/csv", text)
    with col2:
        render_download(PHASE83_ARTIFACTS["summary_json"], text["download_json"], "application/json", text)
    with col3:
        render_download(PHASE83_ARTIFACTS["report"], text["download_md"], "text/markdown", text)


def render_benchmark(text: Dict[str, Any]) -> None:
    st.title(text["benchmark_suite"])
    benchmark_files = list_benchmark_files()
    if not benchmark_files:
        st.warning(text["no_benchmarks"])
        return
    default_index = 0
    for index, path in enumerate(benchmark_files):
        if path.name == "cybermatch_standard_v1.json":
            default_index = index
            break
    selected_benchmark = st.selectbox(
        text["benchmark_json"],
        benchmark_files,
        index=default_index,
        format_func=lambda path: path.name,
    )
    render_benchmark_metadata(selected_benchmark, text)
    st.code(str(selected_benchmark.relative_to(ROOT)), language="text")
    if st.button(text["run_standard_benchmark"], type="primary", disabled=runner_is_active()):
        start_runner(
            [
                sys.executable,
                "-c",
                "from run_scenarios import run_phase85_standard_benchmark; run_phase85_standard_benchmark()",
            ],
            PHASE85_LOG_PATH,
            "phase85_done",
        )
        st.rerun()
    render_runner_status(text)

    st.subheader("横断ベンチマーク比較の結果")
    if not PHASE85_ARTIFACTS["summary_csv"].exists():
        st.warning(text["benchmark_results_missing"])
        st.code(str(PHASE85_OUTPUT_DIR.relative_to(ROOT)), language="text")
        return
    st.dataframe(read_csv_rows(PHASE85_ARTIFACTS["summary_csv"]), use_container_width=True, hide_index=True)
    for key in ("ranking", "scenario_heatmap", "topology_heatmap", "mission_heatmap"):
        if PHASE85_ARTIFACTS[key].exists():
            st.image(str(PHASE85_ARTIFACTS[key]))
    report = read_text(PHASE85_ARTIFACTS["report"])
    if report:
        st.markdown(localize_report_markdown(report, PHASE85_ARTIFACTS["report"].name, text["report_locale"]))


def main() -> None:
    st.set_page_config(page_title="CyberMatch", layout="wide")
    language = st.sidebar.selectbox("Language / 言語", ["日本語", "English"], index=0)
    text = TEXT[language]
    page = st.sidebar.radio("CyberMatch", text["nav"])
    page_key = text["nav_to_key"][page]
    st.sidebar.caption("CyberMatch Dashboard MVP")
    st.sidebar.caption(text["scope"])

    if page_key == "home":
        render_home(text)
    elif page_key == "scenario":
        render_scenario(text)
    elif page_key == "products":
        render_products(text)
    elif page_key == "run":
        render_run(text)
    elif page_key == "results":
        render_results(text)
    elif page_key == "benchmark":
        render_benchmark(text)


if __name__ == "__main__":
    main()
