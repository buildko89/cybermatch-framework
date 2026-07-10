from __future__ import annotations

from apps.streamlit_app import build_decision_recommendations, build_user_run_summary, localize_report_markdown


def test_decision_recommendations_selects_winner_and_primary_driver():
    rows = [
        {
            "profile_id": "sample_ids",
            "product_profile_name": "Sample IDS A",
            "product_category": "ids",
            "mission_name": "profit",
            "mission_effectiveness": "0.45",
            "mission_success_delta": "0.10",
            "mission_disruption_delta": "0.20",
            "mission_detection_delta": "0.70",
            "diversion_delta": "0.05",
            "best_mission": "profit",
            "worst_mission": "profit",
        },
        {
            "profile_id": "sample_xdr",
            "product_profile_name": "Sample XDR",
            "product_category": "xdr",
            "mission_name": "profit",
            "mission_effectiveness": "0.65",
            "mission_success_delta": "0.30",
            "mission_disruption_delta": "0.10",
            "mission_detection_delta": "0.20",
            "diversion_delta": "0.05",
            "best_mission": "profit",
            "worst_mission": "profit",
        },
    ]

    recommendations = build_decision_recommendations(rows)

    assert recommendations == [
        {
            "mission_name": "profit",
            "profile_id": "sample_xdr",
            "product_profile_name": "Sample XDR",
            "mission_effectiveness": 0.65,
            "driver_key": "success",
            "driver_value": 0.3,
        }
    ]


def test_user_run_summary_reads_manifest_conditions_and_best_candidate():
    summary = build_user_run_summary(
        {
            "inputs": {
                "topology": "enterprise",
                "missions": ["profit", "achievement"],
                "product_profiles": {
                    "sample_ids": "profiles/products/sample_ids.json",
                    "sample_xdr": "profiles/products/sample_xdr.json",
                },
                "seeds": [0],
            }
        },
        {
            "best_product_overall": {
                "profile_id": "sample_xdr",
                "name": "Sample XDR",
                "score": 0.72,
            }
        },
    )

    assert summary == {
        "topology": "enterprise",
        "missions": ["profit", "achievement"],
        "product_ids": ["sample_ids", "sample_xdr"],
        "seeds": "0",
        "best_product_id": "sample_xdr",
        "best_product_name": "Sample XDR",
        "best_product_score": 0.72,
    }


def test_phase90_report_is_localized_for_japanese_gui():
    source = """# Phase9.0 Intent Inference Report

## Summary
- Mission inference accuracy: `0.750`.

## Method
Phase9.0 estimates mission from observed behavior only.

## Rows
| true | inferred | confidence |
|---|---|---:|
| profit | profit | 0.422 |
"""

    localized = localize_report_markdown(source, "PHASE90_INTENT_INFERENCE_REPORT.md", "ja")

    assert "# 攻撃者の目的を推定する分析レポート" in localized
    assert "## 結果の要約" in localized
    assert "目的推定の一致率" in localized
    assert "## 分析の前提" in localized
    assert "設定値" in localized
    assert "Phase9.0" not in localized


def test_report_is_unchanged_for_english_gui():
    source = "# Phase9.0 Intent Inference Report\n\n## Summary\n"

    assert localize_report_markdown(source, "PHASE90_INTENT_INFERENCE_REPORT.md", "en") == source
