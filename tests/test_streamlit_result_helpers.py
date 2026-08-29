from __future__ import annotations

from apps.streamlit_app import (
    TEXT,
    build_decision_recommendations,
    build_hunting_bubble_rows,
    build_hunting_event_summary,
    build_hunting_evidence_timeline,
    build_hunting_heatmap_rows,
    build_hunting_model_summary,
    build_hunting_summary_cards,
    build_recipe_operation_rows,
    build_user_run_summary,
    localize_report_markdown,
)


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


def test_hunting_navigation_is_available_in_both_languages():
    assert TEXT["日本語"]["nav_to_key"]["脅威ハンティング"] == "hunting"
    assert TEXT["English"]["nav_to_key"]["Threat Hunting"] == "hunting"


def test_hunting_summary_and_charts_use_only_succeeded_rows():
    rows = [
        {
            "status": "succeeded",
            "mission_name": "critical_hunter",
            "product_profile": "product_a",
            "recipe_id": "recipe_a",
            "noise_profile": "none",
            "f1": 0.75,
            "finding_count": 2,
            "false_positives_per_100_steps": 1.5,
        },
        {
            "status": "unsupported",
            "mission_name": "critical_hunter",
            "product_profile": "product_b",
            "recipe_id": "recipe_a",
            "noise_profile": "none",
            "f1": 1.0,
            "finding_count": 10,
        },
    ]

    cards = build_hunting_summary_cards(
        rows,
        {"evaluation_matrix_size": 2, "benchmark_completeness": 0.5},
    )
    heatmap = build_hunting_heatmap_rows(rows)
    bubbles = build_hunting_bubble_rows(rows)

    assert cards == {
        "evaluation_matrix_size": 2,
        "succeeded_cases": 1,
        "completeness": 0.5,
        "finding_count": 2,
        "mean_f1": 0.75,
    }
    assert heatmap == [
        {
            "mission": "critical_hunter",
            "product": "product_a",
            "recipe": "recipe_a",
            "mean_f1": 0.75,
        }
    ]
    assert bubbles[0]["false_positives_per_100_steps"] == 1.5


def test_hunting_model_summary_exposes_reproducibility_fields():
    rows = build_hunting_model_summary(
        {
            "plugin_id": "sklearn_kmeans_distance_v1",
            "model_kind": "kmeans_distance",
            "feature_schema": ["attributes.bytes", "step"],
            "training_data_ids": ["seed-1", "seed-2"],
            "random_seed": 17,
            "threshold": 1.23456,
            "model_hash": "abc123",
        }
    )

    assert rows == [
        {
            "plugin": "sklearn_kmeans_distance_v1",
            "model": "kmeans_distance",
            "features": "attributes.bytes, step",
            "training_data_count": 2,
            "random_seed": 17,
            "threshold": 1.2346,
            "model_hash": "abc123",
        }
    ]


def test_hunting_data_summary_and_evidence_timeline_are_deterministic():
    events = [
        {
            "event_id": "event-b",
            "step": 2,
            "event_type": "critical_path_progress",
            "signal_class": "derived_signal",
            "source_role": None,
            "target_role": "critical_asset",
        },
        {
            "event_id": "event-a",
            "step": 1,
            "event_type": "credential_use",
            "signal_class": "telemetry",
            "source_role": "identity_server",
            "target_role": None,
        },
        {
            "event_id": "event-c",
            "step": 3,
            "event_type": "credential_use",
            "signal_class": "telemetry",
            "source_role": None,
            "target_role": None,
        },
    ]

    assert build_hunting_event_summary(events)[0] == {
        "event_type": "credential_use",
        "signal_class": "telemetry",
        "count": 2,
    }
    timeline = build_hunting_evidence_timeline(events, ["event-b", "event-a"])
    assert [row["event_id"] for row in timeline] == ["event-a", "event-b"]


def test_recipe_operation_rows_end_with_finding_node():
    rows = build_recipe_operation_rows(
        {
            "operations": [
                {"operator": "filter", "field": "event_type", "predicate": "eq", "value": "scan"}
            ],
            "finding": {"score": 0.5},
        }
    )

    assert [row["operator"] for row in rows] == ["filter", "finding"]
