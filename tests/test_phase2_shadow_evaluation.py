"""Tests for CyberMatch Phase 2 Shadow Evaluation Engine."""
from __future__ import annotations

import pytest

from cybermatch.defense import (
    ShadowEvaluator,
    generate_golden_replay_dataset,
    TransactionRecord,
)


def test_generate_golden_replay_dataset_counts_and_determinism():
    """Verify dataset generates exactly 3000 normal transactions + 100 attacks deterministically."""
    ds1 = generate_golden_replay_dataset(seed=42, normal_count=3000, attack_count=100)
    assert len(ds1) == 3100

    normal_txns = [t for t in ds1 if t.is_legitimate_business]
    attack_txns = [t for t in ds1 if not t.is_legitimate_business]
    assert len(normal_txns) == 3000
    assert len(attack_txns) == 100

    # Category quota verification
    categories = {t.category for t in ds1}
    assert "routine_query" in categories
    assert "scheduled_maint" in categories
    assert "batch_export" in categories
    assert "peak_traffic" in categories
    assert "rare_emergency" in categories
    assert "attack_simulation" in categories

    # Determinism verification
    ds2 = generate_golden_replay_dataset(seed=42, normal_count=3000, attack_count=100)
    assert [t.transaction_id for t in ds1] == [t.transaction_id for t in ds2]
    assert [t.path for t in ds1] == [t.path for t in ds2]


def test_shadow_evaluation_zero_false_positives_and_high_block_rate():
    """Verify candidate policy achieves 0 FP across 3000 normal txns and blocks attacks."""
    dataset = generate_golden_replay_dataset(seed=42, normal_count=3000, attack_count=100)

    # Multi-policy mitigation suite covering both exploit vectors
    candidate_policies = [
        {
            "policy_id": "mitigation_scoped_exploit_01",
            "target_path_scope": "/api/v1/control/exploit",
            "action_type": "scoped_path_block",
            "action_parameters": {
                "http_methods": ["POST", "PUT"],
            },
        },
        {
            "policy_id": "mitigation_scoped_temp_override_02",
            "target_path_scope": "/api/v1/control/temp_limit",
            "action_type": "scoped_path_block",
            "action_parameters": {
                "http_methods": ["POST"],  # Block unapproved POST to control/temp_limit
            },
        },
    ]

    evaluator = ShadowEvaluator(run_id="eval-run-prod-01")
    result = evaluator.evaluate(candidate_policies, dataset, min_attack_block_rate=99.0)

    assert result.passed is True
    assert result.total_evaluated == 3100
    assert result.normal_samples_count == 3000
    assert result.false_positives_count == 0
    assert result.overall_fp_rate == 0.0

    # Statistical one-sided 95% upper bound for N=3000, 0 FP must be <= 0.10% (0.0998%)
    assert result.one_sided_95_upper_bound < 0.0010
    assert f"{result.one_sided_95_upper_bound * 100:.3f}" == "0.100"

    # 100% Attack neutralization rate on exploit vectors
    assert result.true_positives_count == 100
    assert result.attack_block_rate == 100.0

    # Every normal category passed with 0 FP
    for cat in ["routine_query", "scheduled_maint", "batch_export", "peak_traffic", "rare_emergency"]:
        cm = result.category_metrics[cat]
        assert cm.passed is True
        assert cm.false_positives == 0

    assert len(result.evidence_bundle_hash) == 64


def test_shadow_evaluation_approved_maintenance_exception():
    """Verify approved maintenance transactions are exempted when policy permits ticket exceptions."""
    dataset = generate_golden_replay_dataset(seed=42, normal_count=3000, attack_count=100)

    # Policy targeting /config/temp_limit with maintenance exception enabled
    policy_with_maint_allow = {
        "policy_id": "mitigation_temp_limit_safe",
        "target_path_scope": "/config/temp_limit",
        "action_type": "scoped_path_block",
        "action_parameters": {
            "http_methods": ["PUT", "POST"],
            "allow_approved_maintenance": True,  # Allows approved ticket transactions!
        },
    }

    evaluator = ShadowEvaluator(run_id="eval-maint-exception")
    res = evaluator.evaluate([policy_with_maint_allow], dataset)

    # All scheduled maintenance PUTs must safely pass without being false positives
    cm_maint = res.category_metrics["scheduled_maint"]
    assert cm_maint.false_positives == 0
    assert cm_maint.passed is True


def test_shadow_evaluation_detects_false_positives_on_overly_broad_policy():
    """Verify evaluator catches false positives and fails when policy scope is overly broad."""
    dataset = generate_golden_replay_dataset(seed=42, normal_count=500, attack_count=50)

    bad_policy = {
        "policy_id": "bad_policy_too_broad",
        "target_path_scope": "/api/v1/business",  # Overly broad: blocks legitimate business traffic!
        "action_type": "scoped_path_block",
        "action_parameters": {
            "http_methods": ["GET", "POST"],
        },
    }

    evaluator = ShadowEvaluator(run_id="eval-bad-policy")
    res = evaluator.evaluate([bad_policy], dataset)

    # Must detect false positives and fail
    assert res.passed is False
    assert res.false_positives_count > 0
    assert len(res.false_positive_details) > 0
    assert any(fp["category"] in ("routine_query", "peak_traffic") for fp in res.false_positive_details)
