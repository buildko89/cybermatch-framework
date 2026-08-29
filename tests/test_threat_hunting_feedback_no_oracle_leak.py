import inspect

import pytest

from cybermatch_core.threat_hunting import (
    GroundTruthLabel,
    ThreatHuntingFeedbackPolicy,
)


def test_feedback_policy_public_api_rejects_truth_objects():
    truth = GroundTruthLabel(
        label_id="truth",
        campaign_id="campaign",
        label_type="critical_compromise",
        start_step=1,
        end_step=1,
        actor_id="attacker-0",
        target_node=4,
        severity="critical",
    )
    with pytest.raises(TypeError, match="Finding"):
        ThreatHuntingFeedbackPolicy().decide(truth, events={}, current_step=1)


def test_feedback_policy_module_has_no_ground_truth_or_evaluator_dependency():
    import src.cybermatch.threat_hunting.feedback_policy as module

    source = inspect.getsource(module)
    assert "GroundTruthLabel" not in source
    assert "ThreatHuntingEvaluator" not in source
    assert "truth_match" not in source
