import pytest

from cybermatch_core.threat_hunting import (
    NullThreatHuntingFeedbackSink,
    ThreatHuntingFeedback,
    ThreatHuntingFeedbackSink,
)


def test_feedback_factory_is_deterministic_and_serializable():
    first = ThreatHuntingFeedback.create(
        finding_id="finding_001",
        action_type="observe_only",
        effective_step=8,
        duration_steps=1,
        target_nodes=(4,),
        confidence=0.7,
        reason="Offline-only feedback contract",
    )
    second = ThreatHuntingFeedback.create(
        finding_id="finding_001",
        action_type="observe_only",
        effective_step=8,
        duration_steps=1,
        target_nodes=(4,),
        confidence=0.7,
        reason="Offline-only feedback contract",
    )

    assert first == second
    assert first.feedback_id.startswith("feedback_")
    assert first.to_dict()["target_nodes"] == [4]


def test_null_feedback_sink_satisfies_protocol_without_retaining_state():
    sink = NullThreatHuntingFeedbackSink()
    feedback = ThreatHuntingFeedback.create(
        finding_id="finding_001",
        action_type="increase_monitoring",
        effective_step=8,
        duration_steps=2,
        confidence=0.8,
        reason="Contract test",
    )

    assert isinstance(sink, ThreatHuntingFeedbackSink)
    assert sink.submit(feedback) is None
    assert vars(sink) == {}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("action_type", "retreat_attacker"),
        ("effective_step", -1),
        ("duration_steps", 0),
        ("confidence", 1.1),
    ],
)
def test_feedback_rejects_invalid_values(field, value):
    payload = {
        "feedback_id": "feedback_001",
        "finding_id": "finding_001",
        "action_type": "observe_only",
        "effective_step": 8,
        "duration_steps": 1,
        "confidence": 0.5,
        "reason": "Contract test",
    }
    payload[field] = value

    with pytest.raises(ValueError):
        ThreatHuntingFeedback(**payload)


def test_null_feedback_sink_rejects_untyped_input():
    with pytest.raises(TypeError, match="ThreatHuntingFeedback"):
        NullThreatHuntingFeedbackSink().submit({"finding_id": "finding_001"})
