import pytest

from cybermatch_core.agentic_security import AgenticContainmentPolicy
from cybermatch_core.threat_hunting import Finding, HuntEvent, summarize_feedback_effects


pytestmark = pytest.mark.agentic_security


def _event(event_id: str, event_type: str) -> HuntEvent:
    return HuntEvent(
        schema_version="1.0",
        event_id=event_id,
        step=4,
        campaign_id="campaign",
        scenario_id="agentic",
        seed=0,
        actor_id="agent-0",
        coalition_id=None,
        event_type=event_type,
        source_node=1,
        target_node=2,
        source_role="shared_service",
        target_role="external",
        signal_class="telemetry",
        attributes={"boundary": "research"},
    )


def _finding(events: list[HuntEvent]) -> Finding:
    return Finding(
        schema_version="1.0",
        finding_id="finding-agentic",
        recipe_id="agentic",
        recipe_version="1.0",
        severity="critical",
        score=0.99,
        campaign_id="campaign",
        actor_id="agent-0",
        start_step=4,
        end_step=4,
        title="boundary violation",
        reason="observable evidence",
        evidence_event_ids=tuple(event.event_id for event in events),
    )


def test_sandbox_escape_triggers_independent_fail_closed_actions():
    event = _event("escape", "sandbox_escape")
    actions = AgenticContainmentPolicy().decide(
        _finding([event]), events={event.event_id: event}, current_step=4
    )
    action_types = {action.action_type for action in actions}

    assert {
        "block_egress",
        "quarantine_zone",
        "pause_workload",
        "terminate_evaluation",
        "preserve_evidence",
    }.issubset(action_types)
    effects = summarize_feedback_effects(actions, source_node=1, target_node=2)
    assert effects.egress_blocked is True
    assert effects.quarantined is True
    assert effects.terminated is True
    assert effects.evidence_preserved is True


def test_third_party_access_requires_notification():
    event = _event("external", "third_party_access")
    actions = AgenticContainmentPolicy().decide(
        _finding([event]), events={event.event_id: event}, current_step=4
    )

    assert "notify_third_party" in {action.action_type for action in actions}
