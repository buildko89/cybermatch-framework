import pytest

from cybermatch_core.agentic_security import (
    AgenticRiskState,
    AgenticThreatModel,
    AgenticThreatProfile,
)
from cybermatch_core.threat_hunting import HuntEvent


pytestmark = pytest.mark.agentic_security


def _event(event_id: str, step: int, event_type: str) -> HuntEvent:
    return HuntEvent(
        schema_version="1.0",
        event_id=event_id,
        step=step,
        campaign_id="campaign",
        scenario_id="agentic",
        seed=0,
        actor_id="agent-0",
        coalition_id="collective",
        event_type=event_type,
        source_node=0,
        target_node=1,
        source_role="sandbox",
        target_role="shared_service",
        signal_class="telemetry",
        attributes={"service": "artifact-service"},
    )


def test_agentic_risk_increases_with_boundary_and_credential_chaining():
    profile = AgenticThreatProfile(
        profile_id="persistent",
        task_solvability=0.1,
        reasoning_horizon_steps=100,
        boundary_pressure_gain=0.8,
        reward_hacking_propensity=0.8,
        unauthorized_coordination_propensity=0.7,
        exploit_chaining_capability=0.9,
        credential_reuse_capability=0.9,
        parallelism=4,
    )
    model = AgenticThreatModel(profile)
    low = model.evaluate([_event("blocked", 0, "task_blocked")])
    high = model.evaluate(
        [
            _event("blocked", 0, "task_blocked"),
            _event("probe", 1, "unintended_tool_probe"),
            _event("egress", 2, "transitive_egress"),
            _event("secret", 3, "secret_discovery"),
            _event("reuse", 4, "credential_reuse"),
            _event("privilege", 5, "privilege_escalation"),
        ]
    )

    assert isinstance(high, AgenticRiskState)
    assert high.risk_score > low.risk_score
    assert high.boundary_violation_count == 2
    assert high.credential_amplification_factor == 2.0
    assert high.exploit_chain_depth >= 4


def test_agentic_profile_rejects_unknown_or_invalid_fields():
    try:
        AgenticThreatProfile.from_dict({"profile_id": "x", "unknown": True})
    except ValueError as exc:
        assert "unknown fields" in str(exc)
    else:
        raise AssertionError("unknown profile field should fail")
