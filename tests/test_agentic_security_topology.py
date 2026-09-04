import pytest

from src.cybermatch.agentic.topology import DefenseControl, LayeredDefenseFailureModel


pytestmark = pytest.mark.agentic_security


def _control(control_id, domain, prevent, detect):
    return DefenseControl(
        control_id=control_id,
        objective="egress",
        layer=control_id,
        failure_domain=domain,
        prevent_effectiveness=prevent,
        detect_effectiveness=detect,
    )


def test_layered_defense_does_not_treat_same_domain_controls_as_independent():
    controls = (
        _control("policy-a", "shared-policy-engine", 0.9, 0.8),
        _control("policy-b", "shared-policy-engine", 0.5, 0.6),
        _control("proxy", "network-appliance", 0.8, 0.9),
    )

    result = LayeredDefenseFailureModel(controls).evaluate()["objectives"]["egress"]

    assert result["independent_layer_count"] == 2
    assert result["breach_probability"] == pytest.approx(0.1)
    assert result["detection_probability"] == pytest.approx(0.96)
    assert result["single_failure_domain_risk"] is False


def test_forced_common_cause_failure_removes_one_independent_layer():
    controls = (
        _control("sandbox", "runtime", 0.9, 0.8),
        _control("proxy", "network", 0.8, 0.9),
    )

    result = LayeredDefenseFailureModel(controls).evaluate(["runtime"])["objectives"]["egress"]

    assert result["breach_probability"] == pytest.approx(0.2)
    assert result["detection_probability"] == pytest.approx(0.9)
    assert result["effective_independent_layer_count"] == 1
    assert result["single_failure_domain_risk"] is True
    assert result["domains"][1]["forced_failed"] is True
