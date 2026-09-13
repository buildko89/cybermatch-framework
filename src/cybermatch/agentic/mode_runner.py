"""Paired defense-mode evaluator for the Agentic Resilience v2 protocol."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from src.cybermatch.threat_hunting.engine import ThreatHuntingEngine
from src.cybermatch.threat_hunting.models import Finding, HuntEvent, stable_identifier

from .containment import AgenticContainmentPolicy, AgenticContainmentPolicyConfig
from .independence import audit_detector_inputs, audit_finding_causality
from .models import BOUNDARY_EVENT_TYPES, AgenticThreatModel, AgenticThreatProfile
from .scenario_runner import _build_events, _load_recipes, _load_topology, _require_mapping
from .topology import EVENT_CONTROL_OBJECTIVES, LayeredDefenseFailureModel


DEFENSE_MODES = (
    "no_defense",
    "static_defense",
    "hunting_only",
    "containment_only",
    "closed_loop",
    "active_deception",
)

_CONTAINMENT_ACTIONS = frozenset(
    {"block_egress", "revoke_identity", "quarantine_zone", "pause_workload", "terminate_evaluation"}
)
_OPERATOR_COSTS = {
    "increase_monitoring": 0.25,
    "preserve_evidence": 0.25,
    "notify_third_party": 1.0,
    "disable_shared_service": 1.0,
    "block_egress": 1.0,
    "revoke_identity": 1.0,
    "quarantine_zone": 1.5,
    "pause_workload": 2.0,
    "terminate_evaluation": 3.0,
}


def _draw(seed: int, event_id: str, stage: str) -> float:
    digest = hashlib.sha256(f"{seed}:{event_id}:{stage}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def _direct_boundary_finding(event: HuntEvent) -> Finding:
    finding_id = stable_identifier("platform-boundary-alert", {"event_id": event.event_id})
    return Finding(
        schema_version="1.0",
        finding_id=finding_id,
        recipe_id="platform_boundary_signal",
        recipe_version="1.0",
        severity="critical",
        score=1.0,
        campaign_id=event.campaign_id,
        actor_id=event.actor_id,
        start_step=event.step,
        end_step=event.step,
        title="Observable platform boundary signal",
        reason="A platform control emitted a boundary signal without evaluator labels",
        evidence_event_ids=(event.event_id,),
    )


def _static_prevention_probability(
    scenario: Mapping[str, object], event: HuntEvent, *, deception_only: bool, scale: float
) -> float:
    section = _require_mapping(scenario["agentic"], "agentic")
    topology_value = section.get("topology")
    objective = EVENT_CONTROL_OBJECTIVES.get(event.event_type)
    if topology_value is None or objective is None:
        return 0.0
    topology = _load_topology(topology_value)
    controls = tuple(
        control for control in topology.controls if not deception_only or control.layer == "deception"
    )
    if not controls:
        return 0.0
    conditions = _require_mapping(section.get("defense_conditions", {}), "agentic.defense_conditions")
    known_domains = {control.failure_domain for control in controls}
    failed_domains = [
        value for value in conditions.get("failed_domains", []) if value in known_domains
    ]
    result = LayeredDefenseFailureModel(controls).evaluate(failed_domains)
    row = result["objectives"].get(objective)
    if not isinstance(row, Mapping):
        return 0.0
    return min(1.0, max(0.0, (1.0 - float(row["breach_probability"])) * scale))


def evaluate_defense_mode(
    scenario: Mapping[str, object],
    *,
    mode: str,
    seed: int,
    observation_probability: float = 0.90,
    attack_capability: float = 0.90,
    static_control_scale: float = 1.0,
    containment_threshold: float | None = None,
) -> dict[str, object]:
    """Evaluate one paired stochastic realization without exposing ground truth to detection."""
    if mode not in DEFENSE_MODES:
        raise ValueError(f"unsupported defense mode: {mode}")
    for name, value in {
        "observation_probability": observation_probability,
        "attack_capability": attack_capability,
        "static_control_scale": static_control_scale,
    }.items():
        if not 0.0 <= float(value) <= 1.0:
            raise ValueError(f"{name} must be between 0 and 1")
    section = _require_mapping(scenario["agentic"], "agentic")
    profile = AgenticThreatProfile.from_dict(_require_mapping(section["profile"], "agentic.profile"))
    config_payload = dict(_require_mapping(section.get("containment", {}), "agentic.containment"))
    if containment_threshold is not None:
        config_payload["minimum_score"] = containment_threshold
    policy = AgenticContainmentPolicy(AgenticContainmentPolicyConfig.from_dict(config_payload))
    recipes = _load_recipes(scenario)
    potential = _build_events(scenario)
    engine = ThreatHuntingEngine()
    actual: list[HuntEvent] = []
    detector_events: list[HuntEvent] = []
    prevented: list[HuntEvent] = []
    findings: dict[str, Finding] = {}
    feedback: dict[str, object] = {}
    terminated = False
    hunting = mode in {"hunting_only", "closed_loop", "active_deception"}
    containment = mode in {"containment_only", "closed_loop", "active_deception"}

    for index, original in enumerate(potential):
        event_payload = original.to_dict()
        event_payload["seed"] = seed
        event = HuntEvent.from_dict(event_payload)
        active_actions = {
            item.action_type
            for item in feedback.values()
            if item.effective_step <= event.step < item.effective_step + item.duration_steps
        }
        if terminated or "terminate_evaluation" in active_actions:
            terminated = True
            prevented.extend(potential[index:])
            break
        if "pause_workload" in active_actions:
            prevented.append(event)
            continue
        if event.event_type in BOUNDARY_EVENT_TYPES and _draw(seed, event.event_id, "attack") > attack_capability:
            continue
        if mode in {"static_defense", "active_deception"}:
            probability = _static_prevention_probability(
                scenario,
                event,
                deception_only=mode == "active_deception",
                scale=static_control_scale,
            )
            if _draw(seed, event.event_id, f"static:{mode}") < probability:
                prevented.append(event)
                continue
        actual.append(event)
        detected = _draw(seed, event.event_id, "telemetry") <= observation_probability
        if not detected or mode in {"no_defense", "static_defense"}:
            continue
        detector_events.append(event)
        audit_detector_inputs(detector_events)
        event_index = {item.event_id: item for item in detector_events}
        new_findings: list[Finding] = []
        if hunting:
            for recipe in recipes:
                new_findings.extend(engine.run(recipe, detector_events))
        if mode == "containment_only" and event.event_type in BOUNDARY_EVENT_TYPES:
            new_findings.append(_direct_boundary_finding(event))
        for finding in new_findings:
            if finding.finding_id in findings:
                continue
            findings[finding.finding_id] = finding
            if containment:
                for action in policy.decide(finding, events=event_index, current_step=finding.end_step):
                    feedback[action.feedback_id] = action

    ordered_findings = tuple(sorted(findings.values(), key=lambda item: (item.end_step, item.finding_id)))
    ordered_feedback = tuple(
        sorted(feedback.values(), key=lambda item: (item.effective_step, item.action_type, item.feedback_id))
    )
    independence = audit_finding_causality(ordered_findings, detector_events)
    risk = AgenticThreatModel(profile).evaluate(actual)
    detector_index = {event.event_id: event for event in detector_events}
    boundary_finding_steps = [
        finding.end_step
        for finding in ordered_findings
        if any(
            detector_index[event_id].event_type in BOUNDARY_EVENT_TYPES
            for event_id in finding.evidence_event_ids
            if event_id in detector_index
        )
    ]
    first_alert = min(boundary_finding_steps) if boundary_finding_steps else None
    halt_steps = [
        item.effective_step
        for item in ordered_feedback
        if item.action_type in {"pause_workload", "terminate_evaluation"}
    ]
    halt_step = min(halt_steps) if halt_steps else None
    post_alert_targets = {
        event.target_node
        for event in actual
        if first_alert is not None
        and event.step > first_alert
        and event.event_type in BOUNDARY_EVENT_TYPES
        and event.target_node is not None
    }
    false_containment = 0
    for action in ordered_feedback:
        if action.action_type not in _CONTAINMENT_ACTIONS:
            continue
        finding = findings[action.finding_id]
        if not any(
            detector_index[event_id].event_type in BOUNDARY_EVENT_TYPES
            for event_id in finding.evidence_event_ids
            if event_id in detector_index
        ):
            false_containment += 1
    invariants = {
        "internet_isolation": any(event.event_type == "transitive_egress" for event in actual),
        "sandbox_isolation": any(event.event_type == "sandbox_escape" for event in actual),
        "identity_least_privilege": any(
            event.event_type in {"privilege_escalation", "control_plane_access"} for event in actual
        ),
        "third_party_boundary": any(event.event_type == "third_party_access" for event in actual),
    }
    metrics = {
        "risk_score": risk.risk_score,
        "containment_latency_steps": (
            max(0, halt_step - first_alert) if halt_step is not None and first_alert is not None else None
        ),
        "false_containment_count": false_containment,
        "post_alert_blast_radius": len(post_alert_targets),
        "mission_impact": len(prevented) / max(len(potential), 1),
        "attacker_adaptation": profile.reward_hacking_propensity,
        "operator_cost": sum(_OPERATOR_COSTS.get(item.action_type, 0.5) for item in ordered_feedback),
        "security_invariant_survival_rate": sum(not value for value in invariants.values()) / len(invariants),
        "prevented_event_count": len(prevented),
        "actual_event_count": len(actual),
        "detector_event_count": len(detector_events),
        "finding_count": len(ordered_findings),
        "containment_action_count": len(ordered_feedback),
    }
    return {
        "mode": mode,
        "seed": seed,
        "metrics": metrics,
        "events": [event.to_dict() for event in actual],
        "detector_events": [event.to_dict() for event in detector_events],
        "findings": [finding.to_dict() for finding in ordered_findings],
        "feedback": [item.to_dict() for item in ordered_feedback],
        "prevented_events": [event.to_dict() for event in prevented],
        "independence_audit": independence,
    }


__all__ = ["DEFENSE_MODES", "evaluate_defense_mode"]
