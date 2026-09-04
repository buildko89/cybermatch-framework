"""Scenario validation and deterministic execution for agentic security."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Mapping

from src.cybermatch.threat_hunting.engine import ThreatHuntingEngine
from src.cybermatch.threat_hunting.models import HuntEvent, canonical_json, stable_identifier
from src.cybermatch.threat_hunting.recipes import ThreatHuntingRecipeLoader, default_recipe_root

from .containment import AgenticContainmentPolicy, AgenticContainmentPolicyConfig
from .intel_integrity import (
    GROUND_TRUTH_LABELS,
    IntegrityGateConfig,
    ThreatIntelAdvisory,
    ThreatIntelIntegrityGate,
    evaluate_integrity_outcomes,
)
from .learning import (
    LearningEpisode,
    RewardHackingLearningConfig,
    evaluate_learning_comparison,
)
from .models import AGENTIC_EVENT_TYPES, BOUNDARY_EVENT_TYPES, AgenticThreatModel, AgenticThreatProfile
from .topology import EVENT_CONTROL_OBJECTIVES, LayeredDefenseFailureModel, TrustBoundaryTopology


AGENTIC_REPORT_FILENAME = "agentic_security_report.json"
AGENTIC_REPORT_MARKDOWN_FILENAME = "AGENTIC_SECURITY_REPORT.md"
_EVENT_FIELDS = frozenset(
    {
        "step",
        "event_type",
        "actor_id",
        "coalition_id",
        "source_node",
        "target_node",
        "source_role",
        "target_role",
        "attributes",
    }
)
_INTEL_EVALUATION_FIELDS = frozenset({"ground_truth", "first_seen_step", "corrected_step"})


def _require_mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def _validate_recipes(paths: object) -> tuple[str, ...]:
    if not isinstance(paths, list) or not paths or any(not isinstance(value, str) or not value for value in paths):
        raise ValueError("agentic.recipes must be a non-empty list of paths")
    root = default_recipe_root().resolve()
    loader = ThreatHuntingRecipeLoader(root)
    normalized: list[str] = []
    repository_root = Path(__file__).resolve().parents[3]
    for value in paths:
        path = (repository_root / value).resolve()
        if not path.is_relative_to(root):
            raise ValueError(f"agentic recipe must be below recipes/threat_hunting: {value}")
        loader.load(path.relative_to(root))
        normalized.append(value)
    return tuple(normalized)


def _load_topology(path_value: object) -> TrustBoundaryTopology:
    if not isinstance(path_value, str) or not path_value:
        raise ValueError("agentic.topology must be a non-empty path")
    repository_root = Path(__file__).resolve().parents[3]
    topology_root = (repository_root / "topologies").resolve()
    path = (repository_root / path_value).resolve()
    if not path.is_relative_to(topology_root):
        raise ValueError("agentic.topology must be below topologies")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to load agentic topology {path_value}: {exc}") from exc
    return TrustBoundaryTopology.from_dict(_require_mapping(payload, "topology"))


def _validate_learning(payload: object) -> None:
    section = _require_mapping(payload, "agentic.learning")
    unknown = sorted(set(section) - {"config", "episodes"})
    if unknown:
        raise ValueError("agentic.learning has unknown fields: " + ", ".join(unknown))
    RewardHackingLearningConfig.from_dict(section.get("config"))
    episodes = section.get("episodes")
    if not isinstance(episodes, list) or not episodes:
        raise ValueError("agentic.learning.episodes must be a non-empty list")
    parsed = [LearningEpisode.from_dict(item) for item in episodes]
    identifiers = [episode.episode_id for episode in parsed]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("agentic.learning episode_id values must be unique")


def _validate_event(payload: object, index: int) -> None:
    event = _require_mapping(payload, f"agentic.events[{index}]")
    unknown = sorted(set(event) - _EVENT_FIELDS)
    if unknown:
        raise ValueError(f"agentic.events[{index}] has unknown fields: {', '.join(unknown)}")
    step = event.get("step")
    if isinstance(step, bool) or not isinstance(step, int) or step < 0:
        raise ValueError(f"agentic.events[{index}].step must be a non-negative integer")
    event_type = event.get("event_type")
    if event_type not in AGENTIC_EVENT_TYPES:
        raise ValueError(f"agentic.events[{index}].event_type is unsupported: {event_type}")
    for name in ("actor_id", "coalition_id", "source_role", "target_role"):
        value = event.get(name)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ValueError(f"agentic.events[{index}].{name} must be a non-empty string")
    for name in ("source_node", "target_node"):
        value = event.get(name)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise ValueError(f"agentic.events[{index}].{name} must be a non-negative integer")
    attributes = event.get("attributes", {})
    if not isinstance(attributes, Mapping):
        raise ValueError(f"agentic.events[{index}].attributes must be an object")
    for key, value in attributes.items():
        if not isinstance(key, str) or not key or not isinstance(value, (str, int, float, bool, type(None))):
            raise ValueError(f"agentic.events[{index}].attributes must contain JSON scalar values")


def _advisory_payload(case: Mapping[str, object]) -> dict[str, object]:
    return {name: case[name] for name in ThreatIntelAdvisory.__dataclass_fields__ if name in case}


def _validate_threat_intelligence(section: object) -> None:
    value = _require_mapping(section, "threat_intelligence")
    unknown = sorted(set(value) - {"gate", "advisories"})
    if unknown:
        raise ValueError("threat_intelligence has unknown fields: " + ", ".join(unknown))
    IntegrityGateConfig.from_dict(value.get("gate"))
    cases = value.get("advisories")
    if not isinstance(cases, list) or not cases:
        raise ValueError("threat_intelligence.advisories must be a non-empty list")
    allowed = set(ThreatIntelAdvisory.__dataclass_fields__) | _INTEL_EVALUATION_FIELDS
    for index, raw_case in enumerate(cases):
        case = _require_mapping(raw_case, f"threat_intelligence.advisories[{index}]")
        unknown_case = sorted(set(case) - allowed)
        if unknown_case:
            raise ValueError(
                f"threat_intelligence.advisories[{index}] has unknown fields: {', '.join(unknown_case)}"
            )
        ThreatIntelAdvisory.from_dict(_advisory_payload(case))
        if case.get("ground_truth", "unknown") not in GROUND_TRUTH_LABELS:
            raise ValueError(f"threat_intelligence.advisories[{index}].ground_truth is invalid")
        first_seen = case.get("first_seen_step", 0)
        corrected = case.get("corrected_step")
        if isinstance(first_seen, bool) or not isinstance(first_seen, int) or first_seen < 0:
            raise ValueError(f"threat_intelligence.advisories[{index}].first_seen_step is invalid")
        if corrected is not None and (
            isinstance(corrected, bool) or not isinstance(corrected, int) or corrected < first_seen
        ):
            raise ValueError(f"threat_intelligence.advisories[{index}].corrected_step is invalid")


def validate_agentic_security_scenario(scenario: Mapping[str, object]) -> None:
    """Validate the opt-in agentic-security sections of a scenario."""

    agentic = scenario.get("agentic")
    threat_intelligence = scenario.get("threat_intelligence")
    if agentic is None and threat_intelligence is None:
        raise ValueError("agentic security scenario requires agentic or threat_intelligence")
    if agentic is not None:
        section = _require_mapping(agentic, "agentic")
        unknown = sorted(
            set(section)
            - {"profile", "events", "recipes", "containment", "topology", "defense_conditions", "learning"}
        )
        if unknown:
            raise ValueError("agentic has unknown fields: " + ", ".join(unknown))
        AgenticThreatProfile.from_dict(_require_mapping(section.get("profile"), "agentic.profile"))
        events = section.get("events")
        if not isinstance(events, list) or not events:
            raise ValueError("agentic.events must be a non-empty list")
        for index, event in enumerate(events):
            _validate_event(event, index)
        _validate_recipes(section.get("recipes"))
        AgenticContainmentPolicyConfig.from_dict(section.get("containment"))
        topology = _load_topology(section["topology"]) if section.get("topology") is not None else None
        if topology is not None:
            for index, raw_event in enumerate(events):
                event = _require_mapping(raw_event, f"agentic.events[{index}]")
                for name in ("source_node", "target_node"):
                    node = event.get(name)
                    if node is not None and node not in topology.node_ids:
                        raise ValueError(f"agentic.events[{index}].{name} is not present in topology")
        defense_conditions = section.get("defense_conditions", {})
        conditions = _require_mapping(defense_conditions, "agentic.defense_conditions")
        unknown_conditions = sorted(set(conditions) - {"failed_domains"})
        if unknown_conditions:
            raise ValueError(
                "agentic.defense_conditions has unknown fields: " + ", ".join(unknown_conditions)
            )
        failed_domains = conditions.get("failed_domains", [])
        if not isinstance(failed_domains, list) or any(
            not isinstance(item, str) or not item for item in failed_domains
        ):
            raise ValueError("agentic.defense_conditions.failed_domains must be a list of strings")
        if topology is None and failed_domains:
            raise ValueError("agentic.defense_conditions requires agentic.topology")
        if topology is not None:
            known_domains = {control.failure_domain for control in topology.controls}
            unknown_domains = sorted(set(failed_domains) - known_domains)
            if unknown_domains:
                raise ValueError("unknown failed defense domains: " + ", ".join(unknown_domains))
        if section.get("learning") is not None:
            _validate_learning(section["learning"])
    if threat_intelligence is not None:
        _validate_threat_intelligence(threat_intelligence)


def _build_events(scenario: Mapping[str, object]) -> tuple[HuntEvent, ...]:
    metadata = _require_mapping(scenario["metadata"], "metadata")
    scenario_name = str(metadata["name"])
    section = _require_mapping(scenario["agentic"], "agentic")
    result: list[HuntEvent] = []
    for ordinal, raw_event in enumerate(section["events"]):
        event = _require_mapping(raw_event, f"agentic.events[{ordinal}]")
        identity = {
            "scenario_id": scenario_name,
            "ordinal": ordinal,
            "step": event["step"],
            "event_type": event["event_type"],
            "actor_id": event.get("actor_id", "agent-0"),
        }
        result.append(
            HuntEvent(
                schema_version="1.0",
                event_id=stable_identifier("agentic-event", identity),
                step=int(event["step"]),
                campaign_id=f"{scenario_name}-campaign",
                scenario_id=scenario_name,
                seed=None,
                actor_id=str(event.get("actor_id", "agent-0")),
                coalition_id=event.get("coalition_id"),
                event_type=str(event["event_type"]),
                source_node=event.get("source_node"),
                target_node=event.get("target_node"),
                source_role=event.get("source_role"),
                target_role=event.get("target_role"),
                signal_class="telemetry",
                attributes=dict(event.get("attributes", {})),
            )
        )
    return tuple(sorted(result, key=lambda item: (item.step, item.event_id)))


def _load_recipes(scenario: Mapping[str, object]):
    root = default_recipe_root().resolve()
    repository_root = Path(__file__).resolve().parents[3]
    loader = ThreatHuntingRecipeLoader(root)
    section = _require_mapping(scenario["agentic"], "agentic")
    return tuple(
        loader.load((repository_root / str(path)).resolve().relative_to(root))
        for path in section["recipes"]
    )


def _run_agentic_path(scenario: Mapping[str, object], *, closed_loop: bool) -> dict[str, object]:
    section = _require_mapping(scenario["agentic"], "agentic")
    profile = AgenticThreatProfile.from_dict(_require_mapping(section["profile"], "agentic.profile"))
    policy = AgenticContainmentPolicy(
        AgenticContainmentPolicyConfig.from_dict(section.get("containment"))
    )
    recipes = _load_recipes(scenario)
    potential_events = _build_events(scenario)
    engine = ThreatHuntingEngine()
    observed: list[HuntEvent] = []
    findings: dict[str, object] = {}
    feedback: dict[str, object] = {}
    prevented_events: list[HuntEvent] = []
    terminated = False
    event_index: dict[str, HuntEvent] = {}

    for index, event in enumerate(potential_events):
        active_actions = (
            {
                item.action_type
                for item in feedback.values()
                if item.effective_step <= event.step < item.effective_step + item.duration_steps
            }
            if closed_loop
            else set()
        )
        if terminated or "terminate_evaluation" in active_actions:
            terminated = True
            prevented_events.extend(potential_events[index:])
            break
        if "pause_workload" in active_actions:
            prevented_events.append(event)
            continue
        observed.append(event)
        event_index = {item.event_id: item for item in observed}
        for recipe in recipes:
            for finding in engine.run(recipe, observed):
                if finding.finding_id in findings:
                    continue
                findings[finding.finding_id] = finding
                if closed_loop:
                    for action in policy.decide(finding, events=event_index, current_step=finding.end_step):
                        feedback[action.feedback_id] = action

    observed_tuple = tuple(observed)
    risk_state = AgenticThreatModel(profile).evaluate(observed_tuple)
    ordered_findings = sorted(
        findings.values(), key=lambda item: (item.start_step, item.end_step, item.finding_id)
    )
    ordered_feedback = sorted(
        feedback.values(), key=lambda item: (item.effective_step, item.action_type, item.feedback_id)
    )
    boundary_steps = [event.step for event in observed_tuple if event.event_type in BOUNDARY_EVENT_TYPES]
    boundary_finding_steps = [
        finding.end_step
        for finding in ordered_findings
        if any(event_index.get(event_id) and event_index[event_id].event_type in BOUNDARY_EVENT_TYPES for event_id in finding.evidence_event_ids)
    ]
    first_boundary_step = min(boundary_steps) if boundary_steps else None
    first_boundary_finding_step = min(boundary_finding_steps) if boundary_finding_steps else None
    halt_steps = [
        action.effective_step
        for action in ordered_feedback
        if action.action_type in {"pause_workload", "terminate_evaluation"}
    ]
    halt_step = min(halt_steps) if halt_steps else None
    post_alert_targets = {
        event.target_node
        for event in observed_tuple
        if first_boundary_finding_step is not None
        and event.step > first_boundary_finding_step
        and event.event_type in BOUNDARY_EVENT_TYPES
        and event.target_node is not None
    }
    invariant_violations = {
        "internet_isolation": any(event.event_type == "transitive_egress" for event in observed_tuple),
        "sandbox_isolation": any(event.event_type == "sandbox_escape" for event in observed_tuple),
        "identity_least_privilege": any(
            event.event_type in {"privilege_escalation", "control_plane_access"} for event in observed_tuple
        ),
        "third_party_boundary": any(event.event_type == "third_party_access" for event in observed_tuple),
    }
    metrics = {
        "mode": "closed_loop" if closed_loop else "open_loop",
        "potential_event_count": len(potential_events),
        "observed_event_count": len(observed_tuple),
        "prevented_event_count": len(prevented_events),
        "finding_count": len(ordered_findings),
        "containment_action_count": len(ordered_feedback),
        "first_boundary_event_step": first_boundary_step,
        "first_boundary_finding_step": first_boundary_finding_step,
        "boundary_detection_delay_steps": (
            max(0, first_boundary_finding_step - first_boundary_step)
            if first_boundary_step is not None and first_boundary_finding_step is not None
            else None
        ),
        "halt_step": halt_step,
        "alert_to_halt_steps": (
            max(0, halt_step - first_boundary_finding_step)
            if halt_step is not None and first_boundary_finding_step is not None
            else None
        ),
        "post_alert_blast_radius": len(post_alert_targets),
        "security_invariant_survival_rate": (
            sum(not value for value in invariant_violations.values()) / len(invariant_violations)
        ),
        "evaluation_terminated": terminated,
        **risk_state.to_dict(),
    }
    result = {
        "profile": profile.to_dict(),
        "events": [event.to_dict() for event in observed_tuple],
        "prevented_events": [event.to_dict() for event in prevented_events],
        "findings": [finding.to_dict() for finding in ordered_findings],
        "feedback": [action.to_dict() for action in ordered_feedback],
        "invariant_violations": invariant_violations,
        "metrics": metrics,
    }
    if section.get("topology") is not None:
        topology = _load_topology(section["topology"])
        conditions = _require_mapping(section.get("defense_conditions", {}), "agentic.defense_conditions")
        result["trust_boundary_topology"] = topology.evaluate_events(observed_tuple)
        defense = LayeredDefenseFailureModel(topology.controls).evaluate(
            conditions.get("failed_domains", [])
        )
        objective_counts: dict[str, int] = {}
        for event in observed_tuple:
            objective = EVENT_CONTROL_OBJECTIVES.get(event.event_type)
            if objective is not None:
                objective_counts[objective] = objective_counts.get(objective, 0) + 1
        for objective, row in defense["objectives"].items():
            row["observed_exposure_count"] = objective_counts.get(objective, 0)
        result["defense_failure_model"] = defense
    return result


def _compare_agentic_paths(
    open_loop: Mapping[str, object], closed_loop: Mapping[str, object]
) -> dict[str, object]:
    open_metrics = _require_mapping(open_loop["metrics"], "agentic.open_loop.metrics")
    closed_metrics = _require_mapping(closed_loop["metrics"], "agentic.closed_loop.metrics")
    result = {
        "prevented_event_lift": closed_metrics["prevented_event_count"]
        - open_metrics["prevented_event_count"],
        "risk_score_reduction": open_metrics["risk_score"] - closed_metrics["risk_score"],
        "boundary_violation_reduction": open_metrics["boundary_violation_count"]
        - closed_metrics["boundary_violation_count"],
        "post_alert_blast_radius_reduction": open_metrics["post_alert_blast_radius"]
        - closed_metrics["post_alert_blast_radius"],
        "security_invariant_survival_lift": closed_metrics["security_invariant_survival_rate"]
        - open_metrics["security_invariant_survival_rate"],
    }
    open_topology = open_loop.get("trust_boundary_topology")
    closed_topology = closed_loop.get("trust_boundary_topology")
    if isinstance(open_topology, Mapping) and isinstance(closed_topology, Mapping):
        result["unauthorized_path_reduction"] = open_topology["unauthorized_path_count"] - closed_topology[
            "unauthorized_path_count"
        ]
    return result


def _run_learning_path(scenario: Mapping[str, object]) -> dict[str, object] | None:
    section = _require_mapping(scenario["agentic"], "agentic")
    if section.get("learning") is None:
        return None
    learning = _require_mapping(section["learning"], "agentic.learning")
    config = RewardHackingLearningConfig.from_dict(learning.get("config"))
    episodes = tuple(LearningEpisode.from_dict(item) for item in learning["episodes"])
    return evaluate_learning_comparison(config, episodes)


def _run_integrity_path(scenario: Mapping[str, object]) -> dict[str, object]:
    section = _require_mapping(scenario["threat_intelligence"], "threat_intelligence")
    gate = ThreatIntelIntegrityGate(IntegrityGateConfig.from_dict(section.get("gate")))
    cases = list(section["advisories"])
    advisories = [ThreatIntelAdvisory.from_dict(_advisory_payload(case)) for case in cases]
    decisions = [gate.evaluate(advisory) for advisory in advisories]
    return {
        "advisories": [advisory.to_dict() for advisory in advisories],
        "decisions": [decision.to_dict() for decision in decisions],
        "metrics": evaluate_integrity_outcomes(decisions, cases),
    }


def _markdown_report(report: Mapping[str, object]) -> str:
    lines = [
        "# Agentic Security Evaluation Report",
        "",
        f"- Scenario: {report['scenario_name']}",
        f"- Schema version: {report['schema_version']}",
    ]
    agentic = report.get("agentic")
    if isinstance(agentic, Mapping):
        metrics = agentic["metrics"]
        lines.extend(
            [
                "",
                "## Agentic containment",
                "",
                f"- Risk score: {metrics['risk_score']:.4f}",
                f"- Prevented events: {metrics['prevented_event_count']}",
                f"- Boundary detection delay: {metrics['boundary_detection_delay_steps']}",
                f"- Alert-to-halt steps: {metrics['alert_to_halt_steps']}",
                f"- Security invariant survival rate: {metrics['security_invariant_survival_rate']:.4f}",
                f"- Open/closed risk reduction: {agentic['comparison']['risk_score_reduction']:.4f}",
            ]
        )
        if isinstance(agentic.get("learning"), Mapping):
            learning = agentic["learning"]
            lines.extend(
                [
                    "",
                    "## Inter-episode reward hacking",
                    "",
                    f"- Open-loop final propensity: {learning['open_loop']['final_propensity']:.4f}",
                    f"- Closed-loop final propensity: {learning['closed_loop']['final_propensity']:.4f}",
                    f"- Propensity reduction: {learning['comparison']['final_propensity_reduction']:.4f}",
                ]
            )
    integrity = report.get("threat_intelligence")
    if isinstance(integrity, Mapping):
        metrics = integrity["metrics"]
        lines.extend(
            [
                "",
                "## Threat intelligence integrity",
                "",
                f"- Fabricated advisory acceptance rate: {metrics['fabricated_advisory_acceptance_rate']:.4f}",
                f"- Valid advisory acceptance rate: {metrics['valid_advisory_acceptance_rate']:.4f}",
                f"- Verification coverage: {metrics['verification_coverage']:.4f}",
                f"- Evidence pass rate: {metrics['evidence_pass_rate']:.4f}",
                f"- Unnecessary remediation count: {metrics['unnecessary_remediation_count']}",
            ]
        )
    lines.extend(["", "This report is a deterministic benchmark result, not a product certification.", ""])
    return "\n".join(lines)


def run_agentic_security_evaluation(
    scenario: Mapping[str, object], *, output_dir: str | None = None
) -> dict[str, object]:
    """Run an agentic-security scenario and write reproducible JSON/Markdown artifacts."""

    validate_agentic_security_scenario(scenario)
    metadata = _require_mapping(scenario["metadata"], "metadata")
    evaluation = _require_mapping(scenario["evaluation"], "evaluation")
    root = Path(output_dir or evaluation.get("output_dir") or "output/agentic_security").resolve()
    if root.exists():
        raise FileExistsError(f"output path already exists: {root}")
    root.mkdir(parents=True, exist_ok=False)
    try:
        report: dict[str, object] = {
            "schema_version": "1.0",
            "scenario_name": metadata["name"],
            "runner": "agentic_security_evaluation",
        }
        if scenario.get("agentic") is not None:
            open_loop = _run_agentic_path(scenario, closed_loop=False)
            closed_loop = _run_agentic_path(scenario, closed_loop=True)
            comparison = _compare_agentic_paths(open_loop, closed_loop)
            learning = _run_learning_path(scenario)
            report["agentic"] = {
                "open_loop": open_loop,
                "closed_loop": closed_loop,
                "comparison": comparison,
                "learning": learning,
                # Stable aliases retain the v1 closed-loop report contract.
                **closed_loop,
            }
        if scenario.get("threat_intelligence") is not None:
            report["threat_intelligence"] = _run_integrity_path(scenario)
        (root / AGENTIC_REPORT_FILENAME).write_text(
            canonical_json(report) + "\n", encoding="utf-8", newline="\n"
        )
        (root / AGENTIC_REPORT_MARKDOWN_FILENAME).write_text(
            _markdown_report(report), encoding="utf-8", newline="\n"
        )
        return report
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


__all__ = [
    "AGENTIC_REPORT_FILENAME",
    "AGENTIC_REPORT_MARKDOWN_FILENAME",
    "run_agentic_security_evaluation",
    "validate_agentic_security_scenario",
]
