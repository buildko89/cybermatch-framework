from cybermatch_core.threat_hunting import (
    ClosedLoopThreatHuntingController,
    Finding,
    HuntEvent,
    ThreatHuntingFeedbackPolicy,
    ThreatHuntingRecipeLoader,
    default_recipe_root,
    summarize_feedback_effects,
)


def _event(event_id, step, event_type, source=1, target=4):
    return HuntEvent(
        schema_version="1.0",
        event_id=event_id,
        step=step,
        campaign_id="campaign",
        scenario_id="scenario",
        seed=0,
        actor_id="attacker-0",
        coalition_id=None,
        event_type=event_type,
        source_node=source,
        target_node=target,
        source_role="dmz",
        target_role="critical_asset",
        signal_class="telemetry",
        attributes={"telemetry_family": "network"},
    )


def _finding(event):
    return Finding(
        schema_version="1.0",
        finding_id=f"finding-{event.event_id}",
        recipe_id="recipe",
        recipe_version="1.0",
        severity="high",
        score=0.9,
        campaign_id="campaign",
        actor_id="attacker-0",
        start_step=event.step,
        end_step=event.step,
        title="observable fixture",
        reason="observable fixture",
        evidence_event_ids=(event.event_id,),
    )


def test_policy_maps_observable_event_families_to_typed_actions():
    policy = ThreatHuntingFeedbackPolicy()
    expected = {
        "credential_use": "require_additional_auth",
        "lateral_move": "block_edge",
        "critical_probe": "redirect_to_decoy",
        "scan": "increase_monitoring",
    }
    for event_type, action_type in expected.items():
        event = _event(f"event-{event_type}", 5, event_type)
        feedback = policy.decide(_finding(event), events={event.event_id: event}, current_step=5)
        assert feedback.action_type == action_type
        assert feedback.effective_step == 6
        assert feedback.finding_id == f"finding-{event.event_id}"


def test_controller_deduplicates_findings_and_activates_feedback_next_step():
    recipe = ThreatHuntingRecipeLoader(default_recipe_root()).load("critical_path_approach_v1.json")
    controller = ClosedLoopThreatHuntingController((recipe,))
    first = _event("critical-1", 1, "critical_path_entry")
    second = _event("critical-2", 2, "critical_path_near_target")

    assert controller.observe((first,), current_step=1) == ()
    created = controller.observe((second,), current_step=2)
    assert len(created) == 1
    assert created[0].action_type == "redirect_to_decoy"
    assert controller.active_at(2) == ()
    assert controller.active_at(3) == created
    assert controller.observe((), current_step=3) == ()


def test_feedback_effect_summary_applies_only_to_matching_target_or_edge():
    policy = ThreatHuntingFeedbackPolicy()
    event = _event("lateral", 3, "lateral_move", source=1, target=4)
    feedback = policy.decide(_finding(event), events={event.event_id: event}, current_step=3)

    matching = summarize_feedback_effects((feedback,), source_node=1, target_node=4)
    other = summarize_feedback_effects((feedback,), source_node=2, target_node=4)

    assert matching.blocked is True
    assert matching.confidence == 0.9
    assert other.blocked is False
