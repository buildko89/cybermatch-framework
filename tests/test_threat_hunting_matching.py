from cybermatch_core.threat_hunting import (
    Finding,
    GroundTruthLabel,
    HuntEvent,
    ThreatHuntingEvaluator,
    TruthMatchingPolicy,
)


def _event(event_id, step, *, actor="actor-a", target=7):
    return HuntEvent(
        schema_version="1.0",
        event_id=event_id,
        step=step,
        campaign_id="campaign",
        scenario_id="scenario",
        seed=1,
        actor_id=actor,
        coalition_id=None,
        event_type="signal",
        source_node=None,
        target_node=target,
        source_role=None,
        target_role=None,
        signal_class="telemetry",
    )


def _finding(finding_id, event, *, start=None, end=None, actor="actor-a"):
    start = event.step if start is None else start
    end = start if end is None else end
    return Finding(
        schema_version="1.0",
        finding_id=finding_id,
        recipe_id="recipe",
        recipe_version="1.0",
        severity="high",
        score=0.8,
        campaign_id="campaign",
        actor_id=actor,
        start_step=start,
        end_step=end,
        title="Signal",
        reason="fixture",
        evidence_event_ids=(event.event_id,),
    )


def _truth(label_id, step, *, actor="actor-a", target=7, attributes=None):
    return GroundTruthLabel(
        label_id=label_id,
        campaign_id="campaign",
        label_type="attacker_success",
        start_step=step,
        end_step=step,
        actor_id=actor,
        target_node=target,
        severity="high",
        attributes=attributes or {},
    )


def test_matching_uses_campaign_window_actor_target_and_declared_event():
    event = _event("event-1", 4)
    finding = _finding("finding-1", event)
    truth = _truth("truth-1", 4, attributes={"event_id": "event-1"})

    result = ThreatHuntingEvaluator().evaluate(
        [finding], [truth], events=[event], total_steps=10
    )

    assert len(result.matches) == 1
    assert result.matches[0].matched_on == (
        "campaign",
        "overlapping_window",
        "actor",
        "target",
        "event",
    )


def test_matching_rejects_known_actor_target_and_event_mismatches():
    event = _event("event-1", 4)
    finding = _finding("finding-1", event)

    for truth in (
        _truth("wrong-actor", 4, actor="actor-b"),
        _truth("wrong-target", 4, target=99),
        _truth("wrong-event", 4, attributes={"source_event_id": "event-2"}),
    ):
        result = ThreatHuntingEvaluator().evaluate(
            [finding], [truth], events=[event], total_steps=10
        )
        assert result.matches == ()


def test_matching_treats_unknown_actor_and_target_as_non_blocking():
    event = _event("event-1", 4, actor=None, target=None)
    finding = _finding("finding-1", event, actor=None)
    truth = _truth("truth-1", 4)

    result = ThreatHuntingEvaluator().evaluate(
        [finding], [truth], events=[event], total_steps=10
    )

    assert len(result.matches) == 1
    assert result.matches[0].matched_on == ("campaign", "overlapping_window")


def test_one_to_one_matching_prevents_duplicate_findings_from_inflating_precision():
    first_event = _event("event-1", 4)
    second_event = _event("event-2", 4)
    findings = [
        _finding("finding-1", first_event),
        _finding("finding-2", second_event),
    ]
    truth = _truth("truth-1", 4)

    result = ThreatHuntingEvaluator().evaluate(
        findings,
        [truth],
        events=[first_event, second_event],
        total_steps=10,
    )

    assert len(result.matches) == 1
    assert result.metrics["precision"] == 0.5
    assert result.metrics["recall"] == 1.0


def test_policy_can_allow_bounded_early_and_late_matches():
    event = _event("event-1", 3)
    finding = _finding("finding-1", event)
    truth = _truth("truth-1", 5)
    policy = TruthMatchingPolicy(max_lead_steps=2)

    result = ThreatHuntingEvaluator(policy).evaluate(
        [finding], [truth], events=[event], total_steps=10
    )

    assert len(result.matches) == 1
    assert result.matches[0].detection_delay_steps == -2
