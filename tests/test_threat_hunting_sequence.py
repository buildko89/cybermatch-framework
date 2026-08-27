import random

from cybermatch_core.threat_hunting import HuntEvent, ThreatHuntingEngine, validate_recipe


def _event(event_id, step, event_type, *, campaign="campaign"):
    return HuntEvent(
        schema_version="1.0",
        event_id=event_id,
        step=step,
        campaign_id=campaign,
        scenario_id="scenario",
        seed=0,
        actor_id=None,
        coalition_id=None,
        event_type=event_type,
        source_node=None,
        target_node=None,
        source_role=None,
        target_role=None,
        signal_class="telemetry",
        attributes={},
    )


def _sequence_recipe(*, overlap=False, max_span=8, second_within=3, third_within=5):
    return validate_recipe(
        {
            "schema_version": "1.0",
            "id": "sequence_test",
            "version": "1.0",
            "title": "Sequence test",
            "hypothesis": "An ordered sequence should match within explicit boundaries.",
            "source": "observed",
            "required_fields": ["campaign_id", "event_id", "event_type", "step"],
            "group_by": ["campaign_id"],
            "operations": [
                {
                    "operator": "sequence",
                    "items": [
                        {"event_type": "credential_use"},
                        {"event_type": "lateral_move", "within_steps": second_within},
                        {
                            "event_type": ["critical_path_near_target", "critical_asset_reach"],
                            "within_steps": third_within,
                        },
                    ],
                    "max_span_steps": max_span,
                    "overlap": overlap,
                }
            ],
            "finding": {
                "severity": "high",
                "title": "Sequence matched",
                "reason": "The ordered sequence matched.",
                "score": 0.8,
            },
        }
    )


def test_sequence_boundaries_are_inclusive_and_input_order_independent():
    events = [
        _event("credential", 0, "credential_use"),
        _event("lateral", 3, "lateral_move"),
        _event("critical", 8, "critical_asset_reach"),
    ]
    shuffled = list(events)
    random.Random(7).shuffle(shuffled)

    first = ThreatHuntingEngine().run(_sequence_recipe(), events)
    second = ThreatHuntingEngine().run(_sequence_recipe(), shuffled)

    assert [finding.to_dict() for finding in first] == [finding.to_dict() for finding in second]
    assert len(first) == 1
    assert first[0].evidence_event_ids == ("credential", "lateral", "critical")
    assert first[0].start_step == 0
    assert first[0].end_step == 8
    assert first[0].observed_value == 3.0


def test_sequence_rejects_pause_or_span_beyond_boundary():
    pause_too_long = [
        _event("credential", 0, "credential_use"),
        _event("lateral", 4, "lateral_move"),
        _event("critical", 8, "critical_asset_reach"),
    ]
    span_too_long = [
        _event("credential", 0, "credential_use"),
        _event("lateral", 3, "lateral_move"),
        _event("critical", 9, "critical_asset_reach"),
    ]

    assert ThreatHuntingEngine().run(_sequence_recipe(), pause_too_long) == []
    assert ThreatHuntingEngine().run(_sequence_recipe(third_within=6), span_too_long) == []


def test_sequence_backtracks_when_a_later_intermediate_event_can_complete_match():
    events = [
        _event("credential", 0, "credential_use"),
        _event("lateral-too-early", 1, "lateral_move"),
        _event("lateral-valid", 3, "lateral_move"),
        _event("critical", 5, "critical_asset_reach"),
    ]

    findings = ThreatHuntingEngine().run(
        _sequence_recipe(second_within=3, third_within=2),
        events,
    )

    assert len(findings) == 1
    assert findings[0].evidence_event_ids == (
        "credential",
        "lateral-valid",
        "critical",
    )


def test_sequence_never_reuses_one_event_for_multiple_positions():
    recipe = validate_recipe(
        {
            "schema_version": "1.0",
            "id": "distinct_evidence",
            "version": "1.0",
            "title": "Distinct evidence",
            "hypothesis": "Repeated items require distinct events.",
            "source": "observed",
            "required_fields": ["campaign_id", "event_id", "event_type", "step"],
            "group_by": ["campaign_id"],
            "operations": [
                {
                    "operator": "sequence",
                    "items": [
                        {"event_type": "scan"},
                        {"event_type": "scan", "within_steps": 0},
                    ],
                    "max_span_steps": 0,
                }
            ],
            "finding": {
                "severity": "low",
                "title": "Two scans",
                "reason": "Two distinct scans occurred.",
                "score": 0.4,
            },
        }
    )

    assert ThreatHuntingEngine().run(recipe, [_event("one", 0, "scan")]) == []
    findings = ThreatHuntingEngine().run(
        recipe,
        [_event("one", 0, "scan"), _event("two", 0, "scan")],
    )
    assert len(findings) == 1
    assert len(set(findings[0].evidence_event_ids)) == 2


def test_sequence_overlap_is_explicit_and_defaults_to_non_overlap():
    events = [
        _event("credential0", 0, "credential_use"),
        _event("credential1", 1, "credential_use"),
        _event("lateral", 2, "lateral_move"),
        _event("critical", 3, "critical_path_near_target"),
    ]

    non_overlap = ThreatHuntingEngine().run(_sequence_recipe(overlap=False), events)
    overlap = ThreatHuntingEngine().run(_sequence_recipe(overlap=True), events)

    assert len(non_overlap) == 1
    assert len(overlap) == 2


def test_sequence_never_crosses_campaign_boundary():
    events = [
        _event("credential", 0, "credential_use", campaign="campaign-a"),
        _event("lateral", 1, "lateral_move", campaign="campaign-b"),
        _event("critical", 2, "critical_asset_reach", campaign="campaign-a"),
    ]

    assert ThreatHuntingEngine().run(_sequence_recipe(), events) == []
