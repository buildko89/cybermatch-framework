import random

import pytest

from cybermatch_core.threat_hunting import (
    HistoryObservationAdapter,
    HuntEvent,
    ThreatHuntingEngine,
    ThreatHuntingRecipeLoader,
    default_recipe_root,
    validate_recipe,
)


def _event(event_id, step, event_type, *, campaign="campaign", actor="actor", source=0, target=1):
    return HuntEvent(
        schema_version="1.0",
        event_id=event_id,
        step=step,
        campaign_id=campaign,
        scenario_id="scenario",
        seed=0,
        actor_id=actor,
        coalition_id=None,
        event_type=event_type,
        source_node=source,
        target_node=target,
        source_role="entry",
        target_role="server",
        signal_class="telemetry",
        attributes={"source_history_keys": "observable_events", "ordinal": step},
    )


def _recipe(operations, *, group_by=None, required_fields=None, finding=None):
    return validate_recipe(
        {
            "schema_version": "1.0",
            "id": "engine_test",
            "version": "1.0",
            "title": "Engine test",
            "hypothesis": "The deterministic operator pipeline should match.",
            "source": "observed",
            "required_fields": required_fields
            or ["campaign_id", "actor_id", "event_id", "event_type", "step"],
            "group_by": group_by or ["campaign_id", "actor_id"],
            "operations": operations,
            "finding": finding
            or {
                "severity": "medium",
                "title": "Activity matched",
                "reason": "The operation pipeline matched observable activity.",
                "score": 0.7,
            },
        }
    )


def test_engine_is_independent_of_input_order_and_deduplicates_findings():
    recipe = _recipe(
        [
            {
                "operator": "filter",
                "field": "event_type",
                "predicate": "contains",
                "value": "critical",
            },
            {"operator": "window", "kind": "tumbling", "size_steps": 5},
            {"operator": "aggregate", "function": "count", "as": "event_count"},
        ],
        finding={
            "severity": "high",
            "title": "Critical activity",
            "reason": "Critical activity exceeded the window threshold.",
            "score": 0.9,
            "condition": {"field": "event_count", "predicate": "gte", "value": 2},
        },
    )
    events = [
        _event("e0", 0, "critical_path_entry"),
        _event("e4", 4, "critical_path_progress"),
        _event("e5", 5, "critical_path_near_target"),
    ]
    shuffled = list(events)
    random.Random(42).shuffle(shuffled)

    ordered_findings = ThreatHuntingEngine().run(recipe, events)
    shuffled_findings = ThreatHuntingEngine().run(recipe, shuffled)

    assert [finding.to_dict() for finding in ordered_findings] == [
        finding.to_dict() for finding in shuffled_findings
    ]
    assert len(ordered_findings) == 1
    finding = ordered_findings[0]
    assert finding.evidence_event_ids == ("e0", "e4")
    assert finding.observed_value == 2.0
    assert finding.threshold == 2.0
    assert finding.attributes["window_start"] == 0
    assert finding.attributes["window_end_exclusive"] == 5
    assert "operator=aggregate" in finding.reason
    assert "threshold=2.0" in finding.reason


def test_sample_recipes_execute_against_current_history_adapter_output():
    events = HistoryObservationAdapter().adapt(
        {
            "observable_events": [
                "credential_use",
                "lateral_move",
                "critical_path_entry",
                "critical_path_progress|critical_path_near_target",
            ],
            "critical_path_events": [
                "",
                "",
                "critical_path_entry",
                "critical_path_progress|critical_path_near_target",
            ],
            "true_mission_history": ["secret", "secret", "secret", "secret"],
            "critical_compromise": [False, False, False, True],
        },
        campaign_id="sample-campaign",
        scenario_id="sample-scenario",
        seed=0,
    )
    loader = ThreatHuntingRecipeLoader(default_recipe_root())
    credential_recipe, approach_recipe = loader.load_many(
        [
            "credential_to_critical_path_v1.json",
            "critical_path_approach_v1.json",
        ]
    )

    credential_findings = ThreatHuntingEngine().run(credential_recipe, events)
    approach_findings = ThreatHuntingEngine().run(approach_recipe, events)

    assert len(credential_findings) == 1
    assert credential_findings[0].evidence_event_ids
    assert len(approach_findings) == 1
    assert approach_findings[0].observed_value == 3.0


def test_fixed_window_is_start_inclusive_and_end_exclusive():
    recipe = _recipe(
        [
            {"operator": "window", "kind": "fixed", "start_step": 2, "size_steps": 3},
            {"operator": "aggregate", "function": "count", "as": "event_count"},
        ]
    )
    events = [
        _event("before", 1, "scan"),
        _event("start", 2, "scan"),
        _event("inside", 4, "scan"),
        _event("end", 5, "scan"),
    ]

    findings = ThreatHuntingEngine().run(recipe, events)

    assert len(findings) == 1
    assert findings[0].evidence_event_ids == ("start", "inside")
    assert findings[0].observed_value == 2.0


@pytest.mark.parametrize(
    ("predicate", "expected", "matching_id"),
    [
        ("eq", "scan", "scan"),
        ("ne", "scan", "credential"),
        ("in", ["credential_use"], "credential"),
        ("contains", "credential", "credential"),
        ("regex", "^credential_[a-z]+$", "credential"),
    ],
)
def test_filter_predicates(predicate, expected, matching_id):
    recipe = _recipe(
        [
            {
                "operator": "filter",
                "field": "event_type",
                "predicate": predicate,
                "value": expected,
            }
        ]
    )
    findings = ThreatHuntingEngine().run(
        recipe,
        [_event("scan", 0, "scan"), _event("credential", 1, "credential_use")],
    )

    assert [finding.evidence_event_ids for finding in findings] == [(matching_id,)]


def test_numeric_filter_predicates():
    recipe = _recipe(
        [
            {
                "operator": "filter",
                "field": "step",
                "predicate": "gte",
                "value": 2,
            }
        ]
    )

    findings = ThreatHuntingEngine().run(
        recipe,
        [_event("early", 1, "scan"), _event("boundary", 2, "scan")],
    )

    assert [finding.evidence_event_ids for finding in findings] == [("boundary",)]


@pytest.mark.parametrize(
    ("function", "field", "expected"),
    [
        ("count", None, 3.0),
        ("sum", "step", 6.0),
        ("avg", "step", 2.0),
        ("min", "step", 1.0),
        ("max", "step", 3.0),
        ("distinct_count", "event_type", 2.0),
        ("values", "event_type", None),
    ],
)
def test_aggregate_functions(function, field, expected):
    operation = {"operator": "aggregate", "function": function, "as": "result"}
    if field is not None:
        operation["field"] = field
    recipe = _recipe(operation and [operation], group_by=["campaign_id"])

    findings = ThreatHuntingEngine().run(
        recipe,
        [
            _event("one", 1, "scan"),
            _event("two", 2, "scan"),
            _event("three", 3, "credential_use"),
        ],
    )

    assert len(findings) == 1
    assert findings[0].observed_value == expected


def test_derive_length_coalesce_and_difference():
    length_recipe = _recipe(
        [
            {"operator": "derive", "function": "length", "field": "event_type", "as": "name_length"},
            {"operator": "filter", "field": "name_length", "predicate": "gt", "value": 5},
        ]
    )
    coalesce_recipe = _recipe(
        [
            {
                "operator": "derive",
                "function": "coalesce",
                "fields": ["source_role", "target_role"],
                "as": "role",
            },
            {"operator": "filter", "field": "role", "predicate": "eq", "value": "entry"},
        ],
        required_fields=["campaign_id", "actor_id", "event_id", "event_type", "step", "source_role", "target_role"],
    )
    difference_recipe = _recipe(
        [
            {
                "operator": "derive",
                "function": "difference",
                "fields": ["target_node", "source_node"],
                "as": "node_delta",
            },
            {"operator": "filter", "field": "node_delta", "predicate": "gte", "value": 1},
        ],
        required_fields=["campaign_id", "actor_id", "event_id", "event_type", "step", "source_node", "target_node"],
    )
    events = [_event("event", 0, "credential_use", source=2, target=4)]

    assert len(ThreatHuntingEngine().run(length_recipe, events)) == 1
    assert len(ThreatHuntingEngine().run(coalesce_recipe, events)) == 1
    assert len(ThreatHuntingEngine().run(difference_recipe, events)) == 1


@pytest.mark.parametrize(
    ("kind", "expected_type"),
    [("top", "scan"), ("rare", "credential_use")],
)
def test_rank_top_and_rare(kind, expected_type):
    recipe = _recipe(
        [
            {"operator": "aggregate", "function": "count", "as": "event_count"},
            {"operator": "rank", "kind": kind, "field": "event_count", "limit": 1},
        ],
        group_by=["campaign_id", "event_type"],
    )
    events = [
        _event("scan0", 0, "scan"),
        _event("scan1", 1, "scan"),
        _event("credential", 2, "credential_use"),
    ]

    findings = ThreatHuntingEngine().run(recipe, events)

    assert len(findings) == 1
    evidence_types = {event.event_type for event in events if event.event_id in findings[0].evidence_event_ids}
    assert evidence_types == {expected_type}


def test_rank_sort_direction_is_explicit():
    recipe = _recipe(
        [
            {"operator": "aggregate", "function": "count", "as": "event_count"},
            {
                "operator": "rank",
                "kind": "sort",
                "field": "event_count",
                "limit": 1,
                "direction": "desc",
            },
        ],
        group_by=["campaign_id", "event_type"],
    )

    findings = ThreatHuntingEngine().run(
        recipe,
        [_event("scan0", 0, "scan"), _event("scan1", 1, "scan"), _event("one", 2, "credential_use")],
    )

    assert len(findings) == 1
    assert findings[0].observed_value == 2.0
