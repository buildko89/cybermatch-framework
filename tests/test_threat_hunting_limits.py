import inspect

import pytest

import src.cybermatch.threat_hunting.engine as engine_module
from cybermatch_core.threat_hunting import (
    GroundTruthLabel,
    HuntEvent,
    ThreatHuntingEngine,
    ThreatHuntingInputError,
    ThreatHuntingLimitError,
    ThreatHuntingRunConfig,
    validate_recipe,
)


def _event(event_id, step, event_type="scan", campaign="campaign"):
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


def _recipe(operations, finding=None, group_by=None):
    return validate_recipe(
        {
            "schema_version": "1.0",
            "id": "limit_test",
            "version": "1.0",
            "title": "Limit test",
            "hypothesis": "Resource limits should fail closed.",
            "source": "observed",
            "required_fields": ["campaign_id", "event_id", "event_type", "step"],
            "group_by": group_by if group_by is not None else ["campaign_id"],
            "operations": operations,
            "finding": finding
            or {
                "severity": "low",
                "title": "Limit finding",
                "reason": "An event matched.",
                "score": 0.3,
            },
        }
    )


def test_max_events_raises_structured_error_without_truncation():
    engine = ThreatHuntingEngine(ThreatHuntingRunConfig(max_events=1))
    recipe = _recipe(
        [{"operator": "filter", "field": "event_type", "predicate": "eq", "value": "scan"}]
    )

    with pytest.raises(ThreatHuntingLimitError) as raised:
        engine.run(recipe, [_event("one", 0), _event("two", 1)])

    assert raised.value.to_dict() == {
        "error": "resource_limit_exceeded",
        "limit_name": "max_events",
        "limit_value": 1,
        "observed": 2,
    }


def test_window_and_sequence_limits_are_checked_before_execution():
    window_recipe = _recipe(
        [{"operator": "window", "kind": "tumbling", "size_steps": 6}]
    )
    sequence_recipe = _recipe(
        [
            {
                "operator": "sequence",
                "items": [
                    {"event_type": "scan"},
                    {"event_type": "scan", "within_steps": 1},
                ],
                "max_span_steps": 2,
            }
        ]
    )

    with pytest.raises(ThreatHuntingLimitError, match="max_window_steps"):
        ThreatHuntingEngine(ThreatHuntingRunConfig(max_window_steps=5)).run(
            window_recipe, [_event("one", 0)]
        )
    with pytest.raises(ThreatHuntingLimitError, match="max_sequence_length"):
        ThreatHuntingEngine(ThreatHuntingRunConfig(max_sequence_length=1)).run(
            sequence_recipe, [_event("one", 0)]
        )


def test_group_limit_fails_closed():
    recipe = _recipe(
        [{"operator": "aggregate", "function": "count", "as": "count"}],
        group_by=["campaign_id", "event_type"],
    )

    with pytest.raises(ThreatHuntingLimitError) as raised:
        ThreatHuntingEngine(ThreatHuntingRunConfig(max_groups=1)).run(
            recipe,
            [_event("scan", 0, "scan"), _event("credential", 1, "credential_use")],
        )

    assert raised.value.limit_name == "max_groups"
    assert raised.value.observed == 2


def test_max_findings_fails_closed_instead_of_returning_partial_results():
    recipe = _recipe(
        [{"operator": "filter", "field": "event_type", "predicate": "eq", "value": "scan"}]
    )

    with pytest.raises(ThreatHuntingLimitError) as raised:
        ThreatHuntingEngine(ThreatHuntingRunConfig(max_findings=1)).run(
            recipe,
            [_event("one", 0), _event("two", 1)],
        )

    assert raised.value.limit_name == "max_findings"


@pytest.mark.parametrize(
    ("pattern", "message"),
    [
        ("a" * 9, "max_regex_length"),
        ("(a+)+", "nested quantifiers"),
        ("(?=scan)", "lookaround"),
        (r"(scan)\1", "backreferences"),
    ],
)
def test_regex_complexity_guards(pattern, message):
    recipe = _recipe(
        [{"operator": "filter", "field": "event_type", "predicate": "regex", "value": pattern}]
    )
    config = ThreatHuntingRunConfig(max_regex_length=8 if len(pattern) == 9 else 512)

    with pytest.raises(ValueError, match=message):
        ThreatHuntingEngine(config).run(recipe, [_event("one", 0)])


def test_engine_rejects_duplicate_event_ids():
    recipe = _recipe(
        [{"operator": "filter", "field": "event_type", "predicate": "eq", "value": "scan"}]
    )

    with pytest.raises(ThreatHuntingInputError, match="must be unique"):
        ThreatHuntingEngine().run(recipe, [_event("same", 0), _event("same", 1)])


def test_engine_contract_has_no_ground_truth_dependency():
    recipe = _recipe(
        [{"operator": "filter", "field": "event_type", "predicate": "eq", "value": "scan"}]
    )
    label = GroundTruthLabel(
        label_id="truth",
        campaign_id="campaign",
        label_type="critical_compromise",
        start_step=0,
        end_step=0,
        actor_id=None,
        target_node=None,
        severity="critical",
    )

    assert "GroundTruthLabel" not in inspect.getsource(engine_module)
    with pytest.raises(ThreatHuntingInputError, match="HuntEvent observations only"):
        ThreatHuntingEngine().run(recipe, [label])
