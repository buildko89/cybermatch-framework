import json

from cybermatch_core.threat_hunting import (
    TELEMETRY_FAMILIES,
    HistoryObservationAdapter,
    TypedTelemetryContext,
    build_typed_telemetry,
    serialize_typed_telemetry,
)


def test_typed_telemetry_covers_minimal_process_dns_network_and_auth_families():
    events = build_typed_telemetry(
        TypedTelemetryContext(
            step=4,
            campaign_id="campaign",
            scenario_id="scenario",
            seed=3,
            actor_id="attacker-0",
            source_node=1,
            target_node=4,
            source_role="dmz",
            target_role="critical_asset",
            observable_event_types=("exploit_attempt", "credential_use", "lateral_move"),
            attack_active=True,
            success=False,
            detected=True,
            credential_used=True,
            c2_jitter_ratio=0.5,
            dns_tunnel_chunk_size=48,
            process_masquerading=True,
            domain_homoglyph_enabled=True,
        )
    )

    families = {event.attributes["telemetry_family"] for event in events}
    assert families == TELEMETRY_FAMILIES
    assert {event.target_node for event in events} == {4}
    assert len({event.event_id for event in events}) == len(events)
    payload = json.loads(serialize_typed_telemetry(events))
    assert len(payload["events"]) == len(events)


def test_typed_telemetry_contains_observations_but_no_truth_or_attacker_belief():
    events = build_typed_telemetry(
        TypedTelemetryContext(
            step=0,
            campaign_id="campaign",
            scenario_id="scenario",
            seed=None,
            actor_id="attacker-0",
            source_node=0,
            target_node=1,
            source_role=None,
            target_role=None,
            observable_event_types=("scan",),
            attack_active=True,
            success=False,
            detected=False,
            credential_used=False,
        )
    )
    serialized = serialize_typed_telemetry(events)

    for forbidden in (
        "true_mission",
        "critical_compromise",
        "attacker_current_belief",
        "attacker_selection_score",
        "truth_match",
    ):
        assert forbidden not in serialized


def test_history_adapter_prefers_typed_telemetry_and_preserves_attributes():
    context = TypedTelemetryContext(
        step=0,
        campaign_id="campaign",
        scenario_id="scenario",
        seed=4,
        actor_id="attacker-0",
        source_node=0,
        target_node=1,
        source_role="entry",
        target_role="dmz",
        observable_event_types=("exploit_attempt",),
        attack_active=True,
        success=True,
        detected=False,
        credential_used=False,
    )
    typed = build_typed_telemetry(context)
    events = HistoryObservationAdapter().adapt(
        {
            "typed_telemetry": [serialize_typed_telemetry(typed)],
            "observable_events": ["fake_truth_bearing_name"],
        },
        campaign_id="campaign",
        scenario_id="scenario",
        seed=4,
    )

    assert events == list(typed)
    assert events[0].attributes["telemetry_family"] == "process"
