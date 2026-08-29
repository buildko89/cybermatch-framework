import json

import pytest

from cybermatch_core.threat_hunting import (
    ExternalFieldMapping,
    ExternalTelemetryAdapter,
    ExternalTelemetryError,
)


def _timestamp_mapping():
    return ExternalFieldMapping(
        mapping_id="jsonl_timestamp_v1",
        field_map={"event_id": "id", "event_type": "type", "actor_id": "principal"},
        attribute_map={"query_length": "query_length"},
        defaults={"signal_class": "telemetry"},
        timestamp_field="timestamp",
        timezone="Asia/Tokyo",
        step_seconds=60,
    )


def test_jsonl_timestamp_mapping_and_round_trip(tmp_path):
    source = tmp_path / "telemetry.jsonl"
    rows = [
        {"id": "dns_1", "timestamp": "2026-08-29T09:00:00", "type": "dns", "principal": "a", "query_length": 12},
        {"id": "dns_2", "timestamp": "2026-08-29T09:02:00", "type": "dns", "principal": "a", "query_length": 90},
    ]
    source.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    adapter = ExternalTelemetryAdapter(
        _timestamp_mapping(), campaign_id="campaign", scenario_id="scenario", seed=2
    )

    events = adapter.from_jsonl(source)
    restored = adapter.from_jsonl(adapter.write_jsonl(tmp_path / "roundtrip.jsonl", events))

    assert [event.step for event in events] == [0, 2]
    assert restored == events


@pytest.mark.parametrize(
    "content, message",
    [
        ("not-json\n", "invalid JSONL line 1"),
        ("[]\n", "must be an object"),
        ('{"id":"x"}\n', "missing fields"),
    ],
)
def test_jsonl_rejects_malformed_records(tmp_path, content, message):
    source = tmp_path / "bad.jsonl"
    source.write_text(content, encoding="utf-8")
    adapter = ExternalTelemetryAdapter(
        _timestamp_mapping(), campaign_id="campaign", scenario_id="scenario"
    )

    with pytest.raises(ExternalTelemetryError, match=message):
        adapter.from_jsonl(source)


def test_jsonl_enforces_record_and_line_limits(tmp_path):
    source = tmp_path / "telemetry.jsonl"
    row = {"id": "dns_1", "timestamp": "2026-08-29T09:00:00", "type": "dns", "principal": "a", "query_length": 12}
    source.write_text(json.dumps(row) + "\n", encoding="utf-8")

    with pytest.raises(ExternalTelemetryError, match="line limit"):
        ExternalTelemetryAdapter(
            _timestamp_mapping(), campaign_id="campaign", scenario_id="scenario", max_line_bytes=10
        ).from_jsonl(source)
    with pytest.raises(ExternalTelemetryError, match="exceeds 1 records"):
        ExternalTelemetryAdapter(
            _timestamp_mapping(), campaign_id="campaign", scenario_id="scenario", max_records=1
        ).adapt_records([row, row])
