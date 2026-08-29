import csv

import pytest

from cybermatch_core.threat_hunting import (
    ExternalFieldMapping,
    ExternalTelemetryAdapter,
    ExternalTelemetryError,
)


def _mapping(**overrides):
    payload = {
        "mapping_id": "csv_vendor_neutral_v1",
        "field_map": {
            "event_id": "id",
            "step": "step",
            "event_type": "kind",
            "actor_id": "actor",
            "source_node": "src",
            "target_node": "dst",
        },
        "attribute_map": {"bytes": "bytes"},
        "defaults": {"signal_class": "telemetry"},
    }
    payload.update(overrides)
    return ExternalFieldMapping(**payload)


def _write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def test_csv_mapping_round_trip_is_lossless(tmp_path):
    source = tmp_path / "telemetry.csv"
    _write_csv(
        source,
        [
            {"id": "external_2", "step": "2", "kind": "network", "actor": "a", "src": "1", "dst": "4", "bytes": "40"},
            {"id": "external_1", "step": "1", "kind": "authentication", "actor": "a", "src": "0", "dst": "1", "bytes": "10"},
        ],
    )
    adapter = ExternalTelemetryAdapter(
        _mapping(), campaign_id="external-campaign", scenario_id="external-scenario", seed=7
    )

    events = adapter.from_csv(source)
    exported = adapter.write_csv(tmp_path / "roundtrip.csv", events)
    restored = adapter.from_csv(exported)

    assert restored == events
    assert [event.step for event in events] == [1, 2]
    assert events[0].attributes["bytes"] == "10"


def test_csv_rejects_unknown_missing_and_duplicate_fields(tmp_path):
    adapter = ExternalTelemetryAdapter(
        _mapping(), campaign_id="campaign", scenario_id="scenario"
    )
    unknown = tmp_path / "unknown.csv"
    _write_csv(
        unknown,
        [{"id": "x", "step": "0", "kind": "network", "actor": "a", "src": "0", "dst": "1", "bytes": "1", "truth": "malicious"}],
    )
    with pytest.raises(ExternalTelemetryError, match="unknown fields: truth"):
        adapter.from_csv(unknown)

    missing = tmp_path / "missing.csv"
    _write_csv(
        missing,
        [{"id": "x", "step": "0", "kind": "network", "actor": "a", "src": "0", "dst": "1"}],
    )
    with pytest.raises(ExternalTelemetryError, match="missing fields: bytes"):
        adapter.from_csv(missing)

    duplicate = tmp_path / "duplicate.csv"
    duplicate.write_text("id,id,step,kind,actor,src,dst,bytes\nx,x,0,network,a,0,1,1\n", encoding="utf-8")
    with pytest.raises(ExternalTelemetryError, match="duplicate fields"):
        adapter.from_csv(duplicate)


def test_mapping_rejects_invalid_timezone_and_implicit_event_type():
    with pytest.raises(ValueError, match="unknown timezone"):
        _mapping(timezone="Mars/Olympus_Mons")
    with pytest.raises(ValueError, match="event_type"):
        _mapping(field_map={"step": "step"}, defaults={})
