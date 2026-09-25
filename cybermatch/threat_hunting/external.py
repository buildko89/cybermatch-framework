"""Safe CSV and JSON Lines adapters for external threat-hunting telemetry."""

from __future__ import annotations

import csv
import json
import math
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from .mappings import ExternalFieldMapping
from .models import HuntEvent, JsonScalar, SCHEMA_VERSION, canonical_json, stable_identifier


class ExternalTelemetryError(ValueError):
    """Raised when an external telemetry source is malformed or unsafe."""


def _source_path(path: str | Path, max_file_bytes: int) -> Path:
    source = Path(path).resolve()
    if not source.is_file():
        raise ExternalTelemetryError(f"telemetry file not found: {source}")
    size = source.stat().st_size
    if size > max_file_bytes:
        raise ExternalTelemetryError(f"telemetry file exceeds {max_file_bytes} bytes")
    return source


def _json_scalar(value: object, field_name: str) -> JsonScalar:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise ExternalTelemetryError(f"{field_name} must contain a finite JSON scalar")


def _optional_string(value: object, field_name: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        value = str(value)
    if not value.strip():
        return None
    return value


def _optional_int(value: object, field_name: str) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise ExternalTelemetryError(f"{field_name} must be a non-negative integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ExternalTelemetryError(f"{field_name} must be a non-negative integer") from exc
    if number < 0 or str(number) != str(value).strip():
        raise ExternalTelemetryError(f"{field_name} must be a non-negative integer")
    return number


class ExternalTelemetryAdapter:
    """Convert explicitly mapped records into immutable HuntEvent observations."""

    def __init__(
        self,
        mapping: ExternalFieldMapping,
        *,
        campaign_id: str,
        scenario_id: str,
        seed: int | None = None,
        max_records: int = 100_000,
        max_file_bytes: int = 64 * 1024 * 1024,
        max_line_bytes: int = 1024 * 1024,
    ) -> None:
        if not isinstance(mapping, ExternalFieldMapping):
            raise TypeError("mapping must be an ExternalFieldMapping")
        for value, name in ((campaign_id, "campaign_id"), (scenario_id, "scenario_id")):
            if not isinstance(value, str) or not value.strip():
                raise ExternalTelemetryError(f"{name} must be a non-empty string")
        if seed is not None and (isinstance(seed, bool) or not isinstance(seed, int) or seed < 0):
            raise ExternalTelemetryError("seed must be a non-negative integer or None")
        for value, name in (
            (max_records, "max_records"),
            (max_file_bytes, "max_file_bytes"),
            (max_line_bytes, "max_line_bytes"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ExternalTelemetryError(f"{name} must be a positive integer")
        self.mapping = mapping
        self.campaign_id = campaign_id
        self.scenario_id = scenario_id
        self.seed = seed
        self.max_records = max_records
        self.max_file_bytes = max_file_bytes
        self.max_line_bytes = max_line_bytes

    def from_csv(self, path: str | Path) -> tuple[HuntEvent, ...]:
        source = _source_path(path, self.max_file_bytes)
        try:
            with source.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                if reader.fieldnames is None:
                    raise ExternalTelemetryError("CSV header is missing")
                if len(set(reader.fieldnames)) != len(reader.fieldnames):
                    raise ExternalTelemetryError("CSV header contains duplicate fields")
                records = [dict(row) for row in reader]
        except (OSError, UnicodeError, csv.Error) as exc:
            raise ExternalTelemetryError(f"unable to read CSV telemetry: {exc}") from exc
        return self.adapt_records(records)

    def from_jsonl(self, path: str | Path) -> tuple[HuntEvent, ...]:
        source = _source_path(path, self.max_file_bytes)
        records: list[Mapping[str, object]] = []
        try:
            with source.open("rb") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    if len(raw_line) > self.max_line_bytes:
                        raise ExternalTelemetryError(f"JSONL line {line_number} exceeds the line limit")
                    if not raw_line.strip():
                        continue
                    try:
                        value = json.loads(raw_line.decode("utf-8"))
                    except (UnicodeError, json.JSONDecodeError) as exc:
                        raise ExternalTelemetryError(f"invalid JSONL line {line_number}: {exc}") from exc
                    if not isinstance(value, Mapping):
                        raise ExternalTelemetryError(f"JSONL line {line_number} must be an object")
                    records.append(value)
        except OSError as exc:
            raise ExternalTelemetryError(f"unable to read JSONL telemetry: {exc}") from exc
        return self.adapt_records(records)

    def adapt_records(self, records: Iterable[Mapping[str, object]]) -> tuple[HuntEvent, ...]:
        materialized = list(records)
        if len(materialized) > self.max_records:
            raise ExternalTelemetryError(f"telemetry exceeds {self.max_records} records")
        normalized: list[dict[str, JsonScalar]] = []
        timestamps: list[datetime | None] = []
        allowed = self.mapping.source_fields
        for ordinal, record in enumerate(materialized):
            if not isinstance(record, Mapping) or any(not isinstance(key, str) for key in record):
                raise ExternalTelemetryError(f"record {ordinal} must be an object with string keys")
            unknown = sorted(set(record) - allowed)
            if unknown and self.mapping.reject_unknown_fields:
                raise ExternalTelemetryError(f"record {ordinal} has unknown fields: {', '.join(unknown)}")
            missing = sorted(field for field in allowed if field not in record)
            if missing:
                raise ExternalTelemetryError(f"record {ordinal} is missing fields: {', '.join(missing)}")
            row = {key: _json_scalar(value, f"record {ordinal}.{key}") for key, value in record.items()}
            normalized.append(row)
            timestamps.append(self._timestamp(row, ordinal))
        dated = [value for value in timestamps if value is not None]
        origin = min(dated) if dated else None
        events = [
            self._event(row, ordinal, timestamp=timestamps[ordinal], origin=origin)
            for ordinal, row in enumerate(normalized)
        ]
        ordered = tuple(sorted(events, key=lambda event: (event.step, event.event_id)))
        if len({event.event_id for event in ordered}) != len(ordered):
            raise ExternalTelemetryError("external records produce duplicate event IDs")
        return ordered

    def _timestamp(self, row: Mapping[str, JsonScalar], ordinal: int) -> datetime | None:
        field = self.mapping.timestamp_field
        if field is None:
            return None
        value = row.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ExternalTelemetryError(f"record {ordinal}.{field} must be a timestamp string")
        try:
            parsed = (
                datetime.strptime(value, self.mapping.timestamp_format)
                if self.mapping.timestamp_format is not None
                else datetime.fromisoformat(value.replace("Z", "+00:00"))
            )
        except ValueError as exc:
            raise ExternalTelemetryError(f"record {ordinal}.{field} has an invalid timestamp") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=ZoneInfo(self.mapping.timezone))
        return parsed.astimezone(ZoneInfo("UTC"))

    def _event(
        self,
        row: Mapping[str, JsonScalar],
        ordinal: int,
        *,
        timestamp: datetime | None,
        origin: datetime | None,
    ) -> HuntEvent:
        values: dict[str, JsonScalar] = dict(self.mapping.defaults)
        for target, source in self.mapping.field_map.items():
            values[target] = row[source]
        if "step" in values:
            step = _optional_int(values["step"], "step")
            if step is None:
                raise ExternalTelemetryError("step must not be empty")
        elif timestamp is not None and origin is not None:
            elapsed = (timestamp - origin).total_seconds() / self.mapping.step_seconds
            step = int(math.floor(elapsed + 1e-12))
        else:
            step = ordinal
        event_type = _optional_string(values.get("event_type"), "event_type")
        if event_type is None:
            raise ExternalTelemetryError("event_type must not be empty")
        attributes = {
            target: row[source]
            for target, source in self.mapping.attribute_map.items()
        }
        identifier_payload = {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "scenario_id": self.scenario_id,
            "step": step,
            "ordinal": ordinal,
            "event_type": event_type,
            "actor_id": values.get("actor_id"),
            "source_node": values.get("source_node"),
            "target_node": values.get("target_node"),
            "attributes": attributes,
        }
        event_id = _optional_string(values.get("event_id"), "event_id") or stable_identifier(
            "event", identifier_payload
        )
        signal_class = _optional_string(values.get("signal_class", "telemetry"), "signal_class")
        return HuntEvent(
            schema_version=SCHEMA_VERSION,
            event_id=event_id,
            step=step,
            campaign_id=self.campaign_id,
            scenario_id=self.scenario_id,
            seed=self.seed,
            actor_id=_optional_string(values.get("actor_id"), "actor_id"),
            coalition_id=_optional_string(values.get("coalition_id"), "coalition_id"),
            event_type=event_type,
            source_node=_optional_int(values.get("source_node"), "source_node"),
            target_node=_optional_int(values.get("target_node"), "target_node"),
            source_role=_optional_string(values.get("source_role"), "source_role"),
            target_role=_optional_string(values.get("target_role"), "target_role"),
            signal_class=signal_class or "telemetry",
            attributes=attributes,
        )

    def to_external_records(self, events: Iterable[HuntEvent]) -> list[dict[str, JsonScalar]]:
        records: list[dict[str, JsonScalar]] = []
        origin = datetime(1970, 1, 1, tzinfo=ZoneInfo("UTC"))
        for event in sorted(events, key=lambda item: (item.step, item.event_id)):
            if event.campaign_id != self.campaign_id or event.scenario_id != self.scenario_id:
                raise ExternalTelemetryError("event metadata does not match adapter metadata")
            record: dict[str, JsonScalar] = {}
            event_payload = event.to_dict()
            for target, source in self.mapping.field_map.items():
                record[source] = _json_scalar(event_payload[target], target)
            for target, source in self.mapping.attribute_map.items():
                if target not in event.attributes:
                    raise ExternalTelemetryError(f"event {event.event_id} is missing attribute {target}")
                record[source] = event.attributes[target]
            if self.mapping.timestamp_field is not None:
                value = origin + timedelta(seconds=event.step * self.mapping.step_seconds)
                record[self.mapping.timestamp_field] = (
                    value.strftime(self.mapping.timestamp_format)
                    if self.mapping.timestamp_format is not None
                    else value.isoformat().replace("+00:00", "Z")
                )
            records.append(record)
        return records

    def write_jsonl(self, path: str | Path, events: Iterable[HuntEvent]) -> Path:
        target = Path(path).resolve()
        if target.exists():
            raise ExternalTelemetryError(f"output path already exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        content = "".join(canonical_json(record) + "\n" for record in self.to_external_records(events))
        target.write_text(content, encoding="utf-8", newline="\n")
        return target

    def write_csv(self, path: str | Path, events: Iterable[HuntEvent]) -> Path:
        target = Path(path).resolve()
        if target.exists():
            raise ExternalTelemetryError(f"output path already exists: {target}")
        records = self.to_external_records(events)
        fieldnames = sorted(self.mapping.source_fields)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with target.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
                writer.writeheader()
                writer.writerows(records)
        except (OSError, csv.Error) as exc:
            raise ExternalTelemetryError(f"unable to write CSV telemetry: {exc}") from exc
        return target


__all__ = ["ExternalTelemetryAdapter", "ExternalTelemetryError"]
