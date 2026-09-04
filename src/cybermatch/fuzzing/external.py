"""Versioned lossless codecs and opt-in transports for external fuzz SUTs."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Protocol, Sequence

from src.cybermatch.threat_hunting import Finding, HuntEvent, canonical_json

from .models import ExecutionLimits


EXTERNAL_MAPPING_SCHEMA_VERSION = "1.0"
EVENT_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "step",
        "campaign_id",
        "scenario_id",
        "seed",
        "actor_id",
        "coalition_id",
        "event_type",
        "source_node",
        "target_node",
        "source_role",
        "target_role",
        "signal_class",
    }
)
FINDING_FIELDS = frozenset(
    {
        "schema_version",
        "finding_id",
        "recipe_id",
        "recipe_version",
        "severity",
        "score",
        "campaign_id",
        "actor_id",
        "start_step",
        "end_step",
        "title",
        "reason",
        "evidence_event_ids",
        "observed_value",
        "baseline_value",
        "threshold",
    }
)
OPTIONAL_EVENT_STRINGS = frozenset(
    {"actor_id", "coalition_id", "source_role", "target_role"}
)
OPTIONAL_EVENT_INTS = frozenset({"seed", "source_node", "target_node"})
OPTIONAL_FINDING_NUMBERS = frozenset({"observed_value", "baseline_value", "threshold"})


class ExternalAdapterError(ValueError):
    """Base class for deterministic external adapter failures."""


class ExternalMappingError(ExternalAdapterError):
    """A mapping is malformed, ambiguous, or outside the repository."""


class ExternalProtocolError(ExternalAdapterError):
    """The external payload or response violates the declared mapping."""


class ExternalInfrastructureError(RuntimeError):
    """Execution environment failure kept separate from detection verdicts."""

    def __init__(self, error_type: str, message: str, *, retryable: bool):
        self.error_type = error_type
        self.retryable = retryable
        super().__init__(message)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExternalProtocolError(f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def _exact_fields(
    value: Mapping[str, object], name: str, expected: frozenset[str]
) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        raise ExternalMappingError(f"{name} is missing fields: {', '.join(missing)}")
    if unknown:
        raise ExternalMappingError(f"{name} has unknown fields: {', '.join(unknown)}")


def _field_mapping(
    value: object, name: str, expected: frozenset[str]
) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise ExternalMappingError(f"{name} must be an object")
    _exact_fields(value, name, expected)
    result: dict[str, str] = {}
    for canonical, external in value.items():
        if not isinstance(external, str) or not external.strip():
            raise ExternalMappingError(f"{name}.{canonical} must be a non-empty string")
        result[str(canonical)] = external
    if len(set(result.values())) != len(result):
        raise ExternalMappingError(f"{name} external field names must be unique")
    return MappingProxyType(result)


@dataclass(frozen=True)
class ExternalSUTMapping:
    schema_version: str
    mapping_id: str
    mapping_version: str
    event_fields: Mapping[str, str]
    event_attributes_field: str
    finding_fields: Mapping[str, str]
    finding_attributes_field: str

    def __post_init__(self) -> None:
        if self.schema_version != EXTERNAL_MAPPING_SCHEMA_VERSION:
            raise ExternalMappingError(
                f"schema_version must be {EXTERNAL_MAPPING_SCHEMA_VERSION!r}"
            )
        for name in (
            "mapping_id",
            "mapping_version",
            "event_attributes_field",
            "finding_attributes_field",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ExternalMappingError(f"{name} must be a non-empty string")
        event_fields = _field_mapping(self.event_fields, "event_fields", EVENT_FIELDS)
        finding_fields = _field_mapping(self.finding_fields, "finding_fields", FINDING_FIELDS)
        if self.event_attributes_field in event_fields.values():
            raise ExternalMappingError("event_attributes_field overlaps event_fields")
        if self.finding_attributes_field in finding_fields.values():
            raise ExternalMappingError("finding_attributes_field overlaps finding_fields")
        object.__setattr__(self, "event_fields", event_fields)
        object.__setattr__(self, "finding_fields", finding_fields)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "mapping_id": self.mapping_id,
            "mapping_version": self.mapping_version,
            "event_fields": dict(self.event_fields),
            "event_attributes_field": self.event_attributes_field,
            "finding_fields": dict(self.finding_fields),
            "finding_attributes_field": self.finding_attributes_field,
        }

    @property
    def mapping_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict()).encode("utf-8")).hexdigest()


def load_external_mapping(path: str | Path) -> ExternalSUTMapping:
    source = Path(path)
    try:
        payload = json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except ExternalProtocolError as exc:
        raise ExternalMappingError(str(exc)) from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExternalMappingError(f"unable to read external mapping: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ExternalMappingError("external mapping root must be an object")
    expected = frozenset(
        {
            "schema_version",
            "mapping_id",
            "mapping_version",
            "event_fields",
            "event_attributes_field",
            "finding_fields",
            "finding_attributes_field",
        }
    )
    _exact_fields(payload, "external mapping", expected)
    return ExternalSUTMapping(**dict(payload))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ExternalCodec:
    """Encode and decode complete HuntEvent/Finding semantics in JSONL or CSV."""

    def __init__(self, mapping: ExternalSUTMapping, *, max_payload_bytes: int = 64 * 1024 * 1024):
        if not isinstance(mapping, ExternalSUTMapping):
            raise TypeError("mapping must be an ExternalSUTMapping")
        if isinstance(max_payload_bytes, bool) or not isinstance(max_payload_bytes, int) or max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be a positive integer")
        self.mapping = mapping
        self.max_payload_bytes = max_payload_bytes

    def _encode_records(self, records: Sequence[Mapping[str, object]], format_name: str) -> bytes:
        if format_name == "jsonl":
            content = "".join(canonical_json(record) + "\n" for record in records)
        elif format_name == "csv":
            if not records:
                raise ExternalProtocolError("CSV payload cannot encode an empty record set")
            fieldnames = list(records[0])
            handle = io.StringIO(newline="")
            writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            for record in records:
                row = {
                    key: canonical_json(value) if isinstance(value, (dict, list)) else "" if value is None else value
                    for key, value in record.items()
                }
                writer.writerow(row)
            content = handle.getvalue()
        else:
            raise ExternalProtocolError(f"unsupported external format: {format_name}")
        data = content.encode("utf-8")
        if len(data) > self.max_payload_bytes:
            raise ExternalProtocolError("external payload exceeds max_payload_bytes")
        return data

    def _decode_records(self, payload: bytes, format_name: str) -> list[dict[str, object]]:
        if len(payload) > self.max_payload_bytes:
            raise ExternalProtocolError("external payload exceeds max_payload_bytes")
        try:
            text = payload.decode("utf-8")
        except UnicodeError as exc:
            raise ExternalProtocolError("external payload is not valid UTF-8") from exc
        if format_name == "jsonl":
            records: list[dict[str, object]] = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
                except json.JSONDecodeError as exc:
                    raise ExternalProtocolError(
                        f"invalid JSONL line {line_number}: {exc}"
                    ) from exc
                if not isinstance(value, dict):
                    raise ExternalProtocolError(f"JSONL line {line_number} must be an object")
                records.append(value)
            return records
        if format_name == "csv":
            try:
                reader = csv.DictReader(io.StringIO(text, newline=""))
                if reader.fieldnames is None:
                    raise ExternalProtocolError("CSV header is missing")
                if len(set(reader.fieldnames)) != len(reader.fieldnames):
                    raise ExternalProtocolError("CSV header contains duplicate fields")
                return [dict(row) for row in reader]
            except csv.Error as exc:
                raise ExternalProtocolError(f"invalid CSV payload: {exc}") from exc
        raise ExternalProtocolError(f"unsupported external format: {format_name}")

    @staticmethod
    def _integer(value: object, name: str, *, optional: bool = False) -> int | None:
        if optional and value in (None, ""):
            return None
        if isinstance(value, bool):
            raise ExternalProtocolError(f"{name} must be an integer")
        try:
            result = int(value)
        except (TypeError, ValueError) as exc:
            raise ExternalProtocolError(f"{name} must be an integer") from exc
        if result < 0 or (isinstance(value, str) and str(result) != value.strip()):
            raise ExternalProtocolError(f"{name} must be a non-negative integer")
        return result

    @staticmethod
    def _number(value: object, name: str, *, optional: bool = False) -> float | None:
        if optional and value in (None, ""):
            return None
        if isinstance(value, bool):
            raise ExternalProtocolError(f"{name} must be numeric")
        try:
            return float(value)
        except (TypeError, ValueError) as exc:
            raise ExternalProtocolError(f"{name} must be numeric") from exc

    @staticmethod
    def _json_object(value: object, name: str) -> dict[str, object]:
        if isinstance(value, str):
            try:
                value = json.loads(value, object_pairs_hook=_reject_duplicate_keys)
            except json.JSONDecodeError as exc:
                raise ExternalProtocolError(f"{name} is invalid JSON") from exc
        if not isinstance(value, dict):
            raise ExternalProtocolError(f"{name} must be an object")
        return value

    @staticmethod
    def _json_array(value: object, name: str) -> list[object]:
        if isinstance(value, str):
            try:
                value = json.loads(value, object_pairs_hook=_reject_duplicate_keys)
            except json.JSONDecodeError as exc:
                raise ExternalProtocolError(f"{name} is invalid JSON") from exc
        if not isinstance(value, list):
            raise ExternalProtocolError(f"{name} must be an array")
        return value

    def encode_events(self, events: Sequence[HuntEvent], format_name: str) -> bytes:
        records: list[dict[str, object]] = []
        for event in sorted(events, key=lambda item: (item.step, item.event_id)):
            if not isinstance(event, HuntEvent):
                raise TypeError("events must contain HuntEvent values only")
            payload = event.to_dict()
            record = {
                external: payload[canonical]
                for canonical, external in self.mapping.event_fields.items()
            }
            record[self.mapping.event_attributes_field] = dict(event.attributes)
            records.append(record)
        if not records:
            raise ExternalProtocolError("external event payload must not be empty")
        return self._encode_records(records, format_name)

    def decode_events(self, payload: bytes, format_name: str) -> tuple[HuntEvent, ...]:
        expected = set(self.mapping.event_fields.values()) | {self.mapping.event_attributes_field}
        events: list[HuntEvent] = []
        for index, record in enumerate(self._decode_records(payload, format_name)):
            if set(record) != expected:
                raise ExternalProtocolError(f"event record {index} fields do not match mapping")
            values = {
                canonical: record[external]
                for canonical, external in self.mapping.event_fields.items()
            }
            values["step"] = self._integer(values["step"], "step")
            for name in OPTIONAL_EVENT_INTS:
                values[name] = self._integer(values[name], name, optional=True)
            for name in OPTIONAL_EVENT_STRINGS:
                if values[name] == "":
                    values[name] = None
            values["attributes"] = self._json_object(
                record[self.mapping.event_attributes_field], "event attributes"
            )
            try:
                events.append(HuntEvent.from_dict(values))
            except (TypeError, ValueError) as exc:
                raise ExternalProtocolError(f"event record {index} is invalid: {exc}") from exc
        if not events:
            raise ExternalProtocolError("external event payload must not be empty")
        ordered = tuple(sorted(events, key=lambda event: (event.step, event.event_id)))
        if len({event.event_id for event in ordered}) != len(ordered):
            raise ExternalProtocolError("external event payload contains duplicate event IDs")
        return ordered

    def encode_findings(self, findings: Sequence[Finding], format_name: str) -> bytes:
        records: list[dict[str, object]] = []
        for finding in sorted(findings, key=lambda item: (item.start_step, item.finding_id)):
            if not isinstance(finding, Finding):
                raise TypeError("findings must contain Finding values only")
            payload = finding.to_dict()
            record = {
                external: payload[canonical]
                for canonical, external in self.mapping.finding_fields.items()
            }
            record[self.mapping.finding_attributes_field] = dict(finding.attributes)
            records.append(record)
        if not records:
            # JSONL has an unambiguous empty response; CSV uses only its mapped header.
            if format_name == "jsonl":
                return b""
            fieldnames = list(self.mapping.finding_fields.values()) + [
                self.mapping.finding_attributes_field
            ]
            handle = io.StringIO(newline="")
            csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n").writeheader()
            return handle.getvalue().encode("utf-8")
        return self._encode_records(records, format_name)

    def decode_findings(
        self,
        payload: bytes,
        format_name: str,
        *,
        allowed_event_ids: frozenset[str],
    ) -> tuple[Finding, ...]:
        expected = set(self.mapping.finding_fields.values()) | {
            self.mapping.finding_attributes_field
        }
        findings: list[Finding] = []
        for index, record in enumerate(self._decode_records(payload, format_name)):
            if set(record) != expected:
                raise ExternalProtocolError(f"finding record {index} fields do not match mapping")
            values = {
                canonical: record[external]
                for canonical, external in self.mapping.finding_fields.items()
            }
            for name in ("start_step", "end_step"):
                values[name] = self._integer(values[name], name)
            values["score"] = self._number(values["score"], "score")
            for name in OPTIONAL_FINDING_NUMBERS:
                values[name] = self._number(values[name], name, optional=True)
            if values["actor_id"] == "":
                values["actor_id"] = None
            evidence = self._json_array(values["evidence_event_ids"], "evidence_event_ids")
            if any(not isinstance(event_id, str) or event_id not in allowed_event_ids for event_id in evidence):
                raise ExternalProtocolError(
                    f"finding record {index} references an unknown evidence event"
                )
            values["evidence_event_ids"] = evidence
            values["attributes"] = self._json_object(
                record[self.mapping.finding_attributes_field], "finding attributes"
            )
            try:
                findings.append(Finding.from_dict(values))
            except (TypeError, ValueError) as exc:
                raise ExternalProtocolError(f"finding record {index} is invalid: {exc}") from exc
        ordered = tuple(sorted(findings, key=lambda finding: (finding.start_step, finding.finding_id)))
        if len({finding.finding_id for finding in ordered}) != len(ordered):
            raise ExternalProtocolError("external response contains duplicate finding IDs")
        return ordered


class ExternalTransport(Protocol):
    def submit(
        self,
        payload: bytes,
        *,
        input_format: str,
        output_format: str,
        timeout_seconds: float,
        limits: ExecutionLimits,
    ) -> bytes: ...


class MockExternalTransport:
    """In-process transport exercising the real codec and Finding normalization path."""

    def __init__(self, codec: ExternalCodec, target) -> None:
        self.codec = codec
        self.target = target

    def submit(
        self,
        payload: bytes,
        *,
        input_format: str,
        output_format: str,
        timeout_seconds: float,
        limits: ExecutionLimits,
    ) -> bytes:
        events = self.codec.decode_events(payload, input_format)
        result = self.target.execute(events, limits)
        if result.status != "completed":
            raise ExternalInfrastructureError(
                f"mock_backend_{result.status}",
                result.error_message or "mock backend did not complete",
                retryable=False,
            )
        return self.codec.encode_findings(result.findings, output_format)


class AllowlistedCommandTransport:
    """Run one exact shell-free command after two explicit opt-in checks."""

    OPT_IN_ENVIRONMENT_VARIABLE = "CYBERMATCH_ALLOW_EXTERNAL_SUT"

    def __init__(
        self,
        *,
        repository_root: str | Path,
        allowlist_path: str | Path,
        command_id: str,
        explicit_opt_in: bool,
        max_response_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        root = Path(repository_root).resolve()
        requested = Path(allowlist_path)
        if requested.is_absolute():
            raise ExternalMappingError("command allowlist path must be repository-relative")
        source = (root / requested).resolve()
        if not source.is_relative_to(root) or not source.is_file():
            raise ExternalMappingError("command allowlist must be a repository file")
        try:
            payload = json.loads(
                source.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ExternalProtocolError) as exc:
            raise ExternalMappingError(f"unable to read command allowlist: {exc}") from exc
        if not isinstance(payload, Mapping) or set(payload) != {"schema_version", "commands"}:
            raise ExternalMappingError("command allowlist has invalid fields")
        if payload["schema_version"] != "1.0" or not isinstance(payload["commands"], list):
            raise ExternalMappingError("command allowlist has invalid schema")
        selected = None
        identifiers: list[str] = []
        for index, item in enumerate(payload["commands"]):
            if not isinstance(item, Mapping) or set(item) != {"id", "executable", "args"}:
                raise ExternalMappingError(f"commands[{index}] has invalid fields")
            identifier = item["id"]
            executable = item["executable"]
            args = item["args"]
            if not isinstance(identifier, str) or not identifier:
                raise ExternalMappingError(f"commands[{index}].id must be a non-empty string")
            identifiers.append(identifier)
            if not isinstance(executable, str) or not Path(executable).is_absolute():
                raise ExternalMappingError(f"commands[{index}].executable must be absolute")
            if not Path(executable).is_file():
                raise ExternalMappingError(f"commands[{index}].executable does not exist")
            if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
                raise ExternalMappingError(f"commands[{index}].args must contain strings")
            placeholders = {part for arg in args for part in ("{input}", "{output}") if part in arg}
            if placeholders != {"{input}", "{output}"}:
                raise ExternalMappingError(
                    f"commands[{index}].args must reference input and output placeholders"
                )
            if identifier == command_id:
                selected = (str(Path(executable).resolve()), tuple(args))
        if len(set(identifiers)) != len(identifiers):
            raise ExternalMappingError("command allowlist IDs must be unique")
        if selected is None:
            raise ExternalMappingError(f"command_id is not allowlisted: {command_id}")
        self.repository_root = root
        self.command_id = command_id
        self.executable, self.args = selected
        self.explicit_opt_in = explicit_opt_in
        self.max_response_bytes = max_response_bytes

    def manifest(self) -> dict[str, object]:
        return {
            "command_id": self.command_id,
            "executable_sha256": _sha256(Path(self.executable).read_bytes()),
            "shell": False,
            "requires_environment_opt_in": self.OPT_IN_ENVIRONMENT_VARIABLE,
        }

    def submit(
        self,
        payload: bytes,
        *,
        input_format: str,
        output_format: str,
        timeout_seconds: float,
        limits: ExecutionLimits,
    ) -> bytes:
        if not self.explicit_opt_in or os.environ.get(self.OPT_IN_ENVIRONMENT_VARIABLE) != "1":
            raise ExternalInfrastructureError(
                "external_execution_not_enabled",
                "external command requires spec opt-in and CYBERMATCH_ALLOW_EXTERNAL_SUT=1",
                retryable=False,
            )
        suffixes = {"jsonl": ".jsonl", "csv": ".csv"}
        with tempfile.TemporaryDirectory(prefix="cybermatch_external_sut_") as temporary:
            root = Path(temporary).resolve()
            input_path = root / f"input{suffixes[input_format]}"
            output_path = root / f"output{suffixes[output_format]}"
            input_path.write_bytes(payload)
            arguments = [
                arg.replace("{input}", str(input_path)).replace("{output}", str(output_path))
                for arg in self.args
            ]
            try:
                completed = subprocess.run(
                    [self.executable, *arguments],
                    cwd=self.repository_root,
                    shell=False,
                    check=False,
                    capture_output=True,
                    timeout=min(timeout_seconds, limits.max_runtime_seconds),
                )
            except subprocess.TimeoutExpired as exc:
                raise ExternalInfrastructureError(
                    "external_timeout", "external command timed out", retryable=True
                ) from exc
            except OSError as exc:
                raise ExternalInfrastructureError(
                    "external_process_error", str(exc), retryable=True
                ) from exc
            if completed.returncode != 0:
                raise ExternalInfrastructureError(
                    "external_process_exit",
                    f"external command exited with code {completed.returncode}",
                    retryable=False,
                )
            if not output_path.is_file():
                raise ExternalInfrastructureError(
                    "external_output_missing", "external command did not create output", retryable=False
                )
            if output_path.stat().st_size > self.max_response_bytes:
                raise ExternalInfrastructureError(
                    "external_output_too_large", "external output exceeds size limit", retryable=False
                )
            return output_path.read_bytes()


__all__ = [
    "AllowlistedCommandTransport",
    "EVENT_FIELDS",
    "EXTERNAL_MAPPING_SCHEMA_VERSION",
    "ExternalAdapterError",
    "ExternalCodec",
    "ExternalInfrastructureError",
    "ExternalMappingError",
    "ExternalProtocolError",
    "ExternalSUTMapping",
    "ExternalTransport",
    "FINDING_FIELDS",
    "MockExternalTransport",
    "load_external_mapping",
]
