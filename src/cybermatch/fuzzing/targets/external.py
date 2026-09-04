"""External SUT target with safe mock and explicitly allowlisted command transports."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Mapping, Sequence

from src.cybermatch.threat_hunting import HuntEvent

from ..external import (
    AllowlistedCommandTransport,
    ExternalCodec,
    ExternalInfrastructureError,
    ExternalMappingError,
    ExternalProtocolError,
    ExternalTransport,
    MockExternalTransport,
    load_external_mapping,
)
from ..models import ExecutionLimits, JsonValue, TargetResult
from .threat_hunting import TargetManifest, ThreatHuntingEngineTarget


def _repository_file(value: object, repository_root: Path, name: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ExternalMappingError(f"{name} must be a non-empty repository-relative path")
    requested = Path(value)
    if requested.is_absolute():
        raise ExternalMappingError(f"{name} must be repository-relative")
    path = (repository_root / requested).resolve()
    if not path.is_relative_to(repository_root) or not path.is_file():
        raise ExternalMappingError(f"{name} must resolve to a repository file")
    return path


class ExternalSUTTarget:
    """Encode observations, invoke a transport, and normalize external Findings."""

    def __init__(
        self,
        recipe_paths: Sequence[str],
        *,
        repository_root: str | Path,
        configuration: Mapping[str, JsonValue],
        transport: ExternalTransport | None = None,
    ) -> None:
        root = Path(repository_root).resolve()
        mapping_path = _repository_file(
            configuration.get("mapping_path"), root, "mapping_path"
        )
        self._mapping = load_external_mapping(mapping_path)
        self._codec = ExternalCodec(self._mapping)
        self._input_format = str(configuration["input_format"])
        self._output_format = str(configuration["output_format"])
        self._timeout_seconds = float(configuration["timeout_seconds"])
        self._max_retries = int(configuration["max_retries"])
        self._retry_backoff_seconds = float(configuration["retry_backoff_ms"]) / 1000.0
        self._rate_limit_per_second = float(configuration["rate_limit_per_second"])
        self._last_request_started: float | None = None
        transport_name = str(configuration["transport"])
        recipes: tuple[dict[str, str], ...] = ()
        transport_manifest: dict[str, object]
        if transport is not None:
            self._transport = transport
            transport_manifest = {"transport": transport_name, "injected_for_test": True}
        elif transport_name == "mock":
            internal = ThreatHuntingEngineTarget(recipe_paths, repository_root=root)
            self._transport = MockExternalTransport(self._codec, internal)
            recipes = internal.manifest.recipes
            transport_manifest = {"transport": "mock", "network_access": False}
        elif transport_name == "command":
            allowlist = configuration.get("command_allowlist")
            _repository_file(allowlist, root, "command_allowlist")
            command = AllowlistedCommandTransport(
                repository_root=root,
                allowlist_path=str(allowlist),
                command_id=str(configuration["command_id"]),
                explicit_opt_in=configuration.get("allow_external_execution") is True,
            )
            self._transport = command
            transport_manifest = {"transport": "command", **command.manifest()}
        else:  # defensive boundary; campaign validation should reject this first
            raise ExternalMappingError(f"unsupported transport: {transport_name}")
        self._manifest = TargetManifest(
            target_id="external_sut",
            version="1.0",
            recipes=recipes,
            configuration={
                "transport": transport_name,
                "input_format": self._input_format,
                "output_format": self._output_format,
                "sut_id": str(configuration["sut_id"]),
                "sut_version": str(configuration["sut_version"]),
                "mapping_id": self._mapping.mapping_id,
                "mapping_version": self._mapping.mapping_version,
                "mapping_sha256": self._mapping.mapping_hash,
                "max_retries": self._max_retries,
                "retry_backoff_ms": int(configuration["retry_backoff_ms"]),
                "timeout_seconds": self._timeout_seconds,
                "rate_limit_per_second": self._rate_limit_per_second,
                **transport_manifest,
            },
        )

    @property
    def manifest(self) -> TargetManifest:
        return self._manifest

    def _rate_limit(self, started: float, budget_seconds: float) -> None:
        if self._last_request_started is None:
            self._last_request_started = started
            return
        minimum_interval = 1.0 / self._rate_limit_per_second
        wait_seconds = minimum_interval - (started - self._last_request_started)
        if wait_seconds > 0.0:
            if wait_seconds > budget_seconds:
                raise ExternalInfrastructureError(
                    "external_rate_limit_budget",
                    "rate-limit wait exceeds execution budget",
                    retryable=False,
                )
            time.sleep(wait_seconds)
        self._last_request_started = time.perf_counter()

    def execute(
        self,
        events: Sequence[HuntEvent],
        limits: ExecutionLimits,
    ) -> TargetResult:
        started = time.perf_counter()
        if len(events) > limits.max_events_per_case:
            return TargetResult(
                status="limit_exceeded",
                findings=(),
                duration_ms=0.0,
                error_type="max_events_per_case",
                error_message=(
                    f"max_events_per_case={limits.max_events_per_case} exceeded by {len(events)}"
                ),
            )
        try:
            payload = self._codec.encode_events(tuple(events), self._input_format)
        except (TypeError, ValueError, ExternalProtocolError) as exc:
            return TargetResult(
                status="rejected",
                findings=(),
                duration_ms=(time.perf_counter() - started) * 1000.0,
                error_type="external_input_encoding",
                error_message=str(exc),
            )

        attempts = 0
        infrastructure_errors: list[str] = []
        response: bytes | None = None
        last_error: ExternalInfrastructureError | None = None
        while attempts <= self._max_retries:
            elapsed = time.perf_counter() - started
            remaining = min(self._timeout_seconds, limits.max_runtime_seconds) - elapsed
            if remaining <= 0.0:
                last_error = ExternalInfrastructureError(
                    "external_execution_budget", "external execution budget exhausted", retryable=False
                )
                infrastructure_errors.append(last_error.error_type)
                break
            try:
                self._rate_limit(time.perf_counter(), remaining)
                attempts += 1
                response = self._transport.submit(
                    payload,
                    input_format=self._input_format,
                    output_format=self._output_format,
                    timeout_seconds=min(self._timeout_seconds, remaining),
                    limits=limits,
                )
                break
            except ExternalInfrastructureError as exc:
                last_error = exc
                infrastructure_errors.append(exc.error_type)
                if not exc.retryable or attempts > self._max_retries:
                    break
                elapsed = time.perf_counter() - started
                remaining = min(self._timeout_seconds, limits.max_runtime_seconds) - elapsed
                if self._retry_backoff_seconds > remaining:
                    break
                if self._retry_backoff_seconds:
                    time.sleep(self._retry_backoff_seconds)
            except Exception as exc:  # pragma: no cover - safety classification boundary
                return TargetResult(
                    status="crashed",
                    findings=(),
                    duration_ms=(time.perf_counter() - started) * 1000.0,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                    state_observations={"attempt_count": attempts},
                )
        if response is None:
            assert last_error is not None
            return TargetResult(
                status="infrastructure_error",
                findings=(),
                duration_ms=(time.perf_counter() - started) * 1000.0,
                error_type=last_error.error_type,
                error_message=str(last_error),
                state_observations={
                    "attempt_count": attempts,
                    "infrastructure_error_types": infrastructure_errors,
                    "detection_verdict_eligible": False,
                    "input_sha256": hashlib.sha256(payload).hexdigest(),
                },
            )
        try:
            event_ids = frozenset(event.event_id for event in events)
            findings = self._codec.decode_findings(
                response, self._output_format, allowed_event_ids=event_ids
            )
            campaign_ids = {event.campaign_id for event in events}
            if any(finding.campaign_id not in campaign_ids for finding in findings):
                raise ExternalProtocolError("external finding campaign_id does not match input")
        except (TypeError, ValueError, ExternalProtocolError) as exc:
            return TargetResult(
                status="rejected",
                findings=(),
                duration_ms=(time.perf_counter() - started) * 1000.0,
                error_type="external_finding_protocol",
                error_message=str(exc),
                state_observations={
                    "attempt_count": attempts,
                    "detection_verdict_eligible": False,
                    "input_sha256": hashlib.sha256(payload).hexdigest(),
                    "output_sha256": hashlib.sha256(response).hexdigest(),
                },
            )
        duration_ms = (time.perf_counter() - started) * 1000.0
        return TargetResult(
            status="completed",
            findings=findings,
            duration_ms=duration_ms,
            coverage={
                "event_types": sorted({event.event_type for event in events}),
                "finding_recipe_ids": sorted({finding.recipe_id for finding in findings}),
                "external_mapping_id": self._mapping.mapping_id,
            },
            state_observations={
                "attempt_count": attempts,
                "infrastructure_error_types": infrastructure_errors,
                "detection_verdict_eligible": True,
                "encoded_event_count": len(events),
                "normalized_finding_count": len(findings),
                "input_format": self._input_format,
                "output_format": self._output_format,
                "input_sha256": hashlib.sha256(payload).hexdigest(),
                "output_sha256": hashlib.sha256(response).hexdigest(),
                "mapping_id": self._mapping.mapping_id,
                "mapping_version": self._mapping.mapping_version,
                "mapping_sha256": self._mapping.mapping_hash,
                "sut_id": self._manifest.configuration["sut_id"],
                "sut_version": self._manifest.configuration["sut_version"],
            },
        )


__all__ = ["ExternalSUTTarget"]
