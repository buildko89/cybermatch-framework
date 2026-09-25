"""Minimal typed telemetry families for closed-loop hunting experiments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import HuntEvent, SCHEMA_VERSION, stable_identifier


TELEMETRY_FAMILIES = frozenset({"process", "dns", "network", "authentication"})


@dataclass(frozen=True)
class TypedTelemetryContext:
    step: int
    campaign_id: str
    scenario_id: str
    seed: int | None
    actor_id: str
    source_node: int | None
    target_node: int | None
    source_role: str | None
    target_role: str | None
    observable_event_types: tuple[str, ...]
    attack_active: bool
    success: bool
    detected: bool
    credential_used: bool
    c2_jitter_ratio: float = 0.0
    dns_tunnel_chunk_size: int = 0
    process_masquerading: bool = False
    domain_homoglyph_enabled: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.step, bool) or not isinstance(self.step, int) or self.step < 0:
            raise ValueError("step must be a non-negative integer")
        for name in ("campaign_id", "scenario_id", "actor_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        event_types = tuple(self.observable_event_types)
        if any(not isinstance(value, str) or not value.strip() for value in event_types):
            raise ValueError("observable_event_types must contain non-empty strings")
        object.__setattr__(self, "observable_event_types", event_types)


def _family(event_type: str) -> str:
    if event_type in {"credential_use", "authentication", "additional_auth"}:
        return "authentication"
    if event_type in {"process_start", "exploit_attempt", "objective_action", "data_access"}:
        return "process"
    if event_type in {"dns_query", "dns_tunnel"}:
        return "dns"
    return "network"


def _attributes(context: TypedTelemetryContext, event_type: str, ordinal: int) -> dict[str, object]:
    family = _family(event_type)
    common: dict[str, object] = {
        "telemetry_family": family,
        "success_observed": bool(context.success),
        "detection_observed": bool(context.detected),
        "ordinal": ordinal,
    }
    if family == "authentication":
        common.update(
            {
                "auth_method": "credential",
                "auth_result": "success" if context.success else "failure",
                "credential_present": bool(context.credential_used),
            }
        )
    elif family == "process":
        common.update(
            {
                "process_name": "svchost.exe" if context.process_masquerading else "remote_tool.exe",
                "parent_process": "services.exe",
                "process_signed": bool(context.process_masquerading),
                "process_masquerading": bool(context.process_masquerading),
            }
        )
    elif family == "dns":
        common.update(
            {
                "query_length": max(int(context.dns_tunnel_chunk_size), 1),
                "query_type": "TXT" if context.dns_tunnel_chunk_size else "A",
                "domain_shape": "homoglyph" if context.domain_homoglyph_enabled else "ordinary",
            }
        )
    else:
        common.update(
            {
                "protocol": "tcp",
                "bytes": max(64, 1024 - int(512 * context.c2_jitter_ratio)),
                "c2_jitter_ratio": float(context.c2_jitter_ratio),
            }
        )
    return common


def build_typed_telemetry(context: TypedTelemetryContext) -> tuple[HuntEvent, ...]:
    """Build typed observations without simulator truth or attacker beliefs."""

    event_types = list(dict.fromkeys(context.observable_event_types))
    if context.attack_active and context.dns_tunnel_chunk_size > 0 and "dns_query" not in event_types:
        event_types.append("dns_query")
    events: list[HuntEvent] = []
    for ordinal, event_type in enumerate(event_types):
        attributes = _attributes(context, event_type, ordinal)
        event_id = stable_identifier(
            "event",
            {
                "schema_version": SCHEMA_VERSION,
                "campaign_id": context.campaign_id,
                "step": context.step,
                "ordinal": ordinal,
                "event_type": event_type,
                "source_node": context.source_node,
                "target_node": context.target_node,
                "attributes": attributes,
            },
        )
        events.append(
            HuntEvent(
                schema_version=SCHEMA_VERSION,
                event_id=event_id,
                step=context.step,
                campaign_id=context.campaign_id,
                scenario_id=context.scenario_id,
                seed=context.seed,
                actor_id=context.actor_id,
                coalition_id=None,
                event_type=event_type,
                source_node=context.source_node,
                target_node=context.target_node,
                source_role=context.source_role,
                target_role=context.target_role,
                signal_class=("derived_signal" if event_type.startswith("critical_") else "telemetry"),
                attributes=attributes,
            )
        )
    return tuple(events)


def serialize_typed_telemetry(events: Iterable[HuntEvent]) -> str:
    from .models import canonical_json

    return canonical_json({"events": [event.to_dict() for event in events]})


__all__ = [
    "TELEMETRY_FAMILIES",
    "TypedTelemetryContext",
    "build_typed_telemetry",
    "serialize_typed_telemetry",
]
