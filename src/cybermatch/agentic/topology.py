"""Trust-boundary topology and correlated layered-defense failure model."""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable, Mapping

from src.cybermatch.threat_hunting.models import HuntEvent


EVENT_CONTROL_OBJECTIVES = {
    "shared_service_write": "shared_service_isolation",
    "unauthorized_agent_coordination": "shared_service_isolation",
    "transitive_egress": "network_egress",
    "sandbox_escape": "sandbox_isolation",
    "secret_discovery": "identity",
    "credential_reuse": "identity",
    "token_mint": "identity",
    "privilege_escalation": "identity",
    "control_plane_access": "control_plane",
    "log_tampering": "audit_integrity",
    "third_party_access": "third_party_boundary",
}


def _probability(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be between 0 and 1")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")
    return result


def _non_empty(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class TrustZone:
    node_id: int
    name: str
    trust_level: str
    internet_access: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.node_id, bool) or not isinstance(self.node_id, int) or self.node_id < 0:
            raise ValueError("zone.node_id must be a non-negative integer")
        _non_empty(self.name, "zone.name")
        _non_empty(self.trust_level, "zone.trust_level")
        if not isinstance(self.internet_access, bool):
            raise ValueError("zone.internet_access must be boolean")

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "TrustZone":
        unknown = sorted(set(payload) - set(cls.__dataclass_fields__))
        if unknown:
            raise ValueError("zone has unknown fields: " + ", ".join(unknown))
        try:
            return cls(**dict(payload))
        except TypeError as exc:
            raise ValueError(f"invalid zone: {exc}") from exc


@dataclass(frozen=True)
class TrustBoundaryEdge:
    source: int
    target: int
    boundary_id: str
    allowed_event_types: tuple[str, ...] = ()
    bidirectional: bool = False

    def __post_init__(self) -> None:
        for name in ("source", "target"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"edge.{name} must be a non-negative integer")
        _non_empty(self.boundary_id, "edge.boundary_id")
        if not isinstance(self.allowed_event_types, tuple) or any(
            not isinstance(item, str) or not item for item in self.allowed_event_types
        ):
            raise ValueError("edge.allowed_event_types must be a list of non-empty strings")
        if not isinstance(self.bidirectional, bool):
            raise ValueError("edge.bidirectional must be boolean")

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "TrustBoundaryEdge":
        normalized = dict(payload)
        if "allowed_event_types" in normalized and isinstance(normalized["allowed_event_types"], list):
            normalized["allowed_event_types"] = tuple(normalized["allowed_event_types"])
        unknown = sorted(set(normalized) - set(cls.__dataclass_fields__))
        if unknown:
            raise ValueError("edge has unknown fields: " + ", ".join(unknown))
        try:
            return cls(**normalized)
        except TypeError as exc:
            raise ValueError(f"invalid edge: {exc}") from exc


@dataclass(frozen=True)
class DefenseControl:
    control_id: str
    objective: str
    layer: str
    failure_domain: str
    prevent_effectiveness: float
    detect_effectiveness: float
    enabled: bool = True

    def __post_init__(self) -> None:
        for name in ("control_id", "objective", "layer", "failure_domain"):
            _non_empty(getattr(self, name), f"control.{name}")
        object.__setattr__(
            self,
            "prevent_effectiveness",
            _probability(self.prevent_effectiveness, "control.prevent_effectiveness"),
        )
        object.__setattr__(
            self,
            "detect_effectiveness",
            _probability(self.detect_effectiveness, "control.detect_effectiveness"),
        )
        if not isinstance(self.enabled, bool):
            raise ValueError("control.enabled must be boolean")

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "DefenseControl":
        unknown = sorted(set(payload) - set(cls.__dataclass_fields__))
        if unknown:
            raise ValueError("control has unknown fields: " + ", ".join(unknown))
        try:
            return cls(**dict(payload))
        except TypeError as exc:
            raise ValueError(f"invalid control: {exc}") from exc


@dataclass(frozen=True)
class TrustBoundaryTopology:
    topology_id: str
    zones: tuple[TrustZone, ...]
    edges: tuple[TrustBoundaryEdge, ...]
    controls: tuple[DefenseControl, ...]

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "TrustBoundaryTopology":
        if not isinstance(payload, Mapping):
            raise ValueError("topology must be an object")
        unknown = sorted(set(payload) - {"schema_version", "topology_id", "zones", "edges", "controls"})
        if unknown:
            raise ValueError("topology has unknown fields: " + ", ".join(unknown))
        if payload.get("schema_version") != "1.0":
            raise ValueError("topology.schema_version must be 1.0")
        for name in ("zones", "edges", "controls"):
            if not isinstance(payload.get(name), list) or not payload[name]:
                raise ValueError(f"topology.{name} must be a non-empty list")
        result = cls(
            topology_id=_non_empty(payload.get("topology_id"), "topology.topology_id"),
            zones=tuple(TrustZone.from_dict(item) for item in payload["zones"]),
            edges=tuple(TrustBoundaryEdge.from_dict(item) for item in payload["edges"]),
            controls=tuple(DefenseControl.from_dict(item) for item in payload["controls"]),
        )
        result.validate()
        return result

    def validate(self) -> None:
        node_ids = [zone.node_id for zone in self.zones]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("topology zone node_id values must be unique")
        known = set(node_ids)
        for edge in self.edges:
            if edge.source not in known or edge.target not in known:
                raise ValueError(f"edge {edge.boundary_id} references an unknown zone")
        control_ids = [control.control_id for control in self.controls]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("topology control_id values must be unique")

    @property
    def node_ids(self) -> frozenset[int]:
        return frozenset(zone.node_id for zone in self.zones)

    def _edge_for(self, source: int, target: int) -> TrustBoundaryEdge | None:
        for edge in self.edges:
            if edge.source == source and edge.target == target:
                return edge
            if edge.bidirectional and edge.source == target and edge.target == source:
                return edge
        return None

    def _reachable(self, source: int, target: int) -> bool:
        graph: dict[int, set[int]] = defaultdict(set)
        for edge in self.edges:
            graph[edge.source].add(edge.target)
            if edge.bidirectional:
                graph[edge.target].add(edge.source)
        queue = deque([source])
        seen = {source}
        while queue:
            current = queue.popleft()
            for neighbor in graph[current]:
                if neighbor == target:
                    return True
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append(neighbor)
        return False

    def evaluate_events(self, events: Iterable[HuntEvent]) -> dict[str, object]:
        zones = {zone.node_id: zone for zone in self.zones}
        crossings = 0
        unauthorized = 0
        transitive = 0
        unknown_node_events: list[str] = []
        violations: list[dict[str, object]] = []
        for event in events:
            if event.source_node is None or event.target_node is None:
                continue
            if event.source_node not in zones or event.target_node not in zones:
                unknown_node_events.append(event.event_id)
                continue
            source_zone = zones[event.source_node]
            target_zone = zones[event.target_node]
            if source_zone.trust_level != target_zone.trust_level:
                crossings += 1
            edge = self._edge_for(event.source_node, event.target_node)
            authorized = edge is not None and event.event_type in edge.allowed_event_types
            if not authorized:
                unauthorized += 1
                is_transitive = edge is None and self._reachable(event.source_node, event.target_node)
                transitive += int(is_transitive or event.event_type == "transitive_egress")
                violations.append(
                    {
                        "event_id": event.event_id,
                        "event_type": event.event_type,
                        "source_node": event.source_node,
                        "target_node": event.target_node,
                        "boundary_id": edge.boundary_id if edge else None,
                        "transitive_path": is_transitive,
                    }
                )
        return {
            "topology_id": self.topology_id,
            "zone_count": len(self.zones),
            "boundary_count": len(self.edges),
            "zones": [
                {
                    "node_id": zone.node_id,
                    "name": zone.name,
                    "trust_level": zone.trust_level,
                    "internet_access": zone.internet_access,
                }
                for zone in self.zones
            ],
            "boundaries": [
                {
                    "boundary_id": edge.boundary_id,
                    "source": edge.source,
                    "target": edge.target,
                    "allowed_event_types": list(edge.allowed_event_types),
                    "bidirectional": edge.bidirectional,
                }
                for edge in self.edges
            ],
            "trust_boundary_crossing_count": crossings,
            "unauthorized_path_count": unauthorized,
            "transitive_path_violation_count": transitive,
            "unknown_node_event_ids": sorted(unknown_node_events),
            "violations": violations,
        }


class LayeredDefenseFailureModel:
    """Combine controls only across independent failure domains.

    Controls sharing a failure domain are treated as fully correlated. The weakest
    enabled control's failure probability is used for that domain, a conservative
    common-cause approximation. Separate domains are multiplied as independent.
    """

    def __init__(self, controls: Iterable[DefenseControl]):
        self.controls = tuple(controls)
        if any(not isinstance(control, DefenseControl) for control in self.controls):
            raise TypeError("controls must contain DefenseControl instances")
        identifiers = [control.control_id for control in self.controls]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("control_id values must be unique")

    def evaluate(self, failed_domains: Iterable[str] = ()) -> dict[str, object]:
        forced_failed = frozenset(failed_domains)
        known_domains = {control.failure_domain for control in self.controls}
        unknown_domains = sorted(forced_failed - known_domains)
        if unknown_domains:
            raise ValueError("unknown failed defense domains: " + ", ".join(unknown_domains))
        objectives = sorted({control.objective for control in self.controls})
        results: dict[str, object] = {}
        for objective in objectives:
            controls = [c for c in self.controls if c.objective == objective and c.enabled]
            grouped: dict[str, list[DefenseControl]] = defaultdict(list)
            for control in controls:
                grouped[control.failure_domain].append(control)
            domain_rows = []
            prevent_failures = []
            detect_failures = []
            for domain, members in sorted(grouped.items()):
                forced = domain in forced_failed
                prevent_failure = 1.0 if forced else max(1.0 - c.prevent_effectiveness for c in members)
                detect_failure = 1.0 if forced else max(1.0 - c.detect_effectiveness for c in members)
                prevent_failures.append(prevent_failure)
                detect_failures.append(detect_failure)
                domain_rows.append(
                    {
                        "failure_domain": domain,
                        "forced_failed": forced,
                        "control_ids": sorted(c.control_id for c in members),
                        "prevention_failure_probability": prevent_failure,
                        "detection_failure_probability": detect_failure,
                    }
                )
            breach_probability = math.prod(prevent_failures) if prevent_failures else 1.0
            detection_probability = 1.0 - (math.prod(detect_failures) if detect_failures else 1.0)
            effective_layers = sum(domain not in forced_failed for domain in grouped)
            results[objective] = {
                "independent_layer_count": len(grouped),
                "effective_independent_layer_count": effective_layers,
                "single_failure_domain_risk": effective_layers < 2,
                "breach_probability": breach_probability,
                "detection_probability": detection_probability,
                "domains": domain_rows,
            }
        return {
            "assumption": "full correlation within a failure domain; independence across domains",
            "failed_domains": sorted(forced_failed),
            "objectives": results,
        }


__all__ = [
    "EVENT_CONTROL_OBJECTIVES",
    "DefenseControl",
    "LayeredDefenseFailureModel",
    "TrustBoundaryEdge",
    "TrustBoundaryTopology",
    "TrustZone",
]
