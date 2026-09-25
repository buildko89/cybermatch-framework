"""Adapters from CyberMatch history to separated hunting contracts."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from numbers import Integral, Real
from pathlib import Path
from typing import TypeAlias

import numpy as np

from .models import GroundTruthLabel, HuntEvent, SCHEMA_VERSION, stable_identifier


HistorySource: TypeAlias = Mapping[str, object] | str | Path

OBSERVED_HISTORY_KEYS = ("typed_telemetry", "observable_events", "critical_path_events")
GROUND_TRUTH_HISTORY_KEYS = frozenset(
    {
        "attacker_critical_true_gain",
        "attacker_current_belief",
        "attacker_detected",
        "attacker_selection_score",
        "attacker_selected_target",
        "attacker_success",
        "critical_compromise",
        "fake_signal_history",
        "noise_history",
        "true_mission_history",
    }
)

# These simulator-internal labels reveal whether an event was injected as
# noise or an adversarial signal. A defender sees the ordinary telemetry, not
# the simulator's truth-bearing classification.
INTERNAL_EVENT_ALIASES = {
    "noise_recon": "scan",
    "noise_scan": "scan",
    "credential_noise": "credential_use",
    "false_path": "lateral_move",
    "fake_critical_probe": "critical_probe",
    "fake_critical_path_entry": "critical_path_entry",
    "fake_critical_path_progress": "critical_path_progress",
    "fake_critical_path_near_target": "critical_path_near_target",
    "fake_objective_action": "objective_action",
}
INTERNAL_EVENT_PREFIXES = ("fake_", "noise_")
CRITICAL_PATH_EVENT_TYPES = frozenset(
    {
        "critical_asset_reach",
        "critical_path_entry",
        "critical_path_near_target",
        "critical_path_progress",
    }
)


class HistoryAdapterError(ValueError):
    """Raised when a history source cannot be converted safely."""


class ObservationPolicyViolation(HistoryAdapterError):
    """Raised when observation code requests a non-observable history field."""


def _require_metadata_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HistoryAdapterError(f"{field_name} must be a non-empty string")
    return value


def _require_seed(seed: object) -> int | None:
    if seed is None:
        return None
    if isinstance(seed, bool) or not isinstance(seed, Integral) or int(seed) < 0:
        raise HistoryAdapterError("seed must be a non-negative integer or None")
    return int(seed)


def _load_history(source: HistorySource) -> dict[str, object]:
    if isinstance(source, Mapping):
        return dict(source)

    path = Path(source)
    if not path.is_file():
        raise HistoryAdapterError(f"history file not found: {path}")
    if path.suffix.lower() != ".npz":
        raise HistoryAdapterError("history file must use the .npz format")
    try:
        with np.load(path, allow_pickle=False) as archive:
            return {key: archive[key] for key in archive.files}
    except (OSError, ValueError) as exc:
        raise HistoryAdapterError(f"unable to read history file {path}: {exc}") from exc


def _as_sequence(value: object, field_name: str) -> list[object]:
    if isinstance(value, np.ndarray):
        if value.ndim == 0:
            return [value.item()]
        return list(value.tolist())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    raise HistoryAdapterError(f"history field {field_name!r} must be a sequence")


def _split_event_value(value: object, field_name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, np.generic):
        value = value.item()
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HistoryAdapterError(f"history field {field_name!r} contains invalid UTF-8") from exc
    if isinstance(value, str):
        return [part.strip() for part in value.split("|") if part.strip()]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        events: list[str] = []
        for item in value:
            events.extend(_split_event_value(item, field_name))
        return events
    raise HistoryAdapterError(f"history field {field_name!r} contains a non-text event value")


def _normalize_observed_event_type(event_type: str) -> str | None:
    if event_type in INTERNAL_EVENT_ALIASES:
        return INTERNAL_EVENT_ALIASES[event_type]
    if event_type.startswith(INTERNAL_EVENT_PREFIXES):
        # Unknown truth-bearing internal labels are safer to omit than expose.
        return None
    return event_type


def _typed_events_at(
    value: object,
    *,
    step: int,
    campaign_id: str,
    scenario_id: str,
    seed: int | None,
) -> list[HuntEvent]:
    if isinstance(value, np.generic):
        value = value.item()
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HistoryAdapterError("typed_telemetry contains invalid UTF-8") from exc
    if not isinstance(value, str):
        raise HistoryAdapterError("typed_telemetry entries must be JSON strings")
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise HistoryAdapterError(f"typed_telemetry step {step} is invalid JSON: {exc}") from exc
    if not isinstance(payload, Mapping) or not isinstance(payload.get("events"), list):
        raise HistoryAdapterError(f"typed_telemetry step {step} must contain an events array")
    result: list[HuntEvent] = []
    for ordinal, item in enumerate(payload["events"]):
        try:
            event = HuntEvent.from_dict(item)
        except (TypeError, ValueError) as exc:
            raise HistoryAdapterError(
                f"typed_telemetry step {step} event {ordinal} is invalid: {exc}"
            ) from exc
        if (
            event.step != step
            or event.campaign_id != campaign_id
            or event.scenario_id != scenario_id
            or event.seed != seed
        ):
            raise HistoryAdapterError(
                f"typed_telemetry step {step} event {ordinal} metadata does not match adapter metadata"
            )
        result.append(event)
    return result


def _bool_value(value: object, field_name: str) -> bool:
    if isinstance(value, (bool, np.bool_)):
        return bool(value)
    if isinstance(value, Integral) and int(value) in (0, 1):
        return bool(value)
    raise HistoryAdapterError(f"history field {field_name!r} must contain boolean values")


def _target_at(targets: list[object] | None, step: int) -> int | None:
    if targets is None or step >= len(targets):
        return None
    value = targets[step]
    if isinstance(value, np.generic):
        value = value.item()
    if isinstance(value, bool) or not isinstance(value, Integral) or int(value) < 0:
        return None
    return int(value)


class HistoryObservationAdapter:
    """Convert an allowlisted subset of history into defender observations."""

    def __init__(self, history_keys: Iterable[str] = OBSERVED_HISTORY_KEYS):
        keys = tuple(history_keys)
        if not keys:
            raise ObservationPolicyViolation("at least one observed history key is required")
        if any(not isinstance(key, str) for key in keys):
            raise ObservationPolicyViolation("observed history keys must be strings")
        if len(set(keys)) != len(keys):
            raise ObservationPolicyViolation("observed history keys must not contain duplicates")
        unsupported = sorted(set(keys) - set(OBSERVED_HISTORY_KEYS))
        if unsupported:
            raise ObservationPolicyViolation(
                "unsupported observed history keys: " + ", ".join(unsupported)
            )
        self._history_keys = tuple(key for key in OBSERVED_HISTORY_KEYS if key in keys)

    @property
    def history_keys(self) -> tuple[str, ...]:
        return self._history_keys

    def adapt(
        self,
        source: HistorySource,
        *,
        campaign_id: str,
        scenario_id: str,
        seed: int | None = None,
    ) -> list[HuntEvent]:
        campaign_id = _require_metadata_string(campaign_id, "campaign_id")
        scenario_id = _require_metadata_string(scenario_id, "scenario_id")
        seed = _require_seed(seed)
        history = _load_history(source)

        available_keys = [key for key in self._history_keys if key in history]
        if not available_keys:
            raise HistoryAdapterError("history contains no supported observed event fields")
        typed_mode = "typed_telemetry" in available_keys
        if typed_mode:
            available_keys = ["typed_telemetry"]
        sequences = {key: _as_sequence(history[key], key) for key in available_keys}
        lengths = {len(values) for values in sequences.values()}
        if len(lengths) != 1:
            details = ", ".join(f"{key}={len(values)}" for key, values in sequences.items())
            raise HistoryAdapterError(f"observed history fields have inconsistent lengths: {details}")

        events: list[HuntEvent] = []
        step_count = lengths.pop()
        for step in range(step_count):
            if "typed_telemetry" in sequences:
                events.extend(
                    _typed_events_at(
                        sequences["typed_telemetry"][step],
                        step=step,
                        campaign_id=campaign_id,
                        scenario_id=scenario_id,
                        seed=seed,
                    )
                )
                continue
            event_sources: dict[str, set[str]] = {}
            for history_key in available_keys:
                for raw_event_type in _split_event_value(sequences[history_key][step], history_key):
                    event_type = _normalize_observed_event_type(raw_event_type)
                    if event_type is None:
                        continue
                    event_sources.setdefault(event_type, set()).add(history_key)

            for ordinal, event_type in enumerate(sorted(event_sources)):
                source_keys = tuple(sorted(event_sources[event_type]))
                signal_class = (
                    "derived_signal"
                    if event_type in CRITICAL_PATH_EVENT_TYPES
                    else "telemetry"
                )
                event_id = stable_identifier(
                    "event",
                    {
                        "schema_version": SCHEMA_VERSION,
                        "campaign_id": campaign_id,
                        "step": step,
                        "ordinal": ordinal,
                        "event_type": event_type,
                    },
                )
                events.append(
                    HuntEvent(
                        schema_version=SCHEMA_VERSION,
                        event_id=event_id,
                        step=step,
                        campaign_id=campaign_id,
                        scenario_id=scenario_id,
                        seed=seed,
                        actor_id=None,
                        coalition_id=None,
                        event_type=event_type,
                        source_node=None,
                        target_node=None,
                        source_role=None,
                        target_role=None,
                        signal_class=signal_class,
                        attributes={
                            "source_history_keys": ",".join(source_keys),
                            "ordinal": ordinal,
                        },
                    )
                )
        if len({event.event_id for event in events}) != len(events):
            raise HistoryAdapterError("observed telemetry contains duplicate event IDs")
        return sorted(events, key=lambda event: (event.step, event.event_id)) if typed_mode else events


class HistoryGroundTruthAdapter:
    """Convert simulator-only history fields into evaluator labels."""

    def adapt(self, source: HistorySource, *, campaign_id: str) -> list[GroundTruthLabel]:
        campaign_id = _require_metadata_string(campaign_id, "campaign_id")
        history = _load_history(source)
        targets = (
            _as_sequence(history["attacker_selected_target"], "attacker_selected_target")
            if "attacker_selected_target" in history
            else None
        )
        labels: list[GroundTruthLabel] = []

        if "critical_compromise" in history:
            values = _as_sequence(history["critical_compromise"], "critical_compromise")
            normalized_values = [
                _bool_value(value, "critical_compromise") for value in values
            ]
            first_step = next(
                (step for step, value in enumerate(normalized_values) if value), None
            )
            if first_step is not None:
                labels.append(
                    self._label(
                        campaign_id=campaign_id,
                        label_type="critical_compromise",
                        start_step=first_step,
                        end_step=first_step,
                        target_node=_target_at(targets, first_step),
                        severity="critical",
                        attributes={"source_history_key": "critical_compromise"},
                    )
                )

        for history_key, label_type, severity in (
            ("attacker_success", "attacker_success", "high"),
            ("attacker_detected", "attacker_detected", "medium"),
        ):
            if history_key not in history:
                continue
            values = _as_sequence(history[history_key], history_key)
            for step, value in enumerate(values):
                if _bool_value(value, history_key):
                    labels.append(
                        self._label(
                            campaign_id=campaign_id,
                            label_type=label_type,
                            start_step=step,
                            end_step=step,
                            target_node=_target_at(targets, step),
                            severity=severity,
                            attributes={"source_history_key": history_key},
                        )
                    )

        if "attacker_critical_true_gain" in history:
            values = _as_sequence(history["attacker_critical_true_gain"], "attacker_critical_true_gain")
            for step, value in enumerate(values):
                if isinstance(value, np.generic):
                    value = value.item()
                if isinstance(value, bool) or not isinstance(value, Real) or not np.isfinite(value):
                    raise HistoryAdapterError(
                        "history field 'attacker_critical_true_gain' must contain finite numbers"
                    )
                if float(value) > 0.0:
                    labels.append(
                        self._label(
                            campaign_id=campaign_id,
                            label_type="critical_true_gain",
                            start_step=step,
                            end_step=step,
                            target_node=_target_at(targets, step),
                            severity="high",
                            attributes={
                                "source_history_key": "attacker_critical_true_gain",
                                "value": float(value),
                            },
                        )
                    )

        if "true_mission_history" in history:
            missions = _as_sequence(history["true_mission_history"], "true_mission_history")
            labels.extend(self._mission_segments(campaign_id, missions))

        return sorted(labels, key=lambda label: (label.start_step, label.label_type, label.label_id))

    def _mission_segments(self, campaign_id: str, missions: list[object]) -> list[GroundTruthLabel]:
        if not missions:
            return []
        normalized: list[str] = []
        for mission in missions:
            if isinstance(mission, np.generic):
                mission = mission.item()
            if not isinstance(mission, str) or not mission.strip():
                raise HistoryAdapterError("history field 'true_mission_history' must contain strings")
            normalized.append(mission)

        labels: list[GroundTruthLabel] = []
        start_step = 0
        for step in range(1, len(normalized) + 1):
            if step < len(normalized) and normalized[step] == normalized[start_step]:
                continue
            labels.append(
                self._label(
                    campaign_id=campaign_id,
                    label_type="true_mission",
                    start_step=start_step,
                    end_step=step - 1,
                    target_node=None,
                    severity="info",
                    attributes={
                        "source_history_key": "true_mission_history",
                        "mission": normalized[start_step],
                    },
                )
            )
            start_step = step
        return labels

    def _label(
        self,
        *,
        campaign_id: str,
        label_type: str,
        start_step: int,
        end_step: int,
        target_node: int | None,
        severity: str,
        attributes: Mapping[str, str | int | float | bool | None],
    ) -> GroundTruthLabel:
        label_id = stable_identifier(
            "truth",
            {
                "campaign_id": campaign_id,
                "label_type": label_type,
                "start_step": start_step,
                "end_step": end_step,
                "target_node": target_node,
                "attributes": dict(attributes),
            },
        )
        return GroundTruthLabel(
            label_id=label_id,
            campaign_id=campaign_id,
            label_type=label_type,
            start_step=start_step,
            end_step=end_step,
            actor_id=None,
            target_node=target_node,
            severity=severity,
            attributes=attributes,
        )


__all__ = [
    "CRITICAL_PATH_EVENT_TYPES",
    "GROUND_TRUTH_HISTORY_KEYS",
    "INTERNAL_EVENT_ALIASES",
    "OBSERVED_HISTORY_KEYS",
    "HistoryAdapterError",
    "HistoryGroundTruthAdapter",
    "HistoryObservationAdapter",
    "HistorySource",
    "ObservationPolicyViolation",
]
