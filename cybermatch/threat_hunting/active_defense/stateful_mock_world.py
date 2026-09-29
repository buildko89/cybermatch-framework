"""T3: 対処に応じて実際の後続観測が変化する、最小の状態付き合成世界。"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from cybermatch.contracts import canonical_sha256

from . import contract_validation as cv
from .contract_validation import ActiveDefenseContractError
from .response_action_sink import StatefulResponseActionSink


OPERATION_KINDS = ("authenticate", "process_start", "lateral_move", "critical_reach")


@dataclass(frozen=True)
class PotentialOperation:
    operation_id: str
    step: int
    campaign_ref: str
    identity_ref: str
    node_ref: str
    operation_kind: str
    session_ref: str
    session_expires_step: int
    legitimate: bool = False

    def __post_init__(self) -> None:
        for name in ("operation_id", "campaign_ref", "identity_ref", "node_ref", "session_ref"):
            cv.ref(getattr(self, name), name)
        cv.step(self.step, "step")
        cv.choice(self.operation_kind, OPERATION_KINDS, "operation_kind")
        cv.step(self.session_expires_step, "session_expires_step")
        if self.session_expires_step <= self.step:
            raise ActiveDefenseContractError("session_expires_stepはoperation stepより後が必要です")

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "PotentialOperation":
        return cls(**cv.exact_fields(payload, {
            "operation_id", "step", "campaign_ref", "identity_ref", "node_ref", "operation_kind",
            "session_ref", "session_expires_step", "legitimate",
        }, "PotentialOperation"))

    def to_dict(self) -> dict[str, object]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class OperationOutcome:
    operation_id: str
    step: int
    campaign_ref: str
    identity_ref: str
    operation_kind: str
    status: str
    reason_code: str
    legitimate: bool

    def to_dict(self) -> dict[str, object]:
        return dict(self.__dict__)


class StatefulMockWorld:
    """潜在graphは不変。対処とsession状態から各操作の成功・失敗を決める。"""

    def __init__(self, *, run_id: str, tenant_id: str, scenario_id: str, seed: int,
                 operations: Sequence[PotentialOperation]):
        self.run_id = cv.ref(run_id, "run_id")
        self.tenant_id = cv.ref(tenant_id, "tenant_id")
        self.scenario_id = cv.ref(scenario_id, "scenario_id")
        self.seed = cv.step(seed, "seed")
        ordered = tuple(sorted(operations, key=lambda item: (item.step, item.operation_id)))
        if len({item.operation_id for item in ordered}) != len(ordered):
            raise ActiveDefenseContractError("operation_idが重複しています")
        self.operations = ordered
        self._sessions: dict[str, tuple[str, int]] = {}
        self._outcomes: list[OperationOutcome] = []

    @property
    def potential_graph_hash(self) -> str:
        return canonical_sha256([item.to_dict() for item in self.operations])

    @property
    def outcomes(self) -> tuple[OperationOutcome, ...]:
        return tuple(self._outcomes)

    def execute_step(self, step: int, sink: StatefulResponseActionSink) -> tuple[dict[str, object], ...]:
        cv.step(step, "step")
        self._sessions = {key: value for key, value in self._sessions.items() if step < value[1]}
        envelopes: list[dict[str, object]] = []
        for operation in (item for item in self.operations if item.step == step):
            status, reason = self._resolve(operation, sink, step)
            self._outcomes.append(OperationOutcome(
                operation.operation_id, step, operation.campaign_ref, operation.identity_ref,
                operation.operation_kind, status, reason, operation.legitimate,
            ))
            envelopes.append(self._envelope(operation, status, reason))
        return tuple(envelopes)

    def _resolve(self, operation: PotentialOperation, sink: StatefulResponseActionSink, step: int) -> tuple[str, str]:
        if operation.operation_kind == "authenticate":
            if sink.is_identity_revoked(operation.identity_ref, step=step):
                return "blocked", "identity_revoked"
            self._sessions[operation.session_ref] = (operation.identity_ref, operation.session_expires_step)
            return "succeeded", "authentication_succeeded"
        session = self._sessions.get(operation.session_ref)
        if session is None or session[0] != operation.identity_ref:
            return "blocked", "no_active_session"
        return "succeeded", "active_session"

    def _envelope(self, operation: PotentialOperation, status: str, reason: str) -> dict[str, object]:
        event_type = {
            "authenticate": "credential_use", "process_start": "process_start",
            "lateral_move": "lateral_move", "critical_reach": "critical_path_near_target",
        }[operation.operation_kind]
        family = "authentication" if operation.operation_kind == "authenticate" else (
            "process" if operation.operation_kind == "process_start" else "network")
        observation: dict[str, object] = {
            "event_type": event_type, "signal_class": "telemetry", "identity_ref": operation.identity_ref,
            "node_ref": operation.node_ref, "workload_ref": None, "telemetry_family": family,
            "exposure_class": None, "auth_result": "success" if status == "succeeded" else "failure",
        }
        if operation.operation_kind == "process_start":
            observation.update({"process_name": "synthetic_remote_tool.exe", "parent_process": "services.exe"})
        return {
            "schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION,
            "observation_id": f"observation-{operation.operation_id}", "run_id": self.run_id,
            "tenant_id": self.tenant_id, "event_id": f"event-{operation.operation_id}",
            "observed_step": operation.step, "available_step": operation.step,
            "source_kind": "synthetic_internal_telemetry",
            "source_ref": f"synthetic-world:{operation.campaign_ref}", "observation": observation,
        }


__all__ = ["OPERATION_KINDS", "OperationOutcome", "PotentialOperation", "StatefulMockWorld"]
