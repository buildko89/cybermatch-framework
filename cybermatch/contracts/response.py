"""対象を明示した対処要求と、追記型の適用結果に関する共通契約。"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, fields
from types import MappingProxyType

from .canonical import canonical_sha256
from .evidence import ContractValidationError

RESPONSE_CONTRACT_VERSION = "1.0"
ACTION_SCOPE_PAIRS = MappingProxyType({
    "revoke_identity": "identity",
    "quarantine_zone": "node",
    "pause_workload": "workload",
})
ACTION_ID_PATTERN = r"response_[0-9a-f]{64}"


class ResponseValidationError(ContractValidationError):
    """対処契約の入力または相互参照が不正。"""


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ResponseValidationError(f"{name}: 空でない前後空白なしの文字列が必要です")
    return value


def _step(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ResponseValidationError(f"{name}: 非負整数が必要です")
    return value


def _refs(value: object, name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise ResponseValidationError(f"{name}: 文字列の配列が必要です")
    result = tuple(sorted({_text(item, name) for item in value}))
    if not result and not allow_empty:
        raise ResponseValidationError(f"{name}: 対象を省略できません")
    return result


def _reason(value: object) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value) is None:
        raise ResponseValidationError("reason_code: 定型の理由コードが必要です")


def _action_id(value: object) -> None:
    if not isinstance(value, str) or re.fullmatch(ACTION_ID_PATTERN, value) is None:
        raise ResponseValidationError("action_id: 有効な対処IDが必要です")


def _payload(cls: type, payload: object) -> dict[str, object]:
    if not isinstance(payload, Mapping):
        raise ResponseValidationError("入力はJSONオブジェクトでなければなりません")
    expected = {item.name for item in fields(cls)}
    if set(payload) != expected:
        raise ResponseValidationError("契約の必須項目不足または未知の項目があります")
    result = dict(payload)
    for name in ("finding_ids", "subject_refs", "affected_subject_refs"):
        if name in result:
            values = result[name]
            normalized = _refs(values, name, allow_empty=name == "affected_subject_refs")
            if list(values) != list(normalized):
                raise ResponseValidationError(f"{name}: wire配列は重複なしの昇順が必要です")
    return result


@dataclass(frozen=True, kw_only=True)
class ScopedResponseAction:
    """run・tenant・対象・期間を限定した、まだ適用されていない要求。"""

    action_id: str
    run_id: str
    tenant_id: str
    finding_ids: tuple[str, ...]
    action_type: str
    scope_kind: str
    subject_refs: tuple[str, ...]
    requested_step: int
    effective_step: int
    expires_step: int
    policy_hash: str
    reason_code: str
    schema_version: str = RESPONSE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RESPONSE_CONTRACT_VERSION:
            raise ResponseValidationError("未対応の対処契約versionです")
        for name in ("run_id", "tenant_id", "action_type", "scope_kind"):
            _text(getattr(self, name), name)
        if ACTION_SCOPE_PAIRS.get(self.action_type) != self.scope_kind:
            raise ResponseValidationError("action_typeとscope_kindの組合せが不正です")
        for name in ("finding_ids", "subject_refs"):
            object.__setattr__(self, name, _refs(getattr(self, name), name))
        for name in ("requested_step", "effective_step", "expires_step"):
            _step(getattr(self, name), name)
        if self.effective_step <= self.requested_step:
            raise ResponseValidationError("effective_stepはrequested_stepの次step以降が必要です")
        if self.expires_step <= self.effective_step:
            raise ResponseValidationError("expires_stepはeffective_stepより後でなければなりません")
        if not isinstance(self.policy_hash, str) or re.fullmatch(r"[0-9a-f]{64}", self.policy_hash) is None:
            raise ResponseValidationError("policy_hashは小文字のSHA-256値が必要です")
        _reason(self.reason_code)
        _action_id(self.action_id)
        if self.action_id != self._identifier(self._semantic_payload()):
            raise ResponseValidationError("action_idと要求内容が一致しません")

    @staticmethod
    def _identifier(payload: Mapping[str, object]) -> str:
        return "response_" + canonical_sha256(payload)

    def _semantic_payload(self) -> dict[str, object]:
        return {
            item.name: list(value) if isinstance(value := getattr(self, item.name), tuple) else value
            for item in fields(self)
            if item.name != "action_id"
        }

    @classmethod
    def create(
        cls, *, run_id: str, tenant_id: str, finding_ids: tuple[str, ...],
        action_type: str, scope_kind: str, subject_refs: tuple[str, ...],
        requested_step: int, effective_step: int, expires_step: int,
        policy_hash: str, reason_code: str,
    ) -> "ScopedResponseAction":
        data = {
            "schema_version": RESPONSE_CONTRACT_VERSION,
            "run_id": run_id,
            "tenant_id": tenant_id,
            "finding_ids": list(_refs(finding_ids, "finding_ids")),
            "action_type": action_type,
            "scope_kind": scope_kind,
            "subject_refs": list(_refs(subject_refs, "subject_refs")),
            "requested_step": requested_step,
            "effective_step": effective_step,
            "expires_step": expires_step,
            "policy_hash": policy_hash,
            "reason_code": reason_code,
        }
        # 非有限値等はJSON符号化の前に拒否し、例外型を契約に揃える。
        for name in ("requested_step", "effective_step", "expires_step"):
            _step(data[name], name)
        try:
            identifier = cls._identifier(data)
        except (TypeError, ValueError) as exc:
            raise ResponseValidationError("対処要求をcanonical JSONへ変換できません") from exc
        return cls(action_id=identifier, **data)

    def active_at(self, step: int) -> bool:
        _step(step, "step")
        return self.effective_step <= step < self.expires_step

    def to_dict(self) -> dict[str, object]:
        return {"action_id": self.action_id, **self._semantic_payload()}

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ScopedResponseAction":
        return cls(**_payload(cls, payload))


@dataclass(frozen=True, kw_only=True)
class ResponseReceipt:
    """状態遷移ごとに追記する結果。要求の存在だけではappliedにしない。"""

    action_id: str
    run_id: str
    status: str
    recorded_step: int
    effect_start_step: int | None
    effect_end_step: int | None
    affected_subject_refs: tuple[str, ...]
    reason_code: str
    schema_version: str = RESPONSE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RESPONSE_CONTRACT_VERSION:
            raise ResponseValidationError("未対応のreceipt versionです")
        _action_id(self.action_id)
        _text(self.run_id, "run_id")
        _step(self.recorded_step, "recorded_step")
        _reason(self.reason_code)
        if not isinstance(self.status, str) or self.status not in {"applied", "rejected", "expired"}:
            raise ResponseValidationError("未知のreceipt statusです")
        refs = _refs(self.affected_subject_refs, "affected_subject_refs", allow_empty=True)
        object.__setattr__(self, "affected_subject_refs", refs)
        if self.status == "rejected":
            if refs or self.effect_start_step is not None or self.effect_end_step is not None:
                raise ResponseValidationError("rejectedは効果なしでなければなりません")
        else:
            _step(self.effect_start_step, "effect_start_step")
            _step(self.effect_end_step, "effect_end_step")
            if not refs or self.effect_end_step <= self.effect_start_step:
                raise ResponseValidationError("適用結果は対象と正の期間が必要です")
            if self.status == "applied" and self.recorded_step != self.effect_start_step:
                raise ResponseValidationError("appliedは実際の開始stepで記録します")
            if self.status == "expired" and self.recorded_step < self.effect_end_step:
                raise ResponseValidationError("期限前にexpiredを記録できません")

    def validate_for(self, action: ScopedResponseAction) -> None:
        if not isinstance(action, ScopedResponseAction):
            raise ResponseValidationError("検証対象はScopedResponseActionでなければなりません")
        if self.action_id != action.action_id or self.run_id != action.run_id:
            raise ResponseValidationError("receiptのrun/actionが一致しません")
        if self.recorded_step < action.requested_step:
            raise ResponseValidationError("要求前のreceiptは不正です")
        if self.status != "rejected" and (
            self.effect_start_step != action.effective_step
            or self.effect_end_step != action.expires_step
            or self.affected_subject_refs != action.subject_refs
        ):
            raise ResponseValidationError("receiptの適用範囲が要求と一致しません")

    def to_dict(self) -> dict[str, object]:
        return {
            item.name: list(value) if isinstance(value := getattr(self, item.name), tuple) else value
            for item in fields(self)
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ResponseReceipt":
        return cls(**_payload(cls, payload))


__all__ = [
    "RESPONSE_CONTRACT_VERSION", "ACTION_SCOPE_PAIRS", "ResponseValidationError",
    "ScopedResponseAction", "ResponseReceipt",
]
