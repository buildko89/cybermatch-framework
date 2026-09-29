"""共通対処契約の証拠検証・予約・適用履歴。実機の操作は行わない。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType

from cybermatch.contracts.response import (
    ACTION_SCOPE_PAIRS, ResponseReceipt, ResponseValidationError, ScopedResponseAction,
)
from cybermatch.threat_hunting.feedback import ThreatHuntingFeedback
from cybermatch.threat_hunting.models import Finding, HuntEvent


def _step(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ResponseValidationError("stepは非負整数でなければなりません")
    return value


def _name(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ResponseValidationError("空でない前後空白なしの識別子が必要です")
    return value


@dataclass(frozen=True)
class _ObservedEvidence:
    available_step: int
    subjects: Mapping[str, frozenset[str]]
    subject_event_ids: Mapping[tuple[str, str], frozenset[str]]


class ScopedResponseController:
    """run/tenant専用の決定論的な模擬対処台帳。

    tickは各stepの世界操作より前に呼ぶ。finding登録とsubmitは操作後に呼ぶ。
    初期subject一覧は管理inventoryであり、攻撃の正解labelを含めない。
    """

    def __init__(
        self, *, run_id: str, tenant_id: str, subjects: Mapping[str, tuple[str, ...]],
        policy_hashes: tuple[str, ...],
    ):
        self._run_id = _name(run_id)
        self._tenant_id = _name(tenant_id)
        if not isinstance(subjects, Mapping) or set(subjects) - set(ACTION_SCOPE_PAIRS.values()):
            raise ResponseValidationError("未知のsubject scopeです")
        copied = {}
        for scope, refs in subjects.items():
            if not isinstance(refs, (tuple, list)):
                raise ResponseValidationError("subjectは識別子の配列で指定してください")
            copied[scope] = frozenset(_name(ref) for ref in refs)
        if not isinstance(policy_hashes, (tuple, list)) or not policy_hashes:
            raise ResponseValidationError("policy allowlistが必要です")
        if any(not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None for item in policy_hashes):
            raise ResponseValidationError("policy allowlistはSHA-256値の配列で指定してください")
        self._subjects = MappingProxyType(copied)
        self._policies = frozenset(policy_hashes)
        self._step = -1
        self._evidence: dict[str, _ObservedEvidence] = {}
        self._finding_payloads: dict[str, dict[str, object]] = {}
        self._event_payloads: dict[str, dict[str, object]] = {}
        self._actions: dict[str, ScopedResponseAction] = {}
        self._status: dict[str, str] = {}
        self._receipts: list[ResponseReceipt] = []
        self._used_evidence: dict[tuple[str, str], set[str]] = {}

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def current_step(self) -> int:
        return self._step

    @property
    def receipts(self) -> tuple[ResponseReceipt, ...]:
        return tuple(self._receipts)

    @property
    def actions(self) -> tuple[ScopedResponseAction, ...]:
        return tuple(sorted(self._actions.values(), key=lambda item: item.action_id))

    def register_finding(self, finding: Finding, events: tuple[HuntEvent, ...]) -> None:
        if self._step < 0:
            raise ResponseValidationError("tick(0)でstepを開始してください")
        if not isinstance(finding, Finding) or not isinstance(events, (tuple, list)):
            raise ResponseValidationError("Findingと観測event配列が必要です")
        if any(not isinstance(event, HuntEvent) for event in events):
            raise ResponseValidationError("証拠にはHuntEventだけを受理します")
        index = {event.event_id: event for event in events}
        if len(index) != len(events) or not set(finding.evidence_event_ids) <= set(index):
            raise ResponseValidationError("証拠IDの重複または未観測の証拠があります")
        if finding.end_step > self._step:
            raise ResponseValidationError("未来のFindingを登録できません")
        subjects = {scope: set() for scope in ACTION_SCOPE_PAIRS.values()}
        subject_events: dict[tuple[str, str], set[str]] = {}
        for event_id in finding.evidence_event_ids:
            event = index[event_id]
            if event_id in self._event_payloads and self._event_payloads[event_id] != event.to_dict():
                raise ResponseValidationError("同じ観測IDの内容を書き換えられません")
            if any(
                token in key.lower()
                for key in event.attributes
                for token in ("ground_truth", "oracle", "expected_label", "true_label", "future_event")
            ):
                raise ResponseValidationError("評価器専用fieldを観測証拠に含められません")
            arrival = event.attributes.get("available_step")
            if event.attributes.get("run_id") != self.run_id or event.attributes.get("tenant_id") != self.tenant_id:
                raise ResponseValidationError("証拠のrun/tenantが一致しません")
            if _step(arrival) < event.step or arrival > self._step:
                raise ResponseValidationError("未到着または不正な観測時刻です")
            if event.campaign_id != finding.campaign_id or not finding.start_step <= event.step <= finding.end_step:
                raise ResponseValidationError("証拠の観測streamまたはFinding期間が一致しません")
            for scope, field in (("identity", "identity_ref"), ("node", "node_ref"), ("workload", "workload_ref")):
                ref = event.attributes.get(field)
                if ref is not None:
                    subjects[scope].add(_name(ref))
                    subject_events.setdefault((scope, ref), set()).add(event_id)
        observed = MappingProxyType({scope: frozenset(refs) for scope, refs in subjects.items()})
        event_refs = MappingProxyType({key: frozenset(ids) for key, ids in subject_events.items()})
        record = _ObservedEvidence(self._step, observed, event_refs)
        if finding.finding_id in self._evidence:
            previous = self._evidence[finding.finding_id]
            if self._finding_payloads[finding.finding_id] != finding.to_dict() or previous.subjects != observed:
                raise ResponseValidationError("同じFinding IDの内容を書き換えられません")
            return
        self._evidence[finding.finding_id] = record
        self._finding_payloads[finding.finding_id] = finding.to_dict()
        self._event_payloads.update({ref: index[ref].to_dict() for ref in finding.evidence_event_ids})

    def _receipt(self, action: ScopedResponseAction, status: str, reason: str) -> ResponseReceipt:
        receipt = ResponseReceipt(
            action_id=action.action_id, run_id=action.run_id, status=status,
            recorded_step=self._step,
            effect_start_step=None if status == "rejected" else action.effective_step,
            effect_end_step=None if status == "rejected" else action.expires_step,
            affected_subject_refs=() if status == "rejected" else action.subject_refs,
            reason_code=reason,
        )
        receipt.validate_for(action)
        self._receipts.append(receipt)
        self._status[action.action_id] = status
        return receipt

    def submit(self, action: ScopedResponseAction) -> ResponseReceipt | None:
        if not isinstance(action, ScopedResponseAction):
            raise ResponseValidationError("ScopedResponseActionが必要です")
        if action.action_id in self._actions:
            return next((r for r in reversed(self._receipts) if r.action_id == action.action_id), None)
        if self._step < 0 or action.requested_step != self._step:
            # 時刻の不正は台帳へ登録せず例外。未来の要求に過去時刻のreceiptを作らない。
            raise ResponseValidationError("requested_stepは現在stepと一致する必要があります")
        self._actions[action.action_id] = action
        reason = self._admission_reason(action)
        if reason:
            return self._receipt(action, "rejected", reason)
        self._status[action.action_id] = "pending"
        for subject in action.subject_refs:
            self._used_evidence.setdefault((action.action_type, subject), set()).update(
                self._supporting_event_ids(action, subject)
            )
        return None

    def _supporting_event_ids(self, action: ScopedResponseAction, subject: str) -> set[str]:
        return set().union(*(
            self._evidence[ref].subject_event_ids.get((action.scope_kind, subject), frozenset())
            for ref in action.finding_ids
        ))

    def _admission_reason(self, action: ScopedResponseAction) -> str | None:
        if action.run_id != self.run_id:
            return "run_mismatch"
        if action.tenant_id != self.tenant_id:
            return "tenant_mismatch"
        if action.policy_hash not in self._policies:
            return "unapproved_policy"
        if not set(action.subject_refs) <= self._subjects.get(action.scope_kind, frozenset()):
            return "unknown_subject"
        evidence = [self._evidence.get(ref) for ref in action.finding_ids]
        if any(item is None for item in evidence):
            return "unobserved_finding"
        if any(item.available_step > action.requested_step for item in evidence):
            return "future_evidence"
        supported = set().union(*(item.subjects[action.scope_kind] for item in evidence))
        if not set(action.subject_refs) <= supported:
            return "unsupported_subject"
        if any(
            self._supporting_event_ids(action, subject) <= self._used_evidence.get((action.action_type, subject), set())
            for subject in action.subject_refs
        ):
            return "no_new_evidence"
        return None

    def tick(self, step: int) -> tuple[ResponseReceipt, ...]:
        step = _step(step)
        if step != self._step + 1:
            raise ResponseValidationError("tickは0から1stepずつ進めてください")
        self._step = step
        created = []
        for action in sorted(self._actions.values(), key=lambda item: item.action_id):
            status = self._status[action.action_id]
            if status == "pending" and step == action.effective_step:
                created.append(self._receipt(action, "applied", "scheduled_action_applied"))
            elif status == "applied" and step == action.expires_step:
                created.append(self._receipt(action, "expired", "action_expired"))
        return tuple(created)

    def is_blocked(self, scope_kind: str, subject_ref: str) -> bool:
        if scope_kind not in ACTION_SCOPE_PAIRS.values():
            raise ResponseValidationError("未知のscopeです")
        _name(subject_ref)
        return any(
            self._status[action.action_id] == "applied" and action.active_at(self._step)
            and action.scope_kind == scope_kind and subject_ref in action.subject_refs
            for action in self._actions.values()
        )


def to_legacy_node_feedback(
    action: ScopedResponseAction, *, run_id: str, tenant_id: str,
    node_ids: Mapping[str, int],
) -> ThreatHuntingFeedback:
    """明示したnode隔離だけを変換する。run/tenantの分離は呼出側でも維持する。"""
    if not isinstance(action, ScopedResponseAction):
        raise ResponseValidationError("ScopedResponseActionが必要です")
    if action.run_id != run_id or action.tenant_id != tenant_id:
        raise ResponseValidationError("legacy変換のrun/tenantが一致しません")
    if action.action_type != "quarantine_zone" or action.scope_kind != "node":
        raise ResponseValidationError("legacyへ変換できるのはnode隔離だけです")
    if len(action.finding_ids) != 1:
        raise ResponseValidationError("複数Findingの証跡をlegacyへ損失なく変換できません")
    if not isinstance(node_ids, Mapping) or not set(action.subject_refs) <= set(node_ids):
        raise ResponseValidationError("node対応表に対象がありません")
    nodes = tuple(node_ids[ref] for ref in action.subject_refs)
    if any(isinstance(node, bool) or not isinstance(node, int) or node < 0 for node in nodes):
        raise ResponseValidationError("node対応表は非負整数IDを保持する必要があります")
    if len(set(nodes)) != len(nodes):
        raise ResponseValidationError("複数subjectが同じnodeに対応しています")
    return ThreatHuntingFeedback.create(
        finding_id=action.finding_ids[0], action_type="quarantine_zone",
        effective_step=action.effective_step,
        duration_steps=action.expires_step - action.effective_step,
        target_nodes=tuple(sorted(nodes)), reason=action.reason_code,
    )


__all__ = ["ScopedResponseController", "to_legacy_node_feedback"]
