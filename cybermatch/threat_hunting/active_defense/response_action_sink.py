"""T3: ScopedResponseActionを状態へ適用し、追記型receiptを発行する模擬sink。"""

from __future__ import annotations

from dataclasses import dataclass

from cybermatch.contracts import ResponseReceipt, ScopedResponseAction

from . import contract_validation as cv
from .contract_validation import ActiveDefenseContractError


@dataclass(frozen=True)
class FindingAuthorization:
    finding_id: str
    tenant_id: str
    subject_refs: tuple[str, ...]


class StatefulResponseActionSink:
    """run/tenantを固定し、identity失効を対象限定かつ冪等に適用する。"""

    def __init__(self, *, run_id: str, tenant_id: str, known_identities: tuple[str, ...],
                 finding_authorizations: tuple[FindingAuthorization, ...] = ()):
        self.run_id = cv.ref(run_id, "run_id")
        self.tenant_id = cv.ref(tenant_id, "tenant_id")
        self.known_identities = frozenset(cv.refs(known_identities, "known_identities", allow_empty=True))
        self._authorizations = {item.finding_id: item for item in finding_authorizations}
        self._actions: dict[str, ScopedResponseAction] = {}
        self._receipts: list[ResponseReceipt] = []
        self._recorded_states: set[tuple[str, str]] = set()

    def authorize(self, authorization: FindingAuthorization) -> None:
        if authorization.tenant_id != self.tenant_id:
            raise ActiveDefenseContractError("Finding authorizationのtenantが一致しません")
        self._authorizations[authorization.finding_id] = authorization

    def submit(self, action: ScopedResponseAction) -> ResponseReceipt | None:
        """有効な要求をqueueへ入れる。同一IDの再submitは何も追加しない。"""
        if action.action_id in self._actions:
            return None
        reason = self._rejection_reason(action)
        self._actions[action.action_id] = action
        if reason is None:
            return None
        receipt = ResponseReceipt(
            action_id=action.action_id, run_id=action.run_id, status="rejected",
            recorded_step=action.requested_step, effect_start_step=None, effect_end_step=None,
            affected_subject_refs=(), reason_code=reason,
        )
        self._append(receipt)
        return receipt

    def advance(self, step: int) -> tuple[ResponseReceipt, ...]:
        """step冒頭に開始・終了状態を反映し、このstepで新規発行したreceiptを返す。"""
        cv.step(step, "step")
        before = len(self._receipts)
        rejected = {receipt.action_id for receipt in self._receipts if receipt.status == "rejected"}
        for action in sorted(self._actions.values(), key=lambda item: item.action_id):
            if action.action_id in rejected:
                continue
            if step == action.effective_step and (action.action_id, "applied") not in self._recorded_states:
                self._append(ResponseReceipt(
                    action_id=action.action_id, run_id=action.run_id, status="applied", recorded_step=step,
                    effect_start_step=action.effective_step, effect_end_step=action.expires_step,
                    affected_subject_refs=action.subject_refs, reason_code="policy_applied",
                ))
            if step == action.expires_step and (action.action_id, "expired") not in self._recorded_states:
                self._append(ResponseReceipt(
                    action_id=action.action_id, run_id=action.run_id, status="expired", recorded_step=step,
                    effect_start_step=action.effective_step, effect_end_step=action.expires_step,
                    affected_subject_refs=action.subject_refs, reason_code="policy_expired",
                ))
        return tuple(self._receipts[before:])

    def is_identity_revoked(self, identity_ref: str, *, step: int) -> bool:
        return any(action.action_type == "revoke_identity" and identity_ref in action.subject_refs
                   and action.active_at(step) and (action.action_id, "applied") in self._recorded_states
                   for action in self._actions.values())

    @property
    def receipts(self) -> tuple[ResponseReceipt, ...]:
        return tuple(self._receipts)

    @property
    def actions(self) -> tuple[ScopedResponseAction, ...]:
        return tuple(sorted(self._actions.values(), key=lambda item: (item.requested_step, item.action_id)))

    def _rejection_reason(self, action: ScopedResponseAction) -> str | None:
        if action.run_id != self.run_id:
            return "run_mismatch"
        if action.tenant_id != self.tenant_id:
            return "tenant_mismatch"
        if action.action_type != "revoke_identity" or action.scope_kind != "identity":
            return "unsupported_scope"
        if any(ref not in self.known_identities for ref in action.subject_refs):
            return "unknown_subject"
        authorizations = [self._authorizations.get(finding_id) for finding_id in action.finding_ids]
        if any(item is None or item.tenant_id != self.tenant_id for item in authorizations):
            return "unknown_finding"
        allowed = set.intersection(*(set(item.subject_refs) for item in authorizations if item is not None))
        if not set(action.subject_refs) <= allowed:
            return "subject_not_in_evidence"
        return None

    def _append(self, receipt: ResponseReceipt) -> None:
        state = (receipt.action_id, receipt.status)
        if state in self._recorded_states:
            return
        self._recorded_states.add(state)
        self._receipts.append(receipt)


__all__ = ["FindingAuthorization", "StatefulResponseActionSink"]
