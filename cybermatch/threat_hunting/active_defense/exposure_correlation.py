"""相関規則v1: CTI予兆とASM資産・観測済みbindingを、時点tの観測だけで突き合わせる。

確定matchにするのは (1) 観測済みidentity–service binding または (2) 正規化endpoint
完全一致 で、確認済みownershipかつ公開中の単一assetに決まる場合だけである。
domainだけの一致、共有endpoint、未確認ownershipは`ambiguous`として記録する。
matchedでもCTIは侵害の証拠ではない。本moduleは対処要求を生成しない。
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ..models import stable_identifier
from . import contract_validation as cv
from .as_of_selection import select_as_of
from .contract_validation import ActiveDefenseContractError
from .exposure_observations import ASMAssetObservation, CTIObservation, ObservedAssetBinding
from .priority_policy import PriorityPolicy

MATCH_STATUSES = ("matched", "ambiguous", "unmatched", "stale")
MATCH_KINDS = ("identity_service", "endpoint_exact", "domain_only", "none")


@dataclass(frozen=True)
class ExposureMatch:
    """一つのCTI観測について、時点computed_stepで得た相関結果。"""

    match_id: str
    tenant_id: str
    cti_ref: str
    asm_ref: str | None
    binding_refs: tuple[str, ...]
    match_kind: str
    status: str
    reason_codes: tuple[str, ...]
    computed_step: int
    priority_bp: int | None
    component_scores: Mapping[str, int] = field(default_factory=dict)
    missing_components: tuple[str, ...] = ()
    identity_ref: str | None = None
    node_ref: str | None = None
    valid_until_step: int | None = None
    policy_hash: str = ""

    def semantic_payload(self) -> dict[str, object]:
        """match_idの元。computed_stepを含めず、同じ相関結果は同じIDになる。"""
        return {
            "tenant_id": self.tenant_id, "cti_ref": self.cti_ref, "asm_ref": self.asm_ref,
            "binding_refs": list(self.binding_refs), "match_kind": self.match_kind,
            "status": self.status, "reason_codes": list(self.reason_codes),
            "priority_bp": self.priority_bp, "component_scores": dict(self.component_scores),
            "missing_components": list(self.missing_components), "identity_ref": self.identity_ref,
            "node_ref": self.node_ref, "valid_until_step": self.valid_until_step,
            "policy_hash": self.policy_hash,
        }

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION, "match_id": self.match_id,
                "computed_step": self.computed_step, **self.semantic_payload()}


@dataclass(frozen=True)
class _AssetState:
    record: ASMAssetObservation
    conflicting: bool


class ExposureCorrelator:
    """tenant固定の決定論的な相関器。truth・内部Finding・未来の観測を受け取らない。"""

    def __init__(self, *, tenant_id: str, policy: PriorityPolicy):
        self._tenant_id = cv.ref(tenant_id, "tenant_id")
        if not isinstance(policy, PriorityPolicy):
            raise ActiveDefenseContractError("policyはPriorityPolicyで指定してください")
        self._policy = policy

    @property
    def policy(self) -> PriorityPolicy:
        return self._policy

    def correlate(
        self, *, step: int, cti_observations: Sequence[CTIObservation],
        asm_observations: Sequence[ASMAssetObservation], bindings: Sequence[ObservedAssetBinding],
    ) -> tuple[ExposureMatch, ...]:
        """step時点で到着済みの各CTI（置換されていない最新版）について一件ずつ返す。"""
        cv.step(step, "step")
        for record in (*cti_observations, *asm_observations, *bindings):
            if record.tenant_id != self._tenant_id:
                raise ActiveDefenseContractError("tenantをまたぐ観測は相関できません")
        cti_view = select_as_of(cti_observations, step=step)
        asm_view = select_as_of(asm_observations, step=step)
        binding_view = select_as_of(bindings, step=step)
        assets = self._asset_states(asm_view.active)
        stale_assets = {record.asset_ref for record in asm_view.stale} - set(assets)
        stale_endpoints = {ep for record in asm_view.stale if record.asset_ref in stale_assets
                           for ep in record.endpoint_refs}
        results = [self._correlate_one(cti, step, assets, binding_view.active, binding_view.stale,
                                       stale_endpoints) for cti in cti_view.active]
        results.extend(self._build(cti, step, status="stale", kind="none", reasons=("cti_expired",))
                       for cti in cti_view.stale)
        return tuple(sorted(results, key=lambda match: match.cti_ref))

    @staticmethod
    def _asset_states(records: Sequence[ASMAssetObservation]) -> dict[str, _AssetState]:
        """assetごとに最新observed_stepの版を使う。同時刻で内容が矛盾すれば一方を選ばない。"""
        grouped: dict[str, list[ASMAssetObservation]] = defaultdict(list)
        for record in records:
            grouped[record.asset_ref].append(record)
        states: dict[str, _AssetState] = {}
        for asset_ref, members in grouped.items():
            latest_step = max(record.observed_step for record in members)
            latest = sorted((r for r in members if r.observed_step == latest_step), key=lambda r: r.record_id)
            distinct = {repr(sorted(r.semantic_state().items())) for r in latest}
            states[asset_ref] = _AssetState(record=latest[0], conflicting=len(distinct) > 1)
        return states

    def _correlate_one(
        self, cti: CTIObservation, step: int, assets: Mapping[str, _AssetState],
        bindings: Sequence[ObservedAssetBinding], stale_bindings: Sequence[ObservedAssetBinding],
        stale_endpoints: set[str],
    ) -> ExposureMatch:
        via_identity: dict[str, list[ObservedAssetBinding]] = defaultdict(list)
        if cti.identity_ref is not None:
            for binding in bindings:
                if cti.identity_ref in binding.identity_refs:
                    via_identity[binding.asset_ref].append(binding)
        via_endpoint = {asset_ref for asset_ref, state in assets.items()
                        if cti.endpoint_ref is not None and cti.endpoint_ref in state.record.endpoint_refs}
        candidates = sorted(set(via_identity) | via_endpoint)
        kind = "identity_service" if via_identity else "endpoint_exact"

        if not candidates:
            return self._no_candidate(cti, step, assets, bindings, stale_bindings, stale_endpoints)
        if len(candidates) > 1:
            return self._build(cti, step, status="ambiguous", kind=kind, reasons=("multiple_candidates",))

        asset_ref = candidates[0]
        kind = "identity_service" if asset_ref in via_identity else "endpoint_exact"
        identity_bindings = via_identity.get(asset_ref, [])
        node_bindings = [b for b in bindings if b.asset_ref == asset_ref and b.node_ref is not None]
        node_refs = sorted({b.node_ref for b in node_bindings if b.node_ref is not None})
        binding_refs = tuple(sorted({b.binding_id for b in (*identity_bindings, *node_bindings)}))
        state = assets.get(asset_ref)
        if state is None:
            return self._build(cti, step, status="ambiguous", kind=kind, binding_refs=binding_refs,
                               reasons=("asset_not_observed_by_asm",))
        asm = state.record
        blockers = []
        if state.conflicting:
            blockers.append("asm_conflicting_observations")
        if asm.ownership_status != "confirmed":
            blockers.append(f"ownership_{asm.ownership_status}")
        if asm.exposure_status != "exposed":
            blockers.append(f"exposure_{asm.exposure_status}")
        if blockers:
            return self._build(cti, step, status="ambiguous", kind=kind, asm=asm,
                               binding_refs=binding_refs, reasons=tuple(blockers))

        reasons = [f"{kind}_match"]
        if len(node_refs) > 1:
            reasons.append("node_binding_ambiguous")
        valid_until = min([cti.valid_until_step, asm.valid_until_step,
                           *(b.valid_until_step for b in (*identity_bindings, *node_bindings))])
        score = self._policy.score(cti, asm)
        return self._build(
            cti, step, status="matched", kind=kind, asm=asm, binding_refs=binding_refs,
            reasons=tuple(reasons), priority=score.priority_bp, components=score.component_dict(),
            missing=score.missing_components,
            identity_ref=cti.identity_ref if kind == "identity_service" else None,
            node_ref=node_refs[0] if len(node_refs) == 1 else None, valid_until=valid_until,
        )

    def _no_candidate(
        self, cti: CTIObservation, step: int, assets: Mapping[str, _AssetState],
        bindings: Sequence[ObservedAssetBinding], stale_bindings: Sequence[ObservedAssetBinding],
        stale_endpoints: set[str],
    ) -> ExposureMatch:
        if cti.domain_ref is not None:
            domain = cti.domain_ref
            hits = [ref for ref, state in assets.items()
                    if any(host == domain or host.endswith("." + domain)
                           for host in (cv.endpoint_host(ep) for ep in state.record.endpoint_refs))]
            if hits:
                # domain一致は調査候補の提示に留め、identity–assetの確定matchにしない。
                return self._build(cti, step, status="ambiguous", kind="domain_only",
                                   reasons=("domain_only_not_confirmed",))
        if cti.identity_ref is not None and any(cti.identity_ref in b.identity_refs for b in stale_bindings):
            return self._build(cti, step, status="stale", kind="identity_service",
                               reasons=("binding_observation_stale",))
        if cti.endpoint_ref is not None and cti.endpoint_ref in stale_endpoints:
            return self._build(cti, step, status="stale", kind="endpoint_exact",
                               reasons=("asm_observation_stale",))
        reasons = ["no_observed_asset"]
        if cti.identity_ref is not None and self._unjoinable(cti.identity_ref, bindings):
            reasons.append("unjoinable_key_version")
        return self._build(cti, step, status="unmatched", kind="none", reasons=tuple(reasons))

    @staticmethod
    def _unjoinable(identity_ref: str, bindings: Sequence[ObservedAssetBinding]) -> bool:
        """HMAC token（`key_version:digest`）の版違いを暗黙に結合せず、理由として報告する。"""
        if ":" not in identity_ref:
            return False
        version = identity_ref.split(":", 1)[0]
        return any(":" in other and other.split(":", 1)[0] != version
                   for binding in bindings for other in binding.identity_refs)

    def _build(
        self, cti: CTIObservation, step: int, *, status: str, kind: str, reasons: tuple[str, ...],
        asm: ASMAssetObservation | None = None, binding_refs: tuple[str, ...] = (),
        priority: int | None = None, components: Mapping[str, int] | None = None,
        missing: tuple[str, ...] = (), identity_ref: str | None = None, node_ref: str | None = None,
        valid_until: int | None = None,
    ) -> ExposureMatch:
        draft = ExposureMatch(
            match_id="", tenant_id=self._tenant_id, cti_ref=cti.observation_id,
            asm_ref=None if asm is None else asm.observation_id, binding_refs=binding_refs,
            match_kind=kind, status=status, reason_codes=tuple(sorted(reasons)), computed_step=step,
            priority_bp=priority, component_scores=dict(components or {}), missing_components=missing,
            identity_ref=identity_ref, node_ref=node_ref, valid_until_step=valid_until,
            policy_hash=self._policy.policy_hash,
        )
        match_id = stable_identifier("match", draft.semantic_payload())
        return ExposureMatch(**{**draft.__dict__, "match_id": match_id})


__all__ = ["ExposureCorrelator", "ExposureMatch", "MATCH_KINDS", "MATCH_STATUSES"]
