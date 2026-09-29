"""CTI予兆・ASM資産・観測済みinventory対応を、時刻付きの不完全な観測として表す契約。

どの型も「真値」ではない。CTIは侵害の証拠ではなく、ASMのunknownはfalseと別値である。
credential値・平文identity・自由記述の秘密情報を保持するfieldは設けない。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields

from . import contract_validation as cv
from .contract_validation import ActiveDefenseContractError

CTI_SOURCE_TYPES = ("synthetic_cti", "replay_cti")
CREDENTIAL_KINDS = ("password", "session_cookie", "api_key")
OWNERSHIP_STATUSES = ("confirmed", "unconfirmed", "unknown")
EXPOSURE_STATUSES = ("exposed", "not_exposed", "unknown")
MFA_STATES = ("enabled", "disabled", "unknown")
VULNERABILITY_STATUSES = ("confirmed_unpatched", "inferred_from_product", "patched")


def _wire(instance: object) -> dict[str, object]:
    result: dict[str, object] = {}
    for item in fields(instance):  # type: ignore[arg-type]
        value = getattr(instance, item.name)
        if isinstance(value, tuple):
            value = [entry.to_dict() if hasattr(entry, "to_dict") else entry for entry in value]
        result[item.name] = value
    return result


def _field_names(cls: type) -> set[str]:
    return {item.name for item in fields(cls)}


@dataclass(frozen=True, kw_only=True)
class CTIObservation:
    """外部で観測された漏洩等の予兆。最低1つの対象refを持つ。"""

    observation_id: str
    tenant_id: str
    source_ref: str
    source_type: str
    observed_step: int
    available_step: int
    valid_until_step: int
    confidence_bp: int
    domain_ref: str | None
    identity_ref: str | None
    endpoint_ref: str | None
    credential_kind: str | None
    supersedes_id: str | None
    schema_version: str = cv.ACTIVE_DEFENSE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        cv.version(self.schema_version, "CTIObservation.schema_version")
        for name in ("observation_id", "tenant_id", "source_ref"):
            cv.ref(getattr(self, name), f"CTIObservation.{name}")
        cv.choice(self.source_type, CTI_SOURCE_TYPES, "CTIObservation.source_type")
        for name in ("observed_step", "available_step", "valid_until_step"):
            cv.step(getattr(self, name), f"CTIObservation.{name}")
        cv.step_window(self.observed_step, self.available_step, self.valid_until_step, "CTIObservation")
        cv.basis_point(self.confidence_bp, "CTIObservation.confidence_bp")
        if self.domain_ref is not None:
            cv.domain_ref(self.domain_ref, "CTIObservation.domain_ref")
        cv.optional_ref(self.identity_ref, "CTIObservation.identity_ref")
        if self.endpoint_ref is not None:
            cv.endpoint_ref(self.endpoint_ref, "CTIObservation.endpoint_ref")
        if self.domain_ref is None and self.identity_ref is None and self.endpoint_ref is None:
            raise ActiveDefenseContractError("CTIObservation: domain/identity/endpointのいずれかが必要です")
        cv.optional_choice(self.credential_kind, CREDENTIAL_KINDS, "CTIObservation.credential_kind")
        cv.optional_ref(self.supersedes_id, "CTIObservation.supersedes_id")
        if self.supersedes_id == self.observation_id:
            raise ActiveDefenseContractError("CTIObservation: 自分自身を置換できません")

    @property
    def record_id(self) -> str:
        return self.observation_id

    def to_dict(self) -> dict[str, object]:
        return _wire(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "CTIObservation":
        return cls(**cv.exact_fields(payload, _field_names(cls), "CTIObservation"))


@dataclass(frozen=True, kw_only=True)
class VulnerabilityObservation:
    """ASMが列挙した脆弱性。確認済みと製品名からの推測を区別する。"""

    vulnerability_ref: str
    status: str

    def __post_init__(self) -> None:
        cv.ref(self.vulnerability_ref, "VulnerabilityObservation.vulnerability_ref")
        cv.choice(self.status, VULNERABILITY_STATUSES, "VulnerabilityObservation.status")

    def to_dict(self) -> dict[str, object]:
        return {"vulnerability_ref": self.vulnerability_ref, "status": self.status}

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "VulnerabilityObservation":
        return cls(**cv.exact_fields(payload, _field_names(cls), "VulnerabilityObservation"))


@dataclass(frozen=True, kw_only=True)
class ASMAssetObservation:
    """観測時点の公開資産。ownership/exposure/MFAのunknownを安全側の値へ変換しない。"""

    observation_id: str
    tenant_id: str
    asset_ref: str
    observed_step: int
    available_step: int
    valid_until_step: int
    source_ref: str
    confidence_bp: int
    ownership_status: str
    exposure_status: str
    endpoint_refs: tuple[str, ...]
    mfa_state: str
    vulnerability_observations: tuple[VulnerabilityObservation, ...] | None
    business_criticality_bp: int | None
    supersedes_id: str | None
    schema_version: str = cv.ACTIVE_DEFENSE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        cv.version(self.schema_version, "ASMAssetObservation.schema_version")
        for name in ("observation_id", "tenant_id", "asset_ref", "source_ref"):
            cv.ref(getattr(self, name), f"ASMAssetObservation.{name}")
        for name in ("observed_step", "available_step", "valid_until_step"):
            cv.step(getattr(self, name), f"ASMAssetObservation.{name}")
        cv.step_window(self.observed_step, self.available_step, self.valid_until_step, "ASMAssetObservation")
        cv.basis_point(self.confidence_bp, "ASMAssetObservation.confidence_bp")
        cv.choice(self.ownership_status, OWNERSHIP_STATUSES, "ASMAssetObservation.ownership_status")
        cv.choice(self.exposure_status, EXPOSURE_STATUSES, "ASMAssetObservation.exposure_status")
        cv.choice(self.mfa_state, MFA_STATES, "ASMAssetObservation.mfa_state")
        endpoints = cv.refs(self.endpoint_refs, "ASMAssetObservation.endpoint_refs", allow_empty=True)
        for endpoint in endpoints:
            cv.endpoint_ref(endpoint, "ASMAssetObservation.endpoint_refs")
        object.__setattr__(self, "endpoint_refs", endpoints)
        vulnerabilities = self.vulnerability_observations
        if vulnerabilities is not None:
            if not isinstance(vulnerabilities, (list, tuple)):
                raise ActiveDefenseContractError("ASMAssetObservation.vulnerability_observations: 配列またはnullが必要です")
            parsed = tuple(
                item if isinstance(item, VulnerabilityObservation) else VulnerabilityObservation.from_dict(item)
                for item in vulnerabilities
            )
            keys = [item.vulnerability_ref for item in parsed]
            if keys != sorted(set(keys)):
                raise ActiveDefenseContractError("ASMAssetObservation.vulnerability_observations: refの重複なし昇順が必要です")
            object.__setattr__(self, "vulnerability_observations", parsed)
        cv.optional_basis_point(self.business_criticality_bp, "ASMAssetObservation.business_criticality_bp")
        cv.optional_ref(self.supersedes_id, "ASMAssetObservation.supersedes_id")
        if self.supersedes_id == self.observation_id:
            raise ActiveDefenseContractError("ASMAssetObservation: 自分自身を置換できません")

    @property
    def record_id(self) -> str:
        return self.observation_id

    @property
    def has_confirmed_unpatched_vulnerability(self) -> bool | None:
        """未scan（null）はNone。推測のCVEは確認済みとして扱わない。"""
        if self.vulnerability_observations is None:
            return None
        return any(item.status == "confirmed_unpatched" for item in self.vulnerability_observations)

    def semantic_state(self) -> dict[str, object]:
        """同一asset観測の矛盾判定に使う内容。ID・source・時刻・信頼度は除く。"""
        payload = self.to_dict()
        for name in ("observation_id", "source_ref", "observed_step", "available_step",
                     "valid_until_step", "confidence_bp", "supersedes_id"):
            payload.pop(name)
        return payload

    def to_dict(self) -> dict[str, object]:
        return _wire(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ASMAssetObservation":
        return cls(**cv.exact_fields(payload, _field_names(cls), "ASMAssetObservation"))


@dataclass(frozen=True, kw_only=True)
class ObservedAssetBinding:
    """inventoryで観測済みのasset→node/identity対応。推測による補完はしない。"""

    binding_id: str
    tenant_id: str
    asset_ref: str
    node_ref: str | None
    identity_refs: tuple[str, ...]
    observed_step: int
    available_step: int
    valid_until_step: int
    source_ref: str
    supersedes_id: str | None
    schema_version: str = cv.ACTIVE_DEFENSE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        cv.version(self.schema_version, "ObservedAssetBinding.schema_version")
        for name in ("binding_id", "tenant_id", "asset_ref", "source_ref"):
            cv.ref(getattr(self, name), f"ObservedAssetBinding.{name}")
        cv.optional_ref(self.node_ref, "ObservedAssetBinding.node_ref")
        identities = cv.refs(self.identity_refs, "ObservedAssetBinding.identity_refs", allow_empty=True)
        object.__setattr__(self, "identity_refs", identities)
        if self.node_ref is None and not identities:
            raise ActiveDefenseContractError("ObservedAssetBinding: nodeまたはidentityの対応が必要です")
        for name in ("observed_step", "available_step", "valid_until_step"):
            cv.step(getattr(self, name), f"ObservedAssetBinding.{name}")
        cv.step_window(self.observed_step, self.available_step, self.valid_until_step, "ObservedAssetBinding")
        cv.optional_ref(self.supersedes_id, "ObservedAssetBinding.supersedes_id")
        if self.supersedes_id == self.binding_id:
            raise ActiveDefenseContractError("ObservedAssetBinding: 自分自身を置換できません")

    @property
    def record_id(self) -> str:
        return self.binding_id

    def to_dict(self) -> dict[str, object]:
        return _wire(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ObservedAssetBinding":
        return cls(**cv.exact_fields(payload, _field_names(cls), "ObservedAssetBinding"))


__all__ = [
    "ASMAssetObservation", "CREDENTIAL_KINDS", "CTIObservation", "CTI_SOURCE_TYPES",
    "EXPOSURE_STATUSES", "MFA_STATES", "OWNERSHIP_STATUSES", "ObservedAssetBinding",
    "VULNERABILITY_STATUSES", "VulnerabilityObservation",
]
