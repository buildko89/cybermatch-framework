"""CTI/ASM相関候補の調査順を決めるpriority policy v1。

priorityは調査順のための人工的な重み付きscoreであり、侵害確率ではない。
unknown成分は0を代入してmissing_componentsへ列挙し、分母は固定する
（欠損を除いて再正規化すると、欠損が高scoreに化けるため）。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from cybermatch.contracts import canonical_sha256

from . import contract_validation as cv
from .contract_validation import ActiveDefenseContractError
from .exposure_observations import ASMAssetObservation, CTIObservation

PRIORITY_COMPONENTS = (
    "cti_confidence", "confirmed_vulnerability", "credential_leak_without_mfa", "business_criticality",
)
_POLICY_FIELDS = {
    "schema_version", "policy_id", "policy_version", "weights_bp", "rounding",
    "unknown_component_value", "identity_normalization_version", "description",
}


@dataclass(frozen=True)
class PriorityScore:
    """一つのmatched候補について、成分と欠損を含めて再計算できる形で保持する。"""

    priority_bp: int
    component_scores: Mapping[str, int]
    missing_components: tuple[str, ...]

    def component_dict(self) -> dict[str, int]:
        return {name: self.component_scores[name] for name in PRIORITY_COMPONENTS}


@dataclass(frozen=True)
class PriorityPolicy:
    """重み・丸め・欠損時の扱いをJSONで固定し、そのcanonical hashを記録する。"""

    policy_id: str
    policy_version: str
    weights_bp: Mapping[str, int]
    identity_normalization_version: str
    description: str

    @property
    def policy_hash(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "weights_bp": {name: self.weights_bp[name] for name in PRIORITY_COMPONENTS},
            "rounding": "floor",
            "unknown_component_value": 0,
            "identity_normalization_version": self.identity_normalization_version,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "PriorityPolicy":
        data = cv.exact_fields(payload, _POLICY_FIELDS, "PriorityPolicy")
        cv.version(data["schema_version"], "PriorityPolicy.schema_version")
        weights = cv.exact_fields(data["weights_bp"], set(PRIORITY_COMPONENTS), "PriorityPolicy.weights_bp")
        parsed = {name: cv.basis_point(weights[name], f"weights_bp.{name}") for name in PRIORITY_COMPONENTS}
        if sum(parsed.values()) != cv.BASIS_POINT_MAX:
            raise ActiveDefenseContractError("PriorityPolicy.weights_bp: 合計は10000が必要です")
        # v1は丸め・欠損値を変更可能にしない。変更は別versionのpolicyとして扱う。
        if data["rounding"] != "floor" or data["unknown_component_value"] != 0 \
                or isinstance(data["unknown_component_value"], bool):
            raise ActiveDefenseContractError("PriorityPolicy: v1はfloor丸め・unknown=0のみ対応です")
        description = data["description"]
        if not isinstance(description, str) or not description.strip():
            raise ActiveDefenseContractError("PriorityPolicy.description: 説明が必要です")
        return cls(
            policy_id=cv.ref(data["policy_id"], "PriorityPolicy.policy_id"),
            policy_version=cv.ref(data["policy_version"], "PriorityPolicy.policy_version"),
            weights_bp=MappingProxyType(parsed),
            identity_normalization_version=cv.ref(
                data["identity_normalization_version"], "PriorityPolicy.identity_normalization_version"),
            description=description,
        )

    def score(self, cti: CTIObservation, asm: ASMAssetObservation) -> PriorityScore:
        """`floor((Σ weight_i × component_i) / 10000)`。全成分は0〜10000の整数。"""
        missing: list[str] = []
        vulnerability = asm.has_confirmed_unpatched_vulnerability
        if vulnerability is None:
            missing.append("confirmed_vulnerability")
        if cti.credential_kind is None:
            credential_leak_without_mfa = 0
            missing.append("credential_leak_without_mfa")
        elif cti.credential_kind != "password" or asm.mfa_state == "enabled":
            credential_leak_without_mfa = 0
        elif asm.mfa_state == "disabled":
            credential_leak_without_mfa = cv.BASIS_POINT_MAX
        else:  # passwordだがMFA状態が不明。安全側（有効）とも危険側とも解釈しない。
            credential_leak_without_mfa = 0
            missing.append("credential_leak_without_mfa")
        if asm.business_criticality_bp is None:
            missing.append("business_criticality")
        components = {
            "cti_confidence": cti.confidence_bp,
            "confirmed_vulnerability": cv.BASIS_POINT_MAX if vulnerability else 0,
            "credential_leak_without_mfa": credential_leak_without_mfa,
            "business_criticality": asm.business_criticality_bp or 0,
        }
        weighted = sum(self.weights_bp[name] * components[name] for name in PRIORITY_COMPONENTS)
        return PriorityScore(
            priority_bp=weighted // cv.BASIS_POINT_MAX,
            component_scores=MappingProxyType(components),
            missing_components=tuple(sorted(missing)),
        )


__all__ = ["PRIORITY_COMPONENTS", "PriorityPolicy", "PriorityScore"]
