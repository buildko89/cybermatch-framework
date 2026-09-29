"""T3: 防御側へ渡る内部telemetryだけを欠損・遅延させる決定論的変換。"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from cybermatch.contracts import canonical_sha256

from . import contract_validation as cv
from .contract_validation import ActiveDefenseContractError


@dataclass(frozen=True)
class TelemetryFamilyRule:
    """telemetry familyごとの観測品質。保持期間はevent発生stepから数える。"""

    drop_rate_bp: int
    delay_steps: int
    retained_fields: tuple[str, ...]
    retention_steps: int

    def __post_init__(self) -> None:
        cv.basis_point(self.drop_rate_bp, "drop_rate_bp")
        cv.step(self.delay_steps, "delay_steps")
        if not isinstance(self.retention_steps, int) or isinstance(self.retention_steps, bool) or self.retention_steps <= 0:
            raise ActiveDefenseContractError("retention_stepsは正の整数が必要です")
        fields = cv.refs(self.retained_fields, "retained_fields", allow_empty=True)
        object.__setattr__(self, "retained_fields", fields)

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "TelemetryFamilyRule":
        data = cv.exact_fields(payload, {"drop_rate_bp", "delay_steps", "retained_fields", "retention_steps"},
                               "TelemetryFamilyRule")
        return cls(drop_rate_bp=data["drop_rate_bp"], delay_steps=data["delay_steps"],
                   retained_fields=tuple(data["retained_fields"]), retention_steps=data["retention_steps"])

    def to_dict(self) -> dict[str, object]:
        return {"drop_rate_bp": self.drop_rate_bp, "delay_steps": self.delay_steps,
                "retained_fields": list(self.retained_fields), "retention_steps": self.retention_steps}


@dataclass(frozen=True)
class LoggingHygieneConfig:
    """profile IDを含むversionedログ健全性設定。"""

    profile_id: str
    family_rules: Mapping[str, TelemetryFamilyRule]
    policy_hash: str

    def __post_init__(self) -> None:
        cv.ref(self.profile_id, "profile_id")
        if not isinstance(self.family_rules, Mapping) or not self.family_rules:
            raise ActiveDefenseContractError("family_rulesは1件以上必要です")
        normalized: dict[str, TelemetryFamilyRule] = {}
        for family, rule in self.family_rules.items():
            cv.ref(family, "telemetry_family")
            normalized[family] = rule if isinstance(rule, TelemetryFamilyRule) else TelemetryFamilyRule.from_dict(rule)
        object.__setattr__(self, "family_rules", dict(sorted(normalized.items())))
        expected = canonical_sha256(self._body())
        if self.policy_hash != expected:
            raise ActiveDefenseContractError("logging hygieneのpolicy_hashと内容が一致しません")

    def _body(self) -> dict[str, object]:
        return {"schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION, "profile_id": self.profile_id,
                "family_rules": {name: rule.to_dict() for name, rule in sorted(self.family_rules.items())}}

    @classmethod
    def create(cls, *, profile_id: str, family_rules: Mapping[str, TelemetryFamilyRule]) -> "LoggingHygieneConfig":
        body = {"schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION, "profile_id": profile_id,
                "family_rules": {name: rule.to_dict() for name, rule in sorted(family_rules.items())}}
        return cls(profile_id=profile_id, family_rules=family_rules, policy_hash=canonical_sha256(body))

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "LoggingHygieneConfig":
        data = cv.exact_fields(payload, {"schema_version", "profile_id", "family_rules", "policy_hash"},
                               "LoggingHygieneConfig")
        cv.version(data["schema_version"], "LoggingHygieneConfig.schema_version")
        if not isinstance(data["family_rules"], Mapping):
            raise ActiveDefenseContractError("family_rulesはobjectが必要です")
        rules = {name: TelemetryFamilyRule.from_dict(rule) for name, rule in data["family_rules"].items()}
        return cls(profile_id=data["profile_id"], family_rules=rules, policy_hash=data["policy_hash"])

    def to_dict(self) -> dict[str, object]:
        return {**self._body(), "policy_hash": self.policy_hash}


@dataclass(frozen=True)
class HygieneTransformResult:
    observations: tuple[dict[str, object], ...]
    dropped_event_ids: tuple[str, ...]
    expired_event_ids: tuple[str, ...]


class LoggingHygieneTransform:
    """真値や模擬世界には触れず、観測envelopeのコピーだけを加工する。"""

    _PRESERVED_FIELDS = frozenset({
        "event_type", "signal_class", "identity_ref", "node_ref", "workload_ref",
        "telemetry_family", "exposure_class",
    })

    def __init__(self, config: LoggingHygieneConfig):
        self.config = config

    def apply(self, observations: Sequence[Mapping[str, object]], *, seed: int) -> HygieneTransformResult:
        cv.step(seed, "seed")
        kept: list[dict[str, object]] = []
        dropped: list[str] = []
        expired: list[str] = []
        for source in sorted(observations, key=lambda item: str(item.get("event_id", ""))):
            event_id = cv.ref(source.get("event_id"), "event_id")
            observation = source.get("observation")
            if not isinstance(observation, Mapping):
                raise ActiveDefenseContractError("observationはobjectが必要です")
            family = observation.get("telemetry_family")
            if not isinstance(family, str) or family not in self.config.family_rules:
                raise ActiveDefenseContractError(f"telemetry_familyに対応するhygiene ruleがありません: {family}")
            rule = self.config.family_rules[family]
            draw = int.from_bytes(hashlib.sha256(
                f"{seed}\0{event_id}\0telemetry_drop\0{self.config.profile_id}".encode("utf-8")
            ).digest()[:8], "big") % 10_000
            if draw < rule.drop_rate_bp:
                dropped.append(event_id)
                continue
            observed_step = cv.step(source.get("observed_step"), "observed_step")
            original_available = cv.step(source.get("available_step"), "available_step")
            available_step = original_available + rule.delay_steps
            if available_step >= observed_step + rule.retention_steps:
                expired.append(event_id)
                continue
            permitted = self._PRESERVED_FIELDS | set(rule.retained_fields)
            transformed_observation = {key: value for key, value in observation.items() if key in permitted}
            transformed = dict(source)
            transformed["available_step"] = available_step
            transformed["observation"] = transformed_observation
            kept.append(transformed)
        kept.sort(key=lambda item: (int(item["available_step"]), str(item["event_id"])))
        return HygieneTransformResult(tuple(kept), tuple(sorted(dropped)), tuple(sorted(expired)))


__all__ = [
    "HygieneTransformResult", "LoggingHygieneConfig", "LoggingHygieneTransform", "TelemetryFamilyRule",
]
