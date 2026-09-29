"""T0観測envelopeを、到着済みのHuntEventだけへ変換するadapter。"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from cybermatch.contracts import (
    AssetSchemaError, SchemaRegistry, SensitiveDataHygieneError, assert_hygienic_payload,
)

from .models import HuntEvent, SCHEMA_VERSION
from .pseudonymization import HmacIdentityPseudonymizer


class T0ObservationAdapterError(ValueError):
    """観測envelopeの境界、時刻、またはPII保護条件が満たされない。"""


class T0ObservationAdapter:
    """run/tenant固定の、合成CTI/ASM観測専用adapter。

    evaluator用truthのpath・payloadは引数に持たない。`current_step`時点で
    available_stepを過ぎた観測だけをHuntEventへ変換する。
    """

    _FORBIDDEN_TOKENS = frozenset({
        "password", "credential_value", "secret", "access_token", "refresh_token",
        "email", "ground_truth", "oracle", "expected_label", "true_label",
    })
    _OPTIONAL_TELEMETRY_FIELDS = ("auth_result", "process_name", "parent_process")

    def __init__(
        self, *, run_id: str, tenant_id: str, scenario_id: str, seed: int = 0,
        identity_pseudonymizer: HmacIdentityPseudonymizer | None = None,
    ):
        self._run_id = self._identifier(run_id, "run_id")
        self._tenant_id = self._identifier(tenant_id, "tenant_id")
        self._scenario_id = self._identifier(scenario_id, "scenario_id")
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise T0ObservationAdapterError("seedは非負整数で指定してください")
        self._seed = seed
        if identity_pseudonymizer is not None and not isinstance(identity_pseudonymizer, HmacIdentityPseudonymizer):
            raise T0ObservationAdapterError("identity_pseudonymizerはHmacIdentityPseudonymizerで指定してください")
        self._identity_pseudonymizer = identity_pseudonymizer
        self._registry = SchemaRegistry()

    @staticmethod
    def _identifier(value: object, name: str) -> str:
        if not isinstance(value, str) or not value.strip() or value != value.strip():
            raise T0ObservationAdapterError(f"{name}は空でない前後空白なしの文字列が必要です")
        return value

    @staticmethod
    def _step(value: object, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise T0ObservationAdapterError(f"{name}は非負整数で指定してください")
        return value

    def adapt(self, payload: Mapping[str, object], *, current_step: int) -> HuntEvent:
        """検証済みかつ到着済みのenvelopeを一つ変換する。"""
        now = self._step(current_step, "current_step")
        try:
            self._registry.validate("cti_observation_envelope", payload)
        except AssetSchemaError as exc:
            raise T0ObservationAdapterError(f"観測envelopeが不正です: {exc}") from exc
        if payload["run_id"] != self._run_id or payload["tenant_id"] != self._tenant_id:
            raise T0ObservationAdapterError("観測envelopeのrun_idまたはtenant_idが一致しません")
        observed_step = self._step(payload["observed_step"], "observed_step")
        available_step = self._step(payload["available_step"], "available_step")
        if available_step < observed_step:
            raise T0ObservationAdapterError("available_stepをobserved_stepより前にできません")
        if available_step > now:
            raise T0ObservationAdapterError("未到着の観測は検知器へ渡せません")
        observation = payload["observation"]
        assert isinstance(observation, Mapping)  # JSON Schemaで検証済み
        self._reject_sensitive_fields(payload)
        identity_ref = observation["identity_ref"]
        if identity_ref is not None and self._identity_pseudonymizer is not None:
            identity_ref = self._identity_pseudonymizer.identity_ref(str(identity_ref))
        event = HuntEvent(
            schema_version=SCHEMA_VERSION,
            event_id=str(payload["event_id"]),
            step=observed_step,
            campaign_id=str(payload["source_ref"]),
            scenario_id=self._scenario_id,
            seed=self._seed,
            actor_id=None,
            coalition_id=None,
            event_type=str(observation["event_type"]),
            source_node=None,
            target_node=None,
            source_role=None,
            target_role=None,
            signal_class=str(observation["signal_class"]),
            attributes={
                "run_id": self._run_id,
                "tenant_id": self._tenant_id,
                "available_step": available_step,
                "source_kind": str(payload["source_kind"]),
                "source_ref": str(payload["source_ref"]),
                "identity_ref": identity_ref,
                "node_ref": observation["node_ref"],
                "workload_ref": observation["workload_ref"],
                "telemetry_family": observation.get("telemetry_family"),
                "exposure_class": observation.get("exposure_class"),
                # 内部telemetryの任意fieldは、envelopeにある場合だけ写す。キー不在は
                # ログ欠損（not_evaluable）として、明示nullは「該当なし」として区別する。
                **{name: observation[name] for name in self._OPTIONAL_TELEMETRY_FIELDS if name in observation},
            },
        )
        try:
            assert_hygienic_payload(event.to_dict())
        except SensitiveDataHygieneError as exc:
            raise T0ObservationAdapterError("変換後の観測に保存禁止データがあります") from exc
        return event

    def adapt_snapshot(
        self, payloads: Iterable[Mapping[str, object]], *, current_step: int,
    ) -> tuple[HuntEvent, ...]:
        """同じas-of stepで到着済み観測を原子的に変換し、固定順で返す。

        途中の一件でも不正・未到着なら結果を返さない。event_idと
        observation_idの重複は、異なるsourceからの上書きを防ぐため拒否する。
        """
        if isinstance(payloads, (str, bytes, bytearray)):
            raise T0ObservationAdapterError("snapshotは観測envelopeの反復可能値で指定してください")
        source = tuple(payloads)
        if any(not isinstance(item, Mapping) for item in source):
            raise T0ObservationAdapterError("snapshotには観測envelopeだけを含められます")
        observation_ids = [item.get("observation_id") for item in source]
        event_ids = [item.get("event_id") for item in source]
        if len(set(observation_ids)) != len(observation_ids) or len(set(event_ids)) != len(event_ids):
            raise T0ObservationAdapterError("snapshot内でobservation_idまたはevent_idが重複しています")
        events = tuple(self.adapt(item, current_step=current_step) for item in source)
        return tuple(sorted(events, key=lambda event: (event.step, event.event_id)))

    def _reject_sensitive_fields(self, value: object) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if not isinstance(key, str):
                    raise T0ObservationAdapterError("観測field名は文字列でなければなりません")
                if key.lower() in self._FORBIDDEN_TOKENS:
                    raise T0ObservationAdapterError(f"禁止されたPIIまたは評価fieldです: {key}")
                self._reject_sensitive_fields(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                self._reject_sensitive_fields(nested)


__all__ = ["T0ObservationAdapter", "T0ObservationAdapterError"]
