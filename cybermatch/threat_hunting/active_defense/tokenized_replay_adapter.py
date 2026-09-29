"""T4a: 事前token化済みCTI/ASM snapshotをread-onlyで取り込むadapter。"""

from __future__ import annotations

import csv
import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from cybermatch.contracts import SensitiveDataHygieneError, assert_hygienic_payload, sha256_file

from .contract_validation import ActiveDefenseContractError
from .exposure_observations import ASMAssetObservation, CTIObservation, ObservedAssetBinding

REPLAY_RECORD_TYPES = ("cti_observation", "asm_observation", "asset_binding", "internal_telemetry")


@dataclass(frozen=True)
class ReplayDataQualityReport:
    input_sha256: str
    input_format: str
    total_record_count: int
    accepted_record_count: int
    rejected_record_count: int
    record_type_counts: Mapping[str, int]
    unsupported_fields: tuple[str, ...]
    rejection_reasons: tuple[str, ...]
    source_refs: tuple[str, ...]
    normalization_version: str
    identity_key_version: str
    retention_days: int

    @property
    def passed(self) -> bool:
        return self.rejected_record_count == 0 and not self.unsupported_fields

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": "1.0", "input_sha256": self.input_sha256,
                "input_format": self.input_format, "total_record_count": self.total_record_count,
                "accepted_record_count": self.accepted_record_count,
                "rejected_record_count": self.rejected_record_count,
                "record_type_counts": dict(sorted(self.record_type_counts.items())),
                "unsupported_fields": list(self.unsupported_fields),
                "rejection_reasons": list(self.rejection_reasons), "source_refs": list(self.source_refs),
                "normalization_version": self.normalization_version,
                "identity_key_version": self.identity_key_version, "retention_days": self.retention_days,
                "passed": self.passed}


@dataclass(frozen=True)
class TokenizedReplaySnapshot:
    cti_observations: tuple[CTIObservation, ...]
    asm_observations: tuple[ASMAssetObservation, ...]
    bindings: tuple[ObservedAssetBinding, ...]
    internal_telemetry: tuple[Mapping[str, object], ...]
    quality: ReplayDataQualityReport


class TokenizedReplayAdapter:
    """raw identityやcredential値を受け取らず、token化済みrecordだけを型へ変換する。"""

    _WRAPPER_FIELDS = frozenset({"record_type", "payload"})
    _CSV_FIELDS = frozenset({"record_type", "payload_json"})

    def __init__(self, *, tenant_id: str, run_id: str, normalization_version: str,
                 identity_key_version: str, retention_days: int, source_refs: tuple[str, ...],
                 max_records: int = 100_000, max_file_bytes: int = 64 * 1024 * 1024):
        for value, name in ((tenant_id, "tenant_id"), (run_id, "run_id"),
                            (normalization_version, "normalization_version"),
                            (identity_key_version, "identity_key_version")):
            if not isinstance(value, str) or not value.strip():
                raise ActiveDefenseContractError(f"{name}は空でない文字列が必要です")
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days <= 0:
            raise ActiveDefenseContractError("replay-backed入力には正のretention_daysが必要です")
        if not source_refs or any(not isinstance(item, str) or not item.strip() for item in source_refs):
            raise ActiveDefenseContractError("source_refsは1件以上必要です")
        self.tenant_id, self.run_id = tenant_id, run_id
        self.normalization_version, self.identity_key_version = normalization_version, identity_key_version
        self.retention_days, self.source_refs = retention_days, tuple(sorted(set(source_refs)))
        self.max_records, self.max_file_bytes = max_records, max_file_bytes

    def load(self, path: Path, *, input_format: str) -> TokenizedReplaySnapshot:
        source = path.resolve()
        if not source.is_file() or source.stat().st_size > self.max_file_bytes:
            raise ActiveDefenseContractError("replay snapshotが存在しないかsize上限を超えています")
        rows = self._read_jsonl(source) if input_format == "jsonl" else (
            self._read_csv(source) if input_format == "csv" else self._unsupported_format(input_format))
        if len(rows) > self.max_records:
            raise ActiveDefenseContractError("replay record数が上限を超えています")
        accepted: dict[str, list[object]] = {name: [] for name in REPLAY_RECORD_TYPES}
        unsupported: set[str] = set()
        reasons: list[str] = []
        counts: Counter[str] = Counter()
        for index, row in enumerate(rows):
            unknown = set(row) - self._WRAPPER_FIELDS
            unsupported.update(f"record[{index}].{name}" for name in unknown)
            record_type, payload = row.get("record_type"), row.get("payload")
            if record_type not in REPLAY_RECORD_TYPES or not isinstance(payload, Mapping):
                reasons.append(f"record[{index}]: record_typeまたはpayloadが不正")
                continue
            counts[str(record_type)] += 1
            try:
                assert_hygienic_payload(payload)
                parsed = self._parse(str(record_type), payload)
            except (SensitiveDataHygieneError, ActiveDefenseContractError, TypeError, ValueError):
                reasons.append(f"record[{index}]: 契約・PII保護条件に不適合")
                continue
            accepted[str(record_type)].append(parsed)
        rejected = len(reasons) + (1 if unsupported else 0)
        quality = ReplayDataQualityReport(
            input_sha256=sha256_file(source), input_format=input_format, total_record_count=len(rows),
            accepted_record_count=sum(len(items) for items in accepted.values()), rejected_record_count=rejected,
            record_type_counts=dict(counts), unsupported_fields=tuple(sorted(unsupported)),
            rejection_reasons=tuple(reasons), source_refs=self.source_refs,
            normalization_version=self.normalization_version, identity_key_version=self.identity_key_version,
            retention_days=self.retention_days,
        )
        return TokenizedReplaySnapshot(
            tuple(accepted["cti_observation"]), tuple(accepted["asm_observation"]),
            tuple(accepted["asset_binding"]), tuple(accepted["internal_telemetry"]), quality)

    def _parse(self, record_type: str, payload: Mapping[str, object]) -> object:
        if record_type == "cti_observation":
            item = CTIObservation.from_dict(payload)
        elif record_type == "asm_observation":
            item = ASMAssetObservation.from_dict(payload)
        elif record_type == "asset_binding":
            item = ObservedAssetBinding.from_dict(payload)
        else:
            item = dict(payload)
            if item.get("source_kind") != "replay_internal_telemetry":
                raise ActiveDefenseContractError("内部観測はreplay_internal_telemetryに限定します")
            if item.get("run_id") != self.run_id or item.get("tenant_id") != self.tenant_id:
                raise ActiveDefenseContractError("内部観測のrun/tenantが一致しません")
            self._check_identity_versions(item)
            return item
        if item.tenant_id != self.tenant_id:
            raise ActiveDefenseContractError("観測のtenantが一致しません")
        self._check_identity_versions(item.to_dict())
        return item

    def _check_identity_versions(self, value: object) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if key in {"identity_ref", "identity_refs"}:
                    refs = nested if isinstance(nested, list) else [nested]
                    for ref in refs:
                        if ref is not None and (not isinstance(ref, str) or not ref.startswith(self.identity_key_version + ":")):
                            raise ActiveDefenseContractError("identity_refのkey versionがmanifestと一致しません")
                self._check_identity_versions(nested)
        elif isinstance(value, list):
            for item in value:
                self._check_identity_versions(item)

    @staticmethod
    def _read_jsonl(path: Path) -> list[dict[str, object]]:
        rows = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ActiveDefenseContractError(f"JSONL {line_number}行目はobjectが必要です")
            rows.append(value)
        return rows

    def _read_csv(self, path: Path) -> list[dict[str, object]]:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if set(reader.fieldnames or ()) != self._CSV_FIELDS:
                raise ActiveDefenseContractError("CSV列はrecord_type,payload_jsonだけを許可します")
            rows = []
            for index, row in enumerate(reader):
                try:
                    payload = json.loads(row["payload_json"])
                except json.JSONDecodeError as exc:
                    raise ActiveDefenseContractError(f"CSV record {index}のpayload_jsonが不正です") from exc
                rows.append({"record_type": row["record_type"], "payload": payload})
            return rows

    @staticmethod
    def _unsupported_format(value: str):
        raise ActiveDefenseContractError(f"未対応のreplay formatです: {value}")


__all__ = [
    "REPLAY_RECORD_TYPES", "ReplayDataQualityReport", "TokenizedReplayAdapter", "TokenizedReplaySnapshot",
]
