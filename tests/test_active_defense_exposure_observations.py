"""T2観測契約（CTI/ASM/binding）の型・範囲・置換規則を検証する。"""

import copy
import json
import math
from pathlib import Path

import pytest

from cybermatch.threat_hunting.active_defense import (
    ASMAssetObservation, ActiveDefenseContractError, CTIObservation, ObservedAssetBinding,
    select_as_of, validate_supersession,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "configs/active_defense/fixtures/t2_identity_lateral_synthetic_v1.json"


def fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def cti_payload(**changes) -> dict:
    payload = copy.deepcopy(fixture()["cti_observations"][0])
    payload.update(changes)
    return payload


def test_all_fixture_records_round_trip_canonically():
    data = fixture()
    for cls, key in ((CTIObservation, "cti_observations"), (ASMAssetObservation, "asm_observations"),
                     (ObservedAssetBinding, "asset_bindings")):
        for item in data[key]:
            assert cls.from_dict(item).to_dict() == item


@pytest.mark.parametrize("changes", [
    {"confidence_bp": True},
    {"confidence_bp": 7000.0},
    {"confidence_bp": math.nan},
    {"confidence_bp": 10001},
    {"observed_step": -1},
    {"available_step": 1},              # observed_step=2より前に利用可能にはできない
    {"valid_until_step": 2},            # 発生stepと同時に失効する観測は不正
    {"identity_ref": None},             # domain/identity/endpointが全てnull
    {"endpoint_ref": "https://VPN.tenant-a.example:443"},   # 未正規化endpoint
    {"endpoint_ref": "https://vpn.tenant-a.example:0443"},
    {"credential_kind": "plaintext"},
    {"source_type": "real_feed"},
    {"source_ref": "feed-malicious-01"},                     # IDへの評価label埋込み
    {"observation_id": "cti 001"},
    {"schema_version": "2.0"},
])
def test_cti_rejects_invalid_values(changes):
    with pytest.raises(ActiveDefenseContractError):
        CTIObservation.from_dict(cti_payload(**changes))


def test_cti_rejects_unknown_and_missing_fields():
    unknown = cti_payload(credential_value="should-not-exist")
    with pytest.raises(ActiveDefenseContractError, match="未知項目"):
        CTIObservation.from_dict(unknown)
    missing = cti_payload()
    del missing["supersedes_id"]
    with pytest.raises(ActiveDefenseContractError, match="必須項目不足"):
        CTIObservation.from_dict(missing)


def test_asm_distinguishes_unknown_from_false_and_inferred_from_confirmed():
    data = {item["observation_id"]: item for item in fixture()["asm_observations"]}
    vpn = ASMAssetObservation.from_dict(data["asm-vpn-001"])
    mail = ASMAssetObservation.from_dict(data["asm-mail-001"])
    cdn = ASMAssetObservation.from_dict(data["asm-cdn-001"])
    assert vpn.has_confirmed_unpatched_vulnerability is True
    assert mail.has_confirmed_unpatched_vulnerability is False   # 製品名からの推測は確認済みにしない
    assert cdn.has_confirmed_unpatched_vulnerability is None     # 未scanはunknown
    unsorted = copy.deepcopy(data["asm-vpn-001"])
    unsorted["endpoint_refs"] = ["https://vpn.tenant-a.example:443", "https://a.tenant-a.example:443"]
    with pytest.raises(ActiveDefenseContractError, match="昇順"):
        ASMAssetObservation.from_dict(unsorted)


def test_binding_requires_node_or_identity():
    item = copy.deepcopy(fixture()["asset_bindings"][0])
    item["node_ref"], item["identity_refs"] = None, []
    with pytest.raises(ActiveDefenseContractError):
        ObservedAssetBinding.from_dict(item)


def test_supersession_selects_latest_available_version_only():
    records = tuple(CTIObservation.from_dict(item) for item in fixture()["cti_observations"])
    validate_supersession(records, name="cti", subject_key=lambda r: (r.identity_ref, r.endpoint_ref, r.domain_ref))
    before = select_as_of(records, step=11)
    after = select_as_of(records, step=12)
    assert "cti-002" in {r.record_id for r in before.active}
    assert "cti-008" not in {r.record_id for r in before.active}
    assert {r.record_id for r in after.active} >= {"cti-008"} and "cti-002" not in {r.record_id for r in after.active}
    assert after.superseded_ids == ("cti-002",)
    # 到着時点で既に期限切れの観測は保持・件数化するが選択しない。
    assert [r.record_id for r in select_as_of(records, step=6).stale] == ["cti-007"]
    assert select_as_of(records, step=3).pending_count == 8


@pytest.mark.parametrize("mutation, message", [
    (lambda items: items[7].update(supersedes_id="cti-missing"), "置換先が存在しません"),
    (lambda items: items[7].update(identity_ref="synthetic-id-001"), "別subject"),
    (lambda items: items.append({**items[7], "observation_id": "cti-009"}), "複数の新版"),
])
def test_supersession_rejects_ambiguous_replacements(mutation, message):
    items = copy.deepcopy(fixture()["cti_observations"])
    mutation(items)
    records = tuple(CTIObservation.from_dict(item) for item in items)
    with pytest.raises(ActiveDefenseContractError, match=message):
        validate_supersession(records, name="cti", subject_key=lambda r: (r.identity_ref, r.endpoint_ref, r.domain_ref))
