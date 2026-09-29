"""priority policy v1の手計算一致と、相関規則v1のmatched/ambiguous/unmatched/stale判定。"""

import copy
import json
import random
from pathlib import Path

import pytest

from cybermatch.threat_hunting.active_defense import (
    ASMAssetObservation, ActiveDefenseContractError, CTIObservation, ExposureCorrelator,
    ObservedAssetBinding, PriorityPolicy,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "configs/active_defense/fixtures/t2_identity_lateral_synthetic_v1.json").read_text(encoding="utf-8"))
POLICY_PAYLOAD = json.loads((ROOT / "configs/active_defense/policies/priority_policy_v1.json").read_text(encoding="utf-8"))


def policy() -> PriorityPolicy:
    return PriorityPolicy.from_dict(POLICY_PAYLOAD)


def records(fixture=FIXTURE):
    return (tuple(CTIObservation.from_dict(i) for i in fixture["cti_observations"]),
            tuple(ASMAssetObservation.from_dict(i) for i in fixture["asm_observations"]),
            tuple(ObservedAssetBinding.from_dict(i) for i in fixture["asset_bindings"]))


def correlate(step, fixture=FIXTURE):
    ctis, asms, bindings = records(fixture)
    result = ExposureCorrelator(tenant_id="tenant-a", policy=policy()).correlate(
        step=step, cti_observations=ctis, asm_observations=asms, bindings=bindings)
    return {match.cti_ref: match for match in result}


def by_id(items, key, value):
    return next(item for item in items if item[key] == value)


def test_priority_matches_hand_calculation():
    ctis, asms, _ = records()
    cti = {c.observation_id: c for c in ctis}
    asm = {a.observation_id: a for a in asms}
    # floor((4000*7000 + 2500*10000 + 2000*10000 + 1500*8000) / 10000) = 8500
    vpn = policy().score(cti["cti-001"], asm["asm-vpn-001"])
    assert vpn.priority_bp == 8500
    assert vpn.component_dict() == {"cti_confidence": 7000, "confirmed_vulnerability": 10000,
                                    "credential_leak_without_mfa": 10000, "business_criticality": 8000}
    assert vpn.missing_components == ()
    # MFA有効・推測CVEのみ・criticality不明: floor(4000*9000/10000) = 3600
    mail = policy().score(cti["cti-002"], asm["asm-mail-001"])
    assert (mail.priority_bp, mail.missing_components) == (3600, ("business_criticality",))
    # 置換版: floor(4000*5000/10000) = 2000
    assert policy().score(cti["cti-008"], asm["asm-mail-001"]).priority_bp == 2000


def test_priority_floors_and_records_unknown_components_without_renormalizing():
    ctis, asms, _ = records()
    cti = next(c for c in ctis if c.observation_id == "cti-001")
    item = copy.deepcopy(by_id(FIXTURE["asm_observations"], "observation_id", "asm-vpn-001"))
    item.update(mfa_state="unknown", vulnerability_observations=None, business_criticality_bp=None)
    unknown = policy().score(cti, ASMAssetObservation.from_dict(item))
    # unknownは0を代入し分母は固定。再正規化すると7000になり欠損が高scoreへ化ける。
    assert unknown.priority_bp == 2800
    assert unknown.missing_components == ("business_criticality", "confirmed_vulnerability", "credential_leak_without_mfa")
    odd = CTIObservation.from_dict({**cti.to_dict(), "confidence_bp": 3333})
    item.update(mfa_state="enabled", vulnerability_observations=[], business_criticality_bp=1)
    assert policy().score(odd, ASMAssetObservation.from_dict(item)).priority_bp == 1333  # floor((4000*3333 + 1500*1) / 10000)


def test_policy_rejects_changed_arithmetic_and_bad_weights():
    for change in ({"rounding": "round"}, {"unknown_component_value": 5000},
                   {"weights_bp": {**POLICY_PAYLOAD["weights_bp"], "cti_confidence": 4001}}):
        with pytest.raises(ActiveDefenseContractError):
            PriorityPolicy.from_dict({**POLICY_PAYLOAD, **change})
    assert len(policy().policy_hash) == 64


def test_correlation_rule_v1_classifies_each_case():
    result = correlate(step=6)
    assert (result["cti-001"].status, result["cti-001"].match_kind, result["cti-001"].priority_bp) == ("matched", "identity_service", 8500)
    assert result["cti-001"].identity_ref == "synthetic-id-001" and result["cti-001"].node_ref == "node-vpn-gw"
    assert result["cti-001"].binding_refs == ("bind-vpn-001",) and result["cti-001"].asm_ref == "asm-vpn-001"
    assert (result["cti-003"].status, result["cti-003"].reason_codes) == ("ambiguous", ("domain_only_not_confirmed",))
    assert (result["cti-004"].status, result["cti-004"].reason_codes) == ("ambiguous", ("multiple_candidates",))
    assert (result["cti-005"].status, result["cti-005"].reason_codes) == ("unmatched", ("no_observed_asset",))
    assert (result["cti-006"].status, result["cti-006"].reason_codes) == ("ambiguous", ("ownership_unconfirmed",))
    assert (result["cti-007"].status, result["cti-007"].reason_codes) == ("stale", ("cti_expired",))
    for ref in ("cti-003", "cti-004", "cti-005", "cti-006", "cti-007"):
        assert result[ref].priority_bp is None and result[ref].identity_ref is None


def test_correlation_uses_only_arrived_observations():
    assert correlate(step=3) == {}
    assert set(correlate(step=4)) == {"cti-001", "cti-003", "cti-004", "cti-005", "cti-006"}
    late_asm = copy.deepcopy(FIXTURE)
    for item in (*late_asm["asm_observations"], *late_asm["asset_bindings"]):
        item["available_step"] = 8
    assert correlate(step=6, fixture=late_asm)["cti-001"].status == "unmatched"
    assert correlate(step=8, fixture=late_asm)["cti-001"].status == "matched"


def test_endpoint_only_cti_and_non_exposed_or_conflicting_assets():
    data = copy.deepcopy(FIXTURE)
    data["cti_observations"] = [{**by_id(FIXTURE["cti_observations"], "observation_id", "cti-004"),
                                 "endpoint_ref": "https://vpn.tenant-a.example:443"}]
    match = correlate(step=6, fixture=data)["cti-004"]
    assert (match.status, match.match_kind, match.identity_ref, match.node_ref) == ("matched", "endpoint_exact", None, "node-vpn-gw")
    exposed = by_id(data["asm_observations"], "observation_id", "asm-vpn-001")
    conflict = {**copy.deepcopy(exposed), "observation_id": "asm-vpn-002", "source_ref": "synthetic-asm-scan-02",
                "mfa_state": "enabled"}
    data["asm_observations"].append(conflict)
    assert correlate(step=6, fixture=data)["cti-004"].reason_codes == ("asm_conflicting_observations",)
    data["asm_observations"].pop()
    exposed["exposure_status"] = "unknown"
    assert correlate(step=6, fixture=data)["cti-004"].reason_codes == ("exposure_unknown",)


def test_stale_asm_and_binding_are_reported_as_stale_not_matched():
    data = copy.deepcopy(FIXTURE)
    for item in data["asset_bindings"]:
        item["valid_until_step"] = 5
    assert correlate(step=6, fixture=data)["cti-001"].reason_codes == ("binding_observation_stale",)


def test_key_version_mismatch_is_not_joined():
    data = copy.deepcopy(FIXTURE)
    data["asset_bindings"][1]["identity_refs"] = ["k2:" + "a" * 64]
    data["cti_observations"] = [{**FIXTURE["cti_observations"][0], "identity_ref": "k1:" + "a" * 64}]
    match = correlate(step=6, fixture=data)["cti-001"]
    assert match.status == "unmatched" and "unjoinable_key_version" in match.reason_codes


def test_cross_tenant_input_is_rejected():
    data = copy.deepcopy(FIXTURE)
    data["asset_bindings"][0]["tenant_id"] = "tenant-b"
    with pytest.raises(ActiveDefenseContractError, match="tenant"):
        correlate(step=6, fixture=data)


def test_correlation_is_independent_of_input_order():
    shuffled = copy.deepcopy(FIXTURE)
    rng = random.Random(7)
    for key in ("cti_observations", "asm_observations", "asset_bindings"):
        rng.shuffle(shuffled[key])
    for step in (4, 6, 12):
        assert [m.to_dict() for m in correlate(step).values()] == \
            [m.to_dict() for m in correlate(step, fixture=shuffled).values()]
