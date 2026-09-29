"""T1 identity仮名化と観測adapterへの適用を検証する。"""

import json
from pathlib import Path

import pytest

from cybermatch_core.threat_hunting import (
    HmacIdentityPseudonymizer,
    IdentityPseudonymizationError,
    T0ObservationAdapter,
)


ROOT = Path(__file__).resolve().parents[1]
KEY = b"0123456789abcdef0123456789abcdef"


def test_hmac_identity_reference_is_deterministic_versioned_and_does_not_contain_input():
    pseudonymizer = HmacIdentityPseudonymizer(key=KEY, key_version="key-v1")
    value = pseudonymizer.identity_ref("person@example.invalid")
    assert value == pseudonymizer.identity_ref("person@example.invalid")
    assert value.startswith("key-v1:")
    assert len(value.split(":", 1)[1]) == 64
    assert "person" not in value
    assert value != HmacIdentityPseudonymizer(key=KEY, key_version="key-v2").identity_ref("person@example.invalid")
    assert value != HmacIdentityPseudonymizer(key=b"a" * 32, key_version="key-v1").identity_ref("person@example.invalid")


@pytest.mark.parametrize("key, version, identity", [
    (b"short", "key-v1", "person"),
    (KEY, "UPPER", "person"),
    (KEY, "key-v1", " "),
])
def test_pseudonymizer_rejects_unsafe_inputs(key, version, identity):
    if key == b"short" or version == "UPPER":
        with pytest.raises(IdentityPseudonymizationError):
            HmacIdentityPseudonymizer(key=key, key_version=version)
    else:
        with pytest.raises(IdentityPseudonymizationError):
            HmacIdentityPseudonymizer(key=key, key_version=version).identity_ref(identity)


def test_adapter_can_replace_raw_identity_before_hunt_event_creation():
    payload = json.loads((ROOT / "configs/threat_hunting/observations/t0_synthetic_cti_observation.json").read_text(encoding="utf-8"))
    payload["observation"]["identity_ref"] = "person@example.invalid"
    pseudonymizer = HmacIdentityPseudonymizer(key=KEY, key_version="key-v1")
    adapter = T0ObservationAdapter(
        run_id="t0-synthetic-run", tenant_id="tenant-example", scenario_id="pseudonym-test",
        identity_pseudonymizer=pseudonymizer,
    )
    event = adapter.adapt(payload, current_step=4)
    assert event.attributes["identity_ref"] == pseudonymizer.identity_ref("person@example.invalid")
    assert "person" not in str(event.to_dict())


def test_adapter_rejects_raw_email_when_no_pseudonymizer_is_supplied():
    payload = json.loads((ROOT / "configs/threat_hunting/observations/t0_synthetic_cti_observation.json").read_text(encoding="utf-8"))
    payload["observation"]["identity_ref"] = "person@example.invalid"
    adapter = T0ObservationAdapter(run_id="t0-synthetic-run", tenant_id="tenant-example", scenario_id="pseudonym-test")
    with pytest.raises(Exception, match="保存禁止"):
        adapter.adapt(payload, current_step=4)
