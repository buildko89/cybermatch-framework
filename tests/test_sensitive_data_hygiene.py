"""平文PII・secretらしい値を成果物へ渡さないための検査。"""

import pytest

from cybermatch_core.contracts import SensitiveDataHygieneError, assert_hygienic_payload


def test_hygiene_accepts_pseudonymized_identity_reference():
    assert_hygienic_payload({"identity_ref": "key-v1:" + "a" * 64, "items": ["synthetic"]})


@pytest.mark.parametrize("payload", [
    {"identity_ref": "person@example.invalid"},
    {"password": "not-logged"},
    {"nested": {"access_token": "not-logged"}},
    {"key": "-----BEGIN PRIVATE KEY-----"},
    {"key": "AKIAABCDEFGHIJKLMNOP"},
])
def test_hygiene_rejects_sensitive_fields_or_values_without_echoing_value(payload):
    with pytest.raises(SensitiveDataHygieneError) as captured:
        assert_hygienic_payload(payload)
    assert "not-logged" not in str(captured.value)
