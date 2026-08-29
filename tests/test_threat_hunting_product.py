from __future__ import annotations

from dataclasses import asdict
import json

import pytest

from cybermatch import SimulationConfig
from cybermatch_core.products import HuntingCapabilities, load_product_profile


pytestmark = pytest.mark.threat_hunting


def test_existing_product_profile_remains_backward_compatible():
    profile = load_product_profile("profiles/products/sample_ids.json")

    assert profile.category == "ids"
    assert profile.product_family is None
    assert profile.hunting_mode is None
    assert profile.hunting is None


@pytest.mark.parametrize(
    "path",
    [
        "profiles/products/sample_threat_hunting_platform.json",
        "profiles/products/sample_behavioral_profiling.json",
        "profiles/products/sample_ml_assisted_hunting.json",
    ],
)
def test_hunting_product_archetypes_load(path):
    profile = load_product_profile(path)

    assert profile.category == "xdr"
    assert profile.product_family
    assert profile.hunting_mode
    assert isinstance(profile.hunting, HuntingCapabilities)
    assert profile.hunting.observable_event_types
    assert 0.0 <= profile.hunting.baseline_quality <= 1.0
    assert 0.0 <= profile.hunting.enrichment_quality <= 1.0


def test_hunting_capability_score_outside_unit_interval_fails(tmp_path):
    payload = {
        "name": "invalid",
        "category": "xdr",
        "hunting": {"baseline_quality": 1.1},
    }
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="baseline_quality must be between 0 and 1"):
        load_product_profile(str(path))


def test_hunting_capability_rejects_unknown_fields(tmp_path):
    payload = {
        "name": "invalid",
        "category": "xdr",
        "hunting": {"oracle_visibility": True},
    }
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="unknown fields: oracle_visibility"):
        load_product_profile(str(path))


def test_threat_hunting_simulation_flag_is_default_off_and_serializable():
    config = SimulationConfig()

    assert config.threat_hunting_enabled is False
    assert asdict(config)["threat_hunting_enabled"] is False


def test_threat_hunting_simulation_flag_requires_boolean():
    with pytest.raises(ValueError, match="threat_hunting_enabled must be a boolean"):
        SimulationConfig(threat_hunting_enabled=1)
