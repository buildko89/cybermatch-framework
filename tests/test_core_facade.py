from __future__ import annotations

import pytest


pytestmark = [pytest.mark.benchmark]


def test_cybermatch_core_facade_imports():
    from cybermatch_core.benchmarks import load_standard_benchmark
    from cybermatch_core.products import ProductProfile, load_product_profile
    from cybermatch_core.scenarios import load_scenario
    from cybermatch_core.topologies import load_topology

    profile = load_product_profile("profiles/products/sample_ids.json")
    scenario = load_scenario("scenarios/catalog/financial_enterprise.json")
    topology = load_topology("topologies/enterprise.json")
    benchmark = load_standard_benchmark()

    assert isinstance(profile, ProductProfile)
    assert scenario["metadata"]["name"] == "financial_enterprise"
    assert topology["metadata"]["name"] == "enterprise"
    assert benchmark["metadata"]["name"] == "cybermatch_standard_v1"
