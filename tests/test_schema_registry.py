import copy
import json
from pathlib import Path

import pytest

from cybermatch_core.contracts import AssetSchemaError, SchemaRegistry
from scripts.validate_assets import main as validate_assets_main


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_registry_schemas_are_valid_and_all_registered_assets_pass():
    registry = SchemaRegistry()

    for registration in registry.registrations:
        assert registry.schema(registration.name)["$schema"].endswith("2020-12/schema")

    summary = registry.validate_repository(REPOSITORY_ROOT)

    assert summary.schema_version == "1.0"
    assert summary.counts == {
        "agentic_protocol": 1,
        "benchmark": 5,
        "external_mapping": 1,
        "fuzz_campaign": 4,
        "product": 10,
        "recipe": 4,
        "scenario": 21,
        "topology": 7,
    }
    assert summary.total == 53


def test_schema_rejects_unknown_scenario_envelope_field():
    scenario = {
        "metadata": {"name": "example", "version": "1.0"},
        "evaluation": {"runner": "phase63_mission_aware_product", "output_dir": "output/example"},
        "missions": ["profit"],
        "products": ["profiles/products/sample_ids.json"],
        "topology": {"preset": "enterprise"},
    }
    invalid = copy.deepcopy(scenario)
    invalid["oracle_answer"] = True

    with pytest.raises(AssetSchemaError, match="oracle_answer"):
        SchemaRegistry().validate("scenario", invalid)


def test_registry_rejects_unknown_schema_name():
    with pytest.raises(AssetSchemaError, match="unknown schema"):
        SchemaRegistry().validate("missing", {})


def test_asset_validation_cli_reports_machine_readable_summary(capsys):
    assert validate_assets_main(["--root", str(REPOSITORY_ROOT)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["schema_version"] == "1.0"
    assert output["total"] == 53
