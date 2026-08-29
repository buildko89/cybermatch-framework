import copy
import json
from pathlib import Path

import pytest

from cybermatch_core.threat_hunting import (
    OPERATOR_REGISTRY,
    RecipeLoadError,
    RecipeValidationError,
    ThreatHuntingRecipe,
    ThreatHuntingRecipeLoader,
    apply_recipe_overrides,
    default_recipe_root,
    validate_recipe,
)


def _recipe_payload():
    return {
        "schema_version": "1.0",
        "id": "test_recipe",
        "version": "1.0",
        "title": "Test recipe",
        "hypothesis": "Observable activity should match.",
        "source": "observed",
        "required_fields": ["campaign_id", "event_id", "event_type", "step"],
        "group_by": ["campaign_id"],
        "operations": [
            {
                "operator": "filter",
                "field": "event_type",
                "predicate": "eq",
                "value": "scan",
            }
        ],
        "finding": {
            "severity": "low",
            "title": "Scan observed",
            "reason": "A scan event matched.",
            "score": 0.5,
        },
        "metadata": {"tags": ["network", "hypothesis"]},
    }


def test_recipe_round_trip_and_hash_ignore_mapping_key_order():
    payload = _recipe_payload()
    reordered = {key: payload[key] for key in reversed(payload)}
    reordered["finding"] = {
        key: payload["finding"][key] for key in reversed(payload["finding"])
    }

    first = validate_recipe(payload)
    second = ThreatHuntingRecipe.from_dict(reordered)

    assert first.to_dict() == second.to_dict()
    assert first.recipe_hash == second.recipe_hash
    assert len(first.recipe_hash) == 64


def test_operator_registry_is_fixed():
    assert OPERATOR_REGISTRY == {
        "filter",
        "derive",
        "window",
        "aggregate",
        "rank",
        "sequence",
    }


def test_default_sample_recipes_load_and_use_observed_fields_only():
    loader = ThreatHuntingRecipeLoader(default_recipe_root())

    recipes = loader.load_many(
        [
            "credential_to_critical_path_v1.json",
            "critical_path_approach_v1.json",
        ]
    )

    assert [recipe.recipe_id for recipe in recipes] == [
        "credential_to_critical_path_v1",
        "critical_path_approach_v1",
    ]
    assert all(recipe.source == "observed" for recipe in recipes)


def test_recipe_overrides_are_validated_and_change_recipe_hash():
    recipe = ThreatHuntingRecipeLoader(default_recipe_root()).load(
        "critical_path_approach_v1.json"
    )

    overridden = apply_recipe_overrides(
        recipe,
        {"window_size_steps": 7, "finding_threshold": 3, "finding_score": 0.8},
    )

    assert overridden.recipe_hash != recipe.recipe_hash
    assert overridden.operations[1].parameters["size_steps"] == 7
    assert overridden.finding.condition["value"] == 3.0
    assert overridden.finding.score == 0.8
    assert overridden.metadata["recipe_overrides"] == {
        "finding_score": 0.8,
        "finding_threshold": 3.0,
        "window_size_steps": 7,
    }


def test_recipe_override_rejects_operator_mismatch_and_unknown_field():
    recipe = ThreatHuntingRecipeLoader(default_recipe_root()).load(
        "critical_path_approach_v1.json"
    )

    with pytest.raises(RecipeValidationError, match="requires a sequence operator"):
        apply_recipe_overrides(recipe, {"sequence_max_span_steps": 4})
    with pytest.raises(RecipeValidationError, match="unknown fields: oracle_threshold"):
        apply_recipe_overrides(recipe, {"oracle_threshold": 1})


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value["operations"][0].update(operator="python"), "unknown"),
        (lambda value: value.update(source="ground_truth"), "source must be 'observed'"),
        (
            lambda value: value.update(required_fields=["event_type", "true_mission_history"]),
            "not available",
        ),
        (lambda value: value["finding"].update(severity="urgent"), "severity"),
        (lambda value: value["finding"].update(score=1.1), "between 0 and 1"),
    ],
)
def test_recipe_rejects_unsafe_or_invalid_contracts(mutate, message):
    payload = _recipe_payload()
    mutate(payload)

    with pytest.raises(RecipeValidationError, match=message):
        validate_recipe(payload)


def test_recipe_rejects_negative_window_and_empty_sequence():
    window_recipe = _recipe_payload()
    window_recipe["operations"] = [
        {"operator": "window", "kind": "tumbling", "size_steps": -1}
    ]
    with pytest.raises(RecipeValidationError, match="positive integer"):
        validate_recipe(window_recipe)

    sequence_recipe = _recipe_payload()
    sequence_recipe["operations"] = [
        {"operator": "sequence", "items": [], "max_span_steps": 5}
    ]
    with pytest.raises(RecipeValidationError, match="non-empty array"):
        validate_recipe(sequence_recipe)


def test_recipe_requires_operation_fields_to_be_declared():
    payload = _recipe_payload()
    payload["required_fields"] = ["campaign_id", "event_id", "step"]

    with pytest.raises(RecipeValidationError, match="unavailable field"):
        validate_recipe(payload)


def test_loader_rejects_absolute_traversal_and_non_json_paths(tmp_path):
    recipe_file = tmp_path / "recipe.json"
    recipe_file.write_text(json.dumps(_recipe_payload()), encoding="utf-8")
    loader = ThreatHuntingRecipeLoader(tmp_path)

    with pytest.raises(RecipeLoadError, match="must be relative"):
        loader.load(recipe_file.resolve())
    with pytest.raises(RecipeLoadError, match="escapes"):
        loader.load("../outside.json")
    with pytest.raises(RecipeLoadError, match=".json extension"):
        loader.load("recipe.txt")


def test_loader_rejects_duplicate_recipe_identity(tmp_path):
    payload = _recipe_payload()
    (tmp_path / "first.json").write_text(json.dumps(payload), encoding="utf-8")
    duplicate = copy.deepcopy(payload)
    duplicate["title"] = "Same identity, different file"
    (tmp_path / "second.json").write_text(json.dumps(duplicate), encoding="utf-8")
    loader = ThreatHuntingRecipeLoader(tmp_path)

    loader.load("first.json")
    with pytest.raises(RecipeLoadError, match="duplicate recipe id/version"):
        loader.load("second.json")


def test_loader_rejects_duplicate_json_keys(tmp_path):
    (tmp_path / "duplicate.json").write_text(
        '{"schema_version":"1.0","schema_version":"1.0"}',
        encoding="utf-8",
    )

    with pytest.raises(RecipeLoadError, match="duplicate key"):
        ThreatHuntingRecipeLoader(tmp_path).load("duplicate.json")


def test_default_recipe_root_is_inside_repository():
    root = default_recipe_root()

    assert root.parts[-2:] == ("recipes", "threat_hunting")
    assert Path(root).is_dir()
