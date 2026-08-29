import json

import pytest

from cybermatch_core.threat_hunting import (
    ExternalFieldMapping,
    Finding,
    GroundTruthLabel,
    HuntEvent,
    ModelPluginManifest,
    SklearnAnomalyPlugin,
    ThreatHuntingArtifactWriter,
    ThreatHuntingEngine,
    ThreatHuntingModelError,
    ThreatHuntingRecipeLoader,
    ThreatHuntingRunConfig,
    compare_detector_findings,
    default_recipe_root,
    load_threat_hunting_artifacts,
)


def _event(index, value, *, campaign="campaign"):
    return HuntEvent(
        schema_version="1.0",
        event_id=f"event_{index}",
        step=index,
        campaign_id=campaign,
        scenario_id="scenario",
        seed=3,
        actor_id="actor",
        coalition_id=None,
        event_type="network",
        source_node=0,
        target_node=1,
        source_role=None,
        target_role=None,
        signal_class="telemetry",
        attributes={"bytes": value, "query_length": value / 2},
    )


def _training_events():
    return tuple(_event(index, value) for index, value in enumerate((9, 10, 10.5, 11, 9.5, 10.2)))


@pytest.mark.parametrize("kind", ["kmeans_distance", "isolation_forest"])
def test_optional_models_are_reproducible_and_emit_provenance(kind):
    training = _training_events()
    plugin = SklearnAnomalyPlugin(
        kind,
        feature_schema=("attributes.bytes", "attributes.query_length"),
        random_seed=17,
        threshold_quantile=0.8,
        n_clusters=2,
    )
    first = plugin.fit(training, training_data_ids=("baseline-seed-1", "baseline-seed-2"))
    second_plugin = SklearnAnomalyPlugin(
        kind,
        feature_schema=("attributes.bytes", "attributes.query_length"),
        random_seed=17,
        threshold_quantile=0.8,
        n_clusters=2,
    )
    second = second_plugin.fit(training, training_data_ids=("baseline-seed-1", "baseline-seed-2"))

    assert first.to_dict() == second.to_dict()
    assert first.model_hash == second.model_hash
    assert first.feature_schema_hash
    assert first.preprocessing["kind"] == "standard_scaler"
    assert first.calibration["sample_count"] == len(training)

    result = plugin.detect((_event(20, 10.1), _event(21, 500)))
    assert result.findings
    assert result.findings[-1].evidence_event_ids == ("event_21",)
    assert all(finding.attributes["model_hash"] == first.model_hash for finding in result.findings)


def test_model_plugin_is_optional_and_core_engine_does_not_depend_on_fit():
    recipe = ThreatHuntingRecipeLoader(default_recipe_root()).load("critical_path_approach_v1.json")
    engine = ThreatHuntingEngine()
    assert engine.run(recipe, ()) == []

    plugin = SklearnAnomalyPlugin("kmeans_distance", feature_schema=("step",))
    with pytest.raises(ThreatHuntingModelError, match="fitted"):
        plugin.detect((_event(0, 1),))


def test_model_manifest_is_hash_verified_as_part_of_h1_artifact(tmp_path):
    training = _training_events()
    plugin = SklearnAnomalyPlugin(
        "kmeans_distance", feature_schema=("attributes.bytes",), threshold_quantile=0.8
    )
    model_manifest = plugin.fit(training, training_data_ids=("training-campaign",))
    evaluated_events = (_event(20, 10.1), _event(21, 500))
    model_findings = plugin.detect(evaluated_events).findings
    recipe = ThreatHuntingRecipeLoader(default_recipe_root()).load("critical_path_approach_v1.json")
    paths = ThreatHuntingArtifactWriter(tmp_path / "artifact").write(
        events=evaluated_events,
        findings=model_findings,
        recipe=recipe,
        config=ThreatHuntingRunConfig(),
        source_history={"observable_events": []},
        campaign_id="campaign",
        scenario_id="scenario",
        seed=3,
        model_manifest=model_manifest,
    )

    loaded = load_threat_hunting_artifacts(paths.output_dir)
    reference = loaded.manifest["model_manifest"]
    assert reference["model_hash"] == model_manifest.model_hash
    model_path = paths.output_dir / reference["path"]
    assert ModelPluginManifest.from_dict(json.loads(model_path.read_text(encoding="utf-8"))) == model_manifest
    assert loaded.findings == model_findings

    payload = json.loads(model_path.read_text(encoding="utf-8"))
    payload["threshold"] += 1
    model_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="model manifest hash verification"):
        load_threat_hunting_artifacts(paths.output_dir)


def test_rule_and_model_performance_and_load_are_comparable_on_same_fixture():
    training = _training_events()
    plugin = SklearnAnomalyPlugin(
        "kmeans_distance", feature_schema=("attributes.bytes",), threshold_quantile=0.8
    )
    plugin.fit(training, training_data_ids=("training-campaign",))
    events = (_event(20, 10.1), _event(21, 500))
    model_findings = plugin.detect(events).findings
    simple_findings = tuple(
        Finding(
            schema_version="1.0",
            finding_id=f"simple_{event.event_id}",
            recipe_id="simple_threshold",
            recipe_version="1.0",
            severity="medium",
            score=0.7,
            campaign_id=event.campaign_id,
            actor_id=event.actor_id,
            start_step=event.step,
            end_step=event.step,
            title="Simple threshold",
            reason="fixture",
            evidence_event_ids=(event.event_id,),
        )
        for event in events
    )
    truth = (
        GroundTruthLabel(
            label_id="truth_anomaly",
            campaign_id="campaign",
            label_type="attacker_success",
            start_step=21,
            end_step=21,
            actor_id="actor",
            target_node=1,
            severity="high",
        ),
    )

    comparison = compare_detector_findings(
        simple_findings=simple_findings,
        model_findings=model_findings,
        ground_truth=truth,
        events=events,
        total_steps=22,
    )

    assert comparison["simple"]["finding_count"] == 2
    assert comparison["model"]["finding_count"] <= 2
    assert comparison["model"]["f1"] >= comparison["simple"]["f1"]
    assert "total_evidence_references" in comparison["delta"]


def test_external_mapping_api_remains_independent_of_model_plugin():
    mapping = ExternalFieldMapping(
        mapping_id="minimal",
        field_map={"step": "step", "event_type": "type"},
    )
    assert mapping.to_dict()["mapping_id"] == "minimal"
