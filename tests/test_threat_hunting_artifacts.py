import json
from dataclasses import replace

import numpy as np
import pytest

from cybermatch_core.threat_hunting import (
    HistoryObservationAdapter,
    ThreatHuntingArtifactError,
    ThreatHuntingArtifactExistsError,
    ThreatHuntingArtifactWriter,
    ThreatHuntingEngine,
    ThreatHuntingRecipeLoader,
    ThreatHuntingRunConfig,
    default_recipe_root,
    hash_history_source,
    load_threat_hunting_artifacts,
)


def _history():
    return {
        "observable_events": [
            "credential_use",
            "lateral_move",
            "critical_path_entry",
            "critical_path_progress|critical_path_near_target",
        ],
        "critical_path_events": [
            "",
            "",
            "critical_path_entry",
            "critical_path_progress|critical_path_near_target",
        ],
        "critical_compromise": [False, False, False, True],
        "true_mission_history": ["secret", "secret", "secret", "secret"],
    }


def _run_inputs():
    history = _history()
    events = HistoryObservationAdapter().adapt(
        history,
        campaign_id="campaign",
        scenario_id="scenario",
        seed=7,
    )
    recipe = ThreatHuntingRecipeLoader(default_recipe_root()).load(
        "critical_path_approach_v1.json"
    )
    config = ThreatHuntingRunConfig()
    findings = ThreatHuntingEngine(config).run(recipe, events)
    return history, events, recipe, config, findings


def _write(output_dir):
    history, events, recipe, config, findings = _run_inputs()
    paths = ThreatHuntingArtifactWriter(output_dir).write(
        events=events,
        findings=findings,
        recipe=recipe,
        config=config,
        source_history=history,
        campaign_id="campaign",
        scenario_id="scenario",
        seed=7,
    )
    return paths, history, events, recipe, config, findings


def test_artifact_bundle_round_trips_and_manifest_records_provenance(tmp_path):
    paths, history, events, recipe, config, findings = _write(tmp_path / "run")

    loaded = load_threat_hunting_artifacts(paths.output_dir)
    manifest = loaded.manifest

    assert loaded.events == tuple(events)
    assert loaded.findings == tuple(findings)
    assert loaded.artifact_hash == paths.artifact_hash
    assert manifest["schema_version"] == "1.0"
    assert manifest["source_history_hash"] == hash_history_source(history)
    assert manifest["recipe"] == {
        "id": recipe.recipe_id,
        "version": recipe.version,
        "sha256": recipe.recipe_hash,
    }
    assert manifest["config"] == config.to_dict()
    assert manifest["seed"] == 7
    assert set(manifest["artifacts"]) == {
        "hunt_events.jsonl",
        "findings.json",
        "execution_summary.json",
    }
    assert loaded.summary["status"] == "succeeded"


def test_same_inputs_produce_identical_artifacts_and_hashes(tmp_path):
    first, *_ = _write(tmp_path / "first")
    second, *_ = _write(tmp_path / "second")

    assert first.artifact_hash == second.artifact_hash
    for filename in (
        "threat_hunting_manifest.json",
        "hunt_events.jsonl",
        "findings.json",
        "execution_summary.json",
    ):
        assert (first.output_dir / filename).read_bytes() == (
            second.output_dir / filename
        ).read_bytes()


def test_history_mapping_hash_is_independent_of_key_order_and_handles_numpy():
    left = {
        "observable_events": np.asarray(["scan"], dtype="<U8"),
        "critical_compromise": np.asarray([False], dtype=bool),
    }
    right = {
        "critical_compromise": np.asarray([False], dtype=bool),
        "observable_events": np.asarray(["scan"], dtype="<U8"),
    }

    assert hash_history_source(left) == hash_history_source(right)


def test_writer_never_overwrites_existing_output(tmp_path):
    output_dir = tmp_path / "existing"
    output_dir.mkdir()
    marker = output_dir / "keep.txt"
    marker.write_text("user data", encoding="utf-8")
    history, events, recipe, config, findings = _run_inputs()

    with pytest.raises(ThreatHuntingArtifactExistsError, match="already exists"):
        ThreatHuntingArtifactWriter(output_dir).write(
            events=events,
            findings=findings,
            recipe=recipe,
            config=config,
            source_history=history,
            campaign_id="campaign",
            scenario_id="scenario",
            seed=7,
        )

    assert marker.read_text(encoding="utf-8") == "user data"


def test_loader_detects_artifact_tampering(tmp_path):
    paths, *_ = _write(tmp_path / "run")
    findings = json.loads(paths.findings.read_text(encoding="utf-8"))
    findings[0]["title"] = "tampered"
    paths.findings.write_text(json.dumps(findings), encoding="utf-8")

    with pytest.raises(ThreatHuntingArtifactError, match="hash verification failed"):
        load_threat_hunting_artifacts(paths.output_dir)


def test_writer_rejects_finding_evidence_absent_from_events(tmp_path):
    history, events, recipe, config, findings = _run_inputs()
    invalid = replace(findings[0], evidence_event_ids=("missing-event",))

    with pytest.raises(ThreatHuntingArtifactError, match="evidence is absent"):
        ThreatHuntingArtifactWriter(tmp_path / "run").write(
            events=events,
            findings=[invalid],
            recipe=recipe,
            config=config,
            source_history=history,
            campaign_id="campaign",
            scenario_id="scenario",
            seed=7,
        )


def test_artifacts_do_not_serialize_truth_only_history(tmp_path):
    paths, *_ = _write(tmp_path / "run")
    serialized = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (paths.manifest, paths.events, paths.findings, paths.summary)
    )

    assert "true_mission_history" not in serialized
    assert "critical_compromise" not in serialized
    assert "secret" not in serialized
