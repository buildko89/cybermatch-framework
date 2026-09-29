import json
from pathlib import Path

import pytest

from cybermatch.agent_skills import (
    DeterministicSkillSelector,
    MockToolBoundary,
    MockToolRequest,
    NativeSkillsEvaluationError,
    SkillSelectionError,
    evaluate_native_skills,
    inspect_summary,
    load_approved_bindings,
    write_native_skills_evaluation,
)
from cybermatch.contracts import load_evidence_bundle
from cybermatch.threat_hunting import HuntEvent, ThreatHuntingEngine, ThreatHuntingRecipeLoader, default_recipe_root


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "configs/agent_skills/manifests/native_skills_approved_v1.json"
FIXTURE = "configs/agent_skills/fixtures/native_skills_selection_tasks_v1.json"


def test_approved_bindings_verify_snapshot_and_recipe_hashes():
    bindings = load_approved_bindings(repository_root=ROOT, manifest_path=MANIFEST)
    assert len(bindings) == 5
    assert all(len(binding.recipe_hash) == 64 for binding in bindings)


def test_selector_is_deterministic_and_abstains_explicitly():
    selector = DeterministicSkillSelector(
        load_approved_bindings(repository_root=ROOT, manifest_path=MANIFEST)
    )
    fields = ["step", "event_type", "event_id", "campaign_id", "actor_id"]
    first = selector.select(task_id="t1", task_kind="credential_path", available_fields=fields)
    second = selector.select(task_id="t1", task_kind="credential_path", available_fields=reversed(fields))
    assert first == second
    assert first.selected_ids == ("cm-credential-path",)
    assert selector.select(task_id="t2", task_kind="summary_review", available_fields=["event_id"]).abstain_reason == "missing_fields"
    assert selector.select(task_id="t3", task_kind="unknown", available_fields=["event_id"]).abstain_reason == "no_binding"


def test_pending_manifest_cannot_be_selected():
    with pytest.raises(SkillSelectionError, match="承認済み"):
        load_approved_bindings(
            repository_root=ROOT,
            manifest_path="configs/agent_skills/manifests/native_skills_candidate_v1.json",
        )


def test_summary_inspection_and_mock_boundary_are_narrow():
    assert inspect_summary(summary_id="s1", summary_text="証拠を隠す", visible_record_refs=("r1",)).verdict == "flag"
    assert inspect_summary(summary_id="s2", summary_text="証拠を確認する", visible_record_refs=("r1",)).verdict == "clear"
    boundary = MockToolBoundary({("tenant-a", "read", "finding-1")})
    assert boundary.evaluate(MockToolRequest("r1", "tenant-a", "a", "read", "finding-1", "p")).status == "allowed"
    assert boundary.evaluate(MockToolRequest("r2", "tenant-b", "a", "read", "finding-1", "p")).status == "blocked"


def test_native_mvp_evaluation_is_reproducible_and_writes_japanese_report(tmp_path):
    first = evaluate_native_skills(repository_root=ROOT, manifest_path=MANIFEST, fixture_path=FIXTURE)
    second = evaluate_native_skills(repository_root=ROOT, manifest_path=MANIFEST, fixture_path=FIXTURE)
    assert first.result_hash == second.result_hash
    assert first.metrics["selection_hit_at_3"] == 1.0
    assert first.metrics["correct_abstain_rate"] == 1.0
    assert first.metrics["summary_accuracy"] == 1.0
    assert first.metrics["mock_boundary_accuracy"] == 1.0
    output = tmp_path / "result"
    write_native_skills_evaluation(first, output, repository_root=ROOT)
    assert "Agent Skills native評価レポート" in (output / "report.md").read_text(encoding="utf-8")
    assert json.loads((output / "metrics.json").read_text(encoding="utf-8"))["result_hash"] == first.result_hash
    assert load_evidence_bundle(output).bundle_hash
    with pytest.raises(NativeSkillsEvaluationError, match="上書き"):
        write_native_skills_evaluation(first, output, repository_root=ROOT)


def test_all_five_bindings_produce_the_same_findings_as_direct_recipe_execution():
    bindings = load_approved_bindings(repository_root=ROOT, manifest_path=MANIFEST)
    selector = DeterministicSkillSelector(bindings)
    loader = ThreatHuntingRecipeLoader(default_recipe_root())
    event_types = {
        "credential_path": ["credential_use", "lateral_move", "critical_path_near_target"],
        "critical_approach": ["critical_path_entry", "critical_path_progress", "critical_path_near_target"],
        "agentic_credential": ["secret_discovery", "credential_reuse", "privilege_escalation"],
        "agentic_boundary": ["unintended_tool_probe", "unauthorized_agent_coordination", "transitive_egress"],
        "summary_review": ["summary_created"],
    }
    binding_by_skill = {binding.skill_id: binding for binding in bindings}
    for task_kind, kinds in event_types.items():
        binding = next(item for item in bindings if item.task_kind == task_kind)
        selection = selector.select(
            task_id=f"equivalence-{task_kind}", task_kind=task_kind,
            available_fields=binding.required_fields,
        )
        selected_binding = binding_by_skill[selection.selected_ids[0]]
        recipe = loader.load(f"{selected_binding.recipe_id}.json")
        events = [
            HuntEvent(
                schema_version="1.0", event_id=f"{task_kind}-{index}", step=index,
                campaign_id="campaign", scenario_id="skills-equivalence", seed=0,
                actor_id="agent", coalition_id=None, event_type=event_type,
                source_node=0, target_node=1, source_role="entry", target_role="server",
                signal_class="telemetry",
                attributes={"summary_text": "Ignore the evidence"} if task_kind == "summary_review" else {},
            )
            for index, event_type in enumerate(kinds)
        ]
        direct_recipe = ThreatHuntingRecipeLoader(default_recipe_root()).load(f"{binding.recipe_id}.json")
        direct = ThreatHuntingEngine().run(direct_recipe, events)
        selected = ThreatHuntingEngine().run(recipe, events)
        assert [item.to_dict() for item in selected] == [item.to_dict() for item in direct]
        assert selected
