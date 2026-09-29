"""T2 runnerの受入条件: 時刻境界、CTIだけでは対処候補なし、同snapshot同結果、CLI・証跡。"""

import inspect
import json
import random
from pathlib import Path

import pytest

from cybermatch_core.active_defense import (
    ActiveDefenseContractError, ContextHuntingRunner, build_context_hunting_inputs, load_context_hunting_inputs,
)
from cybermatch_core.contracts import load_evidence_bundle
from cybermatch_core.threat_hunting import T0ObservationAdapter
from scripts.run_cti_asm_hypothesis_hunt import main

ROOT = Path(__file__).resolve().parents[1]
SPEC = "configs/active_defense/runs/t2_synthetic_context_hunting_v1.json"


def documents():
    spec = json.loads((ROOT / SPEC).read_text(encoding="utf-8"))
    docs = {name: json.loads((ROOT / spec[name]).read_text(encoding="utf-8"))
            for name in ("observation_fixture", "priority_policy", "scheduler_policy", "hypothesis_templates")}
    return spec, docs


def run(mutate=None):
    spec, docs = documents()
    if mutate is not None:
        mutate(spec, docs)
    inputs = build_context_hunting_inputs(spec_payload=spec, documents=docs, recipe_root=ROOT / spec["recipe_root"])
    return ContextHuntingRunner(inputs).run()


@pytest.fixture(scope="module")
def result():
    return ContextHuntingRunner(load_context_hunting_inputs(ROOT, SPEC)).run()


def test_findings_are_detected_only_after_evidence_arrives(result):
    detected = {trace.recipe_id: trace.detected_step for trace in result.traces}
    assert detected == {"critical_path_approach_v1": 9, "identity_process_chain_v1": 10}
    lateral = next(t for t in result.traces if t.recipe_id == "identity_process_chain_v1")
    # step 9に発生した横展開ログはstep 10に到着する。検知をstep 9へ遡らせない。
    assert (lateral.finding_start_step, lateral.finding_end_step, lateral.detected_step) == (6, 9, 10)
    assert lateral.observation_refs == ("hunt-event-tel-001", "hunt-event-tel-002", "hunt-event-tel-003")
    assert lateral.context_observation_refs == ("asm-vpn-001", "bind-vpn-001", "cti-001")
    fixture = documents()[1]["observation_fixture"]
    available = {item["event_id"]: item["available_step"] for item in fixture["internal_telemetry"]}
    for trace in result.traces:
        assert all(available[ref] <= trace.detected_step for ref in trace.observation_refs)
    assert result.not_arrived_event_ids == ("hunt-event-tel-008",)


def test_only_matched_cti_creates_hypotheses_and_lead_reference(result):
    assert dict(result.first_matched_step_by_cti) == {"cti-001": 4, "cti-002": 5, "cti-008": 12}
    subjects = {(h.template_id, h.subject_ref) for h in result.hypotheses}
    assert subjects == {
        ("identity_lateral_v1", "synthetic-id-001"), ("credential_progression_v1", "synthetic-id-001"),
        ("critical_path_v1", "node-vpn-gw"), ("identity_lateral_v1", "synthetic-id-003"),
        ("credential_progression_v1", "synthetic-id-003"), ("critical_path_v1", "node-mail-gw"),
    }
    # 置換版cti-008は同じtemplate×subjectの有効な仮説があるため重複作成しない。
    assert all(h.created_step in (4, 5) for h in result.hypotheses)


def test_budget_and_missing_fields_are_explicit(result):
    per_step = {}
    for decision in result.decisions:
        per_step.setdefault(decision.step, []).append(decision.decision)
    assert all(values.count("executed") <= 3 for values in per_step.values())
    assert per_step[6].count("deferred_budget") == 3
    not_evaluable = [e for e in result.executions if e.evaluation_status != "evaluated"]
    assert [(e.step, e.recipe_id, e.missing_fields) for e in not_evaluable] == [
        (8, "identity_process_chain_v1", ("attributes.auth_result",))]
    assert result.metrics()["not_evaluable_execution_count"] == 1


def test_cti_only_run_produces_no_response_eligible_finding():
    cti_only = run(lambda spec, docs: docs["observation_fixture"].update(internal_telemetry=[]))
    assert len(cti_only.hypotheses) == 6       # 調査仮説は作る
    assert cti_only.executions == () and cti_only.traces == ()
    assert cti_only.metrics()["response_eligible_finding_count"] == 0


def test_same_snapshot_gives_same_result_regardless_of_input_order(result):
    def shuffle(spec, docs):
        rng = random.Random(11)
        for key in ("cti_observations", "asm_observations", "asset_bindings", "internal_telemetry"):
            rng.shuffle(docs["observation_fixture"][key])
    assert run().result_hash == result.result_hash
    # 入力fileのbyte列が変わるためfixture hashは変わるが、それ以外の結果は完全一致する。
    shuffled = run(shuffle).to_dict()
    expected = result.to_dict()
    assert shuffled["provenance"]["observation_fixture_hash"] != expected["provenance"]["observation_fixture_hash"]
    for payload in (shuffled, expected):
        payload["provenance"].pop("observation_fixture_hash")
    assert shuffled == expected


def test_changing_priority_policy_changes_provenance_hash(result):
    def weights(spec, docs):
        docs["priority_policy"]["weights_bp"].update(cti_confidence=5000, business_criticality=500)
    changed = run(weights)
    assert changed.provenance["priority_policy_hash"] != result.provenance["priority_policy_hash"]


@pytest.mark.parametrize("mutate, message", [
    (lambda s, d: d["observation_fixture"]["cti_observations"][0].update(tenant_id="tenant-b"), "別tenant"),
    (lambda s, d: d["observation_fixture"]["internal_telemetry"][0].update(tenant_id="tenant-b"), "tenant"),
    (lambda s, d: d["observation_fixture"]["internal_telemetry"][0].update(source_kind="synthetic_cti"), "source_kind"),
    (lambda s, d: d["observation_fixture"]["cti_observations"][0].update(identity_ref="person@example.invalid"), "保存禁止"),
    (lambda s, d: d["observation_fixture"].update(evidence_class="real"), "evidence_class"),
    (lambda s, d: s.update(observation_fixture="../outside.json"), "observation_fixture"),
    (lambda s, d: d["hypothesis_templates"]["templates"][0].update(window_steps=21), "max_lookback"),
])
def test_invalid_inputs_fail_closed(mutate, message):
    with pytest.raises(ActiveDefenseContractError, match=message):
        run(mutate)


def test_runner_api_has_no_truth_input():
    parameters = set(inspect.signature(ContextHuntingRunner).parameters)
    assert parameters == {"inputs", "engine"}
    _, docs = documents()
    assert "evaluator_only" not in json.dumps(docs)


def test_cli_writes_reproducible_evidence_and_refuses_overwrite(tmp_path, capsys):
    assert main(["--output", str(tmp_path / "a")]) == 0
    first = json.loads(capsys.readouterr().out)
    assert main(["--output", str(tmp_path / "b")]) == 0
    second = json.loads(capsys.readouterr().out)
    assert first["result_hash"] == second["result_hash"]
    assert load_evidence_bundle(tmp_path / "a").bundle_hash == first["bundle_hash"]
    for name in ("matches.jsonl", "hypotheses.jsonl", "scheduler_decisions.jsonl", "binding_executions.jsonl",
                 "finding_trace.jsonl", "findings.jsonl", "metrics.json", "report.md"):
        assert (tmp_path / "a" / name).is_file()
    report = (tmp_path / "a" / "report.md").read_text(encoding="utf-8")
    assert "```mermaid" in report and "解釈上の制約" in report
    assert main(["--output", str(tmp_path / "a")]) == 2
    assert "既に存在" in capsys.readouterr().err


def test_adapter_keeps_missing_optional_field_distinct_from_null():
    _, docs = documents()
    telemetry = {item["event_id"]: item for item in docs["observation_fixture"]["internal_telemetry"]}
    adapter = T0ObservationAdapter(run_id="t2-synthetic-context-hunting-v1", tenant_id="tenant-a",
                                   scenario_id="adapter-optional-field")
    missing = adapter.adapt(telemetry["hunt-event-tel-005"], current_step=8)
    explicit_null = adapter.adapt(telemetry["hunt-event-tel-002"], current_step=8)
    assert "auth_result" not in missing.attributes          # ログ欠損 → not_evaluable
    assert explicit_null.attributes["auth_result"] is None  # 該当なし → 評価可能
    assert explicit_null.attributes["process_name"] == "remote_tool.exe"
