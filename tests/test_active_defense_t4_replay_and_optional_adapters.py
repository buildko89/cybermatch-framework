import csv
import json
from pathlib import Path

import pytest

from apps.active_defense_pilot_view import render_active_defense_pilot_view
from cybermatch.contracts import load_evidence_bundle, sha256_file
from cybermatch.threat_hunting.active_defense import (
    AttackerConsequenceAdapter, ObservableDefenderConsequence, TokenizedReplayAdapter,
    TokenizedReplayRunner, build_hypothesis_pilot_view, load_tokenized_replay_inputs,
    run_hypothesis_pilot_shadow, write_tokenized_replay_outputs,
)
from cybermatch.threat_hunting.active_defense.stateful_mock_world import OperationOutcome


ROOT = Path(__file__).resolve().parents[1]
SPEC = "configs/active_defense/runs/t4a_tokenized_replay_v1.json"


@pytest.fixture
def t4a_output(tmp_path):
    inputs = load_tokenized_replay_inputs(ROOT, SPEC)
    result = TokenizedReplayRunner(inputs).run()
    output = tmp_path / "t4a-pilot-input"
    write_tokenized_replay_outputs(result=result, inputs=inputs, output_dir=output, repository_root=ROOT)
    return output


def test_t4a_tokenized_replay_is_read_only_and_detection_compatibility_only(tmp_path):
    source = ROOT / "configs/active_defense/replay/t4a_tokenized_snapshot_v1.jsonl"
    before = sha256_file(source)
    inputs = load_tokenized_replay_inputs(ROOT, SPEC)
    result = TokenizedReplayRunner(inputs).run()
    assert sha256_file(source) == before
    assert inputs.quality.passed
    assert result.to_dict()["claim_scope"] == "detection_compatibility_only"
    assert result.hunting.metrics()["finding_count"] == 1
    output = tmp_path / "t4a"
    summary = write_tokenized_replay_outputs(
        result=result, inputs=inputs, output_dir=output, repository_root=ROOT)
    assert summary["evidence_class"] == "replay-backed"
    assert load_evidence_bundle(output).bundle_hash == summary["bundle_hash"]
    report = (output / "report.md").read_text(encoding="utf-8")
    assert "検知適合性のみ" in report and "対処効果" in report


def test_t4a_data_quality_explicitly_reports_unsupported_field(tmp_path):
    source = tmp_path / "snapshot.jsonl"
    source.write_text(json.dumps({"record_type": "cti_observation", "payload": {},
                                  "unsupported_vendor_blob": "x"}) + "\n", encoding="utf-8")
    adapter = TokenizedReplayAdapter(
        tenant_id="tenant-a", run_id="run-a", normalization_version="v1",
        identity_key_version="kv1", retention_days=30, source_refs=("source-a",))
    snapshot = adapter.load(source, input_format="jsonl")
    assert not snapshot.quality.passed
    assert snapshot.quality.unsupported_fields == ("record[0].unsupported_vendor_blob",)
    assert snapshot.quality.rejected_record_count > 0


def test_t4a_requires_retention_setting():
    with pytest.raises(ValueError, match="retention_days"):
        TokenizedReplayAdapter(tenant_id="tenant-a", run_id="run-a", normalization_version="v1",
                               identity_key_version="kv1", retention_days=0, source_refs=("source-a",))


def test_t4a_csv_wrapper_is_supported(tmp_path):
    first = json.loads((ROOT / "configs/active_defense/replay/t4a_tokenized_snapshot_v1.jsonl")
                       .read_text(encoding="utf-8").splitlines()[0])
    source = tmp_path / "snapshot.csv"
    with source.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["record_type", "payload_json"])
        writer.writeheader()
        writer.writerow({"record_type": first["record_type"],
                         "payload_json": json.dumps(first["payload"], ensure_ascii=False)})
    adapter = TokenizedReplayAdapter(
        tenant_id="tenant-replay-a", run_id="t4a-tokenized-replay-v1", normalization_version="v1",
        identity_key_version="kv1", retention_days=30, source_refs=("source-a",))
    snapshot = adapter.load(source, input_format="csv")
    assert snapshot.quality.passed and len(snapshot.cti_observations) == 1


class _Observer:
    def __init__(self):
        self.received = None

    def observe_defender_consequence(self, **kwargs):
        self.received = kwargs


def test_t4b_attacker_adapter_exposes_only_observable_consequences():
    outcome = OperationOutcome("op-1", 3, "campaign-a", "identity-a", "authenticate",
                               "blocked", "identity_revoked", False)
    adapter = AttackerConsequenceAdapter(confidence_decay=0.8, frustration_increase=2.0)
    consequence = adapter.from_operation_outcome(outcome)
    observer = _Observer()
    adapter.notify(observer, consequence)
    assert consequence == ObservableDefenderConsequence(True, False, False, False)
    assert set(observer.received) == {"blocked", "delayed", "detected", "redirected",
                                     "confidence_decay", "frustration_increase"}
    serialized = json.dumps(observer.received)
    assert "finding" not in serialized and "cti" not in serialized and "score" not in serialized


class _InvalidGateway:
    provider_id = "invalid-test"
    model_id = "invalid-v1"

    def select(self, view):
        return {"selected_hypothesis_ids": ["not-allowlisted"]}


class _FailingGateway:
    provider_id = "failure-test"
    model_id = "failure-v1"

    def select(self, view):
        raise RuntimeError("provider unavailable")


def test_t4b_pilot_is_shadow_allowlisted_and_failures_abstain(t4a_output):
    view = build_hypothesis_pilot_view(t4a_output)
    accepted = run_hypothesis_pilot_shadow(view)
    assert accepted["status"] == "accepted_shadow"
    assert accepted["execution_authorized"] is False
    assert accepted["proposal"]["selected_hypothesis_ids"][0] in {
        item["hypothesis_id"] for item in view["candidates"]}
    for gateway in (_InvalidGateway(), _FailingGateway()):
        abstained = run_hypothesis_pilot_shadow(view, gateway)
        assert abstained["status"] == "abstained"
        assert abstained["proposal"]["abstain"] is True
        assert abstained["proposal"]["selected_hypothesis_ids"] == []


class _FakeUi:
    def __init__(self):
        self.values = []
    def subheader(self, value): self.values.append(("subheader", value))
    def caption(self, value): self.values.append(("caption", value))
    def metric(self, name, value): self.values.append(("metric", name, value))
    def json(self, value): self.values.append(("json", value))
    def warning(self, value): self.values.append(("warning", value))


def test_t4b_cli_and_ui_use_the_same_sanitized_view(t4a_output):
    view = build_hypothesis_pilot_view(t4a_output)
    shadow = run_hypothesis_pilot_shadow(view)
    ui = _FakeUi()
    render_active_defense_pilot_view(ui, view, shadow)
    rendered = next(item[1] for item in ui.values if item[0] == "json")
    assert rendered["proposal"] == shadow["proposal"]
    assert rendered["execution_authorized"] is False
