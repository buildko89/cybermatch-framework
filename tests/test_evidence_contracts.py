import json

import pytest

from cybermatch_core.contracts import (
    ContractValidationError,
    EvaluationRun,
    EvidenceArtifact,
    EvidenceBundle,
    MetricSet,
    RunManifest,
    canonical_json,
)


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def _run() -> EvaluationRun:
    return EvaluationRun(
        manifest=RunManifest(
            run_id="run-001",
            runner="agentic_security_evaluation",
            scenario_id="hybrid_ransom_swarm",
            seed=0,
            framework_version="1.0.1",
            code_revision="bb65f59",
            dependency_lock_sha256=DIGEST_A,
            input_hashes={"scenario": DIGEST_B},
            created_at="2026-09-13T00:00:00Z",
        ),
        metrics=MetricSet({"risk_score": 0.42, "prevented": 3, "valid": True}),
        artifacts=(
            EvidenceArtifact(
                path="reports/summary.json",
                sha256=DIGEST_A,
                size_bytes=123,
                role="summary",
                media_type="application/json",
            ),
        ),
    )


def test_evidence_bundle_round_trip_is_deterministic_and_hash_verified():
    first = EvidenceBundle(_run())
    second = EvidenceBundle.from_dict(json.loads(canonical_json(first.to_dict())))

    assert second == first
    assert second.bundle_hash == first.bundle_hash
    assert second.run.manifest.manifest_hash == first.run.manifest.manifest_hash


def test_evidence_bundle_detects_tampering():
    payload = EvidenceBundle(_run()).to_dict()
    payload["run"]["metrics"]["values"]["risk_score"] = 0.99

    with pytest.raises(ContractValidationError, match="bundle_hash verification failed"):
        EvidenceBundle.from_dict(payload)


def test_contract_rejects_nonportable_artifacts_and_nonfinite_metrics():
    with pytest.raises(ContractValidationError, match="relative path"):
        EvidenceArtifact("../escape.json", DIGEST_A, 1, "summary", "application/json")
    with pytest.raises(ContractValidationError, match="finite"):
        MetricSet({"risk": float("nan")})


def test_manifest_rejects_unknown_fields():
    payload = _run().manifest.to_dict()
    payload["unexpected"] = True

    with pytest.raises(ContractValidationError, match="unknown"):
        RunManifest.from_dict(payload)
