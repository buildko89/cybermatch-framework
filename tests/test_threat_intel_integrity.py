import pytest

from cybermatch_core.agentic_security import (
    IntegrityGateConfig,
    ThreatIntelAdvisory,
    ThreatIntelIntegrityGate,
    evaluate_integrity_outcomes,
)


pytestmark = pytest.mark.agentic_security


def _advisory(advisory_id: str, **overrides) -> ThreatIntelAdvisory:
    payload = {
        "advisory_id": advisory_id,
        "source_identity": "maintainer",
        "source_trust": 0.95,
        "vendor_corroboration": True,
        "affected_version_consistency": True,
        "code_reference_validity": True,
        "fix_commit_present": True,
        "poc_present": True,
        "poc_reproduced": True,
        "independent_source_count": 2,
        "status": "confirmed",
    }
    payload.update(overrides)
    return ThreatIntelAdvisory(**payload)


def test_integrity_gate_accepts_corroborated_and_rejects_fabricated_advisory():
    gate = ThreatIntelIntegrityGate()
    valid = gate.evaluate(_advisory("VALID"))
    fabricated = gate.evaluate(
        _advisory(
            "FAKE",
            source_identity="anonymous",
            source_trust=0.1,
            vendor_corroboration=False,
            affected_version_consistency=False,
            code_reference_validity=False,
            fix_commit_present=False,
            poc_reproduced=False,
            independent_source_count=0,
            status="rejected",
        )
    )

    assert valid.decision == "accept"
    assert fabricated.decision == "reject"
    assert fabricated.evidence_score < valid.evidence_score
    metrics = evaluate_integrity_outcomes(
        [valid, fabricated],
        [
            {"advisory_id": "VALID", "ground_truth": "valid", "first_seen_step": 1},
            {
                "advisory_id": "FAKE",
                "ground_truth": "fabricated",
                "first_seen_step": 0,
                "corrected_step": 12,
            },
        ],
    )
    assert metrics["fabricated_advisory_acceptance_rate"] == 0.0
    assert metrics["valid_advisory_acceptance_rate"] == 1.0
    assert metrics["mean_correction_latency_steps"] == 12


def test_integrity_gate_quarantines_incomplete_but_plausible_evidence():
    gate = ThreatIntelIntegrityGate(IntegrityGateConfig(accept_threshold=0.75, quarantine_threshold=0.4))
    decision = gate.evaluate(
        _advisory(
            "AMBIGUOUS",
            source_trust=0.7,
            vendor_corroboration=False,
            fix_commit_present=False,
            poc_reproduced=False,
            independent_source_count=1,
            status="published",
        )
    )

    assert decision.decision == "quarantine"
