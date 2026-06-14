import json

import pytest

from archetype_analysis import ArchetypeInterpreter
from run_scenarios import run_phase94_archetype_interpretation


pytestmark = [pytest.mark.phase94, pytest.mark.archetype]


def _sample_rows():
    return [
        {
            "row_id": "u1",
            "true_mission": "profit",
            "behavior_profile": "utility_seeking",
            "archetype": "Archetype-1",
            "utility_activity": 0.9,
            "expected_utility_activity": 0.8,
            "deception_activity": 0.1,
            "adaptation_activity": 0.2,
            "critical_focus": 0.4,
            "stealth_activity": 0.2,
            "coalition_activity": 0.1,
        },
        {
            "row_id": "u2",
            "true_mission": "achievement",
            "behavior_profile": "utility_seeking",
            "archetype": "Archetype-1",
            "utility_activity": 0.8,
            "expected_utility_activity": 0.7,
            "deception_activity": 0.1,
            "adaptation_activity": 0.3,
            "critical_focus": 0.3,
            "stealth_activity": 0.2,
            "coalition_activity": 0.1,
        },
        {
            "row_id": "d1",
            "true_mission": "persistence",
            "behavior_profile": "deceptive_adaptive",
            "archetype": "Archetype-2",
            "utility_activity": 0.3,
            "expected_utility_activity": 0.3,
            "deception_activity": 0.9,
            "adaptation_activity": 0.8,
            "critical_focus": 0.2,
            "stealth_activity": 0.7,
            "coalition_activity": 0.4,
        },
        {
            "row_id": "d2",
            "true_mission": "critical_hunter",
            "behavior_profile": "deceptive_adaptive",
            "archetype": "Archetype-2",
            "utility_activity": 0.2,
            "expected_utility_activity": 0.2,
            "deception_activity": 0.8,
            "adaptation_activity": 0.9,
            "critical_focus": 0.3,
            "stealth_activity": 0.8,
            "coalition_activity": 0.4,
        },
    ]


def test_archetype_interpreter_generates_signatures_and_metrics():
    result = ArchetypeInterpreter().analyze(_sample_rows())

    assert len(result.archetype_summary) == 2
    assert "high utility_activity" in result.archetype_signature["Archetype-1"]
    assert "high deception_activity" in result.archetype_signature["Archetype-2"]
    assert result.archetype_feature_distance["Archetype-1"]["Archetype-2"] > 0.0
    assert 0.0 <= result.archetype_mission_overlap <= 1.0
    assert 0.0 <= result.archetype_profile_overlap <= 1.0
    assert 0.0 <= result.archetype_interpretability_score <= 1.0


def test_phase94_artifacts_generated_from_existing_rows(tmp_path):
    output_dir = tmp_path / "phase94_archetype_interpretation"
    result = run_phase94_archetype_interpretation(
        output_dir=str(output_dir),
        source_rows=_sample_rows(),
    )

    assert result["summary"]
    assert (output_dir / "archetype_summary.csv").exists()
    assert (output_dir / "archetype_summary.json").exists()
    assert (output_dir / "archetype_feature_comparison.png").exists()
    assert (output_dir / "archetype_mission_distribution.png").exists()
    assert (output_dir / "archetype_profile_distribution.png").exists()
    assert (output_dir / "archetype_distance_matrix.png").exists()
    assert (output_dir / "PHASE94_ARCHETYPE_INTERPRETATION_REPORT.md").exists()

    summary = json.loads((output_dir / "archetype_summary.json").read_text(encoding="utf-8"))
    assert "archetype_signature" in summary["analysis"]
    assert "archetype_feature_distance" in summary["analysis"]
