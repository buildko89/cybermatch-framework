import json

import pytest

from decision_graph import DecisionGraphBuilder
from run_scenarios import run_phase99_decision_graph_evaluation


pytestmark = [pytest.mark.phase99, pytest.mark.decision_graph]


def _sample_rows():
    return [
        {
            "intent": "financial_gain",
            "mission": "credential_theft",
            "target": "identity_infrastructure",
            "strategy_type": "credential_hunter",
            "behavior_profile": "utility_seeking",
            "archetype": "Archetype-1",
        },
        {
            "intent": "espionage",
            "mission": "data_exfiltration",
            "target": "research_system",
            "strategy_type": "research_explorer",
            "behavior_profile": "stealth_seeking",
            "archetype": "Archetype-2",
        },
        {
            "intent": "destruction",
            "mission": "service_disruption",
            "target": "industrial_control_system",
            "strategy_type": "process_manipulator",
            "behavior_profile": "critical_path_seeking",
            "archetype": "Archetype-2",
        },
    ]


def test_decision_graph_generation():
    graph = DecisionGraphBuilder().build(_sample_rows())

    assert graph.metrics["graph_valid"] is True
    assert graph.metrics["decision_graph_nodes"] >= 12
    assert graph.metrics["decision_graph_edges"] >= 10
    assert graph.metrics["decision_path_count"] == 3


def test_decision_path_generation_and_explainability():
    graph = DecisionGraphBuilder().build(_sample_rows())
    explanation = graph.explain_decision_path(graph.paths[0])

    assert "intent resulted in" in explanation
    assert "using" in explanation
    assert graph.paths[0]["strategy"]


def test_decision_graph_edge_matrix():
    builder = DecisionGraphBuilder()
    graph = builder.build(_sample_rows())
    matrix = builder.edge_matrix(graph, "target", "strategy")

    assert matrix["identity_infrastructure"]["credential_hunter"] == 1
    assert matrix["research_system"]["research_explorer"] == 1


def test_phase99_artifacts_generated(tmp_path):
    output_dir = tmp_path / "phase99_decision_graph"
    result = run_phase99_decision_graph_evaluation(
        output_dir=str(output_dir),
        source_rows=_sample_rows(),
    )

    assert result["analysis"]["graph_valid"] is True
    assert (output_dir / "decision_graph.png").exists()
    assert (output_dir / "intent_mission_graph.png").exists()
    assert (output_dir / "mission_target_graph.png").exists()
    assert (output_dir / "target_strategy_graph.png").exists()
    assert (output_dir / "strategy_behavior_graph.png").exists()
    assert (output_dir / "decision_graph_summary.csv").exists()
    assert (output_dir / "decision_graph_summary.json").exists()
    assert (output_dir / "PHASE99_DECISION_GRAPH_REPORT.md").exists()

    summary = json.loads((output_dir / "decision_graph_summary.json").read_text(encoding="utf-8"))
    assert "nodes" in summary
    assert "explanations" in summary
