"""Decision graph analysis for CyberMatch Phase9.9.

The graph integrates existing Intent, Mission, Target, Strategy, Behavior
Profile, and Archetype labels into an analysis-only attacker decision model.
It does not change simulation behavior or introduce new attackers, defenders,
learning, APIs, ProfileCore changes, or benchmark changes.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

import numpy as np

from behavior_profile import BehaviorProfileEngine
from mission_taxonomy import EXISTING_MISSION_TAXONOMY, MISSION_DEFAULT_TARGET, MISSION_TARGET_MAP, TARGET_STRATEGY_MAP


GRAPH_LAYERS = ("intent", "mission", "target", "strategy", "behavior_profile", "archetype")
GRAPH_EDGE_LAYERS = (
    ("intent", "mission"),
    ("mission", "target"),
    ("target", "strategy"),
    ("strategy", "behavior_profile"),
    ("behavior_profile", "archetype"),
)


@dataclass(frozen=True)
class DecisionGraph:
    nodes: Dict[str, List[str]]
    edges: Dict[str, Dict[str, int]]
    paths: List[Dict[str, str]]
    metrics: Dict[str, object]

    def explain_decision_path(self, path: Mapping[str, str]) -> str:
        intent = path.get("intent", "unknown_intent")
        mission = path.get("mission", "unknown_mission")
        target = path.get("target", "unknown_target")
        strategy = path.get("strategy", "unknown_strategy")
        behavior = path.get("behavior_profile", "unknown_behavior")
        archetype = path.get("archetype", "unknown_archetype")
        return (
            f"{intent} intent resulted in {mission} mission, targeting {target}, "
            f"using {strategy} strategy, producing {behavior} behavior and {archetype} archetype."
        )


class DecisionGraphBuilder:
    """Build an analysis-only decision graph from existing CyberMatch rows."""

    def __init__(self) -> None:
        self.behavior_engine = BehaviorProfileEngine()

    def build(self, rows: Sequence[Mapping[str, object]]) -> DecisionGraph:
        paths = self.enumerate_paths(rows)
        nodes = self._nodes(paths)
        edges = self._edges(paths)
        metrics = self._metrics(nodes, edges, paths)
        return DecisionGraph(nodes=nodes, edges=edges, paths=paths, metrics=metrics)

    def enumerate_paths(self, rows: Sequence[Mapping[str, object]]) -> List[Dict[str, str]]:
        paths: List[Dict[str, str]] = []
        seen: set[Tuple[str, str, str, str, str, str]] = set()
        for row in rows:
            path = self._path_from_row(row)
            key = tuple(path[layer] for layer in GRAPH_LAYERS)
            if key in seen:
                continue
            seen.add(key)
            paths.append(path)
        return sorted(paths, key=lambda path: tuple(path[layer] for layer in GRAPH_LAYERS))

    def edge_matrix(self, graph: DecisionGraph, from_layer: str, to_layer: str) -> Dict[str, Dict[str, int]]:
        prefix = f"{from_layer}->{to_layer}:"
        matrix: Dict[str, Dict[str, int]] = {}
        for edge_key, targets in graph.edges.items():
            if not edge_key.startswith(prefix):
                continue
            source = edge_key[len(prefix) :]
            matrix[source] = dict(sorted(targets.items()))
        return dict(sorted(matrix.items()))

    def _path_from_row(self, row: Mapping[str, object]) -> Dict[str, str]:
        existing_mission = str(row.get("existing_mission") or row.get("true_mission") or row.get("attacker_mission") or "")
        mission = str(row.get("mission") or "")
        taxonomy = EXISTING_MISSION_TAXONOMY.get(existing_mission, {})
        intent = str(row.get("intent") or "")
        if not intent and taxonomy:
            intent = str(taxonomy.get("intent", ["unknown_intent"])[0])
        if not mission:
            mission = str(taxonomy.get("mission", [existing_mission or "unknown_mission"])[0])
        target = str(row.get("target") or row.get("target_type") or "")
        if not target:
            target = MISSION_DEFAULT_TARGET.get(existing_mission, "")
        if not target:
            target = str(MISSION_TARGET_MAP.get(mission, ["unknown_target"])[0])
        strategy = str(row.get("strategy_type") or row.get("strategy") or "")
        if not strategy:
            strategy = str(TARGET_STRATEGY_MAP.get(target, ["unknown_strategy"])[0])
        behavior = str(row.get("behavior_profile") or "")
        if not behavior:
            behavior = self.behavior_engine.infer(row).behavior_profile
        archetype = str(row.get("archetype") or "")
        if not archetype:
            archetype = "archetype_unobserved"
        return {
            "intent": intent or "unknown_intent",
            "mission": mission or "unknown_mission",
            "target": target or "unknown_target",
            "strategy": strategy or "unknown_strategy",
            "behavior_profile": behavior or "unknown_behavior",
            "archetype": archetype,
        }

    def _nodes(self, paths: Sequence[Mapping[str, str]]) -> Dict[str, List[str]]:
        return {
            layer: sorted({str(path.get(layer)) for path in paths if path.get(layer)})
            for layer in GRAPH_LAYERS
        }

    def _edges(self, paths: Sequence[Mapping[str, str]]) -> Dict[str, Dict[str, int]]:
        edges: Dict[str, Dict[str, int]] = {}
        for path in paths:
            for source_layer, target_layer in GRAPH_EDGE_LAYERS:
                source = str(path.get(source_layer) or "")
                target = str(path.get(target_layer) or "")
                if not source or not target:
                    continue
                key = f"{source_layer}->{target_layer}:{source}"
                edges.setdefault(key, {})
                edges[key][target] = edges[key].get(target, 0) + 1
        return {source: dict(sorted(targets.items())) for source, targets in sorted(edges.items())}

    def _metrics(
        self,
        nodes: Mapping[str, Sequence[str]],
        edges: Mapping[str, Mapping[str, int]],
        paths: Sequence[Mapping[str, str]],
    ) -> Dict[str, object]:
        node_count = sum(len(values) for values in nodes.values())
        edge_count = sum(len(values) for values in edges.values())
        possible_edges = sum(
            max(len(nodes.get(left, [])) * len(nodes.get(right, [])), 1)
            for left, right in GRAPH_EDGE_LAYERS
        )
        density = edge_count / possible_edges if possible_edges > 0 else 0.0
        connectivity = self._connectivity(nodes, edges)
        consistency = self._consistency(edges)
        entropy = self._graph_entropy(edges)
        explainability = float(np.clip(np.mean([connectivity, consistency, 1.0 - entropy]) if paths else 0.0, 0.0, 1.0))
        return {
            "graph_valid": bool(paths and connectivity > 0.0),
            "decision_graph_nodes": int(node_count),
            "decision_graph_edges": int(edge_count),
            "decision_graph_density": float(np.clip(density, 0.0, 1.0)),
            "decision_graph_connectivity": connectivity,
            "decision_graph_consistency": consistency,
            "decision_graph_entropy": entropy,
            "decision_path_count": len(paths),
            "path_count": len(paths),
            "graph_connectivity": connectivity,
            "graph_consistency": consistency,
            "decision_explainability": explainability,
        }

    def _connectivity(self, nodes: Mapping[str, Sequence[str]], edges: Mapping[str, Mapping[str, int]]) -> float:
        if not nodes:
            return 0.0
        connected = 0
        total = 0
        for layer in GRAPH_LAYERS:
            for node in nodes.get(layer, []):
                total += 1
                outgoing = any(edge_key.endswith(f":{node}") and targets for edge_key, targets in edges.items())
                incoming = any(node in targets for targets in edges.values())
                if outgoing or incoming:
                    connected += 1
        return float(np.clip(connected / max(total, 1), 0.0, 1.0))

    def _consistency(self, edges: Mapping[str, Mapping[str, int]]) -> float:
        scores: List[float] = []
        for targets in edges.values():
            total = sum(int(value) for value in targets.values())
            if total <= 0:
                continue
            scores.append(max(int(value) for value in targets.values()) / total)
        return float(np.clip(np.mean(scores) if scores else 0.0, 0.0, 1.0))

    def _graph_entropy(self, edges: Mapping[str, Mapping[str, int]]) -> float:
        values = [value for targets in edges.values() for value in targets.values()]
        return self._entropy(values)

    def _entropy(self, counts: Iterable[int]) -> float:
        values = np.asarray([float(value) for value in counts if float(value) > 0.0], dtype=float)
        total = float(np.sum(values))
        if total <= 0.0 or values.size <= 1:
            return 0.0
        probabilities = values / total
        return float(np.clip(-np.sum(probabilities * np.log(probabilities)) / math.log(values.size), 0.0, 1.0))
