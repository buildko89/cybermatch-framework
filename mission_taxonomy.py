"""Mission, target, and intent taxonomy for CyberMatch Phase9.6.

This module is taxonomy and analysis only. It reorganizes existing CyberMatch
mission labels into an Intent -> Mission -> Target -> Strategy hierarchy without
changing simulation logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence

import numpy as np


INTENT_CLASSES = (
    "financial_gain",
    "espionage",
    "disruption",
    "destruction",
    "control",
    "long_term_presence",
)

MISSION_LAYER_CLASSES = (
    "ransomware_operation",
    "credential_theft",
    "data_exfiltration",
    "service_disruption",
    "infrastructure_takeover",
    "long_term_persistence",
    "supply_chain_compromise",
)

TARGET_CLASSES = (
    "identity_infrastructure",
    "critical_database",
    "business_application",
    "cloud_control_plane",
    "backup_system",
    "research_system",
    "industrial_control_system",
    "trust_relationship",
)


EXISTING_MISSION_TAXONOMY = {
    "profit": {
        "intent": ["financial_gain"],
        "mission": ["credential_theft", "ransomware_operation"],
        "target": ["identity_infrastructure", "backup_system", "business_application"],
    },
    "achievement": {
        "intent": ["espionage", "control"],
        "mission": ["data_exfiltration", "infrastructure_takeover"],
        "target": ["critical_database", "research_system", "business_application"],
    },
    "persistence": {
        "intent": ["long_term_presence", "control"],
        "mission": ["long_term_persistence", "supply_chain_compromise"],
        "target": ["trust_relationship", "cloud_control_plane", "identity_infrastructure"],
    },
    "critical_hunter": {
        "intent": ["destruction", "control"],
        "mission": ["infrastructure_takeover", "service_disruption"],
        "target": ["industrial_control_system", "critical_database", "cloud_control_plane"],
    },
}

MISSION_TARGET_MAP = {
    "ransomware_operation": ["backup_system", "business_application", "identity_infrastructure"],
    "credential_theft": ["identity_infrastructure", "trust_relationship"],
    "data_exfiltration": ["critical_database", "research_system"],
    "service_disruption": ["business_application", "industrial_control_system", "cloud_control_plane"],
    "infrastructure_takeover": ["cloud_control_plane", "industrial_control_system", "critical_database"],
    "long_term_persistence": ["trust_relationship", "identity_infrastructure", "cloud_control_plane"],
    "supply_chain_compromise": ["trust_relationship", "business_application", "cloud_control_plane"],
}

TARGET_STRATEGY_MAP = {
    "identity_infrastructure": ["credential_hunter", "identity_mapper", "trust_abuser"],
    "critical_database": ["critical_asset_hunter", "secret_hunter", "credential_hunter"],
    "business_application": ["resource_exhaustion", "availability_attacker", "credential_hunter"],
    "cloud_control_plane": ["permission_escalator", "secret_hunter", "api_abuser"],
    "backup_system": ["backup_destroyer", "resource_exhaustion"],
    "research_system": ["research_explorer", "credential_hunter"],
    "industrial_control_system": ["process_manipulator", "controller_hunter", "availability_attacker"],
    "trust_relationship": ["trust_abuser", "persistence_builder"],
}

MISSION_DEFAULT_TARGET = {
    "profit": "identity_infrastructure",
    "achievement": "research_system",
    "persistence": "trust_relationship",
    "critical_hunter": "industrial_control_system",
}


@dataclass(frozen=True)
class TaxonomyResult:
    rows: List[Dict[str, object]]
    intent_mission_matrix: Dict[str, Dict[str, int]]
    mission_target_matrix: Dict[str, Dict[str, int]]
    target_strategy_matrix: Dict[str, Dict[str, int]]
    metrics: Dict[str, object]


class MissionTaxonomyAnalyzer:
    """Analyze the CyberMatch attacker decision taxonomy."""

    intents = INTENT_CLASSES
    missions = MISSION_LAYER_CLASSES
    targets = TARGET_CLASSES

    def analyze(self, rows: Sequence[Mapping[str, object]] | None = None) -> TaxonomyResult:
        taxonomy_rows = self.expand_rows(rows or [])
        intent_mission = self.matrix(taxonomy_rows, "intent", "mission")
        mission_target = self.matrix(taxonomy_rows, "mission", "target")
        target_strategy = self.matrix(taxonomy_rows, "target", "strategy")
        metrics = {
            "intent_count": len(INTENT_CLASSES),
            "mission_count": len(MISSION_LAYER_CLASSES),
            "target_count": len(TARGET_CLASSES),
            "taxonomy_completeness": self.completeness(taxonomy_rows),
            "mission_target_overlap": self.overlap(mission_target),
            "target_strategy_overlap": self.overlap(target_strategy),
        }
        return TaxonomyResult(taxonomy_rows, intent_mission, mission_target, target_strategy, metrics)

    def expand_rows(self, rows: Sequence[Mapping[str, object]]) -> List[Dict[str, object]]:
        source_missions = sorted(EXISTING_MISSION_TAXONOMY) if not rows else [
            str(row.get("true_mission") or row.get("attacker_mission") or "")
            for row in rows
        ]
        expanded: List[Dict[str, object]] = []
        for index, source_mission in enumerate(source_missions):
            mapping = EXISTING_MISSION_TAXONOMY.get(source_mission)
            if not mapping:
                continue
            observed_strategy = ""
            if rows and index < len(rows):
                observed_strategy = str(rows[index].get("strategy_type") or "")
            for intent in mapping["intent"]:
                for mission in mapping["mission"]:
                    for target in MISSION_TARGET_MAP.get(mission, mapping["target"]):
                        strategies = TARGET_STRATEGY_MAP.get(target, [])
                        strategy_values = [observed_strategy] if observed_strategy else strategies
                        for strategy in strategy_values:
                            if not strategy:
                                continue
                            expanded.append(
                                {
                                    "existing_mission": source_mission,
                                    "intent": intent,
                                    "mission": mission,
                                    "target": target,
                                    "strategy": strategy,
                                }
                            )
        return expanded

    def matrix(self, rows: Sequence[Mapping[str, object]], row_key: str, column_key: str) -> Dict[str, Dict[str, int]]:
        matrix: Dict[str, Dict[str, int]] = {}
        for row in rows:
            row_label = str(row.get(row_key) or "")
            column_label = str(row.get(column_key) or "")
            if not row_label or not column_label:
                continue
            matrix.setdefault(row_label, {})
            matrix[row_label][column_label] = matrix[row_label].get(column_label, 0) + 1
        return {row: dict(sorted(values.items())) for row, values in sorted(matrix.items())}

    def completeness(self, rows: Sequence[Mapping[str, object]]) -> float:
        if not rows:
            return 0.0
        covered_intents = {str(row.get("intent")) for row in rows if row.get("intent")}
        covered_missions = {str(row.get("mission")) for row in rows if row.get("mission")}
        covered_targets = {str(row.get("target")) for row in rows if row.get("target")}
        scores = [
            len(covered_intents) / len(INTENT_CLASSES),
            len(covered_missions) / len(MISSION_LAYER_CLASSES),
            len(covered_targets) / len(TARGET_CLASSES),
        ]
        return float(np.clip(np.mean(scores), 0.0, 1.0))

    def overlap(self, matrix: Mapping[str, Mapping[str, int]]) -> float:
        labels = sorted(matrix)
        if len(labels) < 2:
            return 0.0
        overlaps: List[float] = []
        for idx, left in enumerate(labels):
            left_counts = matrix[left]
            left_total = sum(int(value) for value in left_counts.values())
            for right in labels[idx + 1 :]:
                right_counts = matrix[right]
                right_total = sum(int(value) for value in right_counts.values())
                if left_total <= 0 or right_total <= 0:
                    overlaps.append(0.0)
                    continue
                columns = set(left_counts) | set(right_counts)
                overlaps.append(
                    sum(
                        min(
                            int(left_counts.get(column, 0)) / left_total,
                            int(right_counts.get(column, 0)) / right_total,
                        )
                        for column in columns
                    )
                )
        return float(np.clip(np.mean(overlaps), 0.0, 1.0)) if overlaps else 0.0

    def infer_target(self, observed: Mapping[str, object]) -> str:
        explicit = str(observed.get("target") or observed.get("target_type") or "")
        if explicit in TARGET_CLASSES:
            return explicit
        mission = str(observed.get("true_mission") or observed.get("attacker_mission") or "")
        if not mission:
            history = observed.get("mission_history") or observed.get("true_mission_history")
            if isinstance(history, np.ndarray) and history.size > 0:
                mission = str(history.reshape(-1)[-1])
            elif isinstance(history, (list, tuple)) and history:
                mission = str(history[-1])
            elif isinstance(history, str):
                mission = history
        return MISSION_DEFAULT_TARGET.get(mission, "")

    def infer_target_history(self, history: Mapping[str, Sequence[object]]) -> Dict[str, List[str]]:
        length = self._history_length(history)
        targets: List[str] = []
        for end in range(1, length + 1):
            prefix = {
                key: value[:end] if hasattr(value, "__getitem__") else value
                for key, value in history.items()
            }
            targets.append(self.infer_target(prefix))
        return {"target_history": targets}

    def _history_length(self, history: Mapping[str, Sequence[object]]) -> int:
        for key in ("actual_utility", "attacker_success", "observable_events", "mission_history"):
            value = history.get(key)
            if hasattr(value, "__len__"):
                return int(len(value))
        return 0
