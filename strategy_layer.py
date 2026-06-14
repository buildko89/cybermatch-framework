"""Strategy layer inference for CyberMatch Phase9.5.

The strategy layer sits between mission and behavior. It is inferred from
existing CyberMatch histories and feature rows only; it does not add attackers,
defenders, learning, APIs, or simulation logic.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence

import numpy as np

from feature_space import FeatureSpaceAnalyzer


STRATEGY_CLASSES = (
    "credential_hunter",
    "critical_asset_hunter",
    "persistence_builder",
    "trust_collapse",
    "disruption_campaign",
    "resource_exhaustion",
    "identity_mapper",
    "trust_abuser",
    "permission_escalator",
    "secret_hunter",
    "api_abuser",
    "process_manipulator",
    "controller_hunter",
    "availability_attacker",
    "research_explorer",
    "backup_destroyer",
)

TARGET_STRATEGY_CANDIDATES = {
    "identity_infrastructure": ("credential_hunter", "identity_mapper", "trust_abuser"),
    "cloud_control_plane": ("permission_escalator", "secret_hunter", "api_abuser"),
    "research_system": ("research_explorer", "credential_hunter"),
    "backup_system": ("backup_destroyer", "resource_exhaustion"),
    "industrial_control_system": ("process_manipulator", "controller_hunter", "availability_attacker"),
    "trust_relationship": ("trust_abuser", "persistence_builder"),
    "critical_database": ("critical_asset_hunter", "secret_hunter", "credential_hunter"),
    "business_application": ("resource_exhaustion", "availability_attacker", "credential_hunter"),
}

STRATEGY_FEATURES = (
    "critical_progress",
    "critical_focus",
    "stealth_activity",
    "trust_collapse_activity",
    "utility_activity",
    "objective_activity",
    "deception_activity",
    "adaptation_activity",
    "campaign_disruption_activity",
    "lateral_movement_activity",
    "survival_activity",
    "planned_critical_activity",
)


@dataclass(frozen=True)
class StrategyInferenceResult:
    strategy_type: str
    strategy_confidence: float
    strategy_entropy: float
    strategy_scores: Dict[str, float]
    features: Dict[str, float]


class StrategyInferenceEngine:
    """Infer attacker strategy from already-observed CyberMatch behavior."""

    strategies = STRATEGY_CLASSES
    feature_names = STRATEGY_FEATURES

    def __init__(self) -> None:
        self.feature_analyzer = FeatureSpaceAnalyzer()

    def infer(self, observed: Mapping[str, object], target: object = None) -> StrategyInferenceResult:
        features = self.extract_features(observed)
        raw_scores = {
            "credential_hunter": (
                0.36 * features["trust_collapse_activity"]
                + 0.24 * features["lateral_movement_activity"]
                + 0.18 * features["stealth_activity"]
                + 0.14 * features["utility_activity"]
                + 0.08 * features["deception_activity"]
            ),
            "critical_asset_hunter": (
                0.34 * features["critical_progress"]
                + 0.28 * features["critical_focus"]
                + 0.18 * features["planned_critical_activity"]
                + 0.14 * features["objective_activity"]
                + 0.06 * features["lateral_movement_activity"]
            ),
            "persistence_builder": (
                0.32 * features["survival_activity"]
                + 0.24 * features["stealth_activity"]
                + 0.20 * features["adaptation_activity"]
                + 0.14 * features["lateral_movement_activity"]
                + 0.10 * features["deception_activity"]
            ),
            "trust_collapse": (
                0.42 * features["trust_collapse_activity"]
                + 0.24 * features["deception_activity"]
                + 0.16 * features["stealth_activity"]
                + 0.10 * features["adaptation_activity"]
                + 0.08 * features["lateral_movement_activity"]
            ),
            "disruption_campaign": (
                0.36 * features["campaign_disruption_activity"]
                + 0.26 * features["deception_activity"]
                + 0.16 * features["objective_activity"]
                + 0.12 * features["adaptation_activity"]
                + 0.10 * features["trust_collapse_activity"]
            ),
            "resource_exhaustion": (
                0.30 * features["utility_activity"]
                + 0.22 * features["adaptation_activity"]
                + 0.18 * features["lateral_movement_activity"]
                + 0.16 * features["deception_activity"]
                + 0.14 * (1.0 - features["critical_focus"])
            ),
            "identity_mapper": (
                0.30 * features["lateral_movement_activity"]
                + 0.26 * features["trust_collapse_activity"]
                + 0.18 * features["stealth_activity"]
                + 0.16 * features["adaptation_activity"]
                + 0.10 * features["utility_activity"]
            ),
            "trust_abuser": (
                0.38 * features["trust_collapse_activity"]
                + 0.24 * features["deception_activity"]
                + 0.18 * features["stealth_activity"]
                + 0.12 * features["survival_activity"]
                + 0.08 * features["lateral_movement_activity"]
            ),
            "permission_escalator": (
                0.28 * features["adaptation_activity"]
                + 0.24 * features["lateral_movement_activity"]
                + 0.20 * features["objective_activity"]
                + 0.16 * features["critical_focus"]
                + 0.12 * features["stealth_activity"]
            ),
            "secret_hunter": (
                0.30 * features["utility_activity"]
                + 0.24 * features["stealth_activity"]
                + 0.18 * features["objective_activity"]
                + 0.16 * features["lateral_movement_activity"]
                + 0.12 * features["trust_collapse_activity"]
            ),
            "api_abuser": (
                0.28 * features["adaptation_activity"]
                + 0.22 * features["utility_activity"]
                + 0.18 * features["objective_activity"]
                + 0.16 * features["deception_activity"]
                + 0.16 * features["lateral_movement_activity"]
            ),
            "process_manipulator": (
                0.32 * features["critical_progress"]
                + 0.24 * features["planned_critical_activity"]
                + 0.18 * features["objective_activity"]
                + 0.14 * features["adaptation_activity"]
                + 0.12 * features["stealth_activity"]
            ),
            "controller_hunter": (
                0.34 * features["critical_focus"]
                + 0.24 * features["critical_progress"]
                + 0.18 * features["planned_critical_activity"]
                + 0.14 * features["lateral_movement_activity"]
                + 0.10 * features["utility_activity"]
            ),
            "availability_attacker": (
                0.34 * features["campaign_disruption_activity"]
                + 0.24 * features["deception_activity"]
                + 0.18 * features["objective_activity"]
                + 0.14 * (1.0 - features["stealth_activity"])
                + 0.10 * features["adaptation_activity"]
            ),
            "research_explorer": (
                0.30 * features["stealth_activity"]
                + 0.22 * features["objective_activity"]
                + 0.18 * features["utility_activity"]
                + 0.16 * features["lateral_movement_activity"]
                + 0.14 * features["survival_activity"]
            ),
            "backup_destroyer": (
                0.34 * features["campaign_disruption_activity"]
                + 0.24 * features["deception_activity"]
                + 0.18 * features["utility_activity"]
                + 0.14 * features["adaptation_activity"]
                + 0.10 * (1.0 - features["critical_focus"])
            ),
        }
        candidates = self.strategy_candidates_for_target(target or observed.get("target") or observed.get("target_type"))
        candidate_scores = {strategy: raw_scores[strategy] for strategy in candidates}
        scores = self._softmaxish(candidate_scores)
        strategy = max(candidates, key=lambda name: (scores[name], raw_scores[name]))
        confidence = float(scores[strategy])
        entropy = self._entropy(scores.values())
        return StrategyInferenceResult(
            strategy_type=strategy,
            strategy_confidence=confidence,
            strategy_entropy=entropy,
            strategy_scores=scores,
            features=features,
        )

    def infer_history(self, history: Mapping[str, Sequence[object]]) -> Dict[str, List[object]]:
        length = self._history_length(history)
        strategy_history: List[str] = []
        confidence_history: List[float] = []
        entropy_history: List[float] = []
        for end in range(1, length + 1):
            prefix = {
                key: value[:end] if hasattr(value, "__getitem__") else value
                for key, value in history.items()
            }
            result = self.infer(prefix)
            strategy_history.append(result.strategy_type)
            confidence_history.append(result.strategy_confidence)
            entropy_history.append(result.strategy_entropy)
        return {
            "strategy_history": strategy_history,
            "strategy_confidence_history": confidence_history,
            "strategy_entropy_history": entropy_history,
        }

    def evaluate(self, observed: Mapping[str, object], expected_strategy: object = None, target: object = None) -> Dict[str, object]:
        result = self.infer(observed, target=target)
        expected = str(expected_strategy or observed.get("expected_strategy") or "")
        match = bool(expected == result.strategy_type) if expected else False
        return {
            "strategy_type": result.strategy_type,
            "strategy_confidence": result.strategy_confidence,
            "strategy_entropy": result.strategy_entropy,
            "strategy_match": match,
            "strategy_distribution": result.strategy_scores,
            "strategy_features": result.features,
        }

    def expected_strategy_for_mission(self, mission: object) -> str:
        mapping = {
            "profit": "credential_hunter",
            "achievement": "critical_asset_hunter",
            "persistence": "persistence_builder",
            "critical_hunter": "critical_asset_hunter",
        }
        return mapping.get(str(mission), "")

    def strategy_candidates_for_target(self, target: object) -> tuple[str, ...]:
        target_name = str(target or "")
        return TARGET_STRATEGY_CANDIDATES.get(target_name, self.strategies)

    def extract_features(self, observed: Mapping[str, object]) -> Dict[str, float]:
        vector = self.feature_analyzer.build_feature_vector(observed)
        return {
            feature: float(np.clip(float(vector.get(feature, 0.0)), 0.0, 1.0))
            for feature in self.feature_names
        }

    def _history_length(self, history: Mapping[str, Sequence[object]]) -> int:
        for key in ("actual_utility", "attacker_success", "observable_events", "mission_history"):
            value = history.get(key)
            if hasattr(value, "__len__"):
                return int(len(value))
        return 0

    def _softmaxish(self, raw_scores: Mapping[str, float]) -> Dict[str, float]:
        labels = list(raw_scores)
        values = np.asarray([float(raw_scores[strategy]) for strategy in labels], dtype=float)
        values = values - float(np.max(values))
        exp_values = np.exp(values * 4.0)
        probs = exp_values / max(float(np.sum(exp_values)), 1e-12)
        return {strategy: float(probs[idx]) for idx, strategy in enumerate(labels)}

    def _entropy(self, probabilities: Iterable[float]) -> float:
        values = [float(prob) for prob in probabilities if float(prob) > 0.0]
        if not values:
            return 0.0
        entropy = -sum(prob * math.log(prob) for prob in values)
        return float(np.clip(entropy / math.log(len(self.strategies)), 0.0, 1.0))
