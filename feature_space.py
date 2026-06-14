"""Feature space analysis for CyberMatch Phase9.2.

This module analyzes existing CyberMatch behavior features before introducing
PCA or ProfileCore integration. It does not change simulation logic.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence

import numpy as np

from behavior_profile import BehaviorProfileEngine
from intent_inference import MissionInferenceEngine


FEATURE_NAMES = (
    "attack_success_rate",
    "utility_activity",
    "expected_utility_activity",
    "deception_activity",
    "adaptation_activity",
    "ttp_change_activity",
    "coalition_activity",
    "critical_progress",
    "critical_focus",
    "critical_probe_activity",
    "stealth_activity",
    "trust_collapse_activity",
    "lateral_movement_activity",
    "mission_mutation_activity",
    "campaign_disruption_activity",
    "survival_activity",
    "objective_activity",
    "planned_critical_activity",
)

CRITICAL_PATH_FEATURES = (
    "critical_progress",
    "critical_focus",
    "critical_probe_activity",
    "planned_critical_activity",
)


@dataclass(frozen=True)
class FeatureSpaceResult:
    feature_vector: Dict[str, float]
    normalized_vector: Dict[str, float]
    dominant_feature: str
    dominant_feature_weight: float
    feature_entropy: float
    feature_concentration: float
    critical_path_bias_score: float


class FeatureSpaceAnalyzer:
    """Build and analyze CyberMatch behavior feature vectors."""

    feature_names = FEATURE_NAMES

    def __init__(self) -> None:
        self.behavior_engine = BehaviorProfileEngine()
        self.intent_engine = MissionInferenceEngine()

    def build_feature_vector(self, observed: Mapping[str, object]) -> Dict[str, float]:
        if any(name in observed for name in self.feature_names):
            return {
                name: float(np.clip(self._number(observed.get(name)), 0.0, 1.0))
                for name in self.feature_names
            }
        behavior_features = self.behavior_engine.extract_features(observed)
        intent_features = self.intent_engine.extract_features(observed)
        vector = {}
        for name in self.feature_names:
            if name in behavior_features:
                value = behavior_features[name]
            else:
                value = intent_features.get(name, 0.0)
            vector[name] = float(np.clip(float(value), 0.0, 1.0))
        return vector

    def _number(self, value: object) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def normalize_feature_vector(self, vector: Mapping[str, float]) -> Dict[str, float]:
        values = np.asarray([max(float(vector.get(name, 0.0)), 0.0) for name in self.feature_names], dtype=float)
        total = float(np.sum(values))
        if total <= 1e-12:
            return {name: 0.0 for name in self.feature_names}
        return {name: float(values[idx] / total) for idx, name in enumerate(self.feature_names)}

    def analyze_one(self, observed: Mapping[str, object]) -> FeatureSpaceResult:
        vector = self.build_feature_vector(observed)
        normalized = self.normalize_feature_vector(vector)
        dominant = max(self.feature_names, key=lambda name: normalized.get(name, 0.0))
        dominant_weight = float(normalized.get(dominant, 0.0))
        entropy = self._entropy(normalized.values())
        concentration = dominant_weight
        critical_bias = float(sum(normalized.get(name, 0.0) for name in CRITICAL_PATH_FEATURES))
        return FeatureSpaceResult(
            feature_vector=vector,
            normalized_vector=normalized,
            dominant_feature=dominant,
            dominant_feature_weight=dominant_weight,
            feature_entropy=entropy,
            feature_concentration=concentration,
            critical_path_bias_score=critical_bias,
        )

    def analyze_rows(self, rows: Sequence[Mapping[str, object]]) -> Dict[str, object]:
        vectors = [self.build_feature_vector(row) for row in rows]
        if not vectors:
            return {
                "dominant_feature": "",
                "dominant_feature_weight": 0.0,
                "feature_entropy": 0.0,
                "feature_concentration": 0.0,
                "critical_path_bias_score": 0.0,
                "feature_dominance": {name: 0.0 for name in self.feature_names},
                "feature_correlation": {},
                "mission_feature_means": {},
                "profile_feature_means": {},
                "mission_feature_separability": 0.0,
                "profile_feature_separability": 0.0,
            }
        mean_vector = {
            name: float(np.mean([vector.get(name, 0.0) for vector in vectors]))
            for name in self.feature_names
        }
        normalized = self.normalize_feature_vector(mean_vector)
        dominant = max(self.feature_names, key=lambda name: normalized.get(name, 0.0))
        return {
            "dominant_feature": dominant,
            "dominant_feature_weight": float(normalized.get(dominant, 0.0)),
            "feature_entropy": self._entropy(normalized.values()),
            "feature_concentration": float(normalized.get(dominant, 0.0)),
            "critical_path_bias_score": float(sum(normalized.get(name, 0.0) for name in CRITICAL_PATH_FEATURES)),
            "feature_dominance": normalized,
            "feature_correlation": self.feature_correlation(vectors),
            "mission_feature_means": self.group_feature_means(rows, "true_mission", vectors),
            "profile_feature_means": self.group_feature_means(rows, "behavior_profile", vectors),
            "mission_feature_separability": self.group_separability(rows, "true_mission", vectors),
            "profile_feature_separability": self.group_separability(rows, "behavior_profile", vectors),
        }

    def feature_correlation(self, vectors: Sequence[Mapping[str, float]]) -> Dict[str, Dict[str, float]]:
        if len(vectors) < 2:
            return {name: {other: 0.0 for other in self.feature_names} for name in self.feature_names}
        matrix = np.asarray([[float(vector.get(name, 0.0)) for name in self.feature_names] for vector in vectors], dtype=float)
        corr = np.zeros((len(self.feature_names), len(self.feature_names)), dtype=float)
        for i in range(len(self.feature_names)):
            for j in range(len(self.feature_names)):
                x = matrix[:, i]
                y = matrix[:, j]
                if float(np.std(x)) <= 1e-12 or float(np.std(y)) <= 1e-12:
                    corr[i, j] = 0.0
                else:
                    corr[i, j] = float(np.corrcoef(x, y)[0, 1])
        return {
            name: {other: float(corr[i, j]) for j, other in enumerate(self.feature_names)}
            for i, name in enumerate(self.feature_names)
        }

    def group_feature_means(
        self,
        rows: Sequence[Mapping[str, object]],
        group_key: str,
        vectors: Sequence[Mapping[str, float]] | None = None,
    ) -> Dict[str, Dict[str, float]]:
        vector_list = list(vectors) if vectors is not None else [self.build_feature_vector(row) for row in rows]
        groups: Dict[str, List[Mapping[str, float]]] = {}
        for row, vector in zip(rows, vector_list):
            group = str(row.get(group_key) or "")
            if not group:
                continue
            groups.setdefault(group, []).append(vector)
        return {
            group: {
                name: float(np.mean([vector.get(name, 0.0) for vector in group_vectors]))
                for name in self.feature_names
            }
            for group, group_vectors in groups.items()
        }

    def group_separability(
        self,
        rows: Sequence[Mapping[str, object]],
        group_key: str,
        vectors: Sequence[Mapping[str, float]] | None = None,
    ) -> float:
        means = self.group_feature_means(rows, group_key, vectors)
        if len(means) < 2:
            return 0.0
        group_vectors = [
            np.asarray([values.get(name, 0.0) for name in self.feature_names], dtype=float)
            for values in means.values()
        ]
        distances = []
        for idx in range(len(group_vectors)):
            for jdx in range(idx + 1, len(group_vectors)):
                distances.append(float(np.linalg.norm(group_vectors[idx] - group_vectors[jdx]) / math.sqrt(len(self.feature_names))))
        return float(np.mean(distances)) if distances else 0.0

    def _entropy(self, probabilities: Iterable[float]) -> float:
        values = [float(prob) for prob in probabilities if float(prob) > 0.0]
        if not values:
            return 0.0
        entropy = -sum(prob * math.log(prob) for prob in values)
        return float(np.clip(entropy / math.log(len(self.feature_names)), 0.0, 1.0))
