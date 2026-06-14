"""Archetype interpretation for CyberMatch Phase9.4.

This module is analysis-only. It interprets archetypes discovered by Phase9.3
from existing feature rows and does not create new archetypes or alter
simulation behavior.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence

import numpy as np

from feature_space import FEATURE_NAMES


SIGNATURE_FEATURES = (
    "utility_activity",
    "deception_activity",
    "adaptation_activity",
    "critical_progress",
    "critical_focus",
    "critical_probe_activity",
    "expected_utility_activity",
    "stealth_activity",
    "coalition_activity",
)

CRITICAL_ACTIVITY_FEATURES = (
    "critical_progress",
    "critical_focus",
    "critical_probe_activity",
    "planned_critical_activity",
)


@dataclass(frozen=True)
class ArchetypeInterpretationResult:
    archetype_summary: List[Dict[str, object]]
    archetype_signature: Dict[str, List[str]]
    feature_means: Dict[str, Dict[str, float]]
    feature_variances: Dict[str, Dict[str, float]]
    mission_distribution: Dict[str, Dict[str, int]]
    behavior_profile_distribution: Dict[str, Dict[str, int]]
    archetype_feature_distance: Dict[str, Dict[str, float]]
    archetype_mission_overlap: float
    archetype_profile_overlap: float
    archetype_stability: float
    archetype_interpretability_score: float


class ArchetypeInterpreter:
    """Describe discovered archetypes using existing behavior feature rows."""

    def analyze(self, rows: Sequence[Mapping[str, object]]) -> ArchetypeInterpretationResult:
        grouped = self._group_by_archetype(rows)
        if not grouped:
            return ArchetypeInterpretationResult([], {}, {}, {}, {}, {}, {}, 0.0, 0.0, 0.0, 0.0)

        feature_means = {
            archetype: self._feature_mean(group_rows)
            for archetype, group_rows in grouped.items()
        }
        feature_variances = {
            archetype: self._feature_variance(group_rows, feature_means[archetype])
            for archetype, group_rows in grouped.items()
        }
        mission_distribution = {
            archetype: self._distribution(row.get("true_mission") for row in group_rows)
            for archetype, group_rows in grouped.items()
        }
        profile_distribution = {
            archetype: self._distribution(row.get("behavior_profile") for row in group_rows)
            for archetype, group_rows in grouped.items()
        }
        signatures = {
            archetype: self.generate_signature(feature_means[archetype])
            for archetype in grouped
        }
        distance = self.feature_distance(feature_means)
        mission_overlap = self.label_overlap(mission_distribution)
        profile_overlap = self.label_overlap(profile_distribution)
        stability = self.stability(feature_variances)
        interpretability = self.interpretability_score(distance, mission_overlap, profile_overlap, stability)
        summary = [
            self._summary_row(
                archetype,
                grouped[archetype],
                feature_means[archetype],
                feature_variances[archetype],
                signatures[archetype],
            )
            for archetype in sorted(grouped)
        ]
        return ArchetypeInterpretationResult(
            archetype_summary=summary,
            archetype_signature=signatures,
            feature_means=feature_means,
            feature_variances=feature_variances,
            mission_distribution=mission_distribution,
            behavior_profile_distribution=profile_distribution,
            archetype_feature_distance=distance,
            archetype_mission_overlap=mission_overlap,
            archetype_profile_overlap=profile_overlap,
            archetype_stability=stability,
            archetype_interpretability_score=interpretability,
        )

    def generate_signature(self, feature_mean: Mapping[str, float]) -> List[str]:
        signature: List[str] = []
        for feature in SIGNATURE_FEATURES:
            value = float(feature_mean.get(feature, 0.0))
            if value >= 0.66:
                level = "high"
            elif value >= 0.33:
                level = "medium"
            else:
                level = "low"
            signature.append(f"{level} {feature}")
        return signature

    def feature_distance(self, feature_means: Mapping[str, Mapping[str, float]]) -> Dict[str, Dict[str, float]]:
        labels = sorted(feature_means)
        matrix: Dict[str, Dict[str, float]] = {label: {} for label in labels}
        for left in labels:
            left_vector = np.asarray([float(feature_means[left].get(name, 0.0)) for name in FEATURE_NAMES], dtype=float)
            for right in labels:
                right_vector = np.asarray([float(feature_means[right].get(name, 0.0)) for name in FEATURE_NAMES], dtype=float)
                matrix[left][right] = float(np.linalg.norm(left_vector - right_vector) / math.sqrt(len(FEATURE_NAMES)))
        return matrix

    def label_overlap(self, grouped_distribution: Mapping[str, Mapping[str, int]]) -> float:
        labels = sorted(grouped_distribution)
        if len(labels) < 2:
            return 0.0
        overlaps: List[float] = []
        for idx, left in enumerate(labels):
            left_counts = grouped_distribution[left]
            left_total = sum(int(value) for value in left_counts.values())
            for right in labels[idx + 1 :]:
                right_counts = grouped_distribution[right]
                right_total = sum(int(value) for value in right_counts.values())
                if left_total <= 0 or right_total <= 0:
                    overlaps.append(0.0)
                    continue
                all_labels = set(left_counts) | set(right_counts)
                overlap = sum(
                    min(
                        int(left_counts.get(label, 0)) / left_total,
                        int(right_counts.get(label, 0)) / right_total,
                    )
                    for label in all_labels
                )
                overlaps.append(float(np.clip(overlap, 0.0, 1.0)))
        return float(np.mean(overlaps)) if overlaps else 0.0

    def stability(self, feature_variances: Mapping[str, Mapping[str, float]]) -> float:
        if not feature_variances:
            return 0.0
        values = [
            float(np.mean([float(variance.get(name, 0.0)) for name in FEATURE_NAMES]))
            for variance in feature_variances.values()
        ]
        mean_variance = float(np.mean(values)) if values else 0.0
        return float(np.clip(1.0 - mean_variance, 0.0, 1.0))

    def interpretability_score(
        self,
        distance: Mapping[str, Mapping[str, float]],
        mission_overlap: float,
        profile_overlap: float,
        stability: float,
    ) -> float:
        pair_distances: List[float] = []
        labels = sorted(distance)
        for idx, left in enumerate(labels):
            for right in labels[idx + 1 :]:
                pair_distances.append(float(distance[left].get(right, 0.0)))
        distance_score = float(np.clip(np.mean(pair_distances), 0.0, 1.0)) if pair_distances else 0.0
        overlap_score = 1.0 - float(np.clip((mission_overlap + profile_overlap) / 2.0, 0.0, 1.0))
        return float(np.clip((distance_score + overlap_score + stability) / 3.0, 0.0, 1.0))

    def _group_by_archetype(self, rows: Sequence[Mapping[str, object]]) -> Dict[str, List[Mapping[str, object]]]:
        grouped: Dict[str, List[Mapping[str, object]]] = {}
        for row in rows:
            archetype = str(row.get("archetype") or "")
            if not archetype:
                continue
            grouped.setdefault(archetype, []).append(row)
        return dict(sorted(grouped.items()))

    def _feature_mean(self, rows: Sequence[Mapping[str, object]]) -> Dict[str, float]:
        return {
            feature: float(np.mean([self._number(row.get(feature)) for row in rows])) if rows else 0.0
            for feature in FEATURE_NAMES
        }

    def _feature_variance(
        self,
        rows: Sequence[Mapping[str, object]],
        means: Mapping[str, float],
    ) -> Dict[str, float]:
        return {
            feature: float(np.mean([(self._number(row.get(feature)) - float(means.get(feature, 0.0))) ** 2 for row in rows]))
            if rows
            else 0.0
            for feature in FEATURE_NAMES
        }

    def _distribution(self, values: Iterable[object]) -> Dict[str, int]:
        distribution: Dict[str, int] = {}
        for value in values:
            label = str(value or "")
            if not label:
                continue
            distribution[label] = distribution.get(label, 0) + 1
        return dict(sorted(distribution.items()))

    def _summary_row(
        self,
        archetype: str,
        rows: Sequence[Mapping[str, object]],
        feature_mean: Mapping[str, float],
        feature_variance: Mapping[str, float],
        signature: Sequence[str],
    ) -> Dict[str, object]:
        dominant_feature = max(FEATURE_NAMES, key=lambda name: float(feature_mean.get(name, 0.0)))
        return {
            "archetype": archetype,
            "row_count": len(rows),
            "dominant_feature": dominant_feature,
            "dominant_feature_mean": float(feature_mean.get(dominant_feature, 0.0)),
            "mean_feature_variance": float(np.mean([float(feature_variance.get(name, 0.0)) for name in FEATURE_NAMES])),
            "adaptation_activity": float(feature_mean.get("adaptation_activity", 0.0)),
            "deception_activity": float(feature_mean.get("deception_activity", 0.0)),
            "critical_activity": float(sum(float(feature_mean.get(name, 0.0)) for name in CRITICAL_ACTIVITY_FEATURES) / len(CRITICAL_ACTIVITY_FEATURES)),
            "utility_activity": float(
                (float(feature_mean.get("utility_activity", 0.0)) + float(feature_mean.get("expected_utility_activity", 0.0))) / 2.0
            ),
            "stealth_activity": float(feature_mean.get("stealth_activity", 0.0)),
            "coalition_activity": float(feature_mean.get("coalition_activity", 0.0)),
            "archetype_signature": "; ".join(signature),
        }

    def _number(self, value: object) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0
