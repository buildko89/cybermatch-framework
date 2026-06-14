"""Strategy validation analysis for CyberMatch Phase9.8.

This module validates the Phase9.7 Target -> Strategy model using existing
analysis rows only. It does not add strategies, attackers, defenders, learning,
external APIs, ProfileCore changes, benchmark changes, or simulation logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Mapping, Sequence

import numpy as np

from mission_taxonomy import TARGET_CLASSES, TARGET_STRATEGY_MAP
from strategy_layer import STRATEGY_CLASSES, STRATEGY_FEATURES


@dataclass(frozen=True)
class StrategyValidationResult:
    rows: List[Dict[str, object]]
    metrics: Dict[str, object]
    strategy_distance_matrix: Dict[str, Dict[str, float]]
    strategy_distinctiveness: Dict[str, float]
    strategy_redundancy: Dict[str, float]
    target_specificity_validation: Dict[str, float]
    mission_strategy_explainability: Dict[str, float]
    strategy_summary: List[Dict[str, object]]


class StrategyValidationEngine:
    """Validate whether observed strategies are distinct and explanatory."""

    strategies = STRATEGY_CLASSES
    features = STRATEGY_FEATURES
    targets = TARGET_CLASSES

    def validate(self, rows: Sequence[Mapping[str, object]]) -> StrategyValidationResult:
        normalized_rows = [self._normalize_row(row) for row in rows]
        distance_matrix = self.strategy_distance_matrix(normalized_rows)
        distinctiveness = self.strategy_distinctiveness(distance_matrix)
        redundancy = self.strategy_redundancy(distance_matrix)
        target_validation = self.target_specificity_validation(normalized_rows)
        mission_explainability = self.mission_strategy_explainability(normalized_rows)
        summary = self.strategy_summary(normalized_rows, distinctiveness, redundancy)
        metrics = self.validation_metrics(
            normalized_rows,
            distinctiveness,
            redundancy,
            target_validation,
            mission_explainability,
        )
        return StrategyValidationResult(
            rows=normalized_rows,
            metrics=metrics,
            strategy_distance_matrix=distance_matrix,
            strategy_distinctiveness=distinctiveness,
            strategy_redundancy=redundancy,
            target_specificity_validation=target_validation,
            mission_strategy_explainability=mission_explainability,
            strategy_summary=summary,
        )

    def strategy_distance_matrix(self, rows: Sequence[Mapping[str, object]]) -> Dict[str, Dict[str, float]]:
        signatures = self._strategy_signatures(rows)
        matrix: Dict[str, Dict[str, float]] = {}
        for left in self.strategies:
            matrix[left] = {}
            for right in self.strategies:
                left_vector = signatures[left]
                right_vector = signatures[right]
                distance = np.linalg.norm(left_vector - right_vector) / max(np.sqrt(left_vector.size), 1.0)
                matrix[left][right] = float(np.clip(distance, 0.0, 1.0))
        return matrix

    def target_specificity_validation(self, rows: Sequence[Mapping[str, object]]) -> Dict[str, float]:
        values: Dict[str, float] = {}
        for target in sorted({str(row.get("target")) for row in rows if row.get("target")}):
            target_rows = [row for row in rows if str(row.get("target")) == target]
            strategies = [str(row.get("strategy_type")) for row in target_rows if row.get("strategy_type")]
            if not strategies:
                values[target] = 0.0
                continue
            distribution = self._distribution(strategies)
            dominant_share = max(distribution.values()) / max(sum(distribution.values()), 1)
            candidate_alignment = np.mean(
                [
                    1.0 if strategy in TARGET_STRATEGY_MAP.get(target, []) else 0.0
                    for strategy in strategies
                ]
            )
            values[target] = float(np.clip((dominant_share + candidate_alignment) / 2.0, 0.0, 1.0))
        return values

    def mission_strategy_explainability(self, rows: Sequence[Mapping[str, object]]) -> Dict[str, float]:
        values: Dict[str, float] = {}
        for mission in sorted({str(row.get("mission")) for row in rows if row.get("mission")}):
            mission_rows = [row for row in rows if str(row.get("mission")) == mission]
            strategies = [str(row.get("strategy_type")) for row in mission_rows if row.get("strategy_type")]
            if not strategies:
                values[mission] = 0.0
                continue
            distribution = self._distribution(strategies)
            entropy = self._entropy(distribution.values())
            dominant_share = max(distribution.values()) / max(sum(distribution.values()), 1)
            values[mission] = float(np.clip((dominant_share + (1.0 - entropy)) / 2.0, 0.0, 1.0))
        return values

    def strategy_distinctiveness(self, matrix: Mapping[str, Mapping[str, float]]) -> Dict[str, float]:
        values: Dict[str, float] = {}
        for strategy, distances in matrix.items():
            peers = [float(value) for peer, value in distances.items() if peer != strategy]
            values[strategy] = float(np.clip(np.mean(peers) if peers else 0.0, 0.0, 1.0))
        return values

    def strategy_redundancy(self, matrix: Mapping[str, Mapping[str, float]], threshold: float = 0.15) -> Dict[str, float]:
        values: Dict[str, float] = {}
        for strategy, distances in matrix.items():
            peers = [float(value) for peer, value in distances.items() if peer != strategy]
            if not peers:
                values[strategy] = 0.0
                continue
            values[strategy] = float(np.mean([1.0 if value < threshold else 0.0 for value in peers]))
        return values

    def validation_metrics(
        self,
        rows: Sequence[Mapping[str, object]],
        distinctiveness: Mapping[str, float],
        redundancy: Mapping[str, float],
        target_validation: Mapping[str, float],
        mission_explainability: Mapping[str, float],
    ) -> Dict[str, object]:
        strategy_consistency = self._strategy_target_consistency(rows)
        strategy_stability = self._strategy_stability(rows)
        target_strategy_confidence = float(
            np.clip(np.mean([self._to_float(row.get("strategy_confidence")) for row in rows]) if rows else 0.0, 0.0, 1.0)
        )
        mission_strategy_consistency = float(
            np.clip(np.mean(list(mission_explainability.values())) if mission_explainability else 0.0, 0.0, 1.0)
        )
        strategy_distinctiveness = float(
            np.clip(np.mean(list(distinctiveness.values())) if distinctiveness else 0.0, 0.0, 1.0)
        )
        strategy_redundancy = float(np.clip(np.mean(list(redundancy.values())) if redundancy else 0.0, 0.0, 1.0))
        target_specificity = float(np.clip(np.mean(list(target_validation.values())) if target_validation else 0.0, 0.0, 1.0))
        strategy_explainability = float(
            np.clip(
                np.mean(
                    [
                        strategy_consistency,
                        target_strategy_confidence,
                        mission_strategy_consistency,
                        strategy_distinctiveness,
                        target_specificity,
                    ]
                ),
                0.0,
                1.0,
            )
        )
        return {
            "strategy_validation_pass": bool(
                strategy_distinctiveness >= 0.10
                and strategy_redundancy <= 0.70
                and strategy_explainability >= 0.45
            ),
            "strategy_consistency": strategy_consistency,
            "strategy_stability": strategy_stability,
            "target_strategy_confidence": target_strategy_confidence,
            "mission_strategy_consistency": mission_strategy_consistency,
            "strategy_redundancy": strategy_redundancy,
            "strategy_distinctiveness": strategy_distinctiveness,
            "strategy_explainability": strategy_explainability,
            "target_specificity_validation": target_specificity,
        }

    def strategy_summary(
        self,
        rows: Sequence[Mapping[str, object]],
        distinctiveness: Mapping[str, float],
        redundancy: Mapping[str, float],
    ) -> List[Dict[str, object]]:
        summaries: List[Dict[str, object]] = []
        for strategy in self.strategies:
            strategy_rows = [row for row in rows if str(row.get("strategy_type")) == strategy]
            target_counts = self._distribution(str(row.get("target")) for row in strategy_rows if row.get("target"))
            mission_counts = self._distribution(str(row.get("mission")) for row in strategy_rows if row.get("mission"))
            summaries.append(
                {
                    "strategy_type": strategy,
                    "row_count": len(strategy_rows),
                    "dominant_target": self._dominant_label(target_counts),
                    "dominant_mission": self._dominant_label(mission_counts),
                    "mean_confidence": float(
                        np.clip(
                            np.mean([self._to_float(row.get("strategy_confidence")) for row in strategy_rows])
                            if strategy_rows
                            else 0.0,
                            0.0,
                            1.0,
                        )
                    ),
                    "distinctiveness": float(distinctiveness.get(strategy, 0.0)),
                    "redundancy": float(redundancy.get(strategy, 0.0)),
                }
            )
        return summaries

    def _strategy_signatures(self, rows: Sequence[Mapping[str, object]]) -> Dict[str, np.ndarray]:
        missions = sorted({str(row.get("mission")) for row in rows if row.get("mission")})
        signatures: Dict[str, np.ndarray] = {}
        for strategy in self.strategies:
            strategy_rows = [row for row in rows if str(row.get("strategy_type")) == strategy]
            feature_values = [
                np.asarray([self._to_float(row.get(feature)) for feature in self.features], dtype=float)
                for row in strategy_rows
            ]
            feature_vector = np.mean(feature_values, axis=0) if feature_values else np.zeros(len(self.features), dtype=float)
            target_vector = self._label_vector(
                [str(row.get("target")) for row in strategy_rows if row.get("target")],
                list(self.targets),
                fallback=self._target_prior(strategy),
            )
            mission_vector = self._label_vector(
                [str(row.get("mission")) for row in strategy_rows if row.get("mission")],
                missions,
                fallback=np.zeros(len(missions), dtype=float),
            )
            signatures[strategy] = np.concatenate([feature_vector, target_vector, mission_vector])
        return signatures

    def _target_prior(self, strategy: str) -> np.ndarray:
        values = np.asarray(
            [
                1.0 if strategy in TARGET_STRATEGY_MAP.get(target, []) else 0.0
                for target in self.targets
            ],
            dtype=float,
        )
        total = float(np.sum(values))
        return values / total if total > 0.0 else values

    def _label_vector(self, values: Sequence[str], labels: Sequence[str], fallback: np.ndarray) -> np.ndarray:
        if not labels:
            return np.zeros(0, dtype=float)
        counts = np.asarray([values.count(label) for label in labels], dtype=float)
        total = float(np.sum(counts))
        if total <= 0.0:
            return fallback.astype(float)
        return counts / total

    def _strategy_target_consistency(self, rows: Sequence[Mapping[str, object]]) -> float:
        scores: List[float] = []
        for strategy in sorted({str(row.get("strategy_type")) for row in rows if row.get("strategy_type")}):
            strategy_rows = [row for row in rows if str(row.get("strategy_type")) == strategy]
            targets = [str(row.get("target")) for row in strategy_rows if row.get("target")]
            if not targets:
                continue
            distribution = self._distribution(targets)
            scores.append(max(distribution.values()) / max(sum(distribution.values()), 1))
        return float(np.clip(np.mean(scores) if scores else 0.0, 0.0, 1.0))

    def _strategy_stability(self, rows: Sequence[Mapping[str, object]]) -> float:
        variances: List[float] = []
        for strategy in sorted({str(row.get("strategy_type")) for row in rows if row.get("strategy_type")}):
            strategy_rows = [row for row in rows if str(row.get("strategy_type")) == strategy]
            if len(strategy_rows) < 2:
                continue
            matrix = np.asarray(
                [[self._to_float(row.get(feature)) for feature in self.features] for row in strategy_rows],
                dtype=float,
            )
            variances.append(float(np.mean(np.var(matrix, axis=0))))
        return float(np.clip(1.0 - (np.mean(variances) if variances else 0.0), 0.0, 1.0))

    def _normalize_row(self, row: Mapping[str, object]) -> Dict[str, object]:
        normalized = dict(row)
        normalized["strategy_type"] = str(row.get("strategy_type") or row.get("strategy") or "")
        normalized["target"] = str(row.get("target") or row.get("target_type") or "")
        normalized["mission"] = str(row.get("mission") or row.get("existing_mission") or row.get("true_mission") or "")
        for feature in self.features:
            normalized[feature] = self._to_float(row.get(feature))
        normalized["strategy_confidence"] = self._to_float(row.get("strategy_confidence"))
        return normalized

    def _distribution(self, values: Sequence[str]) -> Dict[str, int]:
        distribution: Dict[str, int] = {}
        for value in values:
            if not value:
                continue
            distribution[value] = distribution.get(value, 0) + 1
        return dict(sorted(distribution.items()))

    def _dominant_label(self, distribution: Mapping[str, int]) -> str:
        if not distribution:
            return ""
        return max(distribution, key=lambda label: (int(distribution[label]), label))

    def _entropy(self, counts: Sequence[int]) -> float:
        values = np.asarray([float(value) for value in counts if float(value) > 0.0], dtype=float)
        total = float(np.sum(values))
        if total <= 0.0 or values.size <= 1:
            return 0.0
        probabilities = values / total
        return float(np.clip(-np.sum(probabilities * np.log(probabilities)) / np.log(values.size), 0.0, 1.0))

    def _to_float(self, value: object) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0
