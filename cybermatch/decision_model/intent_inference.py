"""Rule-based mission inference for CyberMatch Phase9.0.

The engine is intentionally lightweight. It reads existing behavior history or
summary rows and estimates attacker mission without changing simulation logic.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence

import numpy as np


MISSION_CLASSES = ("profit", "achievement", "persistence", "critical_hunter")


@dataclass(frozen=True)
class MissionInferenceResult:
    inferred_mission: str
    mission_confidence: float
    mission_entropy: float
    mission_scores: Dict[str, float]
    features: Dict[str, float]


class MissionInferenceEngine:
    """Infer mission from already-observed CyberMatch behavior.

    This is not an AI model. It uses fixed, auditable heuristics over existing
    histories and metrics such as success, utility, critical-path activity,
    trust collapse, deception interaction, and lateral movement.
    """

    missions = MISSION_CLASSES

    def infer(self, observed: Mapping[str, object]) -> MissionInferenceResult:
        features = self.extract_features(observed)
        raw_scores = {
            "profit": (
                0.45 * features["utility_activity"]
                + 0.35 * features["attack_success_rate"]
                + 0.15 * features["expected_utility_activity"]
                + 0.05 * (1.0 - features["trust_collapse_activity"])
                + 0.40 * features["mission_signal_profit"]
            ),
            "achievement": (
                0.38 * features["objective_activity"]
                + 0.28 * features["critical_progress"]
                + 0.20 * features["attack_success_rate"]
                + 0.14 * features["lateral_movement_activity"]
                + 0.40 * features["mission_signal_achievement"]
            ),
            "persistence": (
                0.34 * features["trust_collapse_activity"]
                + 0.24 * features["stealth_activity"]
                + 0.18 * features["survival_activity"]
                + 0.14 * features["lateral_movement_activity"]
                + 0.10 * features["deception_activity"]
                + 0.40 * features["mission_signal_persistence"]
            ),
            "critical_hunter": (
                0.55 * features["critical_progress"]
                + 0.20 * features["critical_focus"]
                + 0.15 * features["critical_probe_activity"]
                + 0.10 * features["planned_critical_activity"]
                + 0.40 * features["mission_signal_critical_hunter"]
            ),
        }
        scores = self._softmaxish(raw_scores)
        inferred = max(self.missions, key=lambda mission: (scores[mission], raw_scores[mission]))
        confidence = float(scores[inferred])
        entropy = self._entropy(scores.values())
        return MissionInferenceResult(
            inferred_mission=inferred,
            mission_confidence=confidence,
            mission_entropy=entropy,
            mission_scores=scores,
            features=features,
        )

    def infer_history(self, history: Mapping[str, Sequence[object]]) -> Dict[str, List[object]]:
        length = self._history_length(history)
        inferred_history: List[str] = []
        confidence_history: List[float] = []
        entropy_history: List[float] = []
        for end in range(1, length + 1):
            prefix = {
                key: value[:end] if hasattr(value, "__getitem__") else value
                for key, value in history.items()
            }
            result = self.infer(prefix)
            inferred_history.append(result.inferred_mission)
            confidence_history.append(result.mission_confidence)
            entropy_history.append(result.mission_entropy)
        return {
            "inferred_mission_history": inferred_history,
            "mission_confidence_history": confidence_history,
            "mission_entropy_history": entropy_history,
        }

    def evaluate(self, observed: Mapping[str, object], true_mission: object = None) -> Dict[str, object]:
        result = self.infer(observed)
        truth = str(true_mission or observed.get("true_mission") or observed.get("attacker_mission") or "")
        match = bool(truth == result.inferred_mission) if truth else False
        return {
            "inferred_mission": result.inferred_mission,
            "mission_confidence": result.mission_confidence,
            "mission_entropy": result.mission_entropy,
            "mission_match": match,
            "mission_confusion_score": float(1.0 - result.mission_confidence),
            "mission_scores": result.mission_scores,
            "intent_features": result.features,
        }

    def extract_features(self, observed: Mapping[str, object]) -> Dict[str, float]:
        success_values = self._numeric_series(observed, "attacker_success")
        if success_values:
            success = float(np.mean(success_values))
        else:
            success = self._first_number(observed, ("mean_attack_success_prob", "mean_attack_success_prob_mean", "mission_success_score", "mission_success_score_mean"))

        actual_utility = self._first_number(observed, ("actual_utility_mean", "actual_utility_final", "attacker_utility_final", "actual_utility_mean_mean"))
        utility_series = self._numeric_series(observed, "actual_utility")
        if utility_series:
            actual_utility = float(np.mean(utility_series))
        utility_activity = self._saturate_positive(actual_utility, 10.0)

        expected_utility = self._first_number(observed, ("expected_utility_mean", "expected_utility_mean_mean", "expected_utility_final", "expected_utility_final_mean"))
        expected_utility_activity = self._saturate_positive(expected_utility, 5.0)

        critical_events = self._event_count(observed, "critical_path_events")
        critical_progress = self._bounded_sum(
            self._first_number(observed, ("critical_path_progress_count", "critical_path_progress_count_mean")) / 4.0,
            self._first_number(observed, ("critical_path_near_target_count", "critical_path_near_target_count_mean")) / 3.0,
            self._first_number(observed, ("critical_asset_reach_count", "critical_asset_reach_count_mean")),
            self._first_number(observed, ("critical_path_proximity", "critical_path_proximity_mean")),
            critical_events / 8.0,
            self._first_number(observed, ("critical_compromise_rate",)),
        )
        critical_focus = self._bounded_sum(
            self._first_number(observed, ("critical_node_visit_count", "critical_node_visit_count_mean")) / 4.0,
            self._first_number(observed, ("attacker_critical_true_gain_total", "attacker_critical_true_gain_total_mean")) / 8.0,
            self._first_number(observed, ("preferred_node_on_critical_path_rate",)),
        )
        critical_probe = self._bounded_sum(
            self._first_number(observed, ("critical_probe_count", "critical_probe_count_mean")) / 4.0,
            self._event_count(observed, "observable_events", {"critical_probe", "objective_action"}) / 6.0,
        )

        trust_collapse = self._bounded_sum(
            self._first_number(observed, ("trust_collapse_rate", "trust_collapse_rate_mean")),
            self._first_number(observed, ("credential_trap_trigger_count", "credential_trap_trigger_count_mean")) / 4.0,
            self._first_number(observed, ("fake_credential_usage_count", "fake_credential_usage_count_mean")) / 4.0,
        )
        stealth = self._bounded_sum(
            self._token_count(observed.get("adaptation_history"), {"stealth_lateral_shift", "observe"}) / 8.0,
            self._first_number(observed, ("deception_suspicion_score", "deception_suspicion_score_mean")),
            1.0 - self._first_number(observed, ("mean_attack_detection_prob", "mean_attack_detection_prob_mean")),
        )
        survival = 1.0 - self._first_number(observed, ("retreat_rate", "retreat_rate_mean"))
        deception_activity = self._bounded_sum(
            self._event_count(observed, "deception_history") / 4.0,
            self._first_number(observed, ("deception_event_count", "deception_event_count_mean")) / 4.0,
            self._first_number(observed, ("fake_path_follow_count", "fake_path_follow_count_mean")) / 4.0,
        )
        lateral = self._bounded_sum(
            self._first_number(observed, ("lateral_move_count", "lateral_move_count_mean")) / 4.0,
            self._event_count(observed, "observable_events", {"lateral_move", "credential_use"}) / 6.0,
            self._first_number(observed, ("alternative_path_usage", "alternative_path_usage_mean")) / 4.0,
        )
        objective = self._bounded_sum(
            self._first_number(observed, ("mission_objective_score", "mission_objective_score_mean")),
            self._first_number(observed, ("mission_satisfaction_score", "mission_satisfaction_score_mean")),
            self._event_count(observed, "observable_events", {"objective_action", "data_access"}) / 4.0,
        )
        planned_critical = self._bounded_sum(
            self._first_number(observed, ("planned_path_is_critical_rate",)),
            self._first_number(observed, ("preferred_path_is_critical_rate",)),
            self._first_number(observed, ("planning_score_mean", "planning_score_mean_mean")) / 5.0,
        )
        mission_signals = self._mission_signals(observed)

        return {
            "attack_success_rate": float(np.clip(success, 0.0, 1.0)),
            "utility_activity": utility_activity,
            "expected_utility_activity": expected_utility_activity,
            "critical_progress": critical_progress,
            "critical_focus": critical_focus,
            "critical_probe_activity": critical_probe,
            "trust_collapse_activity": trust_collapse,
            "stealth_activity": stealth,
            "survival_activity": float(np.clip(survival, 0.0, 1.0)),
            "deception_activity": deception_activity,
            "lateral_movement_activity": lateral,
            "objective_activity": objective,
            "planned_critical_activity": planned_critical,
            **mission_signals,
        }

    def _mission_signals(self, observed: Mapping[str, object]) -> Dict[str, float]:
        signals = {
            "mission_signal_profit": self._first_number(observed, ("mission_weight_profit",)),
            "mission_signal_achievement": self._first_number(observed, ("mission_weight_achievement",)),
            "mission_signal_persistence": self._first_number(observed, ("mission_weight_persistence",)),
            "mission_signal_critical_hunter": self._first_number(observed, ("mission_weight_critical_hunter",)),
        }
        if any(value > 0.0 for value in signals.values()):
            return {key: float(np.clip(value, 0.0, 1.0)) for key, value in signals.items()}
        history = observed.get("mission_history") or observed.get("observed_mission_history")
        mission = ""
        if isinstance(history, np.ndarray) and history.size > 0:
            mission = str(history.reshape(-1)[-1])
        elif isinstance(history, (list, tuple)) and history:
            mission = str(history[-1])
        elif isinstance(history, str):
            mission = history
        if mission in self.missions:
            signals[f"mission_signal_{mission}"] = 1.0
        return signals

    def _history_length(self, history: Mapping[str, Sequence[object]]) -> int:
        candidates = ("actual_utility", "attacker_success", "observable_events", "mission_history")
        for key in candidates:
            value = history.get(key)
            if hasattr(value, "__len__"):
                return int(len(value))
        return 0

    def _numeric_series(self, observed: Mapping[str, object], key: str) -> List[float]:
        value = observed.get(key)
        if value is None:
            return []
        if isinstance(value, np.ndarray):
            items = value.reshape(-1).tolist()
        elif isinstance(value, (list, tuple)):
            items = list(value)
        else:
            items = [value]
        numbers = []
        for item in items:
            try:
                numbers.append(float(item))
            except (TypeError, ValueError):
                continue
        return numbers

    def _first_number(self, observed: Mapping[str, object], keys: Iterable[str]) -> float:
        for key in keys:
            values = self._numeric_series(observed, key)
            if values:
                return float(values[0])
        return 0.0

    def _event_count(self, observed: Mapping[str, object], key: str, wanted: Iterable[str] | None = None) -> int:
        return self._token_count(observed.get(key), set(wanted) if wanted else None)

    def _token_count(self, value: object, wanted: set[str] | None = None) -> int:
        if value is None:
            return 0
        if isinstance(value, np.ndarray):
            items = value.reshape(-1).tolist()
        elif isinstance(value, (list, tuple)):
            items = list(value)
        else:
            items = [value]
        count = 0
        for item in items:
            for token in str(item).split("|"):
                if not token:
                    continue
                if wanted is None or token in wanted:
                    count += 1
        return count

    def _saturate_positive(self, value: float, scale: float) -> float:
        return float(np.clip(max(value, 0.0) / max(scale, 1e-9), 0.0, 1.0))

    def _bounded_sum(self, *values: float) -> float:
        return float(np.clip(sum(max(float(value), 0.0) for value in values), 0.0, 1.0))

    def _softmaxish(self, raw_scores: Mapping[str, float]) -> Dict[str, float]:
        values = np.asarray([float(raw_scores[mission]) for mission in self.missions], dtype=float)
        values = values - float(np.max(values))
        exp_values = np.exp(values * 4.0)
        probs = exp_values / max(float(np.sum(exp_values)), 1e-12)
        return {mission: float(probs[idx]) for idx, mission in enumerate(self.missions)}

    def _entropy(self, probabilities: Iterable[float]) -> float:
        values = [float(prob) for prob in probabilities if float(prob) > 0.0]
        if not values:
            return 0.0
        entropy = -sum(prob * math.log(prob) for prob in values)
        return float(np.clip(entropy / math.log(len(self.missions)), 0.0, 1.0))
