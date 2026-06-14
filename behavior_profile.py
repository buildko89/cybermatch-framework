"""Rule-based behavior profile extraction for CyberMatch Phase9.1.

Behavior profiles are deliberately separate from attacker missions. The engine
summarizes observed behavior into reusable profile classes without changing
simulation logic or introducing learning models.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence

import numpy as np


PROFILE_CLASSES = (
    "utility_seeking",
    "stealth_seeking",
    "disruption_seeking",
    "critical_path_seeking",
    "adaptive",
    "opportunistic",
)


@dataclass(frozen=True)
class BehaviorProfileResult:
    behavior_profile: str
    profile_confidence: float
    profile_entropy: float
    profile_score: float
    profile_distribution: Dict[str, float]
    features: Dict[str, float]


class BehaviorProfileEngine:
    """Extract behavior profile from existing attack history and metrics."""

    profiles = PROFILE_CLASSES

    def infer(self, observed: Mapping[str, object]) -> BehaviorProfileResult:
        features = self.extract_features(observed)
        raw_scores = {
            "utility_seeking": (
                0.55 * features["utility_activity"]
                + 0.35 * features["attack_success_rate"]
                + 0.10 * features["expected_utility_activity"]
            ),
            "stealth_seeking": (
                0.45 * features["stealth_activity"]
                + 0.30 * features["trust_collapse_activity"]
                + 0.15 * features["survival_activity"]
                + 0.10 * features["deception_activity"]
            ),
            "disruption_seeking": (
                0.36 * features["deception_activity"]
                + 0.24 * features["trust_collapse_activity"]
                + 0.22 * features["campaign_disruption_activity"]
                + 0.18 * features["coalition_activity"]
            ),
            "critical_path_seeking": (
                0.60 * features["critical_progress"]
                + 0.25 * features["critical_focus"]
                + 0.15 * features["critical_probe_activity"]
            ),
            "adaptive": (
                0.38 * features["adaptation_activity"]
                + 0.28 * features["ttp_change_activity"]
                + 0.20 * features["mission_mutation_activity"]
                + 0.14 * features["lateral_movement_activity"]
            ),
            "opportunistic": (
                0.34 * features["attack_success_rate"]
                + 0.24 * features["lateral_movement_activity"]
                + 0.22 * features["utility_activity"]
                + 0.20 * (1.0 - features["critical_focus"])
            ),
        }
        distribution = self._softmaxish(raw_scores)
        profile = max(self.profiles, key=lambda name: (distribution[name], raw_scores[name]))
        confidence = float(distribution[profile])
        entropy = self._entropy(distribution.values())
        return BehaviorProfileResult(
            behavior_profile=profile,
            profile_confidence=confidence,
            profile_entropy=entropy,
            profile_score=float(raw_scores[profile]),
            profile_distribution=distribution,
            features=features,
        )

    def infer_history(self, history: Mapping[str, Sequence[object]]) -> Dict[str, List[object]]:
        length = self._history_length(history)
        profile_history: List[str] = []
        confidence_history: List[float] = []
        entropy_history: List[float] = []
        for end in range(1, length + 1):
            prefix = {
                key: value[:end] if hasattr(value, "__getitem__") else value
                for key, value in history.items()
            }
            result = self.infer(prefix)
            profile_history.append(result.behavior_profile)
            confidence_history.append(result.profile_confidence)
            entropy_history.append(result.profile_entropy)
        return {
            "behavior_profile_history": profile_history,
            "profile_confidence_history": confidence_history,
            "profile_entropy_history": entropy_history,
        }

    def evaluate(self, observed: Mapping[str, object], expected_profile: object = None) -> Dict[str, object]:
        result = self.infer(observed)
        expected = str(expected_profile or "")
        match = bool(expected == result.behavior_profile) if expected else False
        return {
            "behavior_profile": result.behavior_profile,
            "profile_confidence": result.profile_confidence,
            "profile_entropy": result.profile_entropy,
            "profile_score": result.profile_score,
            "profile_match": match,
            "profile_distribution": result.profile_distribution,
            "behavior_features": result.features,
        }

    def expected_profile_for_mission(self, mission: object) -> str:
        mapping = {
            "profit": "utility_seeking",
            "achievement": "disruption_seeking",
            "persistence": "stealth_seeking",
            "critical_hunter": "critical_path_seeking",
        }
        return mapping.get(str(mission), "")

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

        expected_utility = self._first_number(observed, ("expected_utility_mean", "expected_utility_mean_mean", "expected_utility_final", "expected_utility_final_mean"))
        critical_events = self._event_count(observed, "critical_path_events")

        critical_progress = self._bounded_sum(
            self._first_number(observed, ("critical_path_progress_count", "critical_path_progress_count_mean")) / 12.0,
            self._first_number(observed, ("critical_path_near_target_count", "critical_path_near_target_count_mean")) / 10.0,
            self._first_number(observed, ("critical_asset_reach_count", "critical_asset_reach_count_mean")) / 12.0,
            self._first_number(observed, ("critical_path_proximity", "critical_path_proximity_mean")),
            critical_events / 30.0,
            self._first_number(observed, ("critical_compromise_rate",)),
        )
        critical_focus = self._bounded_sum(
            self._first_number(observed, ("critical_node_visit_count", "critical_node_visit_count_mean")) / 50.0,
            self._first_number(observed, ("attacker_critical_true_gain_total", "attacker_critical_true_gain_total_mean")) / 20.0,
            self._first_number(observed, ("preferred_node_on_critical_path_rate",)),
        )
        critical_probe = self._bounded_sum(
            self._first_number(observed, ("critical_probe_count", "critical_probe_count_mean")) / 12.0,
            self._event_count(observed, "observable_events", {"critical_probe", "objective_action"}) / 24.0,
        )
        trust_collapse = self._bounded_sum(
            self._first_number(observed, ("trust_collapse_rate", "trust_collapse_rate_mean")),
            self._first_number(observed, ("credential_trap_trigger_count", "credential_trap_trigger_count_mean")) / 8.0,
            self._first_number(observed, ("fake_credential_usage_count", "fake_credential_usage_count_mean")) / 8.0,
        )
        stealth = self._bounded_sum(
            self._token_count(observed.get("adaptation_history"), {"stealth_lateral_shift", "observe"}) / 20.0,
            self._first_number(observed, ("deception_suspicion_score", "deception_suspicion_score_mean")),
            1.0 - self._first_number(observed, ("mean_attack_detection_prob", "mean_attack_detection_prob_mean")),
        )
        deception = self._bounded_sum(
            self._event_count(observed, "deception_history") / 10.0,
            self._first_number(observed, ("deception_event_count", "deception_event_count_mean")) / 8.0,
            self._first_number(observed, ("fake_path_follow_count", "fake_path_follow_count_mean")) / 8.0,
            self._first_number(observed, ("attacker_diversion_score", "attacker_diversion_score_mean")) / 1.0,
        )
        lateral = self._bounded_sum(
            self._first_number(observed, ("lateral_move_count", "lateral_move_count_mean")) / 40.0,
            self._event_count(observed, "observable_events", {"lateral_move", "credential_use"}) / 60.0,
            self._first_number(observed, ("alternative_path_usage", "alternative_path_usage_mean")) / 8.0,
        )
        adaptation = self._bounded_sum(
            self._first_number(observed, ("adaptation_count", "adaptation_count_mean")) / 8.0,
            self._token_count(observed.get("adaptation_history"), None) / 60.0,
        )
        ttp_change = self._first_number(observed, ("ttp_change_count", "ttp_change_count_mean")) / 8.0
        mission_mutation = self._first_number(observed, ("mission_change_count", "mission_change_count_mean", "mission_mutation_count")) / 8.0
        coalition = self._bounded_sum(
            self._first_number(observed, ("coalition_coordination_score", "coalition_coordination_score_mean")),
            self._first_number(observed, ("coordination_efficiency", "coordination_efficiency_mean")),
        )

        return {
            "attack_success_rate": float(np.clip(success, 0.0, 1.0)),
            "utility_activity": self._saturate_positive(actual_utility, 150.0),
            "expected_utility_activity": self._saturate_positive(expected_utility, 10.0),
            "deception_activity": deception,
            "adaptation_activity": adaptation,
            "ttp_change_activity": float(np.clip(ttp_change, 0.0, 1.0)),
            "coalition_activity": coalition,
            "critical_progress": critical_progress,
            "critical_focus": critical_focus,
            "critical_probe_activity": critical_probe,
            "stealth_activity": stealth,
            "trust_collapse_activity": trust_collapse,
            "lateral_movement_activity": lateral,
            "mission_mutation_activity": float(np.clip(mission_mutation, 0.0, 1.0)),
            "campaign_disruption_activity": self._first_number(observed, ("campaign_disruption_score", "campaign_disruption_score_mean")),
            "survival_activity": float(np.clip(1.0 - self._first_number(observed, ("retreat_rate", "retreat_rate_mean")), 0.0, 1.0)),
        }

    def _history_length(self, history: Mapping[str, Sequence[object]]) -> int:
        for key in ("actual_utility", "attacker_success", "observable_events", "mission_history"):
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
        values = np.asarray([float(raw_scores[profile]) for profile in self.profiles], dtype=float)
        values = values - float(np.max(values))
        exp_values = np.exp(values * 4.0)
        probs = exp_values / max(float(np.sum(exp_values)), 1e-12)
        return {profile: float(probs[idx]) for idx, profile in enumerate(self.profiles)}

    def _entropy(self, probabilities: Iterable[float]) -> float:
        values = [float(prob) for prob in probabilities if float(prob) > 0.0]
        if not values:
            return 0.0
        entropy = -sum(prob * math.log(prob) for prob in values)
        return float(np.clip(entropy / math.log(len(self.profiles)), 0.0, 1.0))
