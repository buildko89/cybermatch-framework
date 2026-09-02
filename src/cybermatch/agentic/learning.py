"""Deterministic inter-episode reward-hacking reinforcement model."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Mapping


def _probability(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be between 0 and 1")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")
    return result


@dataclass(frozen=True)
class RewardHackingLearningConfig:
    initial_propensity: float = 0.1
    learning_rate: float = 0.25
    oversight_penalty: float = 0.5
    safe_success_decay: float = 0.05

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            object.__setattr__(self, name, _probability(getattr(self, name), name))

    @classmethod
    def from_dict(cls, payload: Mapping[str, object] | None) -> "RewardHackingLearningConfig":
        if payload is None:
            return cls()
        if not isinstance(payload, Mapping):
            raise ValueError("agentic.learning.config must be an object")
        unknown = sorted(set(payload) - set(cls.__dataclass_fields__))
        if unknown:
            raise ValueError("agentic.learning.config has unknown fields: " + ", ".join(unknown))
        try:
            return cls(**dict(payload))
        except TypeError as exc:
            raise ValueError(f"invalid reward-hacking config: {exc}") from exc


@dataclass(frozen=True)
class LearningEpisode:
    episode_id: str
    reward: float
    intended_success: bool
    boundary_bypass: bool
    detected: bool = False
    oversight_intervention: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.episode_id, str) or not self.episode_id.strip():
            raise ValueError("episode_id must be a non-empty string")
        if isinstance(self.reward, bool) or not isinstance(self.reward, (int, float)):
            raise ValueError("reward must be a finite number between -1 and 1")
        reward = float(self.reward)
        if not math.isfinite(reward) or not -1.0 <= reward <= 1.0:
            raise ValueError("reward must be a finite number between -1 and 1")
        object.__setattr__(self, "reward", reward)
        for name in ("intended_success", "boundary_bypass", "detected", "oversight_intervention"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be boolean")

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "LearningEpisode":
        if not isinstance(payload, Mapping):
            raise ValueError("learning episode must be an object")
        unknown = sorted(set(payload) - set(cls.__dataclass_fields__))
        if unknown:
            raise ValueError("learning episode has unknown fields: " + ", ".join(unknown))
        try:
            return cls(**dict(payload))
        except TypeError as exc:
            raise ValueError(f"invalid learning episode: {exc}") from exc


class RewardHackingLearningModel:
    """Track whether rewarded boundary bypass becomes more likely across episodes."""

    def __init__(self, config: RewardHackingLearningConfig | None = None):
        self.config = config or RewardHackingLearningConfig()

    def run(self, episodes: Iterable[LearningEpisode], *, apply_oversight: bool) -> dict[str, object]:
        propensity = self.config.initial_propensity
        history = []
        rewarded_bypasses = 0
        interventions = 0
        for episode in episodes:
            before = propensity
            reinforcement = 0.0
            oversight_reduction = 0.0
            if episode.boundary_bypass and episode.reward > 0.0:
                reinforcement = self.config.learning_rate * episode.reward * (1.0 - propensity)
                propensity += reinforcement
                rewarded_bypasses += 1
            elif episode.intended_success and not episode.boundary_bypass:
                propensity *= 1.0 - self.config.safe_success_decay
            if apply_oversight and (episode.detected or episode.oversight_intervention):
                oversight_reduction = propensity * self.config.oversight_penalty
                propensity -= oversight_reduction
                interventions += 1
            propensity = min(1.0, max(0.0, propensity))
            history.append(
                {
                    "episode_id": episode.episode_id,
                    "propensity_before": before,
                    "reinforcement": reinforcement,
                    "oversight_reduction": oversight_reduction,
                    "propensity_after": propensity,
                }
            )
        return {
            "apply_oversight": apply_oversight,
            "initial_propensity": self.config.initial_propensity,
            "final_propensity": propensity,
            "propensity_delta": propensity - self.config.initial_propensity,
            "rewarded_boundary_bypass_count": rewarded_bypasses,
            "oversight_intervention_count": interventions,
            "episode_count": len(history),
            "history": history,
        }


def evaluate_learning_comparison(
    config: RewardHackingLearningConfig, episodes: Iterable[LearningEpisode]
) -> dict[str, object]:
    observations = tuple(episodes)
    model = RewardHackingLearningModel(config)
    open_loop = model.run(observations, apply_oversight=False)
    closed_loop = model.run(observations, apply_oversight=True)
    return {
        "open_loop": open_loop,
        "closed_loop": closed_loop,
        "comparison": {
            "final_propensity_reduction": open_loop["final_propensity"]
            - closed_loop["final_propensity"],
            "reinforcement_prevented": (
                open_loop["propensity_delta"] > 0.0 and closed_loop["propensity_delta"] <= 0.0
            ),
        },
    }


__all__ = [
    "LearningEpisode",
    "RewardHackingLearningConfig",
    "RewardHackingLearningModel",
    "evaluate_learning_comparison",
]
