import pytest

from src.cybermatch.agentic.learning import (
    LearningEpisode,
    RewardHackingLearningConfig,
    evaluate_learning_comparison,
)


pytestmark = pytest.mark.agentic_security


def test_rewarded_boundary_bypass_reinforces_across_episodes_without_oversight():
    config = RewardHackingLearningConfig(initial_propensity=0.2, learning_rate=0.5)
    episodes = (
        LearningEpisode("one", 1.0, False, True),
        LearningEpisode("two", 1.0, True, True),
    )

    result = evaluate_learning_comparison(config, episodes)

    assert result["open_loop"]["final_propensity"] == pytest.approx(0.8)
    assert result["open_loop"]["history"][1]["propensity_before"] == pytest.approx(0.6)


def test_oversight_counteracts_inter_episode_reward_hacking():
    config = RewardHackingLearningConfig(
        initial_propensity=0.2,
        learning_rate=0.5,
        oversight_penalty=0.75,
    )
    episodes = (
        LearningEpisode("one", 1.0, False, True, detected=True),
        LearningEpisode("two", 1.0, True, True, oversight_intervention=True),
    )

    result = evaluate_learning_comparison(config, episodes)

    assert result["closed_loop"]["final_propensity"] < result["open_loop"]["final_propensity"]
    assert result["comparison"]["final_propensity_reduction"] > 0.0
    assert result["comparison"]["reinforcement_prevented"] is True
