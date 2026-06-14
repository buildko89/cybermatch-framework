import pytest


SLOW_TEST_NAME_TOKENS = (
    "outputs",
    "output_",
    "multiseed",
    "multi_seed",
    "plots_created",
    "summary_created",
    "summary_contains",
    "best_policy_json_created",
    "run_scenarios_creates",
    "targeted_neutralization_evaluation",
)


def pytest_collection_modifyitems(items):
    for item in items:
        name = item.name
        if "phase92" in name or "feature_space" in name:
            item.add_marker(pytest.mark.phase92)
            item.add_marker(pytest.mark.feature)
        elif "phase91" in name or "behavior_profile" in name or "behavior" in name:
            item.add_marker(pytest.mark.phase91)
            item.add_marker(pytest.mark.behavior)
        elif "phase90" in name or "intent" in name or "mission_inference" in name:
            item.add_marker(pytest.mark.phase90)
            item.add_marker(pytest.mark.intent)
        elif "phase51" in name or "phase52" in name or "phase53" in name or "phase54" in name or "phase55" in name or "coalition" in name or "counter_deception" in name or "awareness" in name or "hunting" in name:
            item.add_marker(pytest.mark.phase5)
        elif "phase4" in name or any(f"phase4{suffix}" in name for suffix in range(7, 26)):
            item.add_marker(pytest.mark.phase4)
        elif "phase3" in name:
            item.add_marker(pytest.mark.phase3)
        elif "phase2" in name or "cognitive" in name or "cns" in name or "frustration" in name or "ai_" in name:
            item.add_marker(pytest.mark.phase2)
        else:
            item.add_marker(pytest.mark.phase1)

        if any(token in name for token in SLOW_TEST_NAME_TOKENS):
            item.add_marker(pytest.mark.slow)
        else:
            item.add_marker(pytest.mark.smoke)
