from __future__ import annotations

from apps.streamlit_app import (
    ROOT,
    build_phase63_command,
    demo_selection_values,
    list_demo_scenario_files,
    load_product_profiles,
    normalized_option_selection,
)
from scenario_loader import load_scenario


def test_demo_scenarios_validate_and_are_listed():
    demo_files = list_demo_scenario_files()

    assert [path.name for path in demo_files] == [
        "demo_deception_value.json",
        "demo_ot_factory_defense.json",
        "demo_vendor_comparison.json",
    ]
    for demo_path in demo_files:
        scenario = load_scenario(str(demo_path))
        assert scenario["evaluation"]["runner"] == "phase63_mission_aware_product"


def test_demo_selection_values_match_vendor_comparison_definition():
    values = demo_selection_values(next(path for path in list_demo_scenario_files() if path.stem == "demo_vendor_comparison"))

    assert values == {
        "missions": ["profit", "achievement"],
        "products": [
            "profiles/products/sample_ids.json",
            "profiles/products/sample_ips.json",
            "profiles/products/sample_xdr.json",
        ],
        "topology_preset": "enterprise",
        "seeds": [0],
    }


def test_gui_profile_paths_are_normalized_for_windows_session_values():
    profile_paths = [row["file"] for row in load_product_profiles()]

    selected = normalized_option_selection(
        ["profiles\\products\\sample_ids.json", "profiles/products/missing.json"],
        profile_paths,
        path_values=True,
    )

    assert selected == ["profiles/products/sample_ids.json"]
    assert all("\\" not in profile_path for profile_path in profile_paths)


def test_gui_selection_filters_legacy_all_mission_and_uses_quick_seed():
    assert normalized_option_selection(["all", "profit"], ["profit", "achievement"]) == ["profit"]

    command = build_phase63_command(
        ROOT / "topologies" / "enterprise.json",
        ["profit"],
        ["profiles/products/sample_ids.json"],
    )

    assert command[-2:] == ["--seed", "0"]
    assert "profiles/products/sample_ids.json" in command
