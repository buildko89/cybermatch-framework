"""Run CyberMatch Phase4 publication evaluations."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from typing import Any

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from run_scenarios import (  # noqa: E402
    run_phase4_adaptive_defender_evaluation,
    run_phase4_cns_guided_evaluation,
    run_phase4_nonstationary_evaluation,
    run_phase4_specialized_policy_evaluation,
    run_phase4_step_adaptive_evaluation,
    run_phase4_switch_benefit_evaluation,
    run_phase47_mission_profile_evaluation,
    run_phase48_mission_aware_evaluation,
    run_phase49_mission_belief_evaluation,
    run_phase410_state_belief_evaluation,
    run_phase411_virtual_topology_evaluation,
    run_phase412_critical_path_evaluation,
    run_phase413_intelligence_defender_evaluation,
    run_phase414_weight_sweep_evaluation,
    run_phase415_decision_matrix_evaluation,
    run_phase416_defense_campaign_evaluation,
    run_phase417_campaign_profile_evaluation,
    run_phase418_mission_objective_evaluation,
    run_phase419_mission_sensitivity_evaluation,
    run_phase420_adaptive_mission_evaluation,
    run_phase421_mission_mutation_evaluation,
    run_phase422_adaptive_intelligence_defender,
    run_phase423_intent_deception_evaluation,
    run_phase424_signal_extraction_evaluation,
    run_phase425_adversarial_signal_evaluation,
)


PhaseRunner = Callable[..., list[dict[str, object]]]


def _parse_seeds(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def _run_phase(
    label: str,
    runner: PhaseRunner,
    *,
    seeds: list[int],
    output_dir: str,
    config_path: str,
    **kwargs: Any,
) -> int:
    print(f"Running {label}...")
    rows = runner(seeds=seeds, output_dir=output_dir, config_path=config_path, **kwargs)
    print(f"{label} rows: {len(rows)}")
    return len(rows)


def _quick_plan() -> list[tuple[str, PhaseRunner, str, dict[str, Any]]]:
    return [
        (
            "Phase4.13 Intelligence Defender",
            run_phase413_intelligence_defender_evaluation,
            "phase413_intelligence_defender",
            {},
        ),
        (
            "Phase4.18 Mission Objectives",
            run_phase418_mission_objective_evaluation,
            "phase418_mission_objectives",
            {},
        ),
        (
            "Phase4.22 Adaptive Intelligence Defender",
            run_phase422_adaptive_intelligence_defender,
            "phase422_adaptive_intelligence",
            {"strategy_profiles": ["balanced"]},
        ),
        (
            "Phase4.25 Adversarial Signal",
            run_phase425_adversarial_signal_evaluation,
            "phase425_adversarial_signal",
            {"strategy_profiles": ["balanced"]},
        ),
    ]


def _publication_plan() -> list[tuple[str, PhaseRunner, str, dict[str, Any]]]:
    return [
        ("Phase4.1 Adaptive Defender", run_phase4_adaptive_defender_evaluation, "phase4_adaptive_defender", {}),
        ("Phase4.2 CNS-Guided Defense", run_phase4_cns_guided_evaluation, "phase4_cns_guided", {}),
        ("Phase4.3 Step-Adaptive Defense", run_phase4_step_adaptive_evaluation, "phase4_step_adaptive", {}),
        ("Phase4.4 Nonstationary Attacker", run_phase4_nonstationary_evaluation, "phase4_nonstationary", {}),
        ("Phase4.5 Switching Benefit", run_phase4_switch_benefit_evaluation, "phase4_switch_benefit", {}),
        ("Phase4.6 Specialized Policy", run_phase4_specialized_policy_evaluation, "phase4_specialized_policy", {}),
        ("Phase4.7 Mission Profiles", run_phase47_mission_profile_evaluation, "phase47_mission_profiles", {}),
        ("Phase4.8 Mission-Aware Defense", run_phase48_mission_aware_evaluation, "phase48_mission_aware", {}),
        ("Phase4.9 Mission Belief", run_phase49_mission_belief_evaluation, "phase49_mission_belief", {}),
        ("Phase4.10 State Belief", run_phase410_state_belief_evaluation, "phase410_state_belief", {}),
        ("Phase4.11 Virtual Topology", run_phase411_virtual_topology_evaluation, "phase411_virtual_topology", {}),
        ("Phase4.12 Critical Path", run_phase412_critical_path_evaluation, "phase412_critical_path", {}),
        ("Phase4.13 Intelligence Defender", run_phase413_intelligence_defender_evaluation, "phase413_intelligence_defender", {}),
        ("Phase4.14 Weight Sweep", run_phase414_weight_sweep_evaluation, "phase414_weight_sweep", {}),
        ("Phase4.15 Decision Matrix", run_phase415_decision_matrix_evaluation, "phase415_decision_matrix", {}),
        ("Phase4.16 Defense Campaign", run_phase416_defense_campaign_evaluation, "phase416_defense_campaign", {}),
        ("Phase4.17 Campaign Profiles", run_phase417_campaign_profile_evaluation, "phase417_campaign_profiles", {}),
        ("Phase4.18 Mission Objectives", run_phase418_mission_objective_evaluation, "phase418_mission_objectives", {}),
        ("Phase4.19 Mission Sensitivity", run_phase419_mission_sensitivity_evaluation, "phase419_mission_sensitivity", {}),
        ("Phase4.20 Adaptive Mission", run_phase420_adaptive_mission_evaluation, "phase420_adaptive_mission", {}),
        ("Phase4.21 Mission Mutation", run_phase421_mission_mutation_evaluation, "phase421_mission_mutation", {}),
        ("Phase4.22 Adaptive Intelligence", run_phase422_adaptive_intelligence_defender, "phase422_adaptive_intelligence", {}),
        ("Phase4.23 Intent Deception", run_phase423_intent_deception_evaluation, "phase423_intent_deception", {}),
        ("Phase4.24 Signal Extraction", run_phase424_signal_extraction_evaluation, "phase424_signal_extraction", {}),
        ("Phase4.25 Adversarial Signal", run_phase425_adversarial_signal_evaluation, "phase425_adversarial_signal", {}),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CyberMatch Phase4 evaluations.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="Run representative Phase4 publication milestones.")
    mode.add_argument("--publication", action="store_true", help="Run the full Phase4.1-Phase4.25 publication workflow.")
    parser.add_argument("--seeds", default="0", help="Comma-separated seed list. Default: 0")
    parser.add_argument("--output-dir", default=os.path.join("output", "phase4_publication"))
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    seeds = _parse_seeds(args.seeds)
    plan = _publication_plan() if args.publication else _quick_plan()
    mode_name = "publication" if args.publication else "quick"

    total_rows = 0
    for label, runner, directory_name, kwargs in plan:
        total_rows += _run_phase(
            label,
            runner,
            seeds=seeds,
            output_dir=os.path.join(args.output_dir, directory_name),
            config_path=args.config,
            **kwargs,
        )

    print(f"Phase4 {mode_name} workflow complete.")
    print(f"Total rows: {total_rows}")
    print(f"Outputs written below {args.output_dir}")


if __name__ == "__main__":
    main()
