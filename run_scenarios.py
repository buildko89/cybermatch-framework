import csv
import json
import os
from dataclasses import asdict
from typing import Dict, List, Optional

import matplotlib.pyplot as plt
import numpy as np

from cybermatch import CyberDefenseSimulator, SimulationConfig, Visualizer


RUN_MULTI_SEED = True
MULTI_SEED_VALUES = list(range(10))
GATED_EDGE_PRESSURE_SWEEP_SCENARIO_NAMES = [
    "gated_edge_pressure_threshold_3",
    "gated_edge_pressure_threshold_5",
    "gated_edge_pressure_threshold_7",
    "gated_edge_pressure_threshold_10",
    "gated_edge_pressure_threshold_15",
    "gated_edge_pressure_cooldown_0",
    "gated_edge_pressure_cooldown_3",
    "gated_edge_pressure_cooldown_5",
    "gated_edge_pressure_cooldown_10",
    "gated_edge_pressure_duration_1",
    "gated_edge_pressure_duration_2",
    "gated_edge_pressure_count_1",
    "gated_edge_pressure_count_2",
]
GATED_EDGE_PRESSURE_HYBRID_SCENARIO_NAMES = [
    "gated_edge_pressure_count2_duration2",
    "gated_edge_pressure_count2_duration2_threshold5",
    "gated_edge_pressure_count2_duration2_threshold7",
    "gated_edge_pressure_count2_duration2_cooldown0",
    "gated_edge_pressure_count2_duration2_cooldown5",
    "gated_edge_pressure_count2_duration2_interval10",
    "gated_edge_pressure_count2_duration1_threshold7",
    "gated_edge_pressure_count1_duration2_threshold7",
]
CONDITIONAL_MTD_SCENARIO_NAMES = [
    "gated_edge_conditional_split_5_10",
    "gated_edge_conditional_split_3_7",
    "gated_edge_conditional_split_7_12",
    "gated_edge_conditional_split_5_15",
    "gated_edge_conditional_critical_vs_post_decoy",
]
HONEYPOT_CREDENTIAL_SCENARIO_NAMES = [
    "honeypot_credential_reference",
    "honeypot_credential_low_bonus",
    "honeypot_credential_high_bonus",
    "honeypot_credential_high_detection",
    "honeypot_credential_path_decoy",
    "honeypot_credential_edge_mtd",
]
CREDENTIAL_AWARE_MTD_SCENARIO_NAMES = [
    "credential_aware_mtd_reference",
    "credential_aware_mtd_force_count2",
    "credential_aware_mtd_force_duration2",
    "credential_aware_mtd_risk_bonus",
    "credential_aware_mtd_window1",
    "credential_aware_mtd_window5",
    "credential_aware_mtd_edge_pressure",
]
CREDENTIAL_STAGED_MTD_SCENARIO_NAMES = [
    "credential_staged_mtd_1_5",
    "credential_staged_mtd_0_3",
    "credential_staged_mtd_1_3",
    "credential_staged_mtd_2_5",
    "credential_staged_mtd_stage1_only",
    "credential_staged_mtd_stage2_only",
    "credential_staged_mtd_with_risk_bonus",
]
PHASE2_PERCEIVED_UTILITY_SCENARIO_NAMES = [
    "phase2_actual_utility_reference",
    "phase2_perceived_decoy",
    "phase2_perceived_credential",
    "phase2_perceived_decoy_credential",
    "phase2_perceived_high_uncertainty",
]
PHASE2_FRUSTRATION_SCENARIO_NAMES = [
    "phase2_frustration_reference",
    "phase2_frustration_decoy",
    "phase2_frustration_credential",
    "phase2_frustration_decoy_credential",
    "phase2_frustration_high_detection",
    "phase2_frustration_path_change",
]
PHASE2_AI_COST_SCENARIO_NAMES = [
    "phase2_ai_cost_reference",
    "phase2_ai_high_uncertainty",
    "phase2_ai_high_trust_degradation",
    "phase2_ai_high_operational_risk",
    "phase2_ai_low_replanning_cost",
    "phase2_ai_balanced",
]
POLICY_SELECTION_SCENARIO_NAMES = [
    "policy_target_frequency_path_decoy",
    "policy_bayesian_default_path_decoy",
    "policy_bayesian_success30_path_decoy",
    "policy_bayesian_decay090_path_decoy",
    "policy_bayesian_edge_mtd",
    "policy_path_decoy_edge_mtd",
    "policy_lateral_multi_decoy",
    "policy_gated_edge_mtd_critical_path",
    "policy_gated_edge_mtd_chokepoint",
    "policy_gated_edge_mtd_edge_pressure",
    "policy_gated_edge_mtd_low_threshold",
    "policy_gated_edge_mtd_high_threshold",
    "gated_edge_pressure_threshold_3",
    "gated_edge_pressure_threshold_5",
    "gated_edge_pressure_threshold_10",
    "gated_edge_pressure_cooldown_5",
    "gated_edge_pressure_duration_2",
    "gated_edge_pressure_count_2",
    "gated_edge_pressure_count2_duration2",
    "gated_edge_pressure_count2_duration2_threshold7",
    "gated_edge_pressure_count2_duration2_cooldown5",
    "gated_edge_pressure_count2_duration2_interval10",
    "gated_edge_pressure_count2_duration1_threshold7",
    "gated_edge_pressure_count1_duration2_threshold7",
    "gated_edge_conditional_split_5_10",
    "gated_edge_conditional_split_3_7",
    "gated_edge_conditional_split_7_12",
    "gated_edge_conditional_split_5_15",
    "credential_aware_mtd_force_count2",
    "credential_aware_mtd_force_duration2",
    "credential_aware_mtd_risk_bonus",
    "credential_aware_mtd_window1",
    "credential_aware_mtd_window5",
    "credential_staged_mtd_1_5",
    "credential_staged_mtd_0_3",
    "credential_staged_mtd_1_3",
    "credential_staged_mtd_2_5",
    "credential_staged_mtd_stage1_only",
    "credential_staged_mtd_stage2_only",
    "credential_staged_mtd_with_risk_bonus",
]
NEUTRALIZATION_SCENARIO_MAP = {
    "baseline": "lateral_baseline",
    "naive_decoy": "lateral_decoy",
    "path_aware_decoy": "lateral_decoy_on_chokepoint",
    "gated_edge_pressure_count_2": "gated_edge_pressure_count_2",
    "gated_edge_pressure_duration_2": "gated_edge_pressure_duration_2",
    "credential_aware_mtd": "credential_aware_mtd_edge_pressure",
    "current_best_policy": "policy_gated_edge_mtd_edge_pressure",
}
NEUTRALIZATION_COLUMNS = [
    "label",
    "scenario",
    "neutralization_score",
    "critical_protection_score",
    "utility_suppression_score",
    "deception_waste_score",
    "friction_score",
    "retreat_score",
    "critical_compromise",
    "critical_compromise_step",
    "attacker_utility_final",
    "attacker_decoy_attack_rate",
    "credential_trigger_rate",
    "mtd_event_count",
    "mtd_edge_block_events",
    "mtd_edge_block_active_steps",
    "post_decoy_real_attack_count",
    "post_decoy_attack_count",
    "attacker_retreated",
    "attacker_retreat_step",
]
MULTI_SEED_SCENARIO_NAMES = [
    "decoy_node2_probabilistic_default",
    "decoy_node2_probabilistic_low_decoy_detection",
    "decoy_node2_probabilistic_high_decoy_success",
    "real_attack_probabilistic_low_detection",
    "adaptive_decoy_node2_learning_no_immediate_retreat",
    "adaptive_real_low_detection_learning",
    "adaptive_decoy_node2_learning_no_immediate_retreat_defense_aware",
    "adaptive_decoy_node2_learning_no_immediate_retreat_defense_aware_high_weight",
    "adaptive_decoy_node2_defense_matching_only",
    "adaptive_decoy_node2_defense_mpc_q",
    "adaptive_decoy_node2_defense_all",
    "adaptive_decoy_defense_estimated_belief_target_freq",
    "adaptive_decoy_defense_estimated_belief_hybrid",
    "adaptive_decoy_defense_oracle_belief_reference",
    "adaptive_decoy_defense_estimated_belief_visible_log",
    "adaptive_decoy_defense_estimated_belief_hybrid_visible",
    "mtd_none_reference",
    "mtd_shuffle_belief",
    "mtd_decay_belief",
    "mtd_increase_uncertainty",
    "mtd_shuffle_belief_high_intensity",
    "mtd_shuffle_belief_short_interval",
    "mtd_sweep_shuffle_interval_5",
    "mtd_sweep_shuffle_interval_10",
    "mtd_sweep_shuffle_interval_20",
    "mtd_sweep_shuffle_intensity_02",
    "mtd_sweep_shuffle_intensity_05",
    "mtd_sweep_shuffle_intensity_09",
    "mtd_sweep_target_frequency",
    "mtd_sweep_visible_log",
    "mtd_sweep_hybrid_visible",
    "lateral_baseline",
    "lateral_decoy",
    "lateral_decoy_mtd",
    "lateral_decoy_mtd_interval5",
    "lateral_decoy_mtd_interval20",
    "lateral_decoy_on_chokepoint",
    "lateral_decoy_on_server_path",
    "lateral_multi_decoy_path",
    "lateral_edge_mtd_chokepoint",
    "lateral_edge_mtd_interval5",
    "lateral_path_decoy_edge_mtd",
    "bayesian_lateral_path_decoy",
    "bayesian_lateral_path_decoy_edge_mtd",
    "bayesian_vs_target_frequency_reference",
    "bayesian_high_critical_path_likelihood",
    "bayesian_low_decay",
    "bayesian_sweep_success_likelihood_10",
    "bayesian_sweep_success_likelihood_30",
    "bayesian_sweep_decoy_likelihood_01",
    "bayesian_sweep_decoy_likelihood_05",
    "bayesian_sweep_critical_path_likelihood_10",
    "bayesian_sweep_critical_path_likelihood_30",
    "bayesian_sweep_decay_090",
    "bayesian_sweep_decay_100",
    "bayesian_defense_objective_default",
    "bayesian_defense_objective_high_critical_weight",
    "bayesian_defense_objective_high_delay_reward",
    "bayesian_defense_objective_low_post_decoy_weight",
    "bayesian_defense_objective_edge_mtd",
    *POLICY_SELECTION_SCENARIO_NAMES,
    *[name for name in GATED_EDGE_PRESSURE_SWEEP_SCENARIO_NAMES if name not in POLICY_SELECTION_SCENARIO_NAMES],
    *[name for name in GATED_EDGE_PRESSURE_HYBRID_SCENARIO_NAMES if name not in POLICY_SELECTION_SCENARIO_NAMES],
    *[name for name in CONDITIONAL_MTD_SCENARIO_NAMES if name not in POLICY_SELECTION_SCENARIO_NAMES],
    *HONEYPOT_CREDENTIAL_SCENARIO_NAMES,
    *[name for name in CREDENTIAL_AWARE_MTD_SCENARIO_NAMES if name not in POLICY_SELECTION_SCENARIO_NAMES],
    *[name for name in CREDENTIAL_STAGED_MTD_SCENARIO_NAMES if name not in POLICY_SELECTION_SCENARIO_NAMES],
    *PHASE2_PERCEIVED_UTILITY_SCENARIO_NAMES,
    *PHASE2_FRUSTRATION_SCENARIO_NAMES,
    *PHASE2_AI_COST_SCENARIO_NAMES,
]

SCENARIOS: Dict[str, Dict[str, object]] = {
    "baseline_no_attacker": {
        "attacker_enabled": False,
    },
    "attacker_greedy_default": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
    },
    "attacker_random_default": {
        "attacker_enabled": True,
        "attacker_target_selection": "random",
    },
    "attacker_greedy_high_detection_penalty": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_detection_penalty": 10.0,
    },
    "attacker_greedy_low_retreat_threshold": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_retreat_threshold": -20.0,
    },
    "attacker_greedy_short_patience": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_patience": 3,
    },
    "attacker_greedy_legacy": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "legacy",
    },
    "attacker_greedy_weighted_risk": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "weighted_risk",
    },
    "attacker_greedy_utility": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
    },
    "attacker_greedy_utility_high_defense_cost": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "attacker_defense_cost_rate": 5.0,
    },
    "attacker_greedy_utility_high_detection_sensitivity": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "attacker_detection_sensitivity": 5.0,
    },
    "attacker_belief_matches_asset_value": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "asset_value": [10.0, 5.0, 1.0, 8.0, 2.0],
        "attacker_belief": [10.0, 5.0, 1.0, 8.0, 2.0],
    },
    "attacker_belief_misled_to_low_value": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "asset_value": [10.0, 5.0, 1.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
    },
    "attacker_belief_overvalues_node4": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "asset_value": [10.0, 5.0, 1.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 1.0, 4.0, 12.0],
    },
    "attacker_belief_underestimates_node0": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "asset_value": [10.0, 5.0, 1.0, 8.0, 2.0],
        "attacker_belief": [1.0, 5.0, 1.0, 8.0, 2.0],
    },
    "decoy_none_reference": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "node_type": ["real", "real", "real", "real", "real"],
        "asset_value": [10.0, 5.0, 1.0, 8.0, 2.0],
        "attacker_belief": [10.0, 5.0, 1.0, 8.0, 2.0],
    },
    "decoy_node2_high_belief": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "decoy_waste_cost": 2.0,
        "decoy_detection_bonus": 3.0,
        "decoy_success_gain_scale": 0.0,
    },
    "decoy_node4_high_belief": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "node_type": ["real", "real", "real", "real", "decoy"],
        "asset_value": [10.0, 5.0, 1.0, 8.0, 0.0],
        "attacker_belief": [2.0, 3.0, 1.0, 4.0, 12.0],
        "decoy_waste_cost": 2.0,
        "decoy_success_gain_scale": 0.0,
    },
    "decoy_node2_high_waste": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "decoy_waste_cost": 10.0,
        "decoy_success_gain_scale": 0.0,
    },
    "decoy_node2_high_detection": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "decoy_detection_bonus": 10.0,
        "decoy_success_gain_scale": 0.0,
    },
    "decoy_node2_probabilistic_default": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "decoy_detection_prob": 0.9,
        "decoy_success_prob": 0.1,
        "decoy_waste_cost": 2.0,
        "decoy_success_gain_scale": 0.0,
    },
    "decoy_node2_probabilistic_low_decoy_detection": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "decoy_detection_prob": 0.3,
        "decoy_success_prob": 0.1,
        "decoy_waste_cost": 2.0,
        "decoy_success_gain_scale": 0.0,
    },
    "decoy_node2_probabilistic_high_decoy_success": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "decoy_detection_prob": 0.9,
        "decoy_success_prob": 0.5,
        "decoy_waste_cost": 2.0,
        "decoy_success_gain_scale": 0.2,
    },
    "real_attack_probabilistic_low_detection": {
        "attacker_enabled": True,
        "attacker_target_selection": "greedy",
        "attacker_greedy_mode": "utility",
        "node_type": ["real", "real", "real", "real", "real"],
        "asset_value": [10.0, 5.0, 1.0, 8.0, 2.0],
        "attacker_belief": [10.0, 5.0, 1.0, 8.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "base_detection_prob": 0.05,
        "defense_detection_scale": 0.05,
    },
    "adaptive_decoy_node2_learning": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "decoy_waste_cost": 2.0,
        "decoy_detection_prob": 0.9,
        "stochastic_detection": True,
        "stochastic_success": True,
    },
    "adaptive_decoy_node2_learning_no_immediate_retreat": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "decoy_waste_cost": 2.0,
        "stochastic_detection": True,
        "stochastic_success": True,
    },
    "adaptive_real_low_detection_learning": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "node_type": ["real", "real", "real", "real", "real"],
        "asset_value": [10.0, 5.0, 1.0, 8.0, 2.0],
        "attacker_belief": [10.0, 5.0, 1.0, 8.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "base_detection_prob": 0.05,
        "defense_detection_scale": 0.05,
    },
    "adaptive_decoy_node2_learning_no_immediate_retreat_defense_aware": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 1.0,
        "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True,
    },
    "adaptive_decoy_node2_learning_no_immediate_retreat_defense_aware_k1": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 1.0,
        "post_decoy_defense_top_k": 1,
        "post_decoy_defense_exclude_decoy": True,
    },
    "adaptive_decoy_node2_learning_no_immediate_retreat_defense_aware_high_weight": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 3.0,
        "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True,
    },
    "adaptive_decoy_node2_defense_matching_only": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 3.0,
        "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True,
        "post_decoy_defense_injection_mode": "matching_only",
    },
    "adaptive_decoy_node2_defense_fallback_only": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 3.0,
        "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True,
        "post_decoy_defense_injection_mode": "fallback_only",
    },
    "adaptive_decoy_node2_defense_mpc_q": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 3.0,
        "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True,
        "post_decoy_defense_injection_mode": "mpc_q",
    },
    "adaptive_decoy_node2_defense_all": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 3.0,
        "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True,
        "post_decoy_defense_injection_mode": "all",
    },
    "adaptive_decoy_defense_oracle_belief_reference": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 3.0,
        "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True,
        "post_decoy_defense_injection_mode": "matching_only",
        "post_decoy_defense_belief_source": "attacker",
        "defender_belief_estimation_enabled": False,
    },
    "adaptive_decoy_defense_estimated_belief_target_freq": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 3.0,
        "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True,
        "post_decoy_defense_injection_mode": "matching_only",
        "post_decoy_defense_belief_source": "estimated",
        "defender_belief_estimation_enabled": True,
        "defender_belief_observation_mode": "target_frequency",
    },
    "adaptive_decoy_defense_estimated_belief_score": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 3.0,
        "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True,
        "post_decoy_defense_injection_mode": "matching_only",
        "post_decoy_defense_belief_source": "estimated",
        "defender_belief_estimation_enabled": True,
        "defender_belief_observation_mode": "selection_score",
    },
    "adaptive_decoy_defense_estimated_belief_hybrid": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 3.0,
        "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True,
        "post_decoy_defense_injection_mode": "matching_only",
        "post_decoy_defense_belief_source": "estimated",
        "defender_belief_estimation_enabled": True,
        "defender_belief_observation_mode": "hybrid",
    },
    "adaptive_decoy_defense_estimated_belief_visible_log": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 3.0,
        "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True,
        "post_decoy_defense_injection_mode": "matching_only",
        "post_decoy_defense_belief_source": "estimated",
        "defender_belief_estimation_enabled": True,
        "defender_belief_observation_mode": "defender_visible_log",
    },
    "adaptive_decoy_defense_estimated_belief_hybrid_visible": {
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True,
        "attacker_retreat_threshold": -50.0,
        "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"],
        "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
        "stochastic_detection": True,
        "stochastic_success": True,
        "post_decoy_defense_enabled": True,
        "post_decoy_defense_weight": 3.0,
        "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True,
        "post_decoy_defense_injection_mode": "matching_only",
        "post_decoy_defense_belief_source": "estimated",
        "defender_belief_estimation_enabled": True,
        "defender_belief_observation_mode": "hybrid_visible",
    },
    "mtd_none_reference": {
        "attacker_enabled": True, "attacker_target_selection": "adaptive", "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True, "attacker_retreat_threshold": -50.0, "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"], "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0], "stochastic_detection": True, "stochastic_success": True,
        "post_decoy_defense_enabled": True, "post_decoy_defense_weight": 3.0, "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True, "post_decoy_defense_injection_mode": "matching_only",
        "post_decoy_defense_belief_source": "estimated", "defender_belief_estimation_enabled": True,
        "defender_belief_observation_mode": "target_frequency", "mtd_enabled": False,
    },
    "mtd_shuffle_belief": {
        "attacker_enabled": True, "attacker_target_selection": "adaptive", "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True, "attacker_retreat_threshold": -50.0, "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"], "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0], "stochastic_detection": True, "stochastic_success": True,
        "post_decoy_defense_enabled": True, "post_decoy_defense_weight": 3.0, "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True, "post_decoy_defense_injection_mode": "matching_only",
        "post_decoy_defense_belief_source": "estimated", "defender_belief_estimation_enabled": True,
        "defender_belief_observation_mode": "target_frequency", "mtd_enabled": True, "mtd_strategy": "shuffle_belief",
        "mtd_interval": 10, "mtd_intensity": 0.5,
    },
    "mtd_decay_belief": {
        "attacker_enabled": True, "attacker_target_selection": "adaptive", "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True, "attacker_retreat_threshold": -50.0, "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"], "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0], "stochastic_detection": True, "stochastic_success": True,
        "post_decoy_defense_enabled": True, "post_decoy_defense_weight": 3.0, "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True, "post_decoy_defense_injection_mode": "matching_only",
        "post_decoy_defense_belief_source": "estimated", "defender_belief_estimation_enabled": True,
        "defender_belief_observation_mode": "target_frequency", "mtd_enabled": True, "mtd_strategy": "decay_belief",
        "mtd_interval": 10, "mtd_intensity": 0.3,
    },
    "mtd_increase_uncertainty": {
        "attacker_enabled": True, "attacker_target_selection": "adaptive", "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True, "attacker_retreat_threshold": -50.0, "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"], "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0], "stochastic_detection": True, "stochastic_success": True,
        "post_decoy_defense_enabled": True, "post_decoy_defense_weight": 3.0, "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True, "post_decoy_defense_injection_mode": "matching_only",
        "post_decoy_defense_belief_source": "estimated", "defender_belief_estimation_enabled": True,
        "defender_belief_observation_mode": "target_frequency", "mtd_enabled": True, "mtd_strategy": "increase_uncertainty",
        "mtd_interval": 10, "mtd_intensity": 0.5,
    },
    "mtd_shuffle_belief_high_intensity": {
        "attacker_enabled": True, "attacker_target_selection": "adaptive", "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True, "attacker_retreat_threshold": -50.0, "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"], "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0], "stochastic_detection": True, "stochastic_success": True,
        "post_decoy_defense_enabled": True, "post_decoy_defense_weight": 3.0, "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True, "post_decoy_defense_injection_mode": "matching_only",
        "post_decoy_defense_belief_source": "estimated", "defender_belief_estimation_enabled": True,
        "defender_belief_observation_mode": "target_frequency", "mtd_enabled": True, "mtd_strategy": "shuffle_belief",
        "mtd_interval": 10, "mtd_intensity": 0.9,
    },
    "mtd_shuffle_belief_short_interval": {
        "attacker_enabled": True, "attacker_target_selection": "adaptive", "attacker_greedy_mode": "utility",
        "attacker_belief_learning_enabled": True, "attacker_retreat_threshold": -50.0, "attacker_patience": 20,
        "node_type": ["real", "real", "decoy", "real", "real"], "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
        "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0], "stochastic_detection": True, "stochastic_success": True,
        "post_decoy_defense_enabled": True, "post_decoy_defense_weight": 3.0, "post_decoy_defense_top_k": 2,
        "post_decoy_defense_exclude_decoy": True, "post_decoy_defense_injection_mode": "matching_only",
        "post_decoy_defense_belief_source": "estimated", "defender_belief_estimation_enabled": True,
        "defender_belief_observation_mode": "target_frequency", "mtd_enabled": True, "mtd_strategy": "shuffle_belief",
        "mtd_interval": 5, "mtd_intensity": 0.5,
    },
}

MTD_SWEEP_BASE = {
    "attacker_enabled": True,
    "attacker_target_selection": "adaptive",
    "attacker_greedy_mode": "utility",
    "attacker_belief_learning_enabled": True,
    "attacker_retreat_threshold": -50.0,
    "attacker_patience": 20,
    "node_type": ["real", "real", "decoy", "real", "real"],
    "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
    "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
    "stochastic_detection": True,
    "stochastic_success": True,
    "post_decoy_defense_enabled": True,
    "post_decoy_defense_weight": 3.0,
    "post_decoy_defense_top_k": 2,
    "post_decoy_defense_exclude_decoy": True,
    "post_decoy_defense_injection_mode": "matching_only",
    "post_decoy_defense_belief_source": "estimated",
    "defender_belief_estimation_enabled": True,
    "defender_belief_observation_mode": "target_frequency",
    "mtd_enabled": True,
    "mtd_strategy": "shuffle_belief",
    "mtd_cost": 1.0,
    "mtd_interval": 10,
    "mtd_intensity": 0.5,
}

SCENARIOS.update(
    {
        "mtd_sweep_shuffle_interval_5": {**MTD_SWEEP_BASE, "mtd_interval": 5},
        "mtd_sweep_shuffle_interval_10": {**MTD_SWEEP_BASE, "mtd_interval": 10},
        "mtd_sweep_shuffle_interval_20": {**MTD_SWEEP_BASE, "mtd_interval": 20},
        "mtd_sweep_shuffle_intensity_02": {**MTD_SWEEP_BASE, "mtd_intensity": 0.2},
        "mtd_sweep_shuffle_intensity_05": {**MTD_SWEEP_BASE, "mtd_intensity": 0.5},
        "mtd_sweep_shuffle_intensity_09": {**MTD_SWEEP_BASE, "mtd_intensity": 0.9},
        "mtd_sweep_shuffle_success_bonus_00": {**MTD_SWEEP_BASE, "mtd_success_decay_bonus": 0.0},
        "mtd_sweep_shuffle_success_bonus_05": {**MTD_SWEEP_BASE, "mtd_success_decay_bonus": 0.5},
        "mtd_sweep_shuffle_detection_bonus_00": {**MTD_SWEEP_BASE, "mtd_detection_bonus": 0.0},
        "mtd_sweep_shuffle_detection_bonus_03": {**MTD_SWEEP_BASE, "mtd_detection_bonus": 0.3},
        "mtd_sweep_shuffle_success05_detection03": {
            **MTD_SWEEP_BASE,
            "mtd_success_decay_bonus": 0.5,
            "mtd_detection_bonus": 0.3,
        },
        "mtd_sweep_target_frequency": {**MTD_SWEEP_BASE, "defender_belief_observation_mode": "target_frequency"},
        "mtd_sweep_visible_log": {**MTD_SWEEP_BASE, "defender_belief_observation_mode": "defender_visible_log"},
        "mtd_sweep_hybrid_visible": {**MTD_SWEEP_BASE, "defender_belief_observation_mode": "hybrid_visible"},
    }
)

LATERAL_BASE = {
    "attacker_enabled": True,
    "attacker_target_selection": "adaptive",
    "attacker_greedy_mode": "utility",
    "attacker_belief_learning_enabled": True,
    "attacker_retreat_threshold": -50.0,
    "attacker_patience": 20,
    "attacker_lateral_enabled": True,
    "attacker_lateral_success_prob": 0.8,
    "attacker_lateral_detection_prob": 0.2,
    "node_type": ["real", "real", "real", "real", "real"],
    "node_layer": ["internet", "dmz", "user", "server", "critical"],
    "adjacency_matrix": [
        [0, 1, 0, 0, 0],
        [1, 0, 1, 1, 0],
        [0, 1, 0, 1, 0],
        [0, 1, 1, 0, 1],
        [0, 0, 0, 1, 0],
    ],
    "entry_nodes": [0],
    "critical_nodes": [4],
    "asset_value": [10.0, 5.0, 2.0, 8.0, 20.0],
    "attacker_belief": [2.0, 4.0, 3.0, 8.0, 20.0],
    "stochastic_detection": True,
    "stochastic_success": True,
    "post_decoy_defense_enabled": True,
    "post_decoy_defense_weight": 3.0,
    "post_decoy_defense_top_k": 2,
    "post_decoy_defense_exclude_decoy": True,
    "post_decoy_defense_injection_mode": "matching_only",
    "post_decoy_defense_belief_source": "estimated",
    "defender_belief_estimation_enabled": True,
    "defender_belief_observation_mode": "target_frequency",
}

SCENARIOS.update(
    {
        "lateral_baseline": {**LATERAL_BASE},
        "lateral_decoy": {
            **LATERAL_BASE,
            "node_type": ["real", "real", "decoy", "real", "real"],
            "decoy_lateral_decay": 0.5,
        },
        "lateral_decoy_mtd": {
            **LATERAL_BASE,
            "node_type": ["real", "real", "decoy", "real", "real"],
            "decoy_lateral_decay": 0.5,
            "mtd_enabled": True,
            "mtd_strategy": "shuffle_belief",
            "mtd_interval": 10,
            "mtd_intensity": 0.5,
            "mtd_shuffle_topology": True,
        },
        "lateral_decoy_mtd_interval5": {
            **LATERAL_BASE,
            "node_type": ["real", "real", "decoy", "real", "real"],
            "decoy_lateral_decay": 0.5,
            "mtd_enabled": True,
            "mtd_strategy": "shuffle_belief",
            "mtd_interval": 5,
            "mtd_intensity": 0.5,
            "mtd_shuffle_topology": True,
        },
        "lateral_decoy_mtd_interval20": {
            **LATERAL_BASE,
            "node_type": ["real", "real", "decoy", "real", "real"],
            "decoy_lateral_decay": 0.5,
            "mtd_enabled": True,
            "mtd_strategy": "shuffle_belief",
            "mtd_interval": 20,
            "mtd_intensity": 0.5,
            "mtd_shuffle_topology": True,
        },
        "lateral_decoy_on_chokepoint": {
            **LATERAL_BASE,
            "node_type": ["real", "decoy", "real", "real", "real"],
            "asset_value": [10, 0, 1, 8, 2],
            "attacker_belief": [2, 12, 3, 4, 2],
            "decoy_lateral_decay": 0.5,
        },
        "lateral_decoy_on_server_path": {
            **LATERAL_BASE,
            "node_type": ["real", "real", "real", "decoy", "real"],
            "asset_value": [10, 5, 1, 0, 2],
            "attacker_belief": [2, 3, 1, 12, 2],
            "decoy_lateral_decay": 0.5,
        },
        "lateral_multi_decoy_path": {
            **LATERAL_BASE,
            "node_type": ["real", "decoy", "real", "decoy", "real"],
            "asset_value": [10, 0, 1, 0, 2],
            "attacker_belief": [2, 12, 1, 10, 2],
            "decoy_lateral_decay": 0.5,
        },
        "lateral_edge_mtd_chokepoint": {
            **LATERAL_BASE,
            "mtd_enabled": True,
            "mtd_strategy": "shuffle_belief",
            "mtd_interval": 10,
            "mtd_intensity": 0.5,
            "mtd_shuffle_topology": True,
            "mtd_block_critical_edges": True,
            "mtd_edge_block_count": 1,
            "mtd_edge_block_duration": 1,
        },
        "lateral_edge_mtd_interval5": {
            **LATERAL_BASE,
            "mtd_enabled": True,
            "mtd_strategy": "shuffle_belief",
            "mtd_interval": 5,
            "mtd_intensity": 0.5,
            "mtd_shuffle_topology": True,
            "mtd_block_critical_edges": True,
            "mtd_edge_block_count": 1,
            "mtd_edge_block_duration": 1,
        },
        "lateral_path_decoy_edge_mtd": {
            **LATERAL_BASE,
            "node_type": ["real", "decoy", "real", "decoy", "real"],
            "asset_value": [10, 0, 1, 0, 2],
            "attacker_belief": [2, 12, 1, 10, 2],
            "decoy_lateral_decay": 0.5,
            "mtd_enabled": True,
            "mtd_strategy": "shuffle_belief",
            "mtd_interval": 5,
            "mtd_intensity": 0.5,
            "mtd_shuffle_topology": True,
            "mtd_block_critical_edges": True,
            "mtd_edge_block_count": 1,
            "mtd_edge_block_duration": 1,
        },
    }
)

BAYESIAN_LATERAL_BASE = {
    "attacker_enabled": True,
    "attacker_target_selection": "adaptive",
    "attacker_greedy_mode": "utility",
    "attacker_belief_learning_enabled": True,
    "attacker_retreat_threshold": -50.0,
    "attacker_patience": 20,
    "attacker_lateral_enabled": True,
    "node_type": ["real", "decoy", "real", "decoy", "real"],
    "asset_value": [10, 0, 1, 0, 2],
    "attacker_belief": [2, 12, 1, 10, 2],
    "stochastic_detection": True,
    "stochastic_success": True,
    "post_decoy_defense_enabled": True,
    "post_decoy_defense_weight": 3.0,
    "post_decoy_defense_top_k": 2,
    "post_decoy_defense_exclude_decoy": True,
    "post_decoy_defense_injection_mode": "matching_only",
    "post_decoy_defense_belief_source": "bayesian",
    "defender_bayesian_update_enabled": True,
}

SCENARIOS.update(
    {
        "bayesian_lateral_path_decoy": {**BAYESIAN_LATERAL_BASE},
        "bayesian_lateral_path_decoy_edge_mtd": {
            **BAYESIAN_LATERAL_BASE,
            "mtd_enabled": True,
            "mtd_strategy": "shuffle_belief",
            "mtd_interval": 10,
            "mtd_shuffle_topology": True,
            "mtd_block_critical_edges": True,
            "mtd_edge_block_count": 1,
            "mtd_edge_block_duration": 1,
        },
        "bayesian_vs_target_frequency_reference": {
            **BAYESIAN_LATERAL_BASE,
            "post_decoy_defense_belief_source": "estimated",
            "defender_bayesian_update_enabled": False,
            "defender_belief_estimation_enabled": True,
            "defender_belief_observation_mode": "target_frequency",
        },
        "bayesian_high_critical_path_likelihood": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_critical_path_likelihood": 3.0,
        },
        "bayesian_low_decay": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_decay": 0.90,
        },
        "bayesian_sweep_prior_05": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_prior_strength": 0.5,
        },
        "bayesian_sweep_prior_20": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_prior_strength": 2.0,
        },
        "bayesian_sweep_success_likelihood_10": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_success_likelihood": 1.0,
        },
        "bayesian_sweep_success_likelihood_30": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_success_likelihood": 3.0,
        },
        "bayesian_sweep_detected_likelihood_02": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_detected_likelihood": 0.2,
        },
        "bayesian_sweep_detected_likelihood_08": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_detected_likelihood": 0.8,
        },
        "bayesian_sweep_decoy_likelihood_01": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_decoy_likelihood": 0.1,
        },
        "bayesian_sweep_decoy_likelihood_05": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_decoy_likelihood": 0.5,
        },
        "bayesian_sweep_critical_path_likelihood_10": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_critical_path_likelihood": 1.0,
        },
        "bayesian_sweep_critical_path_likelihood_30": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_critical_path_likelihood": 3.0,
        },
        "bayesian_sweep_decay_090": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_decay": 0.90,
        },
        "bayesian_sweep_decay_098": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_decay": 0.98,
        },
        "bayesian_sweep_decay_100": {
            **BAYESIAN_LATERAL_BASE,
            "defender_bayesian_decay": 1.0,
        },
        "bayesian_defense_objective_default": {
            **BAYESIAN_LATERAL_BASE,
        },
        "bayesian_defense_objective_high_critical_weight": {
            **BAYESIAN_LATERAL_BASE,
            "defense_objective_critical_weight": 2000.0,
        },
        "bayesian_defense_objective_high_delay_reward": {
            **BAYESIAN_LATERAL_BASE,
            "defense_objective_delay_reward": 20.0,
        },
        "bayesian_defense_objective_low_post_decoy_weight": {
            **BAYESIAN_LATERAL_BASE,
            "defense_objective_post_decoy_weight": 0.2,
        },
        "bayesian_defense_objective_edge_mtd": {
            **BAYESIAN_LATERAL_BASE,
            "mtd_enabled": True,
            "mtd_strategy": "shuffle_belief",
            "mtd_interval": 10,
            "mtd_shuffle_topology": True,
            "mtd_block_critical_edges": True,
            "mtd_edge_block_count": 1,
            "mtd_edge_block_duration": 1,
        },
    }
)

POLICY_SELECTION_BASE = {
    "attacker_enabled": True,
    "attacker_target_selection": "adaptive",
    "attacker_greedy_mode": "utility",
    "attacker_belief_learning_enabled": True,
    "attacker_retreat_threshold": -50.0,
    "attacker_patience": 20,
    "attacker_lateral_enabled": True,
    "node_type": ["real", "decoy", "real", "decoy", "real"],
    "asset_value": [10, 0, 1, 0, 2],
    "attacker_belief": [2, 12, 1, 10, 2],
    "stochastic_detection": True,
    "stochastic_success": True,
    "post_decoy_defense_enabled": True,
    "post_decoy_defense_weight": 3.0,
    "post_decoy_defense_top_k": 2,
    "post_decoy_defense_exclude_decoy": True,
    "post_decoy_defense_injection_mode": "matching_only",
}

POLICY_TARGET_FREQUENCY_BASE = {
    **POLICY_SELECTION_BASE,
    "post_decoy_defense_belief_source": "estimated",
    "defender_belief_estimation_enabled": True,
    "defender_belief_observation_mode": "target_frequency",
    "defender_bayesian_update_enabled": False,
    "mtd_enabled": False,
}

POLICY_BAYESIAN_BASE = {
    **POLICY_SELECTION_BASE,
    "post_decoy_defense_belief_source": "bayesian",
    "defender_bayesian_update_enabled": True,
    "mtd_enabled": False,
}

POLICY_EDGE_MTD = {
    "mtd_enabled": True,
    "mtd_strategy": "shuffle_belief",
    "mtd_shuffle_topology": True,
    "mtd_block_critical_edges": True,
    "mtd_interval": 10,
    "mtd_edge_block_count": 1,
    "mtd_edge_block_duration": 1,
}

POLICY_GATED_EDGE_MTD = {
    **POLICY_EDGE_MTD,
    "mtd_interval": 5,
    "mtd_risk_gating_enabled": True,
}

GATED_EDGE_PRESSURE_SWEEP_BASE = {
    **POLICY_TARGET_FREQUENCY_BASE,
    **POLICY_GATED_EDGE_MTD,
    "mtd_risk_gate_mode": "critical_edge_pressure",
    "mtd_risk_gate_threshold": 5.0,
    "mtd_risk_gate_cooldown": 3,
    "mtd_edge_block_count": 1,
    "mtd_edge_block_duration": 1,
}

GATED_EDGE_PRESSURE_HYBRID_BASE = {
    **GATED_EDGE_PRESSURE_SWEEP_BASE,
    "mtd_edge_block_count": 2,
    "mtd_edge_block_duration": 2,
    "mtd_risk_gate_threshold": 5.0,
    "mtd_risk_gate_cooldown": 3,
    "mtd_interval": 5,
}

CONDITIONAL_MTD_BASE = {
    **GATED_EDGE_PRESSURE_SWEEP_BASE,
    "mtd_risk_gating_enabled": True,
    "mtd_risk_gate_mode": "critical_edge_pressure",
    "mtd_conditional_policy_enabled": True,
    "mtd_conditional_policy_mode": "edge_pressure_split",
    "mtd_conditional_low_risk_threshold": 5.0,
    "mtd_conditional_high_risk_threshold": 10.0,
}

HONEYPOT_CREDENTIAL_BASE = {
    **POLICY_TARGET_FREQUENCY_BASE,
    "honeypot_credential_enabled": True,
    "credential_node_ids": [1, 3],
    "credential_attraction_bonus": 3.0,
    "credential_detection_bonus": 5.0,
    "credential_reuse_decay": 0.5,
}

CREDENTIAL_AWARE_MTD_BASE = {
    **HONEYPOT_CREDENTIAL_BASE,
    **GATED_EDGE_PRESSURE_SWEEP_BASE,
    "honeypot_credential_enabled": True,
    "credential_node_ids": [1, 3],
    "credential_attraction_bonus": 3.0,
    "credential_detection_bonus": 5.0,
    "credential_reuse_decay": 0.5,
    "mtd_enabled": True,
    "mtd_shuffle_topology": True,
    "mtd_block_critical_edges": True,
    "mtd_interval": 5,
    "mtd_risk_gating_enabled": True,
    "mtd_risk_gate_mode": "critical_edge_pressure",
    "mtd_risk_gate_threshold": 5.0,
    "credential_aware_mtd_enabled": True,
    "credential_trigger_mtd_window": 3,
    "credential_trigger_block_count": 2,
    "credential_trigger_block_duration": 1,
    "credential_trigger_force_mtd": True,
    "credential_trigger_risk_bonus": 5.0,
}

CREDENTIAL_STAGED_MTD_BASE = {
    **CREDENTIAL_AWARE_MTD_BASE,
    "credential_trigger_mtd_window": 5,
    "credential_trigger_force_mtd": True,
    "credential_staged_mtd_enabled": True,
    "credential_stage1_window": 1,
    "credential_stage1_block_count": 2,
    "credential_stage1_block_duration": 1,
    "credential_stage2_window": 5,
    "credential_stage2_block_count": 1,
    "credential_stage2_block_duration": 2,
}

PHASE2_PERCEIVED_UTILITY_BASE = {
    **POLICY_TARGET_FREQUENCY_BASE,
    "perceived_utility_enabled": True,
    "retreat_based_on": "perceived",
    "attacker_retreat_threshold": -10.0,
    "attacker_patience": 20,
    "perceived_success_confidence": 0.6,
    "perceived_decoy_penalty": 15.0,
    "perceived_detection_penalty": 2.0,
    "perceived_uncertainty_decay": 0.70,
}

PHASE2_FRUSTRATION_BASE = {
    **PHASE2_PERCEIVED_UTILITY_BASE,
    "retreat_based_on": "frustration",
    "attacker_retreat_threshold": -999.0,
    "attacker_patience": 50,
    "frustration_enabled": True,
    "frustration_decoy_hit": 3.0,
    "frustration_credential_trap": 2.0,
    "frustration_detection": 1.0,
    "frustration_path_change": 0.5,
    "frustration_no_progress": 0.5,
    "frustration_decay": 0.95,
    "frustration_retreat_threshold": 8.0,
}

SCENARIOS.update(
    {
        "policy_target_frequency_path_decoy": {**POLICY_TARGET_FREQUENCY_BASE},
        "policy_bayesian_default_path_decoy": {**POLICY_BAYESIAN_BASE},
        "policy_bayesian_success30_path_decoy": {
            **POLICY_BAYESIAN_BASE,
            "defender_bayesian_success_likelihood": 3.0,
        },
        "policy_bayesian_decay090_path_decoy": {
            **POLICY_BAYESIAN_BASE,
            "defender_bayesian_decay": 0.90,
        },
        "policy_bayesian_edge_mtd": {
            **POLICY_BAYESIAN_BASE,
            **POLICY_EDGE_MTD,
        },
        "policy_path_decoy_edge_mtd": {
            **POLICY_TARGET_FREQUENCY_BASE,
            **POLICY_EDGE_MTD,
        },
        "policy_lateral_multi_decoy": {
            **POLICY_TARGET_FREQUENCY_BASE,
            "decoy_lateral_decay": 0.5,
        },
        "policy_gated_edge_mtd_critical_path": {
            **POLICY_TARGET_FREQUENCY_BASE,
            **POLICY_GATED_EDGE_MTD,
            "mtd_risk_gate_mode": "critical_path_risk",
        },
        "policy_gated_edge_mtd_chokepoint": {
            **POLICY_TARGET_FREQUENCY_BASE,
            **POLICY_GATED_EDGE_MTD,
            "mtd_risk_gate_mode": "chokepoint_risk",
        },
        "policy_gated_edge_mtd_edge_pressure": {
            **POLICY_TARGET_FREQUENCY_BASE,
            **POLICY_GATED_EDGE_MTD,
            "mtd_risk_gate_mode": "critical_edge_pressure",
        },
        "policy_gated_edge_mtd_low_threshold": {
            **POLICY_TARGET_FREQUENCY_BASE,
            **POLICY_GATED_EDGE_MTD,
            "mtd_risk_gate_threshold": 2.0,
        },
        "policy_gated_edge_mtd_high_threshold": {
            **POLICY_TARGET_FREQUENCY_BASE,
            **POLICY_GATED_EDGE_MTD,
            "mtd_risk_gate_threshold": 10.0,
        },
        "gated_edge_pressure_threshold_3": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_risk_gate_threshold": 3.0,
        },
        "gated_edge_pressure_threshold_5": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_risk_gate_threshold": 5.0,
        },
        "gated_edge_pressure_threshold_7": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_risk_gate_threshold": 7.0,
        },
        "gated_edge_pressure_threshold_10": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_risk_gate_threshold": 10.0,
        },
        "gated_edge_pressure_threshold_15": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_risk_gate_threshold": 15.0,
        },
        "gated_edge_pressure_cooldown_0": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_risk_gate_cooldown": 0,
        },
        "gated_edge_pressure_cooldown_3": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_risk_gate_cooldown": 3,
        },
        "gated_edge_pressure_cooldown_5": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_risk_gate_cooldown": 5,
        },
        "gated_edge_pressure_cooldown_10": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_risk_gate_cooldown": 10,
        },
        "gated_edge_pressure_duration_1": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_edge_block_duration": 1,
        },
        "gated_edge_pressure_duration_2": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_edge_block_duration": 2,
        },
        "gated_edge_pressure_count_1": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_edge_block_count": 1,
        },
        "gated_edge_pressure_count_2": {
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "mtd_edge_block_count": 2,
        },
        "gated_edge_pressure_count2_duration2": {
            **GATED_EDGE_PRESSURE_HYBRID_BASE,
        },
        "gated_edge_pressure_count2_duration2_threshold5": {
            **GATED_EDGE_PRESSURE_HYBRID_BASE,
            "mtd_risk_gate_threshold": 5.0,
        },
        "gated_edge_pressure_count2_duration2_threshold7": {
            **GATED_EDGE_PRESSURE_HYBRID_BASE,
            "mtd_risk_gate_threshold": 7.0,
        },
        "gated_edge_pressure_count2_duration2_cooldown0": {
            **GATED_EDGE_PRESSURE_HYBRID_BASE,
            "mtd_risk_gate_cooldown": 0,
        },
        "gated_edge_pressure_count2_duration2_cooldown5": {
            **GATED_EDGE_PRESSURE_HYBRID_BASE,
            "mtd_risk_gate_cooldown": 5,
        },
        "gated_edge_pressure_count2_duration2_interval10": {
            **GATED_EDGE_PRESSURE_HYBRID_BASE,
            "mtd_interval": 10,
        },
        "gated_edge_pressure_count2_duration1_threshold7": {
            **GATED_EDGE_PRESSURE_HYBRID_BASE,
            "mtd_edge_block_count": 2,
            "mtd_edge_block_duration": 1,
            "mtd_risk_gate_threshold": 7.0,
        },
        "gated_edge_pressure_count1_duration2_threshold7": {
            **GATED_EDGE_PRESSURE_HYBRID_BASE,
            "mtd_edge_block_count": 1,
            "mtd_edge_block_duration": 2,
            "mtd_risk_gate_threshold": 7.0,
        },
        "gated_edge_conditional_split_5_10": {
            **CONDITIONAL_MTD_BASE,
            "mtd_conditional_low_risk_threshold": 5.0,
            "mtd_conditional_high_risk_threshold": 10.0,
        },
        "gated_edge_conditional_split_3_7": {
            **CONDITIONAL_MTD_BASE,
            "mtd_conditional_low_risk_threshold": 3.0,
            "mtd_conditional_high_risk_threshold": 7.0,
        },
        "gated_edge_conditional_split_7_12": {
            **CONDITIONAL_MTD_BASE,
            "mtd_conditional_low_risk_threshold": 7.0,
            "mtd_conditional_high_risk_threshold": 12.0,
        },
        "gated_edge_conditional_split_5_15": {
            **CONDITIONAL_MTD_BASE,
            "mtd_conditional_low_risk_threshold": 5.0,
            "mtd_conditional_high_risk_threshold": 15.0,
        },
        "gated_edge_conditional_critical_vs_post_decoy": {
            **CONDITIONAL_MTD_BASE,
            "mtd_conditional_policy_mode": "critical_vs_post_decoy",
        },
        "honeypot_credential_reference": {
            **HONEYPOT_CREDENTIAL_BASE,
        },
        "honeypot_credential_low_bonus": {
            **HONEYPOT_CREDENTIAL_BASE,
            "credential_attraction_bonus": 0.5,
        },
        "honeypot_credential_high_bonus": {
            **HONEYPOT_CREDENTIAL_BASE,
            "credential_attraction_bonus": 6.0,
        },
        "honeypot_credential_high_detection": {
            **HONEYPOT_CREDENTIAL_BASE,
            "credential_detection_bonus": 10.0,
        },
        "honeypot_credential_path_decoy": {
            **HONEYPOT_CREDENTIAL_BASE,
            "credential_node_ids": [1, 3],
        },
        "honeypot_credential_edge_mtd": {
            **HONEYPOT_CREDENTIAL_BASE,
            **GATED_EDGE_PRESSURE_SWEEP_BASE,
            "honeypot_credential_enabled": True,
            "credential_node_ids": [1, 3],
            "credential_attraction_bonus": 3.0,
            "credential_detection_bonus": 5.0,
            "credential_reuse_decay": 0.5,
            "mtd_edge_block_count": 2,
            "mtd_edge_block_duration": 1,
        },
        "credential_aware_mtd_reference": {
            **CREDENTIAL_AWARE_MTD_BASE,
        },
        "credential_aware_mtd_force_count2": {
            **CREDENTIAL_AWARE_MTD_BASE,
            "credential_trigger_force_mtd": True,
            "credential_trigger_block_count": 2,
            "credential_trigger_block_duration": 1,
            "credential_trigger_mtd_window": 3,
        },
        "credential_aware_mtd_force_duration2": {
            **CREDENTIAL_AWARE_MTD_BASE,
            "credential_trigger_force_mtd": True,
            "credential_trigger_block_count": 1,
            "credential_trigger_block_duration": 2,
            "credential_trigger_mtd_window": 3,
        },
        "credential_aware_mtd_risk_bonus": {
            **CREDENTIAL_AWARE_MTD_BASE,
            "credential_trigger_force_mtd": False,
            "credential_trigger_risk_bonus": 10.0,
        },
        "credential_aware_mtd_window1": {
            **CREDENTIAL_AWARE_MTD_BASE,
            "credential_trigger_mtd_window": 1,
        },
        "credential_aware_mtd_window5": {
            **CREDENTIAL_AWARE_MTD_BASE,
            "credential_trigger_mtd_window": 5,
        },
        "credential_aware_mtd_edge_pressure": {
            **CREDENTIAL_AWARE_MTD_BASE,
            "mtd_risk_gate_mode": "critical_edge_pressure",
        },
        "credential_staged_mtd_1_5": {
            **CREDENTIAL_STAGED_MTD_BASE,
            "credential_stage1_window": 1,
            "credential_stage2_window": 5,
            "credential_stage1_block_count": 2,
            "credential_stage1_block_duration": 1,
            "credential_stage2_block_count": 1,
            "credential_stage2_block_duration": 2,
        },
        "credential_staged_mtd_0_3": {
            **CREDENTIAL_STAGED_MTD_BASE,
            "credential_stage1_window": 0,
            "credential_stage2_window": 3,
        },
        "credential_staged_mtd_1_3": {
            **CREDENTIAL_STAGED_MTD_BASE,
            "credential_stage1_window": 1,
            "credential_stage2_window": 3,
        },
        "credential_staged_mtd_2_5": {
            **CREDENTIAL_STAGED_MTD_BASE,
            "credential_stage1_window": 2,
            "credential_stage2_window": 5,
        },
        "credential_staged_mtd_stage1_only": {
            **CREDENTIAL_STAGED_MTD_BASE,
            "credential_stage1_window": 5,
            "credential_stage2_window": 5,
            "credential_stage1_block_count": 2,
            "credential_stage1_block_duration": 1,
            "credential_stage2_block_count": 2,
            "credential_stage2_block_duration": 1,
        },
        "credential_staged_mtd_stage2_only": {
            **CREDENTIAL_STAGED_MTD_BASE,
            "credential_stage1_window": 0,
            "credential_stage2_window": 5,
            "credential_stage1_block_count": 1,
            "credential_stage1_block_duration": 2,
            "credential_stage2_block_count": 1,
            "credential_stage2_block_duration": 2,
        },
        "credential_staged_mtd_with_risk_bonus": {
            **CREDENTIAL_STAGED_MTD_BASE,
            "credential_trigger_risk_bonus": 10.0,
        },
        "phase2_actual_utility_reference": {
            **POLICY_TARGET_FREQUENCY_BASE,
            "perceived_utility_enabled": False,
            "retreat_based_on": "actual",
            "attacker_retreat_threshold": -10.0,
            "attacker_patience": 20,
        },
        "phase2_perceived_decoy": {
            **PHASE2_PERCEIVED_UTILITY_BASE,
        },
        "phase2_perceived_credential": {
            **PHASE2_PERCEIVED_UTILITY_BASE,
            "node_type": ["real", "real", "real", "decoy", "real"],
            "asset_value": [10, 5, 1, 0, 2],
            "attacker_belief": [2, 4, 1, 14, 2],
            "honeypot_credential_enabled": True,
            "credential_node_ids": [3],
            "credential_attraction_bonus": 5.0,
        },
        "phase2_perceived_decoy_credential": {
            **PHASE2_PERCEIVED_UTILITY_BASE,
            "honeypot_credential_enabled": True,
            "credential_node_ids": [1, 3],
            "credential_attraction_bonus": 5.0,
            "credential_detection_bonus": 5.0,
        },
        "phase2_perceived_high_uncertainty": {
            **PHASE2_PERCEIVED_UTILITY_BASE,
            "honeypot_credential_enabled": True,
            "credential_node_ids": [1, 3],
            "credential_attraction_bonus": 6.0,
            "perceived_success_confidence": 0.3,
            "perceived_decoy_penalty": 25.0,
            "perceived_detection_penalty": 3.0,
            "perceived_uncertainty_decay": 0.45,
            "attacker_retreat_threshold": -5.0,
        },
        "phase2_frustration_reference": {
            **PHASE2_FRUSTRATION_BASE,
            "node_type": ["real", "real", "real", "real", "real"],
            "honeypot_credential_enabled": False,
            "frustration_retreat_threshold": 30.0,
        },
        "phase2_frustration_decoy": {
            **PHASE2_FRUSTRATION_BASE,
            "frustration_retreat_threshold": 6.0,
        },
        "phase2_frustration_credential": {
            **PHASE2_FRUSTRATION_BASE,
            "node_type": ["real", "real", "real", "decoy", "real"],
            "asset_value": [10, 5, 1, 0, 2],
            "attacker_belief": [2, 4, 1, 14, 2],
            "honeypot_credential_enabled": True,
            "credential_node_ids": [3],
            "credential_attraction_bonus": 5.0,
            "frustration_credential_trap": 4.0,
            "frustration_retreat_threshold": 7.0,
        },
        "phase2_frustration_decoy_credential": {
            **PHASE2_FRUSTRATION_BASE,
            "honeypot_credential_enabled": True,
            "credential_node_ids": [1, 3],
            "credential_attraction_bonus": 5.0,
            "credential_detection_bonus": 5.0,
            "frustration_decoy_hit": 3.5,
            "frustration_credential_trap": 3.0,
            "frustration_retreat_threshold": 7.0,
        },
        "phase2_frustration_high_detection": {
            **PHASE2_FRUSTRATION_BASE,
            "stochastic_detection": True,
            "base_detection_prob": 0.8,
            "defense_detection_scale": 0.2,
            "decoy_detection_prob": 1.0,
            "frustration_detection": 3.0,
            "frustration_retreat_threshold": 6.0,
        },
        "phase2_frustration_path_change": {
            **PHASE2_FRUSTRATION_BASE,
            "attacker_lateral_enabled": True,
            "mtd_enabled": True,
            "mtd_interval": 1,
            "mtd_block_critical_edges": True,
            "mtd_edge_block_count": 1,
            "mtd_edge_block_duration": 1,
            "frustration_path_change": 2.0,
            "frustration_no_progress": 1.0,
            "frustration_retreat_threshold": 5.0,
        },
        "phase2_ai_cost_reference": {
            **PHASE2_FRUSTRATION_BASE,
            "node_type": ["real", "real", "real", "real", "real"],
            "honeypot_credential_enabled": False,
            "frustration_retreat_threshold": 30.0,
        },
        "phase2_ai_high_uncertainty": {
            **PHASE2_FRUSTRATION_BASE,
            "frustration_retreat_threshold": 6.0,
            "ai_uncertainty_weight": 3.0,
        },
        "phase2_ai_high_trust_degradation": {
            **PHASE2_FRUSTRATION_BASE,
            "node_type": ["real", "real", "real", "decoy", "real"],
            "asset_value": [10, 5, 1, 0, 2],
            "attacker_belief": [2, 4, 1, 14, 2],
            "honeypot_credential_enabled": True,
            "credential_node_ids": [3],
            "credential_attraction_bonus": 5.0,
            "frustration_credential_trap": 4.0,
            "frustration_retreat_threshold": 7.0,
            "ai_trust_degradation_weight": 3.5,
        },
        "phase2_ai_high_operational_risk": {
            **PHASE2_FRUSTRATION_BASE,
            "stochastic_detection": True,
            "base_detection_prob": 0.8,
            "defense_detection_scale": 0.2,
            "decoy_detection_prob": 1.0,
            "frustration_detection": 3.0,
            "frustration_retreat_threshold": 6.0,
            "ai_operational_risk_weight": 2.5,
        },
        "phase2_ai_low_replanning_cost": {
            **PHASE2_FRUSTRATION_BASE,
            "attacker_lateral_enabled": True,
            "mtd_enabled": True,
            "mtd_interval": 1,
            "mtd_block_critical_edges": True,
            "mtd_edge_block_count": 1,
            "mtd_edge_block_duration": 1,
            "frustration_path_change": 2.0,
            "frustration_no_progress": 1.0,
            "frustration_retreat_threshold": 5.0,
            "ai_replanning_weight": 0.25,
        },
        "phase2_ai_balanced": {
            **PHASE2_FRUSTRATION_BASE,
            "honeypot_credential_enabled": True,
            "credential_node_ids": [1, 3],
            "credential_attraction_bonus": 5.0,
            "credential_detection_bonus": 5.0,
            "frustration_decoy_hit": 3.5,
            "frustration_credential_trap": 3.0,
            "frustration_retreat_threshold": 7.0,
            "ai_uncertainty_weight": 1.0,
            "ai_replanning_weight": 1.0,
            "ai_search_weight": 1.0,
            "ai_operational_risk_weight": 1.0,
            "ai_trust_degradation_weight": 1.0,
        },
    }
)

SCENARIOS.update(
    {
        "phase3_adaptive_reference": {
            **SCENARIOS["phase2_frustration_reference"],
        },
        "phase3_adaptive_frustration_decoy": {
            **SCENARIOS["phase2_frustration_decoy"],
        },
        "phase3_adaptive_ai_balanced": {
            **SCENARIOS["phase2_ai_balanced"],
        },
        "phase3_adaptive_gated_count2": {
            **SCENARIOS["gated_edge_pressure_count_2"],
            "perceived_utility_enabled": True,
            "retreat_based_on": "frustration",
            "attacker_retreat_threshold": -999.0,
            "attacker_patience": 50,
            "frustration_enabled": True,
            "frustration_retreat_threshold": 8.0,
        },
        "phase3_preference_reference": {
            **SCENARIOS["phase2_frustration_reference"],
        },
        "phase3_preference_frustration_decoy": {
            **SCENARIOS["phase2_frustration_decoy"],
        },
        "phase3_preference_ai_balanced": {
            **SCENARIOS["phase2_ai_balanced"],
        },
        "phase3_preference_gated_count2": {
            **SCENARIOS["gated_edge_pressure_count_2"],
            "perceived_utility_enabled": True,
            "retreat_based_on": "frustration",
            "attacker_retreat_threshold": -999.0,
            "attacker_patience": 50,
            "frustration_enabled": True,
            "frustration_retreat_threshold": 8.0,
        },
        "phase3_path_reference": {
            **SCENARIOS["phase2_frustration_reference"],
        },
        "phase3_path_frustration_decoy": {
            **SCENARIOS["phase2_frustration_decoy"],
        },
        "phase3_path_ai_balanced": {
            **SCENARIOS["phase2_ai_balanced"],
        },
        "phase3_path_gated_count2": {
            **SCENARIOS["gated_edge_pressure_count_2"],
            "perceived_utility_enabled": True,
            "retreat_based_on": "frustration",
            "attacker_retreat_threshold": -999.0,
            "attacker_patience": 50,
            "frustration_enabled": True,
            "frustration_retreat_threshold": 8.0,
        },
        "phase3_planning_reference": {
            **SCENARIOS["phase2_frustration_reference"],
        },
        "phase3_planning_frustration_decoy": {
            **SCENARIOS["phase2_frustration_decoy"],
        },
        "phase3_planning_ai_balanced": {
            **SCENARIOS["phase2_ai_balanced"],
        },
        "phase3_planning_gated_count2": {
            **SCENARIOS["gated_edge_pressure_count_2"],
            "perceived_utility_enabled": True,
            "retreat_based_on": "frustration",
            "attacker_retreat_threshold": -999.0,
            "attacker_patience": 50,
            "frustration_enabled": True,
            "frustration_retreat_threshold": 8.0,
        },
        "phase3_trust_reference": {
            **SCENARIOS["phase2_frustration_reference"],
        },
        "phase3_trust_frustration_decoy": {
            **SCENARIOS["phase2_frustration_decoy"],
        },
        "phase3_trust_ai_balanced": {
            **SCENARIOS["phase2_ai_balanced"],
        },
        "phase3_trust_gated_count2": {
            **SCENARIOS["gated_edge_pressure_count_2"],
            "perceived_utility_enabled": True,
            "retreat_based_on": "frustration",
            "attacker_retreat_threshold": -999.0,
            "attacker_patience": 50,
            "frustration_enabled": True,
            "frustration_retreat_threshold": 8.0,
        },
        "phase3_expected_reference": {
            **SCENARIOS["phase2_frustration_reference"],
        },
        "phase3_expected_frustration_decoy": {
            **SCENARIOS["phase2_frustration_decoy"],
        },
        "phase3_expected_ai_balanced": {
            **SCENARIOS["phase2_ai_balanced"],
        },
        "phase3_expected_gated_count2": {
            **SCENARIOS["gated_edge_pressure_count_2"],
            "perceived_utility_enabled": True,
            "retreat_based_on": "frustration",
            "attacker_retreat_threshold": -999.0,
            "attacker_patience": 50,
            "frustration_enabled": True,
            "frustration_retreat_threshold": 8.0,
        },
    }
)

SUMMARY_COLUMNS = [
    "scenario",
    "steps",
    "attacker_enabled",
    "attacker_retreated",
    "attacker_retreat_step",
    "attacker_utility_final",
    "actual_utility_final",
    "perceived_utility_final",
    "actual_gain",
    "actual_cost",
    "perceived_gain",
    "perceived_cost",
    "mean_confidence",
    "frustration_final",
    "frustration_mean",
    "frustration_max",
    "frustration_retreats",
    "frustration_enabled",
    "ai_uncertainty_cost",
    "ai_replanning_cost",
    "ai_search_cost",
    "ai_operational_risk_cost",
    "ai_trust_degradation_cost",
    "ai_total_decision_cost",
    "ai_weighted_cost",
    "human_vs_ai_cost_ratio",
    "ai_uncertainty_weight",
    "ai_replanning_weight",
    "ai_search_weight",
    "ai_operational_risk_weight",
    "ai_trust_degradation_weight",
    "cognitive_neutralization_score",
    "cognitive_human_score",
    "cognitive_ai_score",
    "cns_objective_score",
    "cns_human_contribution",
    "cns_ai_contribution",
    "cns_protection_contribution",
    "retreat_based_on",
    "perceived_utility_enabled",
    "attacker_total_cost",
    "attacker_compromised_value",
    "attacker_success_count",
    "attacker_detected_count",
    "final_risk_sum",
    "max_risk",
    "mean_risk",
    "weighted_cumulative_risk",
    "cumulative_resource",
    "matching_update_count",
    "ilp_fallback_count",
    "mpc_fallback_count",
    "asset_value",
    "attacker_belief",
    "attacker_belief_error_l1",
    "attacker_belief_error_l2",
    "attacker_greedy_mode",
    "attacker_lateral_enabled",
    "attacker_lateral_success_prob",
    "attacker_lateral_detection_prob",
    "attacker_current_node_final",
    "attacker_visited_nodes_final",
    "attacker_compromised_nodes_final",
    "critical_path_count",
    "critical_paths",
    "node_path_frequency",
    "edge_path_frequency",
    "chokepoint_nodes",
    "critical_edges",
    "decoy_on_critical_path",
    "critical_compromise",
    "critical_compromise_step",
    "neutralization_score",
    "critical_protection_score",
    "utility_suppression_score",
    "deception_waste_score",
    "friction_score",
    "retreat_score",
    "attacker_most_targeted_node",
    "attacker_target_counts",
    "node_type",
    "node_layer",
    "entry_nodes",
    "critical_nodes",
    "decoy_node_count",
    "attacker_decoy_attack_count",
    "attacker_decoy_attack_rate",
    "attacker_decoy_waste_total",
    "attacker_real_attack_count",
    "honeypot_credential_enabled",
    "credential_node_ids",
    "credential_attraction_bonus",
    "credential_detection_bonus",
    "credential_reuse_decay",
    "credential_obtained_count",
    "credential_used_count",
    "credential_decoy_trigger_count",
    "credential_trigger_rate",
    "credential_aware_mtd_enabled",
    "credential_trigger_mtd_window",
    "credential_trigger_block_count",
    "credential_trigger_block_duration",
    "credential_trigger_force_mtd",
    "credential_trigger_risk_bonus",
    "credential_trigger_mtd_event_count",
    "credential_trigger_recently_active_count",
    "credential_staged_mtd_enabled",
    "credential_stage1_window",
    "credential_stage2_window",
    "credential_stage1_block_count",
    "credential_stage1_block_duration",
    "credential_stage2_block_count",
    "credential_stage2_block_duration",
    "credential_stage1_action_count",
    "credential_stage2_action_count",
    "credential_stage_none_count",
    "stochastic_detection",
    "stochastic_success",
    "mean_attack_success_prob",
    "mean_attack_detection_prob",
    "mean_target_defense_strength",
    "attacker_belief_learning_enabled",
    "adaptive_attacker_enabled",
    "adaptive_memory_success_mean",
    "adaptive_memory_decoy_mean",
    "adaptive_memory_detection_mean",
    "adaptive_preference_enabled",
    "preference_mean",
    "preference_max",
    "preferred_node_id",
    "preferred_node_score",
    "preferred_node_on_critical_path",
    "adaptive_path_enabled",
    "path_preference_mean",
    "path_preference_max",
    "preferred_path",
    "preferred_path_score",
    "preferred_path_is_critical",
    "adaptive_planning_enabled",
    "planning_depth",
    "planning_score_mean",
    "planning_score_max",
    "planned_path",
    "planned_path_score",
    "planned_path_is_critical",
    "attacker_belief_change_l1",
    "attacker_belief_change_l2",
    "attacker_belief_decoy_reduction",
    "attacker_final_belief",
    "first_decoy_step",
    "post_decoy_attack_count",
    "post_decoy_real_attack_count",
    "post_decoy_decoy_attack_count",
    "post_decoy_compromised_value",
    "post_decoy_utility",
    "post_decoy_target_counts",
    "post_decoy_most_targeted_node",
    "attack_transition_matrix",
    "post_decoy_defense_enabled",
    "post_decoy_defense_injection_mode",
    "post_decoy_defense_belief_source",
    "defender_belief_estimation_enabled",
    "defender_belief_observation_mode",
    "visible_log_observation_enabled",
    "defender_estimation_error_l1",
    "defender_estimation_error_l2",
    "defender_bayesian_update_enabled",
    "defender_bayesian_prior_strength",
    "defender_bayesian_success_likelihood",
    "defender_bayesian_detected_likelihood",
    "defender_bayesian_decoy_likelihood",
    "defender_bayesian_critical_path_likelihood",
    "defender_bayesian_decay",
    "defender_bayesian_error_l1",
    "defender_bayesian_error_l2",
    "defense_objective_critical_weight",
    "defense_objective_post_decoy_weight",
    "defense_objective_delay_reward",
    "defense_objective_score",
    "mtd_enabled",
    "mtd_strategy",
    "mtd_interval",
    "mtd_intensity",
    "mtd_success_decay_bonus",
    "mtd_detection_bonus",
    "mtd_shuffle_topology",
    "mtd_block_critical_edges",
    "mtd_edge_block_count",
    "mtd_edge_block_duration",
    "mtd_risk_gating_enabled",
    "mtd_risk_gate_mode",
    "mtd_risk_gate_threshold",
    "mtd_risk_gate_cooldown",
    "mtd_risk_gate_fire_count",
    "mtd_risk_gate_suppressed_count",
    "mtd_risk_gate_score_mean",
    "mtd_conditional_policy_enabled",
    "mtd_conditional_policy_mode",
    "mtd_conditional_high_risk_threshold",
    "mtd_conditional_low_risk_threshold",
    "mtd_conditional_count2_action_count",
    "mtd_conditional_duration2_action_count",
    "mtd_conditional_suppress_count",
    "mtd_blocked_edges",
    "mtd_blocked_edge_count",
    "mtd_edge_block_events",
    "mtd_edge_block_active_steps",
    "mtd_event_count",
    "mtd_total_cost",
    "mtd_compromised_delta_vs_reference",
    "mtd_utility_delta_vs_reference",
    "mtd_cost_adjusted_delta",
    "bayesian_compromise_delta_vs_target_frequency",
    "bayesian_post_decoy_delta_vs_target_frequency",
    "bayesian_error_delta_vs_target_frequency",
    "defense_objective_delta_vs_target_frequency",
    "critical_rate_delta_vs_target_frequency",
    "post_decoy_delta_vs_target_frequency",
    "post_decoy_defense_active_count",
    "post_decoy_defense_mpc_q_active_count",
    "post_decoy_defense_matching_active_count",
    "post_decoy_defense_fallback_active_count",
    "effective_defense_weight_final",
]

MULTI_SEED_RUN_COLUMNS = [
    "scenario",
    "seed",
    "defender_belief_observation_mode",
    "post_decoy_defense_belief_source",
    "attacker_retreated",
    "attacker_retreat_step",
    "attacker_lateral_enabled",
    "critical_path_count",
    "decoy_on_critical_path",
    "chokepoint_nodes",
    "critical_edges",
    "critical_compromise",
    "critical_compromise_step",
    "neutralization_score",
    "critical_protection_score",
    "utility_suppression_score",
    "deception_waste_score",
    "friction_score",
    "retreat_score",
    "attacker_utility_final",
    "actual_utility_final",
    "perceived_utility_final",
    "actual_gain",
    "actual_cost",
    "perceived_gain",
    "perceived_cost",
    "mean_confidence",
    "frustration_final",
    "frustration_mean",
    "frustration_max",
    "frustration_retreats",
    "frustration_enabled",
    "ai_uncertainty_cost",
    "ai_replanning_cost",
    "ai_search_cost",
    "ai_operational_risk_cost",
    "ai_trust_degradation_cost",
    "ai_total_decision_cost",
    "ai_weighted_cost",
    "human_vs_ai_cost_ratio",
    "ai_uncertainty_weight",
    "ai_replanning_weight",
    "ai_search_weight",
    "ai_operational_risk_weight",
    "ai_trust_degradation_weight",
    "cognitive_neutralization_score",
    "cognitive_human_score",
    "cognitive_ai_score",
    "cns_objective_score",
    "cns_human_contribution",
    "cns_ai_contribution",
    "cns_protection_contribution",
    "retreat_based_on",
    "perceived_utility_enabled",
    "attacker_total_cost",
    "attacker_compromised_value",
    "attacker_success_count",
    "attacker_detected_count",
    "attacker_decoy_attack_rate",
    "attacker_decoy_waste_total",
    "honeypot_credential_enabled",
    "credential_node_ids",
    "credential_attraction_bonus",
    "credential_detection_bonus",
    "credential_reuse_decay",
    "credential_obtained_count",
    "credential_used_count",
    "credential_decoy_trigger_count",
    "credential_trigger_rate",
    "credential_aware_mtd_enabled",
    "credential_trigger_mtd_window",
    "credential_trigger_block_count",
    "credential_trigger_block_duration",
    "credential_trigger_force_mtd",
    "credential_trigger_risk_bonus",
    "credential_trigger_mtd_event_count",
    "credential_trigger_recently_active_count",
    "credential_staged_mtd_enabled",
    "credential_stage1_window",
    "credential_stage2_window",
    "credential_stage1_block_count",
    "credential_stage1_block_duration",
    "credential_stage2_block_count",
    "credential_stage2_block_duration",
    "credential_stage1_action_count",
    "credential_stage2_action_count",
    "credential_stage_none_count",
    "mean_attack_success_prob",
    "mean_attack_detection_prob",
    "adaptive_attacker_enabled",
    "adaptive_memory_success_mean",
    "adaptive_memory_decoy_mean",
    "adaptive_memory_detection_mean",
    "adaptive_preference_enabled",
    "preference_mean",
    "preference_max",
    "preferred_node_id",
    "preferred_node_score",
    "preferred_node_on_critical_path",
    "adaptive_path_enabled",
    "path_preference_mean",
    "path_preference_max",
    "preferred_path",
    "preferred_path_score",
    "preferred_path_is_critical",
    "adaptive_planning_enabled",
    "planning_depth",
    "planning_score_mean",
    "planning_score_max",
    "planned_path",
    "planned_path_score",
    "planned_path_is_critical",
    "trust_enabled",
    "trust_mean",
    "trust_min",
    "trust_max",
    "trust_collapse_rate",
    "least_trusted_node",
    "most_trusted_node",
    "expected_utility_enabled",
    "expected_utility_final",
    "expected_utility_mean",
    "expected_gain_estimate",
    "expected_detection_risk",
    "expected_search_cost",
    "target_switch_count",
    "weighted_cumulative_risk",
    "final_risk_sum",
    "attacker_belief_change_l1",
    "attacker_belief_decoy_reduction",
    "post_decoy_real_attack_count",
    "post_decoy_compromised_value",
    "post_decoy_utility",
    "post_decoy_target_counts",
    "post_decoy_defense_active_count",
    "defender_estimation_error_l1",
    "defender_estimation_error_l2",
    "defender_bayesian_update_enabled",
    "defender_bayesian_prior_strength",
    "defender_bayesian_success_likelihood",
    "defender_bayesian_detected_likelihood",
    "defender_bayesian_decoy_likelihood",
    "defender_bayesian_critical_path_likelihood",
    "defender_bayesian_decay",
    "defender_bayesian_error_l1",
    "defender_bayesian_error_l2",
    "defense_objective_critical_weight",
    "defense_objective_post_decoy_weight",
    "defense_objective_delay_reward",
    "defense_objective_score",
    "mtd_enabled",
    "mtd_strategy",
    "mtd_interval",
    "mtd_intensity",
    "mtd_success_decay_bonus",
    "mtd_detection_bonus",
    "mtd_shuffle_topology",
    "mtd_block_critical_edges",
    "mtd_edge_block_count",
    "mtd_edge_block_duration",
    "mtd_risk_gating_enabled",
    "mtd_risk_gate_mode",
    "mtd_risk_gate_threshold",
    "mtd_risk_gate_cooldown",
    "mtd_risk_gate_fire_count",
    "mtd_risk_gate_suppressed_count",
    "mtd_risk_gate_score_mean",
    "mtd_conditional_policy_enabled",
    "mtd_conditional_policy_mode",
    "mtd_conditional_high_risk_threshold",
    "mtd_conditional_low_risk_threshold",
    "mtd_conditional_count2_action_count",
    "mtd_conditional_duration2_action_count",
    "mtd_conditional_suppress_count",
    "mtd_edge_block_events",
    "mtd_edge_block_active_steps",
    "mtd_event_count",
    "mtd_total_cost",
    "post_decoy_defense_mpc_q_active_count",
    "post_decoy_defense_matching_active_count",
    "post_decoy_defense_fallback_active_count",
]

MULTI_SEED_STATS_COLUMNS = [
    "scenario",
    "num_runs",
    "defender_belief_observation_mode",
    "post_decoy_defense_belief_source",
    "defender_bayesian_update_enabled",
    "defender_bayesian_prior_strength",
    "defender_bayesian_success_likelihood",
    "defender_bayesian_detected_likelihood",
    "defender_bayesian_decoy_likelihood",
    "defender_bayesian_critical_path_likelihood",
    "defender_bayesian_decay",
    "defense_objective_critical_weight",
    "defense_objective_post_decoy_weight",
    "defense_objective_delay_reward",
    "attacker_lateral_enabled",
    "honeypot_credential_enabled",
    "credential_node_ids",
    "credential_attraction_bonus",
    "credential_detection_bonus",
    "credential_reuse_decay",
    "credential_aware_mtd_enabled",
    "credential_trigger_mtd_window",
    "credential_trigger_block_count",
    "credential_trigger_block_duration",
    "credential_trigger_force_mtd",
    "credential_trigger_risk_bonus",
    "credential_staged_mtd_enabled",
    "credential_stage1_window",
    "credential_stage2_window",
    "credential_stage1_block_count",
    "credential_stage1_block_duration",
    "credential_stage2_block_count",
    "credential_stage2_block_duration",
    "critical_path_count",
    "decoy_on_critical_path",
    "chokepoint_nodes",
    "critical_edges",
    "critical_compromise_rate",
    "critical_compromise_step_mean",
    "critical_compromise_step_std",
    "mtd_enabled",
    "mtd_strategy",
    "mtd_interval",
    "mtd_intensity",
    "mtd_success_decay_bonus",
    "mtd_detection_bonus",
    "mtd_block_critical_edges",
    "mtd_edge_block_count",
    "mtd_edge_block_duration",
    "mtd_risk_gating_enabled",
    "mtd_risk_gate_mode",
    "mtd_risk_gate_threshold",
    "mtd_risk_gate_cooldown",
    "mtd_risk_gate_fire_count_mean",
    "mtd_risk_gate_suppressed_count_mean",
    "mtd_risk_gate_score_mean",
    "mtd_conditional_policy_enabled",
    "mtd_conditional_policy_mode",
    "mtd_conditional_high_risk_threshold",
    "mtd_conditional_low_risk_threshold",
    "mtd_conditional_count2_action_count_mean",
    "mtd_conditional_duration2_action_count_mean",
    "mtd_conditional_suppress_count_mean",
    "mtd_edge_block_events_mean",
    "mtd_edge_block_active_steps_mean",
    "retreat_rate",
    "retreat_step_mean",
    "retreat_step_std",
    "attacker_utility_final_mean",
    "attacker_utility_final_std",
    "actual_utility_mean",
    "actual_utility_std",
    "perceived_utility_mean",
    "perceived_utility_std",
    "confidence_mean",
    "confidence_std",
    "frustration_mean",
    "frustration_std",
    "frustration_max",
    "frustration_max_std",
    "frustration_retreats_mean",
    "frustration_retreats_std",
    "ai_uncertainty_cost_mean",
    "ai_uncertainty_cost_std",
    "ai_replanning_cost_mean",
    "ai_replanning_cost_std",
    "ai_search_cost_mean",
    "ai_search_cost_std",
    "ai_operational_risk_cost_mean",
    "ai_operational_risk_cost_std",
    "ai_trust_degradation_cost_mean",
    "ai_trust_degradation_cost_std",
    "ai_total_decision_cost",
    "ai_total_decision_cost_std",
    "ai_weighted_cost",
    "ai_weighted_cost_std",
    "human_vs_ai_cost_ratio_mean",
    "human_vs_ai_cost_ratio_std",
    "ai_uncertainty_weight",
    "ai_replanning_weight",
    "ai_search_weight",
    "ai_operational_risk_weight",
    "ai_trust_degradation_weight",
    "neutralization_score_mean",
    "neutralization_score_std",
    "cognitive_neutralization_score_mean",
    "cognitive_neutralization_score_std",
    "cognitive_human_score_mean",
    "cognitive_human_score_std",
    "cognitive_ai_score_mean",
    "cognitive_ai_score_std",
    "cns_objective_score_mean",
    "cns_objective_score_std",
    "cns_human_contribution_mean",
    "cns_human_contribution_std",
    "cns_ai_contribution_mean",
    "cns_ai_contribution_std",
    "cns_protection_contribution_mean",
    "cns_protection_contribution_std",
    "critical_protection_score_mean",
    "critical_protection_score_std",
    "utility_suppression_score_mean",
    "utility_suppression_score_std",
    "deception_waste_score_mean",
    "deception_waste_score_std",
    "friction_score_mean",
    "friction_score_std",
    "retreat_score_mean",
    "retreat_score_std",
    "retreat_based_on",
    "perceived_utility_enabled",
    "frustration_enabled",
    "adaptive_attacker_enabled",
    "adaptive_preference_enabled",
    "adaptive_path_enabled",
    "adaptive_planning_enabled",
    "planning_depth",
    "mtd_event_count_mean",
    "mtd_total_cost_mean",
    "mtd_compromised_delta_vs_reference",
    "mtd_utility_delta_vs_reference",
    "mtd_cost_adjusted_delta",
    "bayesian_compromise_delta_vs_target_frequency",
    "bayesian_post_decoy_delta_vs_target_frequency",
    "bayesian_error_delta_vs_target_frequency",
    "attacker_total_cost_mean",
    "attacker_total_cost_std",
    "attacker_compromised_value_mean",
    "attacker_compromised_value_std",
    "attacker_success_count_mean",
    "attacker_success_count_std",
    "attacker_detected_count_mean",
    "attacker_detected_count_std",
    "attacker_decoy_attack_rate_mean",
    "attacker_decoy_attack_rate_std",
    "credential_obtained_count_mean",
    "credential_obtained_count_std",
    "credential_used_count_mean",
    "credential_used_count_std",
    "credential_decoy_trigger_count_mean",
    "credential_decoy_trigger_count_std",
    "credential_trigger_rate_mean",
    "credential_trigger_rate_std",
    "credential_trigger_mtd_event_count_mean",
    "credential_trigger_mtd_event_count_std",
    "credential_trigger_recently_active_count_mean",
    "credential_trigger_recently_active_count_std",
    "credential_stage1_action_count_mean",
    "credential_stage1_action_count_std",
    "credential_stage2_action_count_mean",
    "credential_stage2_action_count_std",
    "credential_stage_none_count_mean",
    "credential_stage_none_count_std",
    "mean_attack_success_prob_mean",
    "mean_attack_detection_prob_mean",
    "adaptive_memory_success_mean",
    "adaptive_memory_success_std",
    "adaptive_memory_decoy_mean",
    "adaptive_memory_decoy_std",
    "adaptive_memory_detection_mean",
    "adaptive_memory_detection_std",
    "preference_mean",
    "preference_std",
    "preference_max_mean",
    "preference_max_std",
    "preferred_node_score_mean",
    "preferred_node_score_std",
    "preferred_node_on_critical_path_rate",
    "path_preference_mean",
    "path_preference_std",
    "path_preference_max_mean",
    "path_preference_max_std",
    "preferred_path",
    "preferred_path_score_mean",
    "preferred_path_score_std",
    "preferred_path_is_critical_rate",
    "planning_score_mean",
    "planning_score_std",
    "planning_score_max_mean",
    "planning_score_max_std",
    "planned_path",
    "planned_path_score_mean",
    "planned_path_score_std",
    "planned_path_is_critical_rate",
    "trust_mean_mean",
    "trust_mean_std",
    "trust_min_mean",
    "trust_min_std",
    "trust_max_mean",
    "trust_max_std",
    "trust_collapse_rate_mean",
    "trust_collapse_rate_std",
    "least_trusted_node_mean",
    "most_trusted_node_mean",
    "expected_utility_final_mean",
    "expected_utility_final_std",
    "expected_utility_mean_mean",
    "expected_utility_mean_std",
    "expected_gain_estimate_mean",
    "expected_detection_risk_mean",
    "expected_search_cost_mean",
    "target_switch_count_mean",
    "target_switch_count_std",
    "weighted_cumulative_risk_mean",
    "weighted_cumulative_risk_std",
    "final_risk_sum_mean",
    "final_risk_sum_std",
    "attacker_belief_change_l1_mean",
    "attacker_belief_change_l1_std",
    "attacker_belief_decoy_reduction_mean",
    "attacker_belief_decoy_reduction_std",
    "post_decoy_real_attack_mean",
    "post_decoy_real_attack_std",
    "post_decoy_compromised_mean",
    "post_decoy_compromised_std",
    "defender_estimation_error_l1_mean",
    "defender_estimation_error_l1_std",
    "defender_estimation_error_l2_mean",
    "defender_estimation_error_l2_std",
    "defender_bayesian_error_l1_mean",
    "defender_bayesian_error_l1_std",
    "defender_bayesian_error_l2_mean",
    "defender_bayesian_error_l2_std",
    "defense_objective_score_mean",
    "defense_objective_score_std",
    "defense_objective_delta_vs_target_frequency",
    "critical_rate_delta_vs_target_frequency",
    "post_decoy_delta_vs_target_frequency",
    "post_decoy_node0_rate",
    "post_decoy_node1_rate",
    "post_decoy_node2_rate",
    "post_decoy_node3_rate",
    "post_decoy_node4_rate",
    "post_decoy_defense_active_count_mean",
    "post_decoy_defense_mpc_q_active_count_mean",
    "post_decoy_defense_matching_active_count_mean",
    "post_decoy_defense_fallback_active_count_mean",
    "post_decoy_utility_mean",
    "post_decoy_utility_std",
]

POLICY_SELECTION_COLUMNS = [
    "policy",
    "num_runs",
    "defense_objective_score_mean",
    "defense_objective_score_std",
    "critical_compromise_rate",
    "critical_compromise_step_mean",
    "post_decoy_compromised_mean",
    "post_decoy_compromised_std",
    "mtd_total_cost_mean",
    "mtd_risk_gating_enabled",
    "mtd_risk_gate_mode",
    "mtd_risk_gate_threshold",
    "mtd_risk_gate_cooldown",
    "mtd_edge_block_duration",
    "mtd_edge_block_count",
    "mtd_conditional_policy_enabled",
    "mtd_conditional_policy_mode",
    "mtd_conditional_high_risk_threshold",
    "mtd_conditional_low_risk_threshold",
    "mtd_conditional_count2_action_count_mean",
    "mtd_conditional_duration2_action_count_mean",
    "mtd_conditional_suppress_count_mean",
    "credential_trigger_rate_mean",
    "credential_trigger_mtd_event_count_mean",
    "credential_aware_mtd_enabled",
    "credential_trigger_mtd_window",
    "credential_trigger_block_count",
    "credential_trigger_block_duration",
    "credential_trigger_force_mtd",
    "credential_trigger_risk_bonus",
    "credential_staged_mtd_enabled",
    "credential_stage1_window",
    "credential_stage2_window",
    "credential_stage1_action_count_mean",
    "credential_stage2_action_count_mean",
    "credential_stage_none_count_mean",
    "mtd_risk_gate_fire_count_mean",
    "mtd_risk_gate_suppressed_count_mean",
    "mtd_risk_gate_score_mean",
    "cost_per_post_decoy_reduction",
    "critical_rate_improvement_vs_reference",
    "post_decoy_reduction_vs_reference",
    "defender_bayesian_error_l1_mean",
    "selected_policy_rank",
]


def _config_to_kwargs(config: SimulationConfig) -> Dict[str, object]:
    values = asdict(config)
    for key, value in list(values.items()):
        if isinstance(value, np.ndarray):
            values[key] = value.copy()
    return values


def load_base_config(config_path: str = "config.json") -> SimulationConfig:
    if os.path.exists(config_path):
        return SimulationConfig.from_json(config_path)
    return SimulationConfig()


def make_scenario_config(base_config: SimulationConfig, overrides: Dict[str, object], seed: int) -> SimulationConfig:
    values = _config_to_kwargs(base_config)
    values.update(overrides)
    values["seed"] = seed
    values["show_plot"] = False
    values["output_metrics"] = True
    values["save_history"] = True
    return SimulationConfig(**values)


def run_one_scenario(
    scenario_name: str,
    config: SimulationConfig,
    output_root: str = os.path.join("output", "scenarios"),
    render_plot: bool = True,
) -> Dict[str, object]:
    scenario_dir = os.path.join(output_root, scenario_name)
    os.makedirs(scenario_dir, exist_ok=True)

    simulator = CyberDefenseSimulator(config)
    history = simulator.run()
    metrics = simulator.save_outputs(scenario_dir)
    config.to_json(os.path.join(scenario_dir, "used_config.json"))
    if render_plot:
        Visualizer.plot_results(
            history,
            config,
            save_path=os.path.join(scenario_dir, "simulation_result.png"),
        )

    row = {"scenario": scenario_name}
    row.update(metrics)
    return row


def build_summary_rows(metrics_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    rows = [{column: row.get(column) for column in SUMMARY_COLUMNS} for row in metrics_rows]
    _add_mtd_reference_deltas(rows, compromised_key="post_decoy_compromised_value", utility_key="post_decoy_utility", cost_key="mtd_total_cost")
    _add_bayesian_target_frequency_deltas(
        rows,
        compromise_key="critical_compromise",
        post_decoy_key="post_decoy_compromised_value",
        error_key="defender_bayesian_error_l1",
    )
    _add_defense_objective_deltas(
        rows,
        objective_key="defense_objective_score",
        critical_rate_key="critical_compromise",
        post_decoy_key="post_decoy_compromised_value",
    )
    return rows


def _add_mtd_reference_deltas(
    rows: List[Dict[str, object]],
    compromised_key: str,
    utility_key: str,
    cost_key: str,
) -> None:
    reference = next((row for row in rows if row.get("scenario") == "mtd_none_reference"), None)
    if reference is None:
        return
    reference_compromised = _to_float(reference.get(compromised_key))
    reference_utility = _to_float(reference.get(utility_key))
    for row in rows:
        if not str(row.get("scenario", "")).startswith("mtd_"):
            continue
        compromised_delta = _to_float(row.get(compromised_key)) - reference_compromised
        utility_delta = _to_float(row.get(utility_key)) - reference_utility
        row["mtd_compromised_delta_vs_reference"] = float(compromised_delta)
        row["mtd_utility_delta_vs_reference"] = float(utility_delta)
        row["mtd_cost_adjusted_delta"] = float(compromised_delta + _to_float(row.get(cost_key)))


def _add_bayesian_target_frequency_deltas(
    rows: List[Dict[str, object]],
    compromise_key: str,
    post_decoy_key: str,
    error_key: str,
) -> None:
    reference = next((row for row in rows if row.get("scenario") == "bayesian_vs_target_frequency_reference"), None)
    if reference is None:
        return
    reference_compromise = _to_float(reference.get(compromise_key))
    reference_post_decoy = _to_float(reference.get(post_decoy_key))
    reference_error = _to_float(reference.get(error_key))
    for row in rows:
        if not str(row.get("scenario", "")).startswith("bayesian_"):
            continue
        row["bayesian_compromise_delta_vs_target_frequency"] = float(_to_float(row.get(compromise_key)) - reference_compromise)
        row["bayesian_post_decoy_delta_vs_target_frequency"] = float(_to_float(row.get(post_decoy_key)) - reference_post_decoy)
        row["bayesian_error_delta_vs_target_frequency"] = float(_to_float(row.get(error_key)) - reference_error)


def _add_defense_objective_deltas(
    rows: List[Dict[str, object]],
    objective_key: str,
    critical_rate_key: str,
    post_decoy_key: str,
) -> None:
    reference = next((row for row in rows if row.get("scenario") == "bayesian_vs_target_frequency_reference"), None)
    if reference is None:
        return
    reference_objective = _to_float(reference.get(objective_key))
    reference_critical_rate = _to_float(reference.get(critical_rate_key))
    reference_post_decoy = _to_float(reference.get(post_decoy_key))
    for row in rows:
        if not str(row.get("scenario", "")).startswith("bayesian_"):
            continue
        row["defense_objective_delta_vs_target_frequency"] = float(_to_float(row.get(objective_key)) - reference_objective)
        row["critical_rate_delta_vs_target_frequency"] = float(_to_float(row.get(critical_rate_key)) - reference_critical_rate)
        row["post_decoy_delta_vs_target_frequency"] = float(_to_float(row.get(post_decoy_key)) - reference_post_decoy)


def write_summary(summary_rows: List[Dict[str, object]], output_root: str) -> None:
    os.makedirs(output_root, exist_ok=True)
    csv_path = os.path.join(output_root, "summary.csv")
    json_path = os.path.join(output_root, "summary.json")

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_COLUMNS)
        writer.writeheader()
        writer.writerows(summary_rows)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary_rows, f, indent=4, ensure_ascii=False)


def plot_summary(summary_rows: List[Dict[str, object]], output_root: str) -> None:
    _plot_bar(
        summary_rows,
        value_key="attacker_utility_final",
        title="Attacker Utility by Scenario",
        ylabel="Final Utility",
        save_path=os.path.join(output_root, "summary_attacker_utility.png"),
    )
    _plot_bar(
        summary_rows,
        value_key="weighted_cumulative_risk",
        title="Weighted Cumulative Risk by Scenario",
        ylabel="Weighted Cumulative Risk",
        save_path=os.path.join(output_root, "summary_risk.png"),
    )
    _plot_target_counts(
        summary_rows,
        save_path=os.path.join(output_root, "summary_target_counts.png"),
    )
    _plot_belief_error_vs_gain(
        summary_rows,
        save_path=os.path.join(output_root, "summary_belief_error_vs_gain.png"),
    )
    _plot_bar(
        summary_rows,
        value_key="attacker_decoy_attack_rate",
        title="Decoy Attack Rate by Scenario",
        ylabel="Decoy Attack Rate",
        save_path=os.path.join(output_root, "summary_decoy_attack_rate.png"),
    )
    _plot_bar(
        summary_rows,
        value_key="attacker_utility_final",
        title="Attacker Utility by Scenario",
        ylabel="Final Utility",
        save_path=os.path.join(output_root, "summary_decoy_utility.png"),
    )
    _plot_probability_effects(
        summary_rows,
        save_path=os.path.join(output_root, "summary_probability_effects.png"),
    )
    _plot_bar(
        summary_rows,
        value_key="attacker_belief_change_l1",
        title="Belief Change L1 by Scenario",
        ylabel="Belief Change L1",
        save_path=os.path.join(output_root, "summary_belief_learning.png"),
    )
    _plot_post_decoy_targets(
        summary_rows,
        save_path=os.path.join(output_root, "summary_post_decoy_targets.png"),
    )
    _plot_transition_matrix(
        summary_rows,
        save_path=os.path.join(output_root, "summary_transition_matrix.png"),
    )
    _plot_bar(
        summary_rows,
        value_key="post_decoy_compromised_value",
        title="Post-Decoy Compromised Value by Scenario",
        ylabel="Post-Decoy Compromised Value",
        save_path=os.path.join(output_root, "summary_post_decoy_defense_effect.png"),
    )
    _plot_bar(
        summary_rows,
        value_key="defender_estimation_error_l1",
        title="Defender Belief Estimation Error by Scenario",
        ylabel="Defender Estimation Error L1",
        save_path=os.path.join(output_root, "summary_belief_estimation_error.png"),
    )
    _plot_estimated_vs_oracle_defense(
        summary_rows,
        save_path=os.path.join(output_root, "summary_estimated_vs_oracle_defense.png"),
    )
    _plot_visible_log_estimation(
        summary_rows,
        save_path=os.path.join(output_root, "summary_visible_log_estimation.png"),
    )
    _plot_mtd_effect(
        summary_rows,
        save_path=os.path.join(output_root, "summary_mtd_effect.png"),
    )
    _plot_bar(
        summary_rows,
        value_key="post_decoy_compromised_value",
        title="Post-Decoy Compromised Value by Injection Mode",
        ylabel="Post-Decoy Compromised Value",
        save_path=os.path.join(output_root, "summary_post_decoy_injection_modes.png"),
    )


def _plot_bar(
    summary_rows: List[Dict[str, object]],
    value_key: str,
    title: str,
    ylabel: str,
    save_path: str,
) -> None:
    labels = [str(row["scenario"]) for row in summary_rows]
    values = [float(row.get(value_key) or 0.0) for row in summary_rows]

    plt.figure(figsize=(12, 6))
    plt.bar(labels, values, color="#4c78a8")
    plt.title(title)
    plt.ylabel(ylabel)
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_target_counts(summary_rows: List[Dict[str, object]], save_path: str) -> None:
    labels = [str(row["scenario"]) for row in summary_rows]
    counts_by_scenario = [_parse_target_counts(row.get("attacker_target_counts")) for row in summary_rows]
    max_nodes = max((len(counts) for counts in counts_by_scenario), default=0)
    if max_nodes == 0:
        return

    x = np.arange(len(labels))
    bottom = np.zeros(len(labels))
    plt.figure(figsize=(12, 6))
    for node_idx in range(max_nodes):
        values = np.array([
            counts[node_idx] if node_idx < len(counts) else 0
            for counts in counts_by_scenario
        ])
        plt.bar(x, values, bottom=bottom, label=f"Node {node_idx}")
        bottom += values

    plt.title("Attacker Target Counts by Scenario")
    plt.ylabel("Target Count")
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _parse_target_counts(value: object) -> List[int]:
    if value is None:
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    if isinstance(value, dict):
        return [int(value[key]) for key in sorted(value, key=lambda item: int(item))]
    return [int(item) for item in value]


def _parse_transition_matrix(value: object) -> Dict[str, int]:
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {}
    return {str(key): int(count) for key, count in dict(value).items()}


def _plot_post_decoy_targets(summary_rows: List[Dict[str, object]], save_path: str) -> None:
    labels = [str(row["scenario"]) for row in summary_rows]
    counts_by_scenario = [_parse_target_counts(row.get("post_decoy_target_counts")) for row in summary_rows]
    max_nodes = max((len(counts) for counts in counts_by_scenario), default=0)
    if max_nodes == 0:
        return

    x = np.arange(len(labels))
    bottom = np.zeros(len(labels))
    plt.figure(figsize=(12, 6))
    for node_idx in range(max_nodes):
        values = np.array([
            counts[node_idx] if node_idx < len(counts) else 0
            for counts in counts_by_scenario
        ])
        plt.bar(x, values, bottom=bottom, label=f"Node {node_idx}")
        bottom += values

    plt.title("Post-Decoy Target Counts by Scenario")
    plt.ylabel("Post-Decoy Target Count")
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_transition_matrix(summary_rows: List[Dict[str, object]], save_path: str) -> None:
    aggregate = np.zeros((5, 5))
    for row in summary_rows:
        transitions = _parse_transition_matrix(row.get("attack_transition_matrix"))
        for key, count in transitions.items():
            try:
                source, target = [int(part) for part in key.split("->")]
            except ValueError:
                continue
            if 0 <= source < 5 and 0 <= target < 5:
                aggregate[source, target] += count

    plt.figure(figsize=(7, 6))
    plt.imshow(aggregate, cmap="Blues")
    plt.title("Aggregate Attack Transition Matrix")
    plt.xlabel("To Node")
    plt.ylabel("From Node")
    plt.xticks(range(5))
    plt.yticks(range(5))
    for i in range(5):
        for j in range(5):
            plt.text(j, i, int(aggregate[i, j]), ha="center", va="center", color="black")
    plt.colorbar(label="Transition Count")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_belief_error_vs_gain(summary_rows: List[Dict[str, object]], save_path: str) -> None:
    x_values = [float(row.get("attacker_belief_error_l1") or 0.0) for row in summary_rows]
    y_values = [float(row.get("attacker_compromised_value") or 0.0) for row in summary_rows]
    labels = [str(row["scenario"]) for row in summary_rows]

    plt.figure(figsize=(10, 6))
    plt.scatter(x_values, y_values, color="#e45756")
    for x_val, y_val, label in zip(x_values, y_values, labels):
        plt.annotate(label, (x_val, y_val), fontsize=7, alpha=0.8)
    plt.title("Belief Error vs Attacker Gain")
    plt.xlabel("Attacker Belief Error L1")
    plt.ylabel("Attacker Compromised Value")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_probability_effects(summary_rows: List[Dict[str, object]], save_path: str) -> None:
    labels = [str(row["scenario"]) for row in summary_rows]
    detection_probs = [float(row.get("mean_attack_detection_prob") or 0.0) for row in summary_rows]
    utilities = [float(row.get("attacker_utility_final") or 0.0) for row in summary_rows]
    x = np.arange(len(labels))
    width = 0.4

    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.bar(x - width / 2, detection_probs, width=width, color="#72b7b2", label="Mean detection prob")
    ax1.set_ylabel("Mean Detection Probability")
    ax1.set_ylim(0, max(1.0, max(detection_probs, default=0.0)))
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, utilities, width=width, color="#f58518", label="Attacker utility")
    ax2.set_ylabel("Attacker Utility Final")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Probability Effects by Scenario")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _build_neutralization_row(label: str, scenario_name: str, metrics_row: Dict[str, object]) -> Dict[str, object]:
    source = dict(metrics_row)
    source["label"] = label
    source["scenario"] = scenario_name
    return {column: source.get(column) for column in NEUTRALIZATION_COLUMNS}


def write_neutralization_summary(rows: List[Dict[str, object]], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, "neutralization_summary.csv")
    json_path = os.path.join(output_dir, "neutralization_summary.json")

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=NEUTRALIZATION_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=4, ensure_ascii=False)


def plot_neutralization_summary(rows: List[Dict[str, object]], output_dir: str) -> None:
    if not rows:
        return
    os.makedirs(output_dir, exist_ok=True)
    ranked = sorted(rows, key=lambda row: _to_float(row.get("neutralization_score")), reverse=True)
    labels = [str(row.get("label")) for row in ranked]
    scores = np.array([_to_float(row.get("neutralization_score")) for row in ranked], dtype=float)

    plt.figure(figsize=(12, 6))
    plt.bar(labels, scores, color="#4c78a8")
    plt.ylim(0.0, 1.0)
    plt.title("Neutralization Ranking")
    plt.ylabel("Neutralization Score")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "neutralization_ranking.png"))
    plt.close()

    subscore_keys = [
        "critical_protection_score",
        "utility_suppression_score",
        "deception_waste_score",
        "friction_score",
        "retreat_score",
    ]
    x = np.arange(len(labels))
    bottom = np.zeros(len(labels), dtype=float)
    colors = ["#4c78a8", "#f58518", "#54a24b", "#eeca3b", "#b279a2"]
    plt.figure(figsize=(14, 7))
    for key, color in zip(subscore_keys, colors):
        values = np.array([_to_float(row.get(key)) for row in ranked], dtype=float)
        plt.bar(x, values, bottom=bottom, label=key.replace("_score", ""), color=color)
        bottom += values
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.ylabel("Subscore Sum")
    plt.title("Neutralization Subscore Breakdown")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "neutralization_breakdown.png"))
    plt.close()


def write_neutralization_report(rows: List[Dict[str, object]], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    ranked = sorted(rows, key=lambda row: _to_float(row.get("neutralization_score")), reverse=True)
    best = ranked[0] if ranked else {}
    critical_protected = [row for row in rows if not bool(row.get("critical_compromise"))]
    waste_best = max(rows, key=lambda row: _to_float(row.get("deception_waste_score"))) if rows else {}
    retreat_rows = [row for row in rows if bool(row.get("attacker_retreated"))]

    lines = [
        "# Neutralization Evaluation Report",
        "",
        "## 1. 無力化の定義",
        "本評価では CyberMatch の最終目標を攻撃の無力化とし、重要資産防護、攻撃者 utility 抑制、欺瞞による浪費誘導、攻撃進行の摩擦、撤退誘導の5軸で 0.0 から 1.0 に正規化して評価する。1.0 に近いほど無力化成功を意味する。",
        "",
        "## 2. 各subscoreの意味",
        "- `critical_protection_score`: critical compromise の未発生、または発生遅延を評価する。",
        "- `utility_suppression_score`: final utility と utility が負である時間割合を評価する。",
        "- `deception_waste_score`: decoy attack、credential trigger、MTD event、post-decoy real attack 抑制を評価する。",
        "- `friction_score`: critical 到達遅延、lateral failure、blocked edge、critical path 削減を評価する。",
        "- `retreat_score`: attacker retreat の有無と早さを評価する。",
        "",
        "## 3. 現状のbest policy",
        f"現状の best policy は `{best.get('label')}` (`{best.get('scenario')}`) で、neutralization_score は `{_to_float(best.get('neutralization_score')):.3f}`。",
        "",
        "## 4. 重要資産防護は達成できているか",
        f"critical compromise が発生しなかった評価対象は {len(critical_protected)}/{len(rows)} 件。best policy の critical_protection_score は `{_to_float(best.get('critical_protection_score')):.3f}`。",
        "",
        "## 5. 攻撃者の浪費誘導はできているか",
        f"deception_waste_score が最大の policy は `{waste_best.get('label')}` で、score は `{_to_float(waste_best.get('deception_waste_score')):.3f}`。decoy/credential/MTD は浪費誘導の測定対象として機能しているが、post-decoy real attack の残存量も併せて見る必要がある。",
        "",
        "## 6. 撤退誘導はまだ弱いか",
        f"attacker_retreated が true になった評価対象は {len(retreat_rows)}/{len(rows)} 件。retreat_score は総合スコア中の補助軸であり、現状では重要資産防護や utility 抑制に比べて弱い可能性がある。",
        "",
        "## 7. Phase1完了条件",
        "Phase1 は、neutralization_score と5つの subscore が全評価対象で出力され、ランキング、breakdown、CSV/JSON、Markdown レポートが再生成可能になった時点で完了とする。",
        "",
        "## 8. Phase2で必要なこと",
        "Phase2 では、複数 seed の neutralization 平均/分散、攻撃者 belief 更新の perceived 化、defender-visible logs ベースの観測、撤退誘導を強化する policy を検討する必要がある。",
        "",
        "## Ranking",
        "",
        "| rank | label | scenario | neutralization_score | critical | utility | deception | friction | retreat |",
        "|---:|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for idx, row in enumerate(ranked, start=1):
        lines.append(
            f"| {idx} | {row.get('label')} | {row.get('scenario')} | "
            f"{_to_float(row.get('neutralization_score')):.3f} | "
            f"{_to_float(row.get('critical_protection_score')):.3f} | "
            f"{_to_float(row.get('utility_suppression_score')):.3f} | "
            f"{_to_float(row.get('deception_waste_score')):.3f} | "
            f"{_to_float(row.get('friction_score')):.3f} | "
            f"{_to_float(row.get('retreat_score')):.3f} |"
        )

    with open(os.path.join(output_dir, "NEUTRALIZATION_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run_neutralization_evaluation(
    config_path: str = "config.json",
    output_dir: str = os.path.join("output", "neutralization"),
    seed: int = 42,
) -> List[Dict[str, object]]:
    base_config = load_base_config(config_path)
    rows = []
    for label, scenario_name in NEUTRALIZATION_SCENARIO_MAP.items():
        overrides = SCENARIOS[scenario_name]
        config = make_scenario_config(base_config, overrides, seed=seed)
        metrics = run_one_scenario(
            scenario_name,
            config,
            output_root=os.path.join(output_dir, "scenarios"),
            render_plot=False,
        )
        rows.append(_build_neutralization_row(label, scenario_name, metrics))

    rows.sort(key=lambda row: _to_float(row.get("neutralization_score")), reverse=True)
    write_neutralization_summary(rows, output_dir)
    plot_neutralization_summary(rows, output_dir)
    write_neutralization_report(rows, output_dir)
    return rows


def _plot_estimated_vs_oracle_defense(summary_rows: List[Dict[str, object]], save_path: str) -> None:
    rows = [
        row
        for row in summary_rows
        if str(row.get("scenario", "")).startswith("adaptive_decoy_defense_")
    ]
    if not rows:
        rows = summary_rows
    _plot_bar(
        rows,
        value_key="post_decoy_compromised_value",
        title="Oracle vs Estimated Belief Defense",
        ylabel="Post-Decoy Compromised Value",
        save_path=save_path,
    )


def _plot_visible_log_estimation(summary_rows: List[Dict[str, object]], save_path: str) -> None:
    modes = {"target_frequency", "selection_score", "defender_visible_log", "hybrid_visible"}
    rows = [
        row
        for row in summary_rows
        if row.get("defender_belief_observation_mode") in modes
        and row.get("post_decoy_defense_belief_source") == "estimated"
    ]
    if not rows:
        return
    labels = [str(row["scenario"]).replace("adaptive_decoy_defense_estimated_belief_", "") for row in rows]
    compromised = np.array([float(row.get("post_decoy_compromised_value") or 0.0) for row in rows])
    errors = np.array([float(row.get("defender_estimation_error_l1") or 0.0) for row in rows])
    x = np.arange(len(labels))
    width = 0.4

    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.bar(x - width / 2, compromised, width=width, color="#4c78a8", label="Post-decoy compromised")
    ax1.set_ylabel("Post-Decoy Compromised Value")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, errors, width=width, color="#f58518", label="Estimation error L1")
    ax2.set_ylabel("Defender Estimation Error L1")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Visible Log Belief Estimation Comparison")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_mtd_effect(summary_rows: List[Dict[str, object]], save_path: str) -> None:
    rows = [row for row in summary_rows if str(row.get("scenario", "")).startswith("mtd_")]
    if not rows:
        return
    labels = [str(row["scenario"]).replace("mtd_", "") for row in rows]
    compromised = np.array([float(row.get("post_decoy_compromised_value") or 0.0) for row in rows])
    costs = np.array([float(row.get("mtd_total_cost") or 0.0) for row in rows])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.bar(x - width / 2, compromised, width=width, color="#4c78a8", label="Post-decoy compromised")
    ax1.set_ylabel("Post-Decoy Compromised Value")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, costs, width=width, color="#f58518", label="MTD total cost")
    ax2.set_ylabel("MTD Total Cost")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("MTD Effect by Scenario")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def run_scenarios(
    config_path: str = "config.json",
    output_root: str = os.path.join("output", "scenarios"),
    scenario_overrides: Optional[Dict[str, Dict[str, object]]] = None,
    seed: int = 42,
) -> List[Dict[str, object]]:
    base_config = load_base_config(config_path)
    scenarios = scenario_overrides or SCENARIOS
    metrics_rows = []

    for scenario_name, overrides in scenarios.items():
        config = make_scenario_config(base_config, overrides, seed=seed)
        metrics_rows.append(run_one_scenario(scenario_name, config, output_root=output_root))

    summary_rows = build_summary_rows(metrics_rows)
    write_summary(summary_rows, output_root)
    plot_summary(summary_rows, output_root)
    return summary_rows


def run_scenarios_multi_seed(
    scenarios: Optional[Dict[str, Dict[str, object]]] = None,
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "scenarios_multiseed"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    base_config = load_base_config(config_path)
    scenario_overrides = scenarios or {
        name: SCENARIOS[name] for name in MULTI_SEED_SCENARIO_NAMES
    }
    seed_values = seeds or MULTI_SEED_VALUES
    run_rows = []

    for scenario_name, overrides in scenario_overrides.items():
        for seed in seed_values:
            config = make_scenario_config(base_config, overrides, seed=seed)
            seed_output_root = os.path.join(output_dir, scenario_name)
            row = run_one_scenario(
                f"seed_{seed}",
                config,
                output_root=seed_output_root,
                render_plot=False,
            )
            run_rows.append(_build_multiseed_run_row(scenario_name, seed, row))

    stats_rows = build_multiseed_stats_rows(run_rows)
    write_multiseed_summaries(run_rows, stats_rows, output_dir)
    plot_multiseed_summary(stats_rows, output_dir)
    return stats_rows


def _build_multiseed_run_row(scenario_name: str, seed: int, metrics_row: Dict[str, object]) -> Dict[str, object]:
    source = dict(metrics_row)
    source["scenario"] = scenario_name
    source["seed"] = seed
    return {column: source.get(column) for column in MULTI_SEED_RUN_COLUMNS}


def build_multiseed_stats_rows(run_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    scenario_names = []
    for row in run_rows:
        if row["scenario"] not in scenario_names:
            scenario_names.append(row["scenario"])

    stats_rows = []
    for scenario_name in scenario_names:
        rows = [row for row in run_rows if row["scenario"] == scenario_name]
        stats_rows.append(_build_multiseed_stats_row(scenario_name, rows))
    _add_mtd_reference_deltas(
        stats_rows,
        compromised_key="post_decoy_compromised_mean",
        utility_key="post_decoy_utility_mean",
        cost_key="mtd_total_cost_mean",
    )
    _add_bayesian_target_frequency_deltas(
        stats_rows,
        compromise_key="critical_compromise_rate",
        post_decoy_key="post_decoy_compromised_mean",
        error_key="defender_bayesian_error_l1_mean",
    )
    _add_defense_objective_deltas(
        stats_rows,
        objective_key="defense_objective_score_mean",
        critical_rate_key="critical_compromise_rate",
        post_decoy_key="post_decoy_compromised_mean",
    )
    return stats_rows


def _build_multiseed_stats_row(scenario_name: str, rows: List[Dict[str, object]]) -> Dict[str, object]:
    retreated = np.array([bool(row.get("attacker_retreated")) for row in rows], dtype=bool)
    critical_compromised = np.array([bool(row.get("critical_compromise")) for row in rows], dtype=bool)
    retreat_steps = [
        float(row["attacker_retreat_step"])
        for row in rows
        if row.get("attacker_retreat_step") is not None and row.get("attacker_retreat_step") != ""
    ]
    critical_steps = [
        float(row["critical_compromise_step"])
        for row in rows
        if row.get("critical_compromise_step") is not None and row.get("critical_compromise_step") != ""
    ]

    result = {
        "scenario": scenario_name,
        "num_runs": len(rows),
        "defender_belief_observation_mode": rows[0].get("defender_belief_observation_mode") if rows else None,
        "post_decoy_defense_belief_source": rows[0].get("post_decoy_defense_belief_source") if rows else None,
        "defender_bayesian_update_enabled": rows[0].get("defender_bayesian_update_enabled") if rows else None,
        "defender_bayesian_prior_strength": rows[0].get("defender_bayesian_prior_strength") if rows else None,
        "defender_bayesian_success_likelihood": rows[0].get("defender_bayesian_success_likelihood") if rows else None,
        "defender_bayesian_detected_likelihood": rows[0].get("defender_bayesian_detected_likelihood") if rows else None,
        "defender_bayesian_decoy_likelihood": rows[0].get("defender_bayesian_decoy_likelihood") if rows else None,
        "defender_bayesian_critical_path_likelihood": rows[0].get("defender_bayesian_critical_path_likelihood") if rows else None,
        "defender_bayesian_decay": rows[0].get("defender_bayesian_decay") if rows else None,
        "defense_objective_critical_weight": rows[0].get("defense_objective_critical_weight") if rows else None,
        "defense_objective_post_decoy_weight": rows[0].get("defense_objective_post_decoy_weight") if rows else None,
        "defense_objective_delay_reward": rows[0].get("defense_objective_delay_reward") if rows else None,
        "attacker_lateral_enabled": rows[0].get("attacker_lateral_enabled") if rows else None,
        "honeypot_credential_enabled": rows[0].get("honeypot_credential_enabled") if rows else None,
        "credential_node_ids": rows[0].get("credential_node_ids") if rows else None,
        "credential_attraction_bonus": rows[0].get("credential_attraction_bonus") if rows else None,
        "credential_detection_bonus": rows[0].get("credential_detection_bonus") if rows else None,
        "credential_reuse_decay": rows[0].get("credential_reuse_decay") if rows else None,
        "credential_aware_mtd_enabled": rows[0].get("credential_aware_mtd_enabled") if rows else None,
        "credential_trigger_mtd_window": rows[0].get("credential_trigger_mtd_window") if rows else None,
        "credential_trigger_block_count": rows[0].get("credential_trigger_block_count") if rows else None,
        "credential_trigger_block_duration": rows[0].get("credential_trigger_block_duration") if rows else None,
        "credential_trigger_force_mtd": rows[0].get("credential_trigger_force_mtd") if rows else None,
        "credential_trigger_risk_bonus": rows[0].get("credential_trigger_risk_bonus") if rows else None,
        "credential_staged_mtd_enabled": rows[0].get("credential_staged_mtd_enabled") if rows else None,
        "credential_stage1_window": rows[0].get("credential_stage1_window") if rows else None,
        "credential_stage2_window": rows[0].get("credential_stage2_window") if rows else None,
        "credential_stage1_block_count": rows[0].get("credential_stage1_block_count") if rows else None,
        "credential_stage1_block_duration": rows[0].get("credential_stage1_block_duration") if rows else None,
        "credential_stage2_block_count": rows[0].get("credential_stage2_block_count") if rows else None,
        "credential_stage2_block_duration": rows[0].get("credential_stage2_block_duration") if rows else None,
        "critical_path_count": rows[0].get("critical_path_count") if rows else None,
        "decoy_on_critical_path": rows[0].get("decoy_on_critical_path") if rows else None,
        "chokepoint_nodes": rows[0].get("chokepoint_nodes") if rows else None,
        "critical_edges": rows[0].get("critical_edges") if rows else None,
        "critical_compromise_rate": float(np.mean(critical_compromised)) if rows else 0.0,
        "critical_compromise_step_mean": _mean_or_none(critical_steps),
        "critical_compromise_step_std": _std_or_none(critical_steps),
        "mtd_enabled": rows[0].get("mtd_enabled") if rows else None,
        "mtd_strategy": rows[0].get("mtd_strategy") if rows else None,
        "mtd_interval": rows[0].get("mtd_interval") if rows else None,
        "mtd_intensity": rows[0].get("mtd_intensity") if rows else None,
        "mtd_success_decay_bonus": rows[0].get("mtd_success_decay_bonus") if rows else None,
        "mtd_detection_bonus": rows[0].get("mtd_detection_bonus") if rows else None,
        "mtd_block_critical_edges": rows[0].get("mtd_block_critical_edges") if rows else None,
        "mtd_edge_block_count": rows[0].get("mtd_edge_block_count") if rows else None,
        "mtd_edge_block_duration": rows[0].get("mtd_edge_block_duration") if rows else None,
        "mtd_risk_gating_enabled": rows[0].get("mtd_risk_gating_enabled") if rows else None,
        "mtd_risk_gate_mode": rows[0].get("mtd_risk_gate_mode") if rows else None,
        "mtd_risk_gate_threshold": rows[0].get("mtd_risk_gate_threshold") if rows else None,
        "mtd_risk_gate_cooldown": rows[0].get("mtd_risk_gate_cooldown") if rows else None,
        "mtd_conditional_policy_enabled": rows[0].get("mtd_conditional_policy_enabled") if rows else None,
        "mtd_conditional_policy_mode": rows[0].get("mtd_conditional_policy_mode") if rows else None,
        "mtd_conditional_high_risk_threshold": rows[0].get("mtd_conditional_high_risk_threshold") if rows else None,
        "mtd_conditional_low_risk_threshold": rows[0].get("mtd_conditional_low_risk_threshold") if rows else None,
        "ai_uncertainty_weight": rows[0].get("ai_uncertainty_weight") if rows else None,
        "ai_replanning_weight": rows[0].get("ai_replanning_weight") if rows else None,
        "ai_search_weight": rows[0].get("ai_search_weight") if rows else None,
        "ai_operational_risk_weight": rows[0].get("ai_operational_risk_weight") if rows else None,
        "ai_trust_degradation_weight": rows[0].get("ai_trust_degradation_weight") if rows else None,
        "retreat_based_on": rows[0].get("retreat_based_on") if rows else None,
        "perceived_utility_enabled": rows[0].get("perceived_utility_enabled") if rows else None,
        "frustration_enabled": rows[0].get("frustration_enabled") if rows else None,
        "adaptive_attacker_enabled": rows[0].get("adaptive_attacker_enabled") if rows else None,
        "adaptive_preference_enabled": rows[0].get("adaptive_preference_enabled") if rows else None,
        "adaptive_path_enabled": rows[0].get("adaptive_path_enabled") if rows else None,
        "adaptive_planning_enabled": rows[0].get("adaptive_planning_enabled") if rows else None,
        "planning_depth": rows[0].get("planning_depth") if rows else None,
        "retreat_rate": float(np.mean(retreated)) if rows else 0.0,
        "retreat_step_mean": _mean_or_none(retreat_steps),
        "retreat_step_std": _std_or_none(retreat_steps),
    }

    for key in [
        "attacker_utility_final",
        "actual_utility_final",
        "perceived_utility_final",
        "actual_gain",
        "actual_cost",
        "perceived_gain",
        "perceived_cost",
        "mean_confidence",
        "adaptive_memory_success_mean",
        "adaptive_memory_decoy_mean",
        "adaptive_memory_detection_mean",
        "preference_mean",
        "preference_max",
        "preferred_node_score",
        "preferred_node_on_critical_path",
        "path_preference_mean",
        "path_preference_max",
        "preferred_path_score",
        "preferred_path_is_critical",
        "planning_score_mean",
        "planning_score_max",
        "planned_path_score",
        "planned_path_is_critical",
        "trust_mean",
        "trust_min",
        "trust_max",
        "trust_collapse_rate",
        "least_trusted_node",
        "most_trusted_node",
        "expected_utility_final",
        "expected_utility_mean",
        "expected_gain_estimate",
        "expected_detection_risk",
        "expected_search_cost",
        "target_switch_count",
        "frustration_final",
        "frustration_mean",
        "frustration_max",
        "frustration_retreats",
        "ai_uncertainty_cost",
        "ai_replanning_cost",
        "ai_search_cost",
        "ai_operational_risk_cost",
        "ai_trust_degradation_cost",
        "ai_total_decision_cost",
        "ai_weighted_cost",
        "human_vs_ai_cost_ratio",
        "cognitive_neutralization_score",
        "cognitive_human_score",
        "cognitive_ai_score",
        "cns_objective_score",
        "cns_human_contribution",
        "cns_ai_contribution",
        "cns_protection_contribution",
        "neutralization_score",
        "critical_protection_score",
        "utility_suppression_score",
        "deception_waste_score",
        "friction_score",
        "retreat_score",
        "attacker_total_cost",
        "attacker_compromised_value",
        "attacker_success_count",
        "attacker_detected_count",
        "attacker_decoy_attack_rate",
        "credential_obtained_count",
        "credential_used_count",
        "credential_decoy_trigger_count",
        "credential_trigger_rate",
        "credential_trigger_mtd_event_count",
        "credential_trigger_recently_active_count",
        "credential_stage1_action_count",
        "credential_stage2_action_count",
        "credential_stage_none_count",
        "weighted_cumulative_risk",
        "final_risk_sum",
        "attacker_belief_change_l1",
        "attacker_belief_decoy_reduction",
        "post_decoy_real_attack_count",
        "post_decoy_defense_active_count",
        "post_decoy_defense_mpc_q_active_count",
        "post_decoy_defense_matching_active_count",
        "post_decoy_defense_fallback_active_count",
        "defender_estimation_error_l1",
        "defender_estimation_error_l2",
        "defender_bayesian_error_l1",
        "defender_bayesian_error_l2",
        "defense_objective_score",
        "mtd_risk_gate_fire_count",
        "mtd_risk_gate_suppressed_count",
        "mtd_conditional_count2_action_count",
        "mtd_conditional_duration2_action_count",
        "mtd_conditional_suppress_count",
        "mtd_edge_block_events",
        "mtd_edge_block_active_steps",
        "mtd_event_count",
        "mtd_total_cost",
    ]:
        values = [_to_float(row.get(key)) for row in rows]
        result[f"{key}_mean"] = _mean_or_none(values)
        result[f"{key}_std"] = _std_or_none(values)
    result["actual_utility_mean"] = result.get("actual_utility_final_mean")
    result["actual_utility_std"] = result.get("actual_utility_final_std")
    result["perceived_utility_mean"] = result.get("perceived_utility_final_mean")
    result["perceived_utility_std"] = result.get("perceived_utility_final_std")
    result["confidence_mean"] = result.get("mean_confidence_mean")
    result["confidence_std"] = result.get("mean_confidence_std")
    result["frustration_mean"] = result.get("frustration_mean_mean")
    result["frustration_std"] = result.get("frustration_mean_std")
    result["frustration_max"] = result.get("frustration_max_mean")
    result["frustration_max_std"] = result.get("frustration_max_std")
    result["ai_total_decision_cost"] = result.get("ai_total_decision_cost_mean")
    result["ai_weighted_cost"] = result.get("ai_weighted_cost_mean")
    result["adaptive_memory_success_mean"] = result.get("adaptive_memory_success_mean_mean")
    result["adaptive_memory_success_std"] = result.get("adaptive_memory_success_mean_std")
    result["adaptive_memory_decoy_mean"] = result.get("adaptive_memory_decoy_mean_mean")
    result["adaptive_memory_decoy_std"] = result.get("adaptive_memory_decoy_mean_std")
    result["adaptive_memory_detection_mean"] = result.get("adaptive_memory_detection_mean_mean")
    result["adaptive_memory_detection_std"] = result.get("adaptive_memory_detection_mean_std")
    result["preference_mean"] = result.get("preference_mean_mean")
    result["preference_std"] = result.get("preference_mean_std")
    result["preference_max_mean"] = result.get("preference_max_mean")
    result["preference_max_std"] = result.get("preference_max_std")
    result["preferred_node_score_mean"] = result.get("preferred_node_score_mean")
    result["preferred_node_score_std"] = result.get("preferred_node_score_std")
    result["preferred_node_on_critical_path_rate"] = result.get("preferred_node_on_critical_path_mean")
    result["path_preference_mean"] = result.get("path_preference_mean_mean")
    result["path_preference_std"] = result.get("path_preference_mean_std")
    result["path_preference_max_mean"] = result.get("path_preference_max_mean")
    result["path_preference_max_std"] = result.get("path_preference_max_std")
    result["preferred_path_score_mean"] = result.get("preferred_path_score_mean")
    result["preferred_path_score_std"] = result.get("preferred_path_score_std")
    result["preferred_path_is_critical_rate"] = result.get("preferred_path_is_critical_mean")
    result["planning_score_mean"] = result.get("planning_score_mean_mean")
    result["planning_score_std"] = result.get("planning_score_mean_std")
    result["planning_score_max_mean"] = result.get("planning_score_max_mean")
    result["planning_score_max_std"] = result.get("planning_score_max_std")
    result["planned_path_score_mean"] = result.get("planned_path_score_mean")
    result["planned_path_score_std"] = result.get("planned_path_score_std")
    result["planned_path_is_critical_rate"] = result.get("planned_path_is_critical_mean")
    preferred_paths = [
        str(row.get("preferred_path"))
        for row in rows
        if row.get("preferred_path") not in (None, "")
    ]
    if preferred_paths:
        result["preferred_path"] = max(set(preferred_paths), key=preferred_paths.count)
    planned_paths = [
        str(row.get("planned_path"))
        for row in rows
        if row.get("planned_path") not in (None, "")
    ]
    if planned_paths:
        result["planned_path"] = max(set(planned_paths), key=planned_paths.count)
    result["mtd_risk_gate_score_mean"] = _mean_or_none(
        [_to_float(row.get("mtd_risk_gate_score_mean")) for row in rows]
    )
    result["post_decoy_real_attack_mean"] = result.get("post_decoy_real_attack_count_mean")
    result["post_decoy_real_attack_std"] = result.get("post_decoy_real_attack_count_std")

    post_compromised_values = [_to_float(row.get("post_decoy_compromised_value")) for row in rows]
    result["post_decoy_compromised_mean"] = _mean_or_none(post_compromised_values)
    result["post_decoy_compromised_std"] = _std_or_none(post_compromised_values)
    post_utility_values = [_to_float(row.get("post_decoy_utility")) for row in rows]
    result["post_decoy_utility_mean"] = _mean_or_none(post_utility_values)
    result["post_decoy_utility_std"] = _std_or_none(post_utility_values)
    node_totals = np.zeros(5)
    total_post_decoy_attacks = 0
    for row in rows:
        counts = _parse_target_counts(row.get("post_decoy_target_counts"))
        for node_idx in range(min(5, len(counts))):
            node_totals[node_idx] += counts[node_idx]
            total_post_decoy_attacks += counts[node_idx]
    for node_idx in range(5):
        result[f"post_decoy_node{node_idx}_rate"] = (
            float(node_totals[node_idx] / total_post_decoy_attacks)
            if total_post_decoy_attacks > 0
            else 0.0
        )

    for key in ["mean_attack_success_prob", "mean_attack_detection_prob"]:
        values = [_to_float(row.get(key)) for row in rows]
        result[f"{key}_mean"] = _mean_or_none(values)

    return {column: result.get(column) for column in MULTI_SEED_STATS_COLUMNS}


def _to_float(value: object) -> float:
    if value is None or value == "":
        return 0.0
    return float(value)


def _mean_or_none(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return float(np.mean(values))


def _std_or_none(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return float(np.std(values))


def write_multiseed_summaries(
    run_rows: List[Dict[str, object]],
    stats_rows: List[Dict[str, object]],
    output_dir: str,
) -> None:
    os.makedirs(output_dir, exist_ok=True)
    _write_rows(
        run_rows,
        MULTI_SEED_RUN_COLUMNS,
        os.path.join(output_dir, "summary_runs.csv"),
        os.path.join(output_dir, "summary_runs.json"),
    )
    _write_rows(
        stats_rows,
        MULTI_SEED_STATS_COLUMNS,
        os.path.join(output_dir, "summary_stats.csv"),
        os.path.join(output_dir, "summary_stats.json"),
    )
    policy_rows = build_policy_selection_rows(stats_rows)
    if policy_rows:
        _write_rows(
            policy_rows,
            POLICY_SELECTION_COLUMNS,
            os.path.join(output_dir, "policy_selection_summary.csv"),
            os.path.join(output_dir, "policy_selection_summary.json"),
        )
        _write_best_policy(policy_rows, os.path.join(output_dir, "best_policy.json"))


def build_policy_selection_rows(stats_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    policy_rows = []
    for row in stats_rows:
        scenario_name = str(row.get("scenario", ""))
        if scenario_name not in POLICY_SELECTION_SCENARIO_NAMES:
            continue
        policy_rows.append(
            {
                "policy": scenario_name,
                "num_runs": row.get("num_runs"),
                "defense_objective_score_mean": row.get("defense_objective_score_mean"),
                "defense_objective_score_std": row.get("defense_objective_score_std"),
                "critical_compromise_rate": row.get("critical_compromise_rate"),
                "critical_compromise_step_mean": row.get("critical_compromise_step_mean"),
                "post_decoy_compromised_mean": row.get("post_decoy_compromised_mean"),
                "post_decoy_compromised_std": row.get("post_decoy_compromised_std"),
                "mtd_total_cost_mean": row.get("mtd_total_cost_mean"),
                "mtd_risk_gating_enabled": row.get("mtd_risk_gating_enabled"),
                "mtd_risk_gate_mode": row.get("mtd_risk_gate_mode"),
                "mtd_risk_gate_threshold": row.get("mtd_risk_gate_threshold"),
                "mtd_risk_gate_cooldown": row.get("mtd_risk_gate_cooldown"),
                "mtd_edge_block_duration": row.get("mtd_edge_block_duration"),
                "mtd_edge_block_count": row.get("mtd_edge_block_count"),
                "mtd_conditional_policy_enabled": row.get("mtd_conditional_policy_enabled"),
                "mtd_conditional_policy_mode": row.get("mtd_conditional_policy_mode"),
                "mtd_conditional_high_risk_threshold": row.get("mtd_conditional_high_risk_threshold"),
                "mtd_conditional_low_risk_threshold": row.get("mtd_conditional_low_risk_threshold"),
                "mtd_conditional_count2_action_count_mean": row.get("mtd_conditional_count2_action_count_mean"),
                "mtd_conditional_duration2_action_count_mean": row.get("mtd_conditional_duration2_action_count_mean"),
                "mtd_conditional_suppress_count_mean": row.get("mtd_conditional_suppress_count_mean"),
                "credential_trigger_rate_mean": row.get("credential_trigger_rate_mean"),
                "credential_trigger_mtd_event_count_mean": row.get("credential_trigger_mtd_event_count_mean"),
                "credential_aware_mtd_enabled": row.get("credential_aware_mtd_enabled"),
                "credential_trigger_mtd_window": row.get("credential_trigger_mtd_window"),
                "credential_trigger_block_count": row.get("credential_trigger_block_count"),
                "credential_trigger_block_duration": row.get("credential_trigger_block_duration"),
                "credential_trigger_force_mtd": row.get("credential_trigger_force_mtd"),
                "credential_trigger_risk_bonus": row.get("credential_trigger_risk_bonus"),
                "credential_staged_mtd_enabled": row.get("credential_staged_mtd_enabled"),
                "credential_stage1_window": row.get("credential_stage1_window"),
                "credential_stage2_window": row.get("credential_stage2_window"),
                "credential_stage1_action_count_mean": row.get("credential_stage1_action_count_mean"),
                "credential_stage2_action_count_mean": row.get("credential_stage2_action_count_mean"),
                "credential_stage_none_count_mean": row.get("credential_stage_none_count_mean"),
                "mtd_risk_gate_fire_count_mean": row.get("mtd_risk_gate_fire_count_mean"),
                "mtd_risk_gate_suppressed_count_mean": row.get("mtd_risk_gate_suppressed_count_mean"),
                "mtd_risk_gate_score_mean": row.get("mtd_risk_gate_score_mean"),
                "cost_per_post_decoy_reduction": None,
                "critical_rate_improvement_vs_reference": None,
                "post_decoy_reduction_vs_reference": None,
                "defender_bayesian_error_l1_mean": row.get("defender_bayesian_error_l1_mean"),
                "selected_policy_rank": None,
            }
        )
    _add_policy_reference_effectiveness(policy_rows)
    policy_rows.sort(key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    for rank, row in enumerate(policy_rows, start=1):
        row["selected_policy_rank"] = rank
    return policy_rows


def _add_policy_reference_effectiveness(policy_rows: List[Dict[str, object]]) -> None:
    reference = next((row for row in policy_rows if row.get("policy") == "policy_target_frequency_path_decoy"), None)
    if reference is None:
        return
    reference_post_decoy = _to_float(reference.get("post_decoy_compromised_mean"))
    reference_critical_rate = _to_float(reference.get("critical_compromise_rate"))
    for row in policy_rows:
        post_decoy_reduction = reference_post_decoy - _to_float(row.get("post_decoy_compromised_mean"))
        critical_rate_improvement = reference_critical_rate - _to_float(row.get("critical_compromise_rate"))
        row["post_decoy_reduction_vs_reference"] = float(post_decoy_reduction)
        row["critical_rate_improvement_vs_reference"] = float(critical_rate_improvement)
        row["cost_per_post_decoy_reduction"] = float(
            _to_float(row.get("mtd_total_cost_mean")) / max(post_decoy_reduction, 1e-6)
        )


def _write_best_policy(policy_rows: List[Dict[str, object]], json_path: str) -> None:
    if not policy_rows:
        return
    best = policy_rows[0]
    payload = {
        "best_policy": best.get("policy"),
        "defense_objective_score_mean": best.get("defense_objective_score_mean"),
        "critical_compromise_rate": best.get("critical_compromise_rate"),
        "post_decoy_compromised_mean": best.get("post_decoy_compromised_mean"),
        "reason": "lowest defense_objective_score_mean",
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)


def _write_rows(rows: List[Dict[str, object]], columns: List[str], csv_path: str, json_path: str) -> None:
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=4, ensure_ascii=False)


def plot_multiseed_summary(stats_rows: List[Dict[str, object]], output_dir: str) -> None:
    _plot_bar(
        stats_rows,
        value_key="retreat_rate",
        title="Retreat Rate by Scenario",
        ylabel="Retreat Rate",
        save_path=os.path.join(output_dir, "summary_retreat_rate.png"),
    )
    _plot_mean_std_bar(
        stats_rows,
        mean_key="attacker_utility_final_mean",
        std_key="attacker_utility_final_std",
        title="Attacker Utility Mean +/- Std",
        ylabel="Attacker Utility Final",
        save_path=os.path.join(output_dir, "summary_utility_mean_std.png"),
    )
    _plot_mean_std_bar(
        stats_rows,
        mean_key="attacker_compromised_value_mean",
        std_key="attacker_compromised_value_std",
        title="Compromised Value Mean +/- Std",
        ylabel="Attacker Compromised Value",
        save_path=os.path.join(output_dir, "summary_compromised_value_mean_std.png"),
    )
    _plot_mean_std_bar(
        stats_rows,
        mean_key="attacker_belief_decoy_reduction_mean",
        std_key="attacker_belief_decoy_reduction_std",
        title="Decoy Belief Reduction Mean +/- Std",
        ylabel="Decoy Belief Reduction",
        save_path=os.path.join(output_dir, "summary_belief_learning_mean_std.png"),
    )
    _plot_mean_std_bar(
        stats_rows,
        mean_key="post_decoy_compromised_mean",
        std_key="post_decoy_compromised_std",
        title="Post-Decoy Compromised Value Mean +/- Std",
        ylabel="Post-Decoy Compromised Value",
        save_path=os.path.join(output_dir, "summary_post_decoy_defense_effect_mean_std.png"),
    )
    _plot_mean_std_bar(
        stats_rows,
        mean_key="post_decoy_compromised_mean",
        std_key="post_decoy_compromised_std",
        title="Post-Decoy Compromised Value by Injection Mode Mean +/- Std",
        ylabel="Post-Decoy Compromised Value",
        save_path=os.path.join(output_dir, "summary_post_decoy_injection_modes_mean_std.png"),
    )
    _plot_mean_std_bar(
        stats_rows,
        mean_key="post_decoy_compromised_mean",
        std_key="post_decoy_compromised_std",
        title="Oracle vs Estimated Belief Defense Mean +/- Std",
        ylabel="Post-Decoy Compromised Value",
        save_path=os.path.join(output_dir, "summary_estimated_vs_oracle_defense_mean_std.png"),
    )
    _plot_visible_log_multiseed_summary(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_visible_log_estimation_mean_std.png"),
    )
    _plot_mtd_multiseed_summary(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_mtd_effect_mean_std.png"),
    )
    _plot_mtd_sweep_compromised(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_mtd_sweep_compromised.png"),
    )
    _plot_mtd_sweep_cost_adjusted(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_mtd_sweep_cost_adjusted.png"),
    )
    _plot_mtd_estimator_compatibility(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_mtd_estimator_compatibility.png"),
    )
    _plot_lateral_compromise_rate(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_lateral_compromise_rate.png"),
    )
    _plot_lateral_compromise_step(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_lateral_compromise_step.png"),
    )
    _plot_lateral_path_aware_compromise_rate(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_lateral_path_aware_compromise_rate.png"),
    )
    _plot_lateral_path_aware_step(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_lateral_path_aware_step.png"),
    )
    _plot_lateral_edge_mtd(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_lateral_edge_mtd.png"),
    )
    _plot_bayesian_compromise_rate(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_bayesian_compromise_rate.png"),
    )
    _plot_bayesian_post_decoy_compromised(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_bayesian_post_decoy_compromised.png"),
    )
    _plot_bayesian_error(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_bayesian_error.png"),
    )
    _plot_bayesian_sweep_compromise_rate(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_bayesian_sweep_compromise_rate.png"),
    )
    _plot_bayesian_sweep_post_decoy(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_bayesian_sweep_post_decoy.png"),
    )
    _plot_bayesian_sweep_error(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_bayesian_sweep_error.png"),
    )
    _plot_bayesian_vs_target_frequency_delta(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_bayesian_vs_target_frequency_delta.png"),
    )
    _plot_defense_objective_score(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_defense_objective_score.png"),
    )
    _plot_defense_objective_tradeoff(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_defense_objective_tradeoff.png"),
    )
    _plot_policy_selection_objective(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_policy_selection_objective.png"),
    )
    _plot_policy_selection_tradeoff(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_policy_selection_tradeoff.png"),
    )
    _plot_gated_mtd_objective(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_gated_mtd_objective.png"),
    )
    _plot_gated_mtd_tradeoff(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_gated_mtd_tradeoff.png"),
    )
    _plot_gated_mtd_fire_count(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_gated_mtd_fire_count.png"),
    )
    _plot_gated_mtd_sweep_objective(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_gated_mtd_sweep_objective.png"),
    )
    _plot_gated_mtd_sweep_cost_effectiveness(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_gated_mtd_sweep_cost_effectiveness.png"),
    )
    _plot_gated_mtd_threshold_tradeoff(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_gated_mtd_threshold_tradeoff.png"),
    )
    _plot_gated_mtd_hybrid_objective(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_gated_mtd_hybrid_objective.png"),
    )
    _plot_gated_mtd_hybrid_tradeoff(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_gated_mtd_hybrid_tradeoff.png"),
    )
    _plot_gated_mtd_hybrid_cost_effectiveness(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_gated_mtd_hybrid_cost_effectiveness.png"),
    )
    _plot_conditional_mtd_objective(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_conditional_mtd_objective.png"),
    )
    _plot_conditional_mtd_tradeoff(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_conditional_mtd_tradeoff.png"),
    )
    _plot_conditional_mtd_actions(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_conditional_mtd_actions.png"),
    )
    _plot_honeypot_objective(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_honeypot_objective.png"),
    )
    _plot_honeypot_tradeoff(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_honeypot_tradeoff.png"),
    )
    _plot_honeypot_trigger_rate(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_honeypot_trigger_rate.png"),
    )
    _plot_credential_aware_mtd_objective(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_credential_aware_mtd_objective.png"),
    )
    _plot_credential_aware_mtd_tradeoff(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_credential_aware_mtd_tradeoff.png"),
    )
    _plot_credential_aware_mtd_events(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_credential_aware_mtd_events.png"),
    )
    _plot_credential_staged_mtd_objective(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_credential_staged_mtd_objective.png"),
    )
    _plot_credential_staged_mtd_tradeoff(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_credential_staged_mtd_tradeoff.png"),
    )
    _plot_credential_staged_mtd_actions(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_credential_staged_mtd_actions.png"),
    )
    _plot_phase2_perceived_vs_actual_utility(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_perceived_vs_actual_utility.png"),
    )
    _plot_phase2_confidence_decay(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_confidence_decay.png"),
    )
    _plot_phase2_perceived_retreat_rate(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_perceived_retreat_rate.png"),
    )
    _plot_phase2_frustration_retreat_rate(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_frustration_retreat_rate.png"),
    )
    _plot_phase2_frustration_distribution(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_frustration_distribution.png"),
    )
    _plot_phase2_frustration_vs_perceived_utility(
        stats_rows,
        save_path=os.path.join(output_dir, "summary_frustration_vs_perceived_utility.png"),
    )


def _plot_mean_std_bar(
    rows: List[Dict[str, object]],
    mean_key: str,
    std_key: str,
    title: str,
    ylabel: str,
    save_path: str,
) -> None:
    labels = [str(row["scenario"]) for row in rows]
    means = np.array([float(row.get(mean_key) or 0.0) for row in rows])
    stds = np.array([float(row.get(std_key) or 0.0) for row in rows])

    plt.figure(figsize=(12, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#59a14f")
    plt.title(title)
    plt.ylabel(ylabel)
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _phase2_perceived_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    wanted = set(PHASE2_PERCEIVED_UTILITY_SCENARIO_NAMES)
    return [row for row in rows if row.get("scenario") in wanted]


def _phase2_perceived_labels(rows: List[Dict[str, object]]) -> List[str]:
    return [str(row["scenario"]).replace("phase2_", "") for row in rows]


def _phase2_frustration_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    wanted = set(PHASE2_FRUSTRATION_SCENARIO_NAMES)
    return [row for row in rows if row.get("scenario") in wanted]


def _phase2_frustration_labels(rows: List[Dict[str, object]]) -> List[str]:
    return [str(row["scenario"]).replace("phase2_frustration_", "") for row in rows]


def _plot_phase2_perceived_vs_actual_utility(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _phase2_perceived_rows(rows)
    if not filtered:
        return
    labels = _phase2_perceived_labels(filtered)
    actual = np.array([float(row.get("actual_utility_mean") or 0.0) for row in filtered])
    perceived = np.array([float(row.get("perceived_utility_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(x - width / 2, actual, width=width, color="#4c78a8", label="Actual utility")
    ax.bar(x + width / 2, perceived, width=width, color="#f58518", label="Perceived utility")
    ax.axhline(0.0, color="#333333", linewidth=1)
    ax.set_ylabel("Utility Mean")
    ax.set_title("Phase2.1 Actual vs Perceived Utility")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase2_confidence_decay(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _phase2_perceived_rows(rows)
    if not filtered:
        return
    labels = _phase2_perceived_labels(filtered)
    confidence = np.array([float(row.get("confidence_mean") or 0.0) for row in filtered])
    plt.figure(figsize=(12, 6))
    plt.bar(labels, confidence, color="#59a14f")
    plt.ylim(0.0, 1.0)
    plt.title("Phase2.1 Mean Confidence")
    plt.ylabel("Mean Confidence")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_phase2_perceived_retreat_rate(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _phase2_perceived_rows(rows)
    if not filtered:
        return
    labels = _phase2_perceived_labels(filtered)
    rates = np.array([float(row.get("retreat_rate") or 0.0) for row in filtered])
    plt.figure(figsize=(12, 6))
    plt.bar(labels, rates, color="#e45756")
    plt.ylim(0.0, 1.0)
    plt.title("Phase2.1 Perceived-Utility Retreat Rate")
    plt.ylabel("Retreat Rate")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_phase2_frustration_retreat_rate(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _phase2_frustration_rows(rows)
    if not filtered:
        return
    labels = _phase2_frustration_labels(filtered)
    rates = np.array([float(row.get("retreat_rate") or 0.0) for row in filtered])
    plt.figure(figsize=(12, 6))
    plt.bar(labels, rates, color="#e45756")
    plt.ylim(0.0, 1.0)
    plt.title("Phase2.2 Frustration-Based Retreat Rate")
    plt.ylabel("Retreat Rate")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_phase2_frustration_distribution(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _phase2_frustration_rows(rows)
    if not filtered:
        return
    labels = _phase2_frustration_labels(filtered)
    means = np.array([float(row.get("frustration_mean") or 0.0) for row in filtered])
    max_values = np.array([float(row.get("frustration_max") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(x - width / 2, means, width=width, color="#4c78a8", label="Mean frustration")
    ax.bar(x + width / 2, max_values, width=width, color="#f58518", label="Max frustration")
    ax.set_ylabel("Frustration")
    ax.set_title("Phase2.2 Frustration Distribution")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase2_frustration_vs_perceived_utility(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _phase2_frustration_rows(rows)
    if not filtered:
        return
    labels = _phase2_frustration_labels(filtered)
    perceived = np.array([float(row.get("perceived_utility_mean") or 0.0) for row in filtered])
    frustration = np.array([float(row.get("frustration_mean") or 0.0) for row in filtered])
    retreat_rate = np.array([float(row.get("retreat_rate") or 0.0) for row in filtered])
    fig, ax = plt.subplots(figsize=(10, 6))
    scatter = ax.scatter(perceived, frustration, s=80 + 220 * retreat_rate, c=retreat_rate, cmap="viridis", vmin=0.0, vmax=1.0)
    for label, x_value, y_value in zip(labels, perceived, frustration):
        ax.annotate(label, (x_value, y_value), textcoords="offset points", xytext=(5, 5), fontsize=8)
    ax.axvline(0.0, color="#333333", linewidth=1)
    ax.set_xlabel("Perceived Utility Mean")
    ax.set_ylabel("Frustration Mean")
    ax.set_title("Phase2.2 Frustration vs Perceived Utility")
    fig.colorbar(scatter, ax=ax, label="Retreat Rate")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


PHASE2_AI_COST_SUMMARY_COLUMNS = [
    "scenario",
    "num_runs",
    "frustration_mean",
    "ai_total_decision_cost",
    "retreat_rate",
    "critical_compromise_rate",
    "ai_uncertainty_cost_mean",
    "ai_replanning_cost_mean",
    "ai_search_cost_mean",
    "ai_operational_risk_cost_mean",
    "ai_trust_degradation_cost_mean",
]


def run_phase2_ai_cost_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase2_ai_cost"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios = {name: SCENARIOS[name] for name in PHASE2_FRUSTRATION_SCENARIO_NAMES}
    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [
        {column: row.get(column) for column in PHASE2_AI_COST_SUMMARY_COLUMNS}
        for row in _phase2_frustration_rows(stats_rows)
    ]
    os.makedirs(output_dir, exist_ok=True)
    _write_phase2_ai_cost_summary(summary_rows, output_dir)
    _plot_phase2_ai_cost_vs_frustration(
        summary_rows,
        save_path=os.path.join(output_dir, "ai_cost_vs_frustration.png"),
    )
    _plot_phase2_ai_cost_vs_retreat_rate(
        summary_rows,
        save_path=os.path.join(output_dir, "ai_cost_vs_retreat_rate.png"),
    )
    return summary_rows


def _write_phase2_ai_cost_summary(rows: List[Dict[str, object]], output_dir: str) -> None:
    csv_path = os.path.join(output_dir, "ai_cost_summary.csv")
    json_path = os.path.join(output_dir, "ai_cost_summary.json")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE2_AI_COST_SUMMARY_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=4, ensure_ascii=False)


def _plot_phase2_ai_cost_vs_frustration(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    labels = _phase2_frustration_labels(rows)
    frustration = np.array([float(row.get("frustration_mean") or 0.0) for row in rows])
    ai_cost = np.array([float(row.get("ai_total_decision_cost") or 0.0) for row in rows])
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.scatter(frustration, ai_cost, s=80, color="#4c78a8")
    for label, x_value, y_value in zip(labels, frustration, ai_cost):
        ax.annotate(label, (x_value, y_value), textcoords="offset points", xytext=(5, 5), fontsize=8)
    max_value = max(float(np.max(frustration)), float(np.max(ai_cost)), 1.0)
    ax.plot([0.0, max_value], [0.0, max_value], color="#333333", linewidth=1, linestyle="--")
    ax.set_xlabel("Frustration Mean")
    ax.set_ylabel("AI Total Decision Cost")
    ax.set_title("Phase2.3 AI Decision Cost vs Human Frustration")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase2_ai_cost_vs_retreat_rate(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    labels = _phase2_frustration_labels(rows)
    ai_cost = np.array([float(row.get("ai_total_decision_cost") or 0.0) for row in rows])
    retreat_rate = np.array([float(row.get("retreat_rate") or 0.0) for row in rows])
    critical_rate = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in rows])
    fig, ax = plt.subplots(figsize=(10, 6))
    scatter = ax.scatter(ai_cost, retreat_rate, s=90 + 180 * critical_rate, c=critical_rate, cmap="plasma", vmin=0.0, vmax=1.0)
    for label, x_value, y_value in zip(labels, ai_cost, retreat_rate):
        ax.annotate(label, (x_value, y_value), textcoords="offset points", xytext=(5, 5), fontsize=8)
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel("AI Total Decision Cost")
    ax.set_ylabel("Retreat Rate")
    ax.set_title("Phase2.3 AI Decision Cost vs Retreat Rate")
    fig.colorbar(scatter, ax=ax, label="Critical Compromise Rate")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


PHASE2_AI_WEIGHT_SWEEP_COLUMNS = [
    "scenario",
    "num_runs",
    "human_cost",
    "ai_weighted_cost",
    "human_minus_ai_cost",
    "human_vs_ai_cost_ratio",
    "retreat_rate",
    "critical_compromise_rate",
    "neutralization_score",
    "ai_uncertainty_cost_mean",
    "ai_replanning_cost_mean",
    "ai_search_cost_mean",
    "ai_operational_risk_cost_mean",
    "ai_trust_degradation_cost_mean",
    "ai_uncertainty_weight",
    "ai_replanning_weight",
    "ai_search_weight",
    "ai_operational_risk_weight",
    "ai_trust_degradation_weight",
]


def run_phase2_ai_weight_sweep_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase2_ai_weight_sweep"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios = {name: SCENARIOS[name] for name in PHASE2_AI_COST_SCENARIO_NAMES}
    scenarios["gated_edge_pressure_count_2"] = {
        **PHASE2_FRUSTRATION_BASE,
        **GATED_EDGE_PRESSURE_SWEEP_BASE,
        "mtd_edge_block_count": 2,
    }
    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase2_ai_weight_row(row) for row in stats_rows]
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase2_ai_weight_sweep(summary_rows)
    _write_phase2_ai_weight_sweep_summary(summary_rows, analysis, output_dir)
    _plot_human_vs_ai_cost(summary_rows, os.path.join(output_dir, "human_vs_ai_cost.png"))
    _plot_human_vs_ai_retreat(summary_rows, os.path.join(output_dir, "human_vs_ai_retreat.png"))
    _plot_human_vs_ai_neutralization(summary_rows, os.path.join(output_dir, "human_vs_ai_neutralization.png"))
    return summary_rows


def _build_phase2_ai_weight_row(row: Dict[str, object]) -> Dict[str, object]:
    human_cost = _to_float(row.get("frustration_mean"))
    ai_cost = _to_float(row.get("ai_weighted_cost"))
    return {
        "scenario": row.get("scenario"),
        "num_runs": row.get("num_runs"),
        "human_cost": human_cost,
        "ai_weighted_cost": ai_cost,
        "human_minus_ai_cost": float(human_cost - ai_cost),
        "human_vs_ai_cost_ratio": row.get("human_vs_ai_cost_ratio_mean"),
        "retreat_rate": row.get("retreat_rate"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "neutralization_score": row.get("neutralization_score_mean"),
        "ai_uncertainty_cost_mean": row.get("ai_uncertainty_cost_mean"),
        "ai_replanning_cost_mean": row.get("ai_replanning_cost_mean"),
        "ai_search_cost_mean": row.get("ai_search_cost_mean"),
        "ai_operational_risk_cost_mean": row.get("ai_operational_risk_cost_mean"),
        "ai_trust_degradation_cost_mean": row.get("ai_trust_degradation_cost_mean"),
        "ai_uncertainty_weight": row.get("ai_uncertainty_weight"),
        "ai_replanning_weight": row.get("ai_replanning_weight"),
        "ai_search_weight": row.get("ai_search_weight"),
        "ai_operational_risk_weight": row.get("ai_operational_risk_weight"),
        "ai_trust_degradation_weight": row.get("ai_trust_degradation_weight"),
    }


def _analyze_phase2_ai_weight_sweep(rows: List[Dict[str, object]]) -> Dict[str, object]:
    if not rows:
        return {}
    best_human = max(rows, key=lambda row: _to_float(row.get("human_cost")))
    best_ai = max(rows, key=lambda row: _to_float(row.get("ai_weighted_cost")))
    best_neutralization = max(rows, key=lambda row: _to_float(row.get("neutralization_score")))
    credential = next((row for row in rows if row.get("scenario") == "phase2_ai_high_trust_degradation"), {})
    decoy = next((row for row in rows if row.get("scenario") == "phase2_ai_high_uncertainty"), {})
    current_policy = "gated_edge_pressure_count_2"
    return {
        "q1_best_defense_changed": best_human.get("scenario") != best_ai.get("scenario"),
        "q1_best_human_defense": best_human.get("scenario"),
        "q1_best_ai_defense": best_ai.get("scenario"),
        "q2_credential_trap_more_effective_against": (
            "ai" if _to_float(credential.get("ai_weighted_cost")) > _to_float(credential.get("human_cost")) else "human"
        ),
        "q3_decoy_more_effective_against": (
            "ai" if _to_float(decoy.get("ai_weighted_cost")) > _to_float(decoy.get("human_cost")) else "human"
        ),
        "q4_current_best_policy": current_policy,
        "q4_current_best_policy_is_ai_best": best_ai.get("scenario") == current_policy,
        "best_neutralization_scenario": best_neutralization.get("scenario"),
        "best_neutralization_score": best_neutralization.get("neutralization_score"),
        "ai_attacker_most_affected_defense": best_ai.get("scenario"),
    }


def _write_phase2_ai_weight_sweep_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    csv_path = os.path.join(output_dir, "ai_weight_sweep_summary.csv")
    json_path = os.path.join(output_dir, "ai_weight_sweep_summary.json")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE2_AI_WEIGHT_SWEEP_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_human_vs_ai_cost(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    labels = [str(row["scenario"]).replace("phase2_ai_", "") for row in rows]
    human = np.array([_to_float(row.get("human_cost")) for row in rows], dtype=float)
    ai = np.array([_to_float(row.get("ai_weighted_cost")) for row in rows], dtype=float)
    x = np.arange(len(labels))
    width = 0.4
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(x - width / 2, human, width=width, color="#4c78a8", label="Human frustration")
    ax.bar(x + width / 2, ai, width=width, color="#f58518", label="AI weighted cost")
    ax.set_ylabel("Cost")
    ax.set_title("Phase2.3 Human Cost vs AI Weighted Cost")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_human_vs_ai_retreat(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    labels = [str(row["scenario"]).replace("phase2_ai_", "") for row in rows]
    ai_cost = np.array([_to_float(row.get("ai_weighted_cost")) for row in rows], dtype=float)
    retreat = np.array([_to_float(row.get("retreat_rate")) for row in rows], dtype=float)
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.scatter(ai_cost, retreat, s=90, color="#e45756")
    for label, x_value, y_value in zip(labels, ai_cost, retreat):
        ax.annotate(label, (x_value, y_value), textcoords="offset points", xytext=(5, 5), fontsize=8)
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel("AI Weighted Cost")
    ax.set_ylabel("Human Retreat Rate")
    ax.set_title("Phase2.3 AI Cost vs Human Retreat")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_human_vs_ai_neutralization(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    labels = [str(row["scenario"]).replace("phase2_ai_", "") for row in rows]
    human = np.array([_to_float(row.get("human_cost")) for row in rows], dtype=float)
    ai = np.array([_to_float(row.get("ai_weighted_cost")) for row in rows], dtype=float)
    neutralization = np.array([_to_float(row.get("neutralization_score")) for row in rows], dtype=float)
    fig, ax = plt.subplots(figsize=(10, 6))
    scatter = ax.scatter(human, ai, s=90 + 180 * neutralization, c=neutralization, cmap="viridis", vmin=0.0, vmax=1.0)
    for label, x_value, y_value in zip(labels, human, ai):
        ax.annotate(label, (x_value, y_value), textcoords="offset points", xytext=(5, 5), fontsize=8)
    ax.set_xlabel("Human Frustration Cost")
    ax.set_ylabel("AI Weighted Cost")
    ax.set_title("Phase2.3 Human vs AI Cost and Neutralization")
    fig.colorbar(scatter, ax=ax, label="Neutralization Score")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


PHASE2_COGNITIVE_SCENARIO_NAMES = [
    "phase2_actual_utility_reference",
    "phase2_perceived_decoy",
    "phase2_perceived_credential",
    "phase2_frustration_decoy",
    "phase2_frustration_credential",
    "phase2_ai_balanced",
    "phase2_ai_high_trust_degradation",
    "gated_edge_pressure_count_2",
    "credential_aware_mtd_window5",
]

PHASE2_COGNITIVE_SUMMARY_COLUMNS = [
    "scenario",
    "num_runs",
    "cognitive_neutralization_score",
    "cognitive_human_score",
    "cognitive_ai_score",
    "neutralization_score",
    "critical_protection_score",
    "retreat_rate",
    "critical_compromise_rate",
    "perceived_utility_mean",
    "confidence_mean",
    "frustration_mean",
    "ai_weighted_cost",
]


def run_phase2_cognitive_neutralization_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase2_cognitive_neutralization"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios = {name: SCENARIOS[name] for name in PHASE2_COGNITIVE_SCENARIO_NAMES}
    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase2_cognitive_row(row) for row in stats_rows]
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase2_cognitive_rows(summary_rows)
    _write_phase2_cognitive_summary(summary_rows, analysis, output_dir)
    _plot_cognitive_ranking(summary_rows, os.path.join(output_dir, "cognitive_ranking.png"))
    _plot_cognitive_human_vs_ai(summary_rows, os.path.join(output_dir, "cognitive_human_vs_ai.png"))
    _plot_cognitive_vs_phase1(summary_rows, os.path.join(output_dir, "cognitive_vs_phase1_neutralization.png"))
    _write_phase2_cognitive_report(summary_rows, analysis, output_dir)
    return summary_rows


def _build_phase2_cognitive_row(row: Dict[str, object]) -> Dict[str, object]:
    return {
        "scenario": row.get("scenario"),
        "num_runs": row.get("num_runs"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cognitive_human_score": row.get("cognitive_human_score_mean"),
        "cognitive_ai_score": row.get("cognitive_ai_score_mean"),
        "neutralization_score": row.get("neutralization_score_mean"),
        "critical_protection_score": row.get("critical_protection_score_mean"),
        "retreat_rate": row.get("retreat_rate"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "perceived_utility_mean": row.get("perceived_utility_mean"),
        "confidence_mean": row.get("confidence_mean"),
        "frustration_mean": row.get("frustration_mean"),
        "ai_weighted_cost": row.get("ai_weighted_cost"),
    }


def _analyze_phase2_cognitive_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    if not rows:
        return {}
    best_human = max(rows, key=lambda row: _to_float(row.get("cognitive_human_score")))
    best_ai = max(rows, key=lambda row: _to_float(row.get("cognitive_ai_score")))
    best_combined = max(rows, key=lambda row: _to_float(row.get("cognitive_neutralization_score")))
    best_phase1 = max(rows, key=lambda row: _to_float(row.get("neutralization_score")))
    current_policy = next((row for row in rows if row.get("scenario") == "gated_edge_pressure_count_2"), {})
    return {
        "best_human_neutralization": best_human.get("scenario"),
        "best_ai_neutralization": best_ai.get("scenario"),
        "best_combined_cognitive_neutralization": best_combined.get("scenario"),
        "best_phase1_neutralization": best_phase1.get("scenario"),
        "phase1_best_policy": "gated_edge_pressure_count_2",
        "phase1_best_policy_cognitive_score": current_policy.get("cognitive_neutralization_score"),
        "phase1_best_policy_is_cognitive_best": current_policy.get("scenario") == best_combined.get("scenario"),
        "human_ai_score_gap_at_best_combined": float(
            _to_float(best_combined.get("cognitive_human_score"))
            - _to_float(best_combined.get("cognitive_ai_score"))
        ),
    }


def _write_phase2_cognitive_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    csv_path = os.path.join(output_dir, "cognitive_summary.csv")
    json_path = os.path.join(output_dir, "cognitive_summary.json")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE2_COGNITIVE_SUMMARY_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_cognitive_ranking(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    ranked = sorted(rows, key=lambda row: _to_float(row.get("cognitive_neutralization_score")), reverse=True)
    labels = [str(row["scenario"]).replace("phase2_", "") for row in ranked]
    values = np.array([_to_float(row.get("cognitive_neutralization_score")) for row in ranked], dtype=float)
    plt.figure(figsize=(14, 6))
    plt.bar(labels, values, color="#4c78a8")
    plt.ylim(0.0, 1.0)
    plt.title("Phase2.4 Cognitive Neutralization Ranking")
    plt.ylabel("Cognitive Neutralization Score")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_cognitive_human_vs_ai(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    labels = [str(row["scenario"]).replace("phase2_", "") for row in rows]
    human = np.array([_to_float(row.get("cognitive_human_score")) for row in rows], dtype=float)
    ai = np.array([_to_float(row.get("cognitive_ai_score")) for row in rows], dtype=float)
    x = np.arange(len(labels))
    width = 0.4
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(x - width / 2, human, width=width, color="#59a14f", label="Human cognitive score")
    ax.bar(x + width / 2, ai, width=width, color="#f58518", label="AI cognitive score")
    ax.set_ylim(0.0, 1.0)
    ax.set_ylabel("Score")
    ax.set_title("Phase2.4 Human vs AI Cognitive Neutralization")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_cognitive_vs_phase1(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    labels = [str(row["scenario"]).replace("phase2_", "") for row in rows]
    phase1 = np.array([_to_float(row.get("neutralization_score")) for row in rows], dtype=float)
    cognitive = np.array([_to_float(row.get("cognitive_neutralization_score")) for row in rows], dtype=float)
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.scatter(phase1, cognitive, s=90, color="#4c78a8")
    for label, x_value, y_value in zip(labels, phase1, cognitive):
        ax.annotate(label, (x_value, y_value), textcoords="offset points", xytext=(5, 5), fontsize=8)
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel("Phase1 Neutralization Score")
    ax.set_ylabel("Cognitive Neutralization Score")
    ax.set_title("Phase2.4 Cognitive vs Phase1 Neutralization")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase2_cognitive_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    human_top = sorted(rows, key=lambda row: _to_float(row.get("cognitive_human_score")), reverse=True)[:3]
    ai_top = sorted(rows, key=lambda row: _to_float(row.get("cognitive_ai_score")), reverse=True)[:3]
    combined_top = sorted(rows, key=lambda row: _to_float(row.get("cognitive_neutralization_score")), reverse=True)[:3]
    lines = [
        "# Phase2.4 Cognitive Neutralization Report",
        "",
        "## Summary",
        f"- Best Human neutralization: `{analysis.get('best_human_neutralization')}`",
        f"- Best AI neutralization: `{analysis.get('best_ai_neutralization')}`",
        f"- Best combined cognitive neutralization: `{analysis.get('best_combined_cognitive_neutralization')}`",
        f"- Best Phase1 neutralization in this target set: `{analysis.get('best_phase1_neutralization')}`",
        f"- Phase1 best policy `gated_edge_pressure_count_2` is cognitive best: `{analysis.get('phase1_best_policy_is_cognitive_best')}`",
        "",
        "## Human Top 3",
        *[
            f"- `{row.get('scenario')}`: { _to_float(row.get('cognitive_human_score')):.3f}"
            for row in human_top
        ],
        "",
        "## AI Top 3",
        *[
            f"- `{row.get('scenario')}`: { _to_float(row.get('cognitive_ai_score')):.3f}"
            for row in ai_top
        ],
        "",
        "## Combined Top 3",
        *[
            f"- `{row.get('scenario')}`: { _to_float(row.get('cognitive_neutralization_score')):.3f}"
            for row in combined_top
        ],
        "",
        "## Human vs AI",
        "Human score emphasizes perceived utility collapse, confidence loss, frustration, and retreat.",
        "AI score emphasizes weighted decision cost, confidence loss, perceived utility collapse, and retreat.",
        "Scenarios with credential trust degradation tend to rank higher for AI than for Human when AI trust weight is high.",
    ]
    with open(os.path.join(output_dir, "PHASE2_COGNITIVE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE2_POLICY_SELECTION_SCENARIO_NAMES = [
    "gated_edge_pressure_count_2",
    "gated_edge_pressure_duration_2",
    "credential_aware_mtd_window5",
    "phase2_frustration_decoy",
    "phase2_frustration_credential",
    "phase2_ai_balanced",
    "phase2_ai_high_trust_degradation",
]

PHASE2_POLICY_SELECTION_COLUMNS = [
    "policy",
    "num_runs",
    "policy_effectiveness_score",
    "phase1_neutralization_score",
    "cognitive_neutralization_score",
    "critical_protection_score",
    "critical_compromise_rate",
    "post_decoy_compromised_mean",
    "retreat_rate",
    "retreat_score",
    "human_score",
    "ai_score",
]


def run_phase2_policy_selection_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase2_policy_selection"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios = {name: SCENARIOS[name] for name in PHASE2_POLICY_SELECTION_SCENARIO_NAMES}
    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase2_policy_selection_row(row) for row in stats_rows]
    summary_rows.sort(key=lambda row: _to_float(row.get("policy_effectiveness_score")), reverse=True)
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase2_policy_selection(summary_rows)
    _write_phase2_policy_selection_summary(summary_rows, analysis, output_dir)
    _plot_phase2_policy_selection_ranking(summary_rows, os.path.join(output_dir, "policy_selection_ranking.png"))
    _plot_phase2_policy_phase1_vs_cns(summary_rows, os.path.join(output_dir, "phase1_vs_cns.png"))
    _plot_phase2_policy_human_vs_ai(summary_rows, os.path.join(output_dir, "human_vs_ai_policy.png"))
    _write_phase2_best_policy_report(summary_rows, analysis, output_dir)
    return summary_rows


def _build_phase2_policy_selection_row(row: Dict[str, object]) -> Dict[str, object]:
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    critical = _to_float(row.get("critical_protection_score_mean"))
    retreat = _to_float(row.get("retreat_score_mean"))
    effectiveness = float(np.clip(0.5 * cns + 0.3 * critical + 0.2 * retreat, 0.0, 1.0))
    return {
        "policy": row.get("scenario"),
        "num_runs": row.get("num_runs"),
        "policy_effectiveness_score": effectiveness,
        "phase1_neutralization_score": row.get("neutralization_score_mean"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "critical_protection_score": row.get("critical_protection_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "post_decoy_compromised_mean": row.get("post_decoy_compromised_mean"),
        "retreat_rate": row.get("retreat_rate"),
        "retreat_score": row.get("retreat_score_mean"),
        "human_score": row.get("cognitive_human_score_mean"),
        "ai_score": row.get("cognitive_ai_score_mean"),
    }


def _analyze_phase2_policy_selection(rows: List[Dict[str, object]]) -> Dict[str, object]:
    if not rows:
        return {}
    best_phase1 = max(rows, key=lambda row: _to_float(row.get("phase1_neutralization_score")))
    best_cns = max(rows, key=lambda row: _to_float(row.get("cognitive_neutralization_score")))
    best_effectiveness = max(rows, key=lambda row: _to_float(row.get("policy_effectiveness_score")))
    best_human = max(rows, key=lambda row: _to_float(row.get("human_score")))
    best_ai = max(rows, key=lambda row: _to_float(row.get("ai_score")))
    critical_candidates = [row for row in rows if _to_float(row.get("critical_protection_score")) >= 0.9]
    if not critical_candidates:
        max_critical = max(_to_float(row.get("critical_protection_score")) for row in rows)
        critical_candidates = [row for row in rows if _to_float(row.get("critical_protection_score")) >= max_critical]
    best_critical_cns = max(critical_candidates, key=lambda row: _to_float(row.get("cognitive_neutralization_score")))
    return {
        "best_phase1_policy": best_phase1.get("policy"),
        "best_cns_policy": best_cns.get("policy"),
        "best_effectiveness_policy": best_effectiveness.get("policy"),
        "best_human_policy": best_human.get("policy"),
        "best_ai_policy": best_ai.get("policy"),
        "best_critical_preserving_cns_policy": best_critical_cns.get("policy"),
        "phase1_and_cns_match": best_phase1.get("policy") == best_cns.get("policy"),
        "human_and_ai_match": best_human.get("policy") == best_ai.get("policy"),
        "recommended_policy": best_effectiveness.get("policy"),
    }


def _write_phase2_policy_selection_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "policy_selection_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE2_POLICY_SELECTION_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "policy_selection_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase2_policy_selection_ranking(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    labels = [str(row["policy"]).replace("phase2_", "") for row in rows]
    values = np.array([_to_float(row.get("policy_effectiveness_score")) for row in rows], dtype=float)
    plt.figure(figsize=(14, 6))
    plt.bar(labels, values, color="#4c78a8")
    plt.ylim(0.0, 1.0)
    plt.title("Phase2.5 CNS-Driven Policy Effectiveness")
    plt.ylabel("Policy Effectiveness Score")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_phase2_policy_phase1_vs_cns(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    labels = [str(row["policy"]).replace("phase2_", "") for row in rows]
    phase1 = np.array([_to_float(row.get("phase1_neutralization_score")) for row in rows], dtype=float)
    cns = np.array([_to_float(row.get("cognitive_neutralization_score")) for row in rows], dtype=float)
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.scatter(phase1, cns, s=90, color="#59a14f")
    for label, x_value, y_value in zip(labels, phase1, cns):
        ax.annotate(label, (x_value, y_value), textcoords="offset points", xytext=(5, 5), fontsize=8)
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel("Phase1 Neutralization Score")
    ax.set_ylabel("Cognitive Neutralization Score")
    ax.set_title("Phase2.5 Phase1 vs CNS Policy Selection")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase2_policy_human_vs_ai(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    labels = [str(row["policy"]).replace("phase2_", "") for row in rows]
    human = np.array([_to_float(row.get("human_score")) for row in rows], dtype=float)
    ai = np.array([_to_float(row.get("ai_score")) for row in rows], dtype=float)
    x = np.arange(len(labels))
    width = 0.4
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(x - width / 2, human, width=width, color="#4c78a8", label="Human score")
    ax.bar(x + width / 2, ai, width=width, color="#f58518", label="AI score")
    ax.set_ylim(0.0, 1.0)
    ax.set_ylabel("Score")
    ax.set_title("Phase2.5 Human vs AI Policy Score")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase2_best_policy_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    best_effective = next((row for row in rows if row.get("policy") == analysis.get("best_effectiveness_policy")), {})
    lines = [
        "# Phase2.5 CNS Driven Policy Selection",
        "",
        "## Best Policy Analysis",
        f"- best_phase1_policy: `{analysis.get('best_phase1_policy')}`",
        f"- best_cns_policy: `{analysis.get('best_cns_policy')}`",
        f"- best_effectiveness_policy: `{analysis.get('best_effectiveness_policy')}`",
        f"- best_human_policy: `{analysis.get('best_human_policy')}`",
        f"- best_ai_policy: `{analysis.get('best_ai_policy')}`",
        f"- recommended_policy: `{analysis.get('recommended_policy')}`",
        "",
        "## Questions",
        f"### Q1 Phase1 Best and CNS Best match: `{analysis.get('phase1_and_cns_match')}`",
        f"### Q2 Human and AI best policies match: `{analysis.get('human_and_ai_match')}`",
        f"### Q3 Critical-preserving CNS policy: `{analysis.get('best_critical_preserving_cns_policy')}`",
        f"### Q4 Current CyberMatch recommendation: `{analysis.get('recommended_policy')}`",
        "",
        "## Definition",
        "policy_effectiveness_score = clip(0.5 * cognitive_neutralization_score + 0.3 * critical_protection_score + 0.2 * retreat_score, 0, 1).",
        "",
        "## Recommended Policy Metrics",
        f"- policy_effectiveness_score: `{_to_float(best_effective.get('policy_effectiveness_score')):.3f}`",
        f"- cognitive_neutralization_score: `{_to_float(best_effective.get('cognitive_neutralization_score')):.3f}`",
        f"- critical_protection_score: `{_to_float(best_effective.get('critical_protection_score')):.3f}`",
    ]
    with open(os.path.join(output_dir, "best_policy_report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE3_ADAPTIVE_SCENARIO_NAMES = [
    "phase3_adaptive_reference",
    "phase3_adaptive_frustration_decoy",
    "phase3_adaptive_ai_balanced",
    "phase3_adaptive_gated_count2",
]

PHASE3_ADAPTIVE_COLUMNS = [
    "scenario",
    "attacker_mode",
    "num_runs",
    "policy_effectiveness_score",
    "cognitive_neutralization_score",
    "cns_delta_vs_static",
    "retreat_rate",
    "retreat_score",
    "critical_protection_score",
    "critical_compromise_rate",
    "post_decoy_compromised_mean",
    "adaptive_memory_success_mean",
    "adaptive_memory_decoy_mean",
    "adaptive_memory_detection_mean",
]


def run_phase3_adaptive_attacker_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase3_adaptive_attacker"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for name in PHASE3_ADAPTIVE_SCENARIO_NAMES:
        base = SCENARIOS[name]
        scenarios[f"{name}__static"] = {
            **base,
            "adaptive_attacker_enabled": False,
            "attacker_target_selection": "greedy",
        }
        scenarios[f"{name}__adaptive"] = {
            **base,
            "adaptive_attacker_enabled": True,
            "attacker_target_selection": "adaptive",
            "adaptive_success_weight": 1.0,
            "adaptive_decoy_weight": 2.0,
            "adaptive_detection_weight": 1.5,
        }

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase3_adaptive_row(row) for row in stats_rows]
    _add_phase3_cns_deltas(summary_rows)
    summary_rows.sort(
        key=lambda row: (str(row.get("scenario")), str(row.get("attacker_mode"))),
    )
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase3_adaptive_rows(summary_rows)
    _write_phase3_adaptive_summary(summary_rows, analysis, output_dir)
    _plot_phase3_adaptive_metric(summary_rows, "retreat_rate", "Adaptive Attacker Retreat Rate", os.path.join(output_dir, "adaptive_retreat_rate.png"))
    _plot_phase3_adaptive_metric(summary_rows, "cognitive_neutralization_score", "Adaptive Attacker CNS", os.path.join(output_dir, "adaptive_cns.png"))
    _plot_phase3_adaptive_metric(summary_rows, "policy_effectiveness_score", "Adaptive Policy Effectiveness", os.path.join(output_dir, "adaptive_policy_effectiveness.png"))
    _write_phase3_adaptive_report(summary_rows, analysis, output_dir)
    return summary_rows


def _build_phase3_adaptive_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario_name = str(row.get("scenario") or "")
    attacker_mode = "adaptive" if scenario_name.endswith("__adaptive") else "static"
    base_scenario = scenario_name.replace("__static", "").replace("__adaptive", "")
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    critical = _to_float(row.get("critical_protection_score_mean"))
    retreat = _to_float(row.get("retreat_score_mean"))
    effectiveness = float(np.clip(0.5 * cns + 0.3 * critical + 0.2 * retreat, 0.0, 1.0))
    return {
        "scenario": base_scenario,
        "attacker_mode": attacker_mode,
        "num_runs": row.get("num_runs"),
        "policy_effectiveness_score": effectiveness,
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_delta_vs_static": 0.0,
        "retreat_rate": row.get("retreat_rate"),
        "retreat_score": row.get("retreat_score_mean"),
        "critical_protection_score": row.get("critical_protection_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "post_decoy_compromised_mean": row.get("post_decoy_compromised_mean"),
        "adaptive_memory_success_mean": row.get("adaptive_memory_success_mean"),
        "adaptive_memory_decoy_mean": row.get("adaptive_memory_decoy_mean"),
        "adaptive_memory_detection_mean": row.get("adaptive_memory_detection_mean"),
    }


def _add_phase3_cns_deltas(rows: List[Dict[str, object]]) -> None:
    static_by_scenario = {
        str(row.get("scenario")): _to_float(row.get("cognitive_neutralization_score"))
        for row in rows
        if row.get("attacker_mode") == "static"
    }
    for row in rows:
        static_cns = static_by_scenario.get(str(row.get("scenario")), 0.0)
        row["cns_delta_vs_static"] = _to_float(row.get("cognitive_neutralization_score")) - static_cns


def _analyze_phase3_adaptive_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    adaptive_rows = [row for row in rows if row.get("attacker_mode") == "adaptive"]
    static_rows = [row for row in rows if row.get("attacker_mode") == "static"]
    mean_static_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in static_rows])) if static_rows else 0.0
    mean_adaptive_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in adaptive_rows])) if adaptive_rows else 0.0
    best_adaptive = max(adaptive_rows, key=lambda row: _to_float(row.get("policy_effectiveness_score"))) if adaptive_rows else {}
    frustration = next((row for row in adaptive_rows if row.get("scenario") == "phase3_adaptive_frustration_decoy"), {})
    best_cns = max(adaptive_rows, key=lambda row: _to_float(row.get("cognitive_neutralization_score"))) if adaptive_rows else {}
    return {
        "mean_static_cns": mean_static_cns,
        "mean_adaptive_cns": mean_adaptive_cns,
        "mean_cns_delta_adaptive_vs_static": mean_adaptive_cns - mean_static_cns,
        "adaptive_retreat_occurs": any(_to_float(row.get("retreat_rate")) > 0.0 for row in adaptive_rows),
        "max_adaptive_retreat_rate": max([_to_float(row.get("retreat_rate")) for row in adaptive_rows], default=0.0),
        "best_adaptive_policy": best_adaptive.get("scenario"),
        "best_adaptive_cns_policy": best_cns.get("scenario"),
        "phase3_frustration_decoy_is_best": frustration.get("scenario") == best_adaptive.get("scenario"),
    }


def _write_phase3_adaptive_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "adaptive_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE3_ADAPTIVE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "adaptive_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase3_adaptive_metric(rows: List[Dict[str, object]], key: str, title: str, save_path: str) -> None:
    if not rows:
        return
    scenarios = list(dict.fromkeys(str(row.get("scenario")) for row in rows))
    x = np.arange(len(scenarios))
    width = 0.38
    static_values = []
    adaptive_values = []
    for scenario in scenarios:
        static_row = next((row for row in rows if row.get("scenario") == scenario and row.get("attacker_mode") == "static"), {})
        adaptive_row = next((row for row in rows if row.get("scenario") == scenario and row.get("attacker_mode") == "adaptive"), {})
        static_values.append(_to_float(static_row.get(key)))
        adaptive_values.append(_to_float(adaptive_row.get(key)))
    labels = [scenario.replace("phase3_adaptive_", "") for scenario in scenarios]
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x - width / 2, static_values, width=width, color="#4c78a8", label="Static attacker")
    ax.bar(x + width / 2, adaptive_values, width=width, color="#f58518", label="Adaptive attacker")
    ax.set_title(title)
    ax.set_ylabel(key)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase3_adaptive_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    lines = [
        "# Phase3 Adaptive Attacker Report",
        "",
        "## Questions",
        f"1. Adaptive attacker CNS delta vs static: `{_to_float(analysis.get('mean_cns_delta_adaptive_vs_static')):.3f}` (static `{_to_float(analysis.get('mean_static_cns')):.3f}`, adaptive `{_to_float(analysis.get('mean_adaptive_cns')):.3f}`).",
        f"2. Adaptive attacker retreat occurs: `{analysis.get('adaptive_retreat_occurs')}` (max retreat_rate `{_to_float(analysis.get('max_adaptive_retreat_rate')):.3f}`).",
        f"3. phase2_frustration_decoy lineage is still strongest: `{analysis.get('phase3_frustration_decoy_is_best')}`.",
        f"4. Strongest adaptive policy: `{analysis.get('best_adaptive_policy')}`.",
        "",
        "## Rows",
        "| scenario | mode | CNS | retreat_rate | effectiveness | success_mem | decoy_mem | detection_mem |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('scenario')} | {row.get('attacker_mode')} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('retreat_rate')):.3f} | "
            f"{_to_float(row.get('policy_effectiveness_score')):.3f} | "
            f"{_to_float(row.get('adaptive_memory_success_mean')):.3f} | "
            f"{_to_float(row.get('adaptive_memory_decoy_mean')):.3f} | "
            f"{_to_float(row.get('adaptive_memory_detection_mean')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE3_ADAPTIVE_ATTACKER_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE3_PREFERENCE_SCENARIO_NAMES = [
    "phase3_preference_reference",
    "phase3_preference_frustration_decoy",
    "phase3_preference_ai_balanced",
    "phase3_preference_gated_count2",
]

PHASE3_PREFERENCE_COLUMNS = [
    "scenario",
    "attacker_mode",
    "num_runs",
    "policy_effectiveness_score",
    "cognitive_neutralization_score",
    "cns_delta_vs_static",
    "cns_delta_vs_memory",
    "retreat_rate",
    "retreat_score",
    "critical_protection_score",
    "critical_compromise_rate",
    "post_decoy_compromised_mean",
    "adaptive_memory_success_mean",
    "adaptive_memory_decoy_mean",
    "adaptive_memory_detection_mean",
    "preference_mean",
    "preference_max",
    "preferred_node_score",
    "preferred_node_on_critical_path_rate",
]


def run_phase3_preference_attacker_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase3_preference_attacker"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for name in PHASE3_PREFERENCE_SCENARIO_NAMES:
        base = SCENARIOS[name]
        scenarios[f"{name}__static"] = {
            **base,
            "adaptive_attacker_enabled": False,
            "adaptive_preference_enabled": False,
            "attacker_target_selection": "greedy",
        }
        scenarios[f"{name}__memory"] = {
            **base,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": False,
            "attacker_target_selection": "adaptive",
            "adaptive_success_weight": 1.0,
            "adaptive_decoy_weight": 2.0,
            "adaptive_detection_weight": 1.5,
        }
        scenarios[f"{name}__preference"] = {
            **base,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "attacker_target_selection": "adaptive",
            "adaptive_success_weight": 1.0,
            "adaptive_decoy_weight": 2.0,
            "adaptive_detection_weight": 1.5,
            "adaptive_preference_weight": 2.0,
            "adaptive_success_reward": 1.0,
            "adaptive_critical_reward": 3.0,
            "adaptive_decoy_penalty": 2.0,
            "adaptive_detection_penalty": 1.5,
        }

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase3_preference_row(row) for row in stats_rows]
    _add_phase3_preference_deltas(summary_rows)
    summary_rows.sort(key=lambda row: (str(row.get("scenario")), str(row.get("attacker_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase3_preference_rows(summary_rows)
    _write_phase3_preference_summary(summary_rows, analysis, output_dir)
    _plot_phase3_preference_metric(summary_rows, "cognitive_neutralization_score", "Preference Attacker CNS", os.path.join(output_dir, "preference_cns.png"))
    _plot_phase3_preference_metric(summary_rows, "retreat_rate", "Preference Attacker Retreat Rate", os.path.join(output_dir, "preference_retreat_rate.png"))
    _plot_phase3_preference_metric(summary_rows, "preferred_node_on_critical_path_rate", "Preference Critical Path Bias", os.path.join(output_dir, "preference_path_bias.png"))
    _write_phase3_preference_report(summary_rows, analysis, output_dir)
    return summary_rows


def _build_phase3_preference_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario_name = str(row.get("scenario") or "")
    if scenario_name.endswith("__preference"):
        attacker_mode = "adaptive_preference"
    elif scenario_name.endswith("__memory"):
        attacker_mode = "adaptive_memory"
    else:
        attacker_mode = "static"
    base_scenario = (
        scenario_name
        .replace("__static", "")
        .replace("__memory", "")
        .replace("__preference", "")
    )
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    critical = _to_float(row.get("critical_protection_score_mean"))
    retreat = _to_float(row.get("retreat_score_mean"))
    effectiveness = float(np.clip(0.5 * cns + 0.3 * critical + 0.2 * retreat, 0.0, 1.0))
    return {
        "scenario": base_scenario,
        "attacker_mode": attacker_mode,
        "num_runs": row.get("num_runs"),
        "policy_effectiveness_score": effectiveness,
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_delta_vs_static": 0.0,
        "cns_delta_vs_memory": 0.0,
        "retreat_rate": row.get("retreat_rate"),
        "retreat_score": row.get("retreat_score_mean"),
        "critical_protection_score": row.get("critical_protection_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "post_decoy_compromised_mean": row.get("post_decoy_compromised_mean"),
        "adaptive_memory_success_mean": row.get("adaptive_memory_success_mean"),
        "adaptive_memory_decoy_mean": row.get("adaptive_memory_decoy_mean"),
        "adaptive_memory_detection_mean": row.get("adaptive_memory_detection_mean"),
        "preference_mean": row.get("preference_mean"),
        "preference_max": row.get("preference_max_mean"),
        "preferred_node_score": row.get("preferred_node_score_mean"),
        "preferred_node_on_critical_path_rate": row.get("preferred_node_on_critical_path_rate"),
    }


def _add_phase3_preference_deltas(rows: List[Dict[str, object]]) -> None:
    static_by_scenario = {
        str(row.get("scenario")): _to_float(row.get("cognitive_neutralization_score"))
        for row in rows
        if row.get("attacker_mode") == "static"
    }
    memory_by_scenario = {
        str(row.get("scenario")): _to_float(row.get("cognitive_neutralization_score"))
        for row in rows
        if row.get("attacker_mode") == "adaptive_memory"
    }
    for row in rows:
        scenario = str(row.get("scenario"))
        row["cns_delta_vs_static"] = _to_float(row.get("cognitive_neutralization_score")) - static_by_scenario.get(scenario, 0.0)
        row["cns_delta_vs_memory"] = _to_float(row.get("cognitive_neutralization_score")) - memory_by_scenario.get(scenario, 0.0)


def _analyze_phase3_preference_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    preference_rows = [row for row in rows if row.get("attacker_mode") == "adaptive_preference"]
    memory_rows = [row for row in rows if row.get("attacker_mode") == "adaptive_memory"]
    static_rows = [row for row in rows if row.get("attacker_mode") == "static"]
    mean_static_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in static_rows])) if static_rows else 0.0
    mean_memory_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in memory_rows])) if memory_rows else 0.0
    mean_preference_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in preference_rows])) if preference_rows else 0.0
    best_preference = max(preference_rows, key=lambda row: _to_float(row.get("policy_effectiveness_score"))) if preference_rows else {}
    frustration = next((row for row in preference_rows if row.get("scenario") == "phase3_preference_frustration_decoy"), {})
    preference_max_values = [_to_float(row.get("preference_max")) for row in preference_rows]
    critical_path_rates = [_to_float(row.get("preferred_node_on_critical_path_rate")) for row in preference_rows]
    return {
        "mean_static_cns": mean_static_cns,
        "mean_memory_cns": mean_memory_cns,
        "mean_preference_cns": mean_preference_cns,
        "mean_cns_delta_preference_vs_static": mean_preference_cns - mean_static_cns,
        "mean_cns_delta_preference_vs_memory": mean_preference_cns - mean_memory_cns,
        "preference_retreat_rate_mean": float(np.mean([_to_float(row.get("retreat_rate")) for row in preference_rows])) if preference_rows else 0.0,
        "memory_retreat_rate_mean": float(np.mean([_to_float(row.get("retreat_rate")) for row in memory_rows])) if memory_rows else 0.0,
        "phase3_frustration_decoy_is_best": frustration.get("scenario") == best_preference.get("scenario"),
        "best_preference_policy": best_preference.get("scenario"),
        "preferred_path_formed": any(value > 0.0 for value in preference_max_values),
        "preferred_node_critical_path_rate_mean": float(np.mean(critical_path_rates)) if critical_path_rates else 0.0,
    }


def _write_phase3_preference_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "preference_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE3_PREFERENCE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "preference_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase3_preference_metric(rows: List[Dict[str, object]], key: str, title: str, save_path: str) -> None:
    if not rows:
        return
    scenarios = list(dict.fromkeys(str(row.get("scenario")) for row in rows))
    modes = ["static", "adaptive_memory", "adaptive_preference"]
    colors = {"static": "#4c78a8", "adaptive_memory": "#f58518", "adaptive_preference": "#59a14f"}
    x = np.arange(len(scenarios))
    width = 0.25
    fig, ax = plt.subplots(figsize=(13, 6))
    for offset, mode in zip([-width, 0.0, width], modes):
        values = []
        for scenario in scenarios:
            row = next((candidate for candidate in rows if candidate.get("scenario") == scenario and candidate.get("attacker_mode") == mode), {})
            values.append(_to_float(row.get(key)))
        ax.bar(x + offset, values, width=width, color=colors[mode], label=mode)
    labels = [scenario.replace("phase3_preference_", "") for scenario in scenarios]
    ax.set_title(title)
    ax.set_ylabel(key)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase3_preference_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    lines = [
        "# Phase3 Preference Attacker Report",
        "",
        "## Questions",
        f"1. Success reinforcement CNS delta vs memory attacker: `{_to_float(analysis.get('mean_cns_delta_preference_vs_memory')):.3f}` (memory `{_to_float(analysis.get('mean_memory_cns')):.3f}`, preference `{_to_float(analysis.get('mean_preference_cns')):.3f}`).",
        f"2. retreat_rate maintained: `{_to_float(analysis.get('preference_retreat_rate_mean')):.3f}` vs memory `{_to_float(analysis.get('memory_retreat_rate_mean')):.3f}`.",
        f"3. phase2_frustration_decoy lineage is still strongest: `{analysis.get('phase3_frustration_decoy_is_best')}`.",
        f"4. Preferred path formed: `{analysis.get('preferred_path_formed')}`.",
        f"5. Preferred node critical-path concentration: `{_to_float(analysis.get('preferred_node_critical_path_rate_mean')):.3f}`.",
        "",
        "## Rows",
        "| scenario | mode | CNS | retreat_rate | effectiveness | preference_max | preferred_critical_path_rate |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('scenario')} | {row.get('attacker_mode')} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('retreat_rate')):.3f} | "
            f"{_to_float(row.get('policy_effectiveness_score')):.3f} | "
            f"{_to_float(row.get('preference_max')):.3f} | "
            f"{_to_float(row.get('preferred_node_on_critical_path_rate')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE3_PREFERENCE_ATTACKER_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE3_PATH_SCENARIO_NAMES = [
    "phase3_path_reference",
    "phase3_path_frustration_decoy",
    "phase3_path_ai_balanced",
    "phase3_path_gated_count2",
]

PHASE3_PATH_COLUMNS = [
    "scenario",
    "attacker_mode",
    "num_runs",
    "policy_effectiveness_score",
    "cognitive_neutralization_score",
    "cns_delta_vs_static",
    "cns_delta_vs_memory",
    "cns_delta_vs_preference",
    "retreat_rate",
    "retreat_score",
    "critical_protection_score",
    "critical_compromise_rate",
    "post_decoy_compromised_mean",
    "preference_max",
    "preferred_node_on_critical_path_rate",
    "path_preference_mean",
    "path_preference_max",
    "preferred_path",
    "preferred_path_score",
    "preferred_path_is_critical_rate",
]


def run_phase3_path_attacker_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase3_path_attacker"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for name in PHASE3_PATH_SCENARIO_NAMES:
        base = SCENARIOS[name]
        scenarios[f"{name}__static"] = {
            **base,
            "adaptive_attacker_enabled": False,
            "adaptive_preference_enabled": False,
            "adaptive_path_enabled": False,
            "attacker_target_selection": "greedy",
        }
        scenarios[f"{name}__memory"] = {
            **base,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": False,
            "adaptive_path_enabled": False,
            "attacker_target_selection": "adaptive",
            "adaptive_success_weight": 1.0,
            "adaptive_decoy_weight": 2.0,
            "adaptive_detection_weight": 1.5,
        }
        scenarios[f"{name}__preference"] = {
            **base,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "adaptive_path_enabled": False,
            "attacker_target_selection": "adaptive",
            "adaptive_success_weight": 1.0,
            "adaptive_decoy_weight": 2.0,
            "adaptive_detection_weight": 1.5,
            "adaptive_preference_weight": 2.0,
            "adaptive_success_reward": 1.0,
            "adaptive_critical_reward": 3.0,
            "adaptive_decoy_penalty": 2.0,
            "adaptive_detection_penalty": 1.5,
        }
        scenarios[f"{name}__path"] = {
            **base,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "adaptive_path_enabled": True,
            "attacker_target_selection": "adaptive",
            "adaptive_success_weight": 1.0,
            "adaptive_decoy_weight": 2.0,
            "adaptive_detection_weight": 1.5,
            "adaptive_preference_weight": 2.0,
            "adaptive_success_reward": 1.0,
            "adaptive_critical_reward": 3.0,
            "adaptive_decoy_penalty": 2.0,
            "adaptive_detection_penalty": 1.5,
            "path_preference_weight": 3.0,
            "path_success_reward": 1.0,
            "path_critical_reward": 5.0,
            "path_decoy_penalty": 2.0,
            "path_detection_penalty": 1.5,
        }

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase3_path_row(row) for row in stats_rows]
    _add_phase3_path_deltas(summary_rows)
    summary_rows.sort(key=lambda row: (str(row.get("scenario")), str(row.get("attacker_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase3_path_rows(summary_rows)
    _write_phase3_path_summary(summary_rows, analysis, output_dir)
    _plot_phase3_path_metric(summary_rows, "cognitive_neutralization_score", "Path Preference Attacker CNS", os.path.join(output_dir, "path_cns.png"))
    _plot_phase3_path_metric(summary_rows, "retreat_rate", "Path Preference Attacker Retreat Rate", os.path.join(output_dir, "path_retreat_rate.png"))
    _plot_phase3_path_metric(summary_rows, "path_preference_max", "Path Preference Strength", os.path.join(output_dir, "path_preference.png"))
    _write_phase3_path_report(summary_rows, analysis, output_dir)
    return summary_rows


def _build_phase3_path_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario_name = str(row.get("scenario") or "")
    if scenario_name.endswith("__path"):
        attacker_mode = "adaptive_path_preference"
    elif scenario_name.endswith("__preference"):
        attacker_mode = "adaptive_preference"
    elif scenario_name.endswith("__memory"):
        attacker_mode = "adaptive_memory"
    else:
        attacker_mode = "static"
    base_scenario = (
        scenario_name
        .replace("__static", "")
        .replace("__memory", "")
        .replace("__preference", "")
        .replace("__path", "")
    )
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    critical = _to_float(row.get("critical_protection_score_mean"))
    retreat = _to_float(row.get("retreat_score_mean"))
    effectiveness = float(np.clip(0.5 * cns + 0.3 * critical + 0.2 * retreat, 0.0, 1.0))
    return {
        "scenario": base_scenario,
        "attacker_mode": attacker_mode,
        "num_runs": row.get("num_runs"),
        "policy_effectiveness_score": effectiveness,
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_delta_vs_static": 0.0,
        "cns_delta_vs_memory": 0.0,
        "cns_delta_vs_preference": 0.0,
        "retreat_rate": row.get("retreat_rate"),
        "retreat_score": row.get("retreat_score_mean"),
        "critical_protection_score": row.get("critical_protection_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "post_decoy_compromised_mean": row.get("post_decoy_compromised_mean"),
        "preference_max": row.get("preference_max_mean"),
        "preferred_node_on_critical_path_rate": row.get("preferred_node_on_critical_path_rate"),
        "path_preference_mean": row.get("path_preference_mean"),
        "path_preference_max": row.get("path_preference_max_mean"),
        "preferred_path": row.get("preferred_path"),
        "preferred_path_score": row.get("preferred_path_score_mean"),
        "preferred_path_is_critical_rate": row.get("preferred_path_is_critical_rate"),
    }


def _add_phase3_path_deltas(rows: List[Dict[str, object]]) -> None:
    static_by_scenario = {
        str(row.get("scenario")): _to_float(row.get("cognitive_neutralization_score"))
        for row in rows
        if row.get("attacker_mode") == "static"
    }
    memory_by_scenario = {
        str(row.get("scenario")): _to_float(row.get("cognitive_neutralization_score"))
        for row in rows
        if row.get("attacker_mode") == "adaptive_memory"
    }
    preference_by_scenario = {
        str(row.get("scenario")): _to_float(row.get("cognitive_neutralization_score"))
        for row in rows
        if row.get("attacker_mode") == "adaptive_preference"
    }
    for row in rows:
        scenario = str(row.get("scenario"))
        cns = _to_float(row.get("cognitive_neutralization_score"))
        row["cns_delta_vs_static"] = cns - static_by_scenario.get(scenario, 0.0)
        row["cns_delta_vs_memory"] = cns - memory_by_scenario.get(scenario, 0.0)
        row["cns_delta_vs_preference"] = cns - preference_by_scenario.get(scenario, 0.0)


def _analyze_phase3_path_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    path_rows = [row for row in rows if row.get("attacker_mode") == "adaptive_path_preference"]
    preference_rows = [row for row in rows if row.get("attacker_mode") == "adaptive_preference"]
    memory_rows = [row for row in rows if row.get("attacker_mode") == "adaptive_memory"]
    mean_path_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in path_rows])) if path_rows else 0.0
    mean_preference_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in preference_rows])) if preference_rows else 0.0
    mean_memory_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in memory_rows])) if memory_rows else 0.0
    best_path = max(path_rows, key=lambda row: _to_float(row.get("policy_effectiveness_score"))) if path_rows else {}
    frustration = next((row for row in path_rows if row.get("scenario") == "phase3_path_frustration_decoy"), {})
    path_preference_max_values = [_to_float(row.get("path_preference_max")) for row in path_rows]
    critical_path_rates = [_to_float(row.get("preferred_path_is_critical_rate")) for row in path_rows]
    return {
        "mean_memory_cns": mean_memory_cns,
        "mean_preference_cns": mean_preference_cns,
        "mean_path_cns": mean_path_cns,
        "mean_cns_delta_path_vs_preference": mean_path_cns - mean_preference_cns,
        "path_retreat_rate_mean": float(np.mean([_to_float(row.get("retreat_rate")) for row in path_rows])) if path_rows else 0.0,
        "preference_retreat_rate_mean": float(np.mean([_to_float(row.get("retreat_rate")) for row in preference_rows])) if preference_rows else 0.0,
        "phase3_frustration_decoy_is_best": frustration.get("scenario") == best_path.get("scenario"),
        "best_path_policy": best_path.get("scenario"),
        "preferred_path_formed": any(value > 0.0 for value in path_preference_max_values),
        "preferred_path_critical_rate_mean": float(np.mean(critical_path_rates)) if critical_path_rates else 0.0,
        "path_aware_decoy_effective": (
            _to_float(frustration.get("critical_compromise_rate")) <= 0.0
            and _to_float(frustration.get("retreat_rate")) >= 1.0
        ),
    }


def _write_phase3_path_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "path_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE3_PATH_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "path_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase3_path_metric(rows: List[Dict[str, object]], key: str, title: str, save_path: str) -> None:
    if not rows:
        return
    scenarios = list(dict.fromkeys(str(row.get("scenario")) for row in rows))
    modes = ["static", "adaptive_memory", "adaptive_preference", "adaptive_path_preference"]
    colors = {
        "static": "#4c78a8",
        "adaptive_memory": "#f58518",
        "adaptive_preference": "#59a14f",
        "adaptive_path_preference": "#e45756",
    }
    x = np.arange(len(scenarios))
    width = 0.2
    fig, ax = plt.subplots(figsize=(14, 6))
    for idx, mode in enumerate(modes):
        values = []
        for scenario in scenarios:
            row = next((candidate for candidate in rows if candidate.get("scenario") == scenario and candidate.get("attacker_mode") == mode), {})
            values.append(_to_float(row.get(key)))
        ax.bar(x + (idx - 1.5) * width, values, width=width, color=colors[mode], label=mode)
    labels = [scenario.replace("phase3_path_", "") for scenario in scenarios]
    ax.set_title(title)
    ax.set_ylabel(key)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase3_path_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    lines = [
        "# Phase3 Path Preference Attacker Report",
        "",
        "## Questions",
        f"1. Path learning CNS delta vs node preference attacker: `{_to_float(analysis.get('mean_cns_delta_path_vs_preference')):.3f}` (preference `{_to_float(analysis.get('mean_preference_cns')):.3f}`, path `{_to_float(analysis.get('mean_path_cns')):.3f}`).",
        f"2. retreat_rate maintained: `{_to_float(analysis.get('path_retreat_rate_mean')):.3f}` vs preference `{_to_float(analysis.get('preference_retreat_rate_mean')):.3f}`.",
        f"3. phase2_frustration_decoy lineage is still strongest: `{analysis.get('phase3_frustration_decoy_is_best')}`.",
        f"4. Preferred path formed: `{analysis.get('preferred_path_formed')}`.",
        f"5. Preferred path critical concentration: `{_to_float(analysis.get('preferred_path_critical_rate_mean')):.3f}`.",
        f"6. Path-aware decoy effective against path learner: `{analysis.get('path_aware_decoy_effective')}`.",
        "",
        "## Rows",
        "| scenario | mode | CNS | retreat_rate | effectiveness | path_pref_max | preferred_path | path_critical_rate |",
        "|---|---:|---:|---:|---:|---:|---|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('scenario')} | {row.get('attacker_mode')} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('retreat_rate')):.3f} | "
            f"{_to_float(row.get('policy_effectiveness_score')):.3f} | "
            f"{_to_float(row.get('path_preference_max')):.3f} | "
            f"{row.get('preferred_path') or ''} | "
            f"{_to_float(row.get('preferred_path_is_critical_rate')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE3_PATH_ATTACKER_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE3_PLANNING_SCENARIO_NAMES = [
    "phase3_planning_reference",
    "phase3_planning_frustration_decoy",
    "phase3_planning_ai_balanced",
    "phase3_planning_gated_count2",
]

PHASE3_PLANNING_COLUMNS = [
    "scenario",
    "attacker_mode",
    "num_runs",
    "policy_effectiveness_score",
    "cognitive_neutralization_score",
    "cns_delta_vs_static",
    "cns_delta_vs_memory",
    "cns_delta_vs_preference",
    "cns_delta_vs_path",
    "retreat_rate",
    "retreat_score",
    "critical_protection_score",
    "critical_compromise_rate",
    "post_decoy_compromised_mean",
    "path_preference_max",
    "planning_depth",
    "planning_score_mean",
    "planning_score_max",
    "planned_path",
    "planned_path_score",
    "planned_path_is_critical_rate",
]


def run_phase3_planning_attacker_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase3_planning_attacker"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for name in PHASE3_PLANNING_SCENARIO_NAMES:
        base = SCENARIOS[name]
        shared_adaptive = {
            "adaptive_success_weight": 1.0,
            "adaptive_decoy_weight": 2.0,
            "adaptive_detection_weight": 1.5,
            "adaptive_preference_weight": 2.0,
            "adaptive_success_reward": 1.0,
            "adaptive_critical_reward": 3.0,
            "adaptive_decoy_penalty": 2.0,
            "adaptive_detection_penalty": 1.5,
            "path_preference_weight": 3.0,
            "path_success_reward": 1.0,
            "path_critical_reward": 5.0,
            "path_decoy_penalty": 2.0,
            "path_detection_penalty": 1.5,
            "planning_depth": 2,
            "planning_success_weight": 1.0,
            "planning_critical_weight": 5.0,
            "planning_decoy_penalty": 2.0,
            "planning_detection_penalty": 1.5,
        }
        scenarios[f"{name}__static"] = {
            **base,
            "adaptive_attacker_enabled": False,
            "adaptive_preference_enabled": False,
            "adaptive_path_enabled": False,
            "adaptive_planning_enabled": False,
            "attacker_target_selection": "greedy",
        }
        scenarios[f"{name}__memory"] = {
            **base,
            **shared_adaptive,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": False,
            "adaptive_path_enabled": False,
            "adaptive_planning_enabled": False,
            "attacker_target_selection": "adaptive",
        }
        scenarios[f"{name}__preference"] = {
            **base,
            **shared_adaptive,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "adaptive_path_enabled": False,
            "adaptive_planning_enabled": False,
            "attacker_target_selection": "adaptive",
        }
        scenarios[f"{name}__path"] = {
            **base,
            **shared_adaptive,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "adaptive_path_enabled": True,
            "adaptive_planning_enabled": False,
            "attacker_target_selection": "adaptive",
        }
        scenarios[f"{name}__planning"] = {
            **base,
            **shared_adaptive,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "adaptive_path_enabled": True,
            "adaptive_planning_enabled": True,
            "attacker_target_selection": "adaptive",
        }

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase3_planning_row(row) for row in stats_rows]
    _add_phase3_planning_deltas(summary_rows)
    summary_rows.sort(key=lambda row: (str(row.get("scenario")), str(row.get("attacker_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase3_planning_rows(summary_rows)
    _write_phase3_planning_summary(summary_rows, analysis, output_dir)
    _plot_phase3_planning_metric(summary_rows, "cognitive_neutralization_score", "Planning Attacker CNS", os.path.join(output_dir, "planning_cns.png"))
    _plot_phase3_planning_metric(summary_rows, "retreat_rate", "Planning Attacker Retreat Rate", os.path.join(output_dir, "planning_retreat_rate.png"))
    _plot_phase3_planning_metric(summary_rows, "planned_path_is_critical_rate", "Planning Critical Path Bias", os.path.join(output_dir, "planning_path_bias.png"))
    _write_phase3_planning_report(summary_rows, analysis, output_dir)
    return summary_rows


def _build_phase3_planning_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario_name = str(row.get("scenario") or "")
    if scenario_name.endswith("__planning"):
        attacker_mode = "adaptive_planning"
    elif scenario_name.endswith("__path"):
        attacker_mode = "adaptive_path_preference"
    elif scenario_name.endswith("__preference"):
        attacker_mode = "adaptive_preference"
    elif scenario_name.endswith("__memory"):
        attacker_mode = "adaptive_memory"
    else:
        attacker_mode = "static"
    base_scenario = (
        scenario_name
        .replace("__static", "")
        .replace("__memory", "")
        .replace("__preference", "")
        .replace("__path", "")
        .replace("__planning", "")
    )
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    critical = _to_float(row.get("critical_protection_score_mean"))
    retreat = _to_float(row.get("retreat_score_mean"))
    effectiveness = float(np.clip(0.5 * cns + 0.3 * critical + 0.2 * retreat, 0.0, 1.0))
    return {
        "scenario": base_scenario,
        "attacker_mode": attacker_mode,
        "num_runs": row.get("num_runs"),
        "policy_effectiveness_score": effectiveness,
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_delta_vs_static": 0.0,
        "cns_delta_vs_memory": 0.0,
        "cns_delta_vs_preference": 0.0,
        "cns_delta_vs_path": 0.0,
        "retreat_rate": row.get("retreat_rate"),
        "retreat_score": row.get("retreat_score_mean"),
        "critical_protection_score": row.get("critical_protection_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "post_decoy_compromised_mean": row.get("post_decoy_compromised_mean"),
        "path_preference_max": row.get("path_preference_max_mean"),
        "planning_depth": row.get("planning_depth"),
        "planning_score_mean": row.get("planning_score_mean"),
        "planning_score_max": row.get("planning_score_max_mean"),
        "planned_path": row.get("planned_path"),
        "planned_path_score": row.get("planned_path_score_mean"),
        "planned_path_is_critical_rate": row.get("planned_path_is_critical_rate"),
    }


def _add_phase3_planning_deltas(rows: List[Dict[str, object]]) -> None:
    by_mode: Dict[str, Dict[str, float]] = {}
    for mode in ["static", "adaptive_memory", "adaptive_preference", "adaptive_path_preference"]:
        by_mode[mode] = {
            str(row.get("scenario")): _to_float(row.get("cognitive_neutralization_score"))
            for row in rows
            if row.get("attacker_mode") == mode
        }
    for row in rows:
        scenario = str(row.get("scenario"))
        cns = _to_float(row.get("cognitive_neutralization_score"))
        row["cns_delta_vs_static"] = cns - by_mode["static"].get(scenario, 0.0)
        row["cns_delta_vs_memory"] = cns - by_mode["adaptive_memory"].get(scenario, 0.0)
        row["cns_delta_vs_preference"] = cns - by_mode["adaptive_preference"].get(scenario, 0.0)
        row["cns_delta_vs_path"] = cns - by_mode["adaptive_path_preference"].get(scenario, 0.0)


def _analyze_phase3_planning_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    planning_rows = [row for row in rows if row.get("attacker_mode") == "adaptive_planning"]
    path_rows = [row for row in rows if row.get("attacker_mode") == "adaptive_path_preference"]
    mean_planning_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in planning_rows])) if planning_rows else 0.0
    mean_path_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in path_rows])) if path_rows else 0.0
    best_planning = max(planning_rows, key=lambda row: _to_float(row.get("policy_effectiveness_score"))) if planning_rows else {}
    frustration = next((row for row in planning_rows if row.get("scenario") == "phase3_planning_frustration_decoy"), {})
    return {
        "mean_path_cns": mean_path_cns,
        "mean_planning_cns": mean_planning_cns,
        "mean_cns_delta_planning_vs_path": mean_planning_cns - mean_path_cns,
        "mean_cns_reduction_planning_vs_path": mean_path_cns - mean_planning_cns,
        "planning_retreat_rate_mean": float(np.mean([_to_float(row.get("retreat_rate")) for row in planning_rows])) if planning_rows else 0.0,
        "path_retreat_rate_mean": float(np.mean([_to_float(row.get("retreat_rate")) for row in path_rows])) if path_rows else 0.0,
        "phase3_frustration_decoy_is_best": frustration.get("scenario") == best_planning.get("scenario"),
        "best_planning_policy": best_planning.get("scenario"),
        "planning_critical_path_rate_mean": float(np.mean([_to_float(row.get("planned_path_is_critical_rate")) for row in planning_rows])) if planning_rows else 0.0,
        "planning_attacker_stronger_than_path_learner": mean_planning_cns < mean_path_cns,
        "path_aware_decoy_effective": (
            _to_float(frustration.get("critical_compromise_rate")) <= 0.0
            and _to_float(frustration.get("retreat_rate")) >= 1.0
        ),
    }


def _write_phase3_planning_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "planning_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE3_PLANNING_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "planning_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase3_planning_metric(rows: List[Dict[str, object]], key: str, title: str, save_path: str) -> None:
    if not rows:
        return
    scenarios = list(dict.fromkeys(str(row.get("scenario")) for row in rows))
    modes = ["static", "adaptive_memory", "adaptive_preference", "adaptive_path_preference", "adaptive_planning"]
    colors = {
        "static": "#4c78a8",
        "adaptive_memory": "#f58518",
        "adaptive_preference": "#59a14f",
        "adaptive_path_preference": "#e45756",
        "adaptive_planning": "#7f3c8d",
    }
    x = np.arange(len(scenarios))
    width = 0.16
    fig, ax = plt.subplots(figsize=(15, 6))
    for idx, mode in enumerate(modes):
        values = []
        for scenario in scenarios:
            row = next((candidate for candidate in rows if candidate.get("scenario") == scenario and candidate.get("attacker_mode") == mode), {})
            values.append(_to_float(row.get(key)))
        ax.bar(x + (idx - 2.0) * width, values, width=width, color=colors[mode], label=mode)
    labels = [scenario.replace("phase3_planning_", "") for scenario in scenarios]
    ax.set_title(title)
    ax.set_ylabel(key)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase3_planning_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    lines = [
        "# Phase3 Planning Attacker Report",
        "",
        "## Questions",
        f"1. Planning attacker CNS reduction vs path learner: `{_to_float(analysis.get('mean_cns_reduction_planning_vs_path')):.3f}` (path `{_to_float(analysis.get('mean_path_cns')):.3f}`, planning `{_to_float(analysis.get('mean_planning_cns')):.3f}`).",
        f"2. retreat_rate maintained: planning `{_to_float(analysis.get('planning_retreat_rate_mean')):.3f}` vs path `{_to_float(analysis.get('path_retreat_rate_mean')):.3f}`.",
        f"3. phase2_frustration_decoy lineage is still strongest: `{analysis.get('phase3_frustration_decoy_is_best')}`.",
        f"4. Planning critical path concentration: `{_to_float(analysis.get('planning_critical_path_rate_mean')):.3f}`.",
        f"5. Planning attacker stronger than path learner: `{analysis.get('planning_attacker_stronger_than_path_learner')}`.",
        f"6. Path-aware decoy effective against planning attacker: `{analysis.get('path_aware_decoy_effective')}`.",
        "",
        "## Rows",
        "| scenario | mode | CNS | retreat_rate | effectiveness | planning_score_max | planned_path | planned_critical_rate |",
        "|---|---:|---:|---:|---:|---:|---|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('scenario')} | {row.get('attacker_mode')} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('retreat_rate')):.3f} | "
            f"{_to_float(row.get('policy_effectiveness_score')):.3f} | "
            f"{_to_float(row.get('planning_score_max')):.3f} | "
            f"{row.get('planned_path') or ''} | "
            f"{_to_float(row.get('planned_path_is_critical_rate')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE3_PLANNING_ATTACKER_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE3_TRUST_SCENARIO_NAMES = [
    "phase3_trust_reference",
    "phase3_trust_frustration_decoy",
    "phase3_trust_ai_balanced",
    "phase3_trust_gated_count2",
]

PHASE3_TRUST_COLUMNS = [
    "scenario",
    "attacker_mode",
    "num_runs",
    "policy_effectiveness_score",
    "cognitive_neutralization_score",
    "cns_delta_vs_static",
    "cns_delta_vs_memory",
    "cns_delta_vs_preference",
    "cns_delta_vs_path",
    "cns_delta_vs_planning",
    "retreat_rate",
    "retreat_score",
    "critical_protection_score",
    "critical_compromise_rate",
    "post_decoy_compromised_mean",
    "planning_score_mean",
    "planning_score_max",
    "planned_path",
    "planned_path_score",
    "planned_path_is_critical_rate",
    "trust_mean",
    "trust_min",
    "trust_max",
    "trust_collapse_rate",
    "least_trusted_node",
    "most_trusted_node",
]


def run_phase3_trust_attacker_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase3_trust_attacker"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for name in PHASE3_TRUST_SCENARIO_NAMES:
        base = SCENARIOS[name]
        shared_adaptive = {
            "adaptive_success_weight": 1.0,
            "adaptive_decoy_weight": 2.0,
            "adaptive_detection_weight": 1.5,
            "adaptive_preference_weight": 2.0,
            "adaptive_success_reward": 1.0,
            "adaptive_critical_reward": 3.0,
            "adaptive_decoy_penalty": 2.0,
            "adaptive_detection_penalty": 1.5,
            "path_preference_weight": 3.0,
            "path_success_reward": 1.0,
            "path_critical_reward": 5.0,
            "path_decoy_penalty": 2.0,
            "path_detection_penalty": 1.5,
            "planning_depth": 2,
            "planning_success_weight": 1.0,
            "planning_critical_weight": 5.0,
            "planning_decoy_penalty": 2.0,
            "planning_detection_penalty": 1.5,
        }
        scenarios[f"{name}__static"] = {
            **base,
            "adaptive_attacker_enabled": False,
            "adaptive_preference_enabled": False,
            "adaptive_path_enabled": False,
            "adaptive_planning_enabled": False,
            "trust_enabled": False,
            "attacker_target_selection": "greedy",
        }
        scenarios[f"{name}__memory"] = {
            **base,
            **shared_adaptive,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": False,
            "adaptive_path_enabled": False,
            "adaptive_planning_enabled": False,
            "trust_enabled": False,
            "attacker_target_selection": "adaptive",
        }
        scenarios[f"{name}__preference"] = {
            **base,
            **shared_adaptive,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "adaptive_path_enabled": False,
            "adaptive_planning_enabled": False,
            "trust_enabled": False,
            "attacker_target_selection": "adaptive",
        }
        scenarios[f"{name}__path"] = {
            **base,
            **shared_adaptive,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "adaptive_path_enabled": True,
            "adaptive_planning_enabled": False,
            "trust_enabled": False,
            "attacker_target_selection": "adaptive",
        }
        scenarios[f"{name}__planning"] = {
            **base,
            **shared_adaptive,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "adaptive_path_enabled": True,
            "adaptive_planning_enabled": True,
            "trust_enabled": False,
            "attacker_target_selection": "adaptive",
        }
        scenarios[f"{name}__trust"] = {
            **base,
            **shared_adaptive,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "adaptive_path_enabled": True,
            "adaptive_planning_enabled": True,
            "trust_enabled": True,
            "trust_decoy_penalty": 0.20,
            "trust_credential_penalty": 0.30,
            "trust_detection_penalty": 0.15,
            "trust_success_reward": 0.05,
            "attacker_target_selection": "adaptive",
        }

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase3_trust_row(row) for row in stats_rows]
    _add_phase3_trust_deltas(summary_rows)
    summary_rows.sort(key=lambda row: (str(row.get("scenario")), str(row.get("attacker_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase3_trust_rows(summary_rows)
    _write_phase3_trust_summary(summary_rows, analysis, output_dir)
    _plot_phase3_trust_metric(summary_rows, "cognitive_neutralization_score", "Trust-Aware Planning CNS", os.path.join(output_dir, "trust_cns.png"))
    _plot_phase3_trust_metric(summary_rows, "retreat_rate", "Trust-Aware Planning Retreat Rate", os.path.join(output_dir, "trust_retreat_rate.png"))
    _plot_phase3_trust_metric(summary_rows, "trust_collapse_rate", "Trust Collapse Rate", os.path.join(output_dir, "trust_collapse.png"))
    _write_phase3_trust_report(summary_rows, analysis, output_dir)
    return summary_rows


def _build_phase3_trust_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario_name = str(row.get("scenario") or "")
    if scenario_name.endswith("__trust"):
        attacker_mode = "trust_aware_planning"
    elif scenario_name.endswith("__planning"):
        attacker_mode = "adaptive_planning"
    elif scenario_name.endswith("__path"):
        attacker_mode = "adaptive_path_preference"
    elif scenario_name.endswith("__preference"):
        attacker_mode = "adaptive_preference"
    elif scenario_name.endswith("__memory"):
        attacker_mode = "adaptive_memory"
    else:
        attacker_mode = "static"
    base_scenario = (
        scenario_name
        .replace("__static", "")
        .replace("__memory", "")
        .replace("__preference", "")
        .replace("__path", "")
        .replace("__planning", "")
        .replace("__trust", "")
    )
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    critical = _to_float(row.get("critical_protection_score_mean"))
    retreat = _to_float(row.get("retreat_score_mean"))
    effectiveness = float(np.clip(0.5 * cns + 0.3 * critical + 0.2 * retreat, 0.0, 1.0))
    return {
        "scenario": base_scenario,
        "attacker_mode": attacker_mode,
        "num_runs": row.get("num_runs"),
        "policy_effectiveness_score": effectiveness,
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_delta_vs_static": 0.0,
        "cns_delta_vs_memory": 0.0,
        "cns_delta_vs_preference": 0.0,
        "cns_delta_vs_path": 0.0,
        "cns_delta_vs_planning": 0.0,
        "retreat_rate": row.get("retreat_rate"),
        "retreat_score": row.get("retreat_score_mean"),
        "critical_protection_score": row.get("critical_protection_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "post_decoy_compromised_mean": row.get("post_decoy_compromised_mean"),
        "planning_score_mean": row.get("planning_score_mean"),
        "planning_score_max": row.get("planning_score_max_mean"),
        "planned_path": row.get("planned_path"),
        "planned_path_score": row.get("planned_path_score_mean"),
        "planned_path_is_critical_rate": row.get("planned_path_is_critical_rate"),
        "trust_mean": row.get("trust_mean_mean"),
        "trust_min": row.get("trust_min_mean"),
        "trust_max": row.get("trust_max_mean"),
        "trust_collapse_rate": row.get("trust_collapse_rate_mean"),
        "least_trusted_node": row.get("least_trusted_node_mean"),
        "most_trusted_node": row.get("most_trusted_node_mean"),
    }


def _add_phase3_trust_deltas(rows: List[Dict[str, object]]) -> None:
    by_mode: Dict[str, Dict[str, float]] = {}
    for mode in ["static", "adaptive_memory", "adaptive_preference", "adaptive_path_preference", "adaptive_planning"]:
        by_mode[mode] = {
            str(row.get("scenario")): _to_float(row.get("cognitive_neutralization_score"))
            for row in rows
            if row.get("attacker_mode") == mode
        }
    for row in rows:
        scenario = str(row.get("scenario"))
        cns = _to_float(row.get("cognitive_neutralization_score"))
        row["cns_delta_vs_static"] = cns - by_mode["static"].get(scenario, 0.0)
        row["cns_delta_vs_memory"] = cns - by_mode["adaptive_memory"].get(scenario, 0.0)
        row["cns_delta_vs_preference"] = cns - by_mode["adaptive_preference"].get(scenario, 0.0)
        row["cns_delta_vs_path"] = cns - by_mode["adaptive_path_preference"].get(scenario, 0.0)
        row["cns_delta_vs_planning"] = cns - by_mode["adaptive_planning"].get(scenario, 0.0)


def _analyze_phase3_trust_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    trust_rows = [row for row in rows if row.get("attacker_mode") == "trust_aware_planning"]
    planning_rows = [row for row in rows if row.get("attacker_mode") == "adaptive_planning"]
    mean_trust_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in trust_rows])) if trust_rows else 0.0
    mean_planning_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in planning_rows])) if planning_rows else 0.0
    best_trust = max(trust_rows, key=lambda row: _to_float(row.get("policy_effectiveness_score"))) if trust_rows else {}
    frustration = next((row for row in trust_rows if row.get("scenario") == "phase3_trust_frustration_decoy"), {})
    collapse_values = np.asarray([_to_float(row.get("trust_collapse_rate")) for row in trust_rows], dtype=float)
    retreat_values = np.asarray([_to_float(row.get("retreat_rate")) for row in trust_rows], dtype=float)
    if len(collapse_values) > 1 and np.std(collapse_values) > 0.0 and np.std(retreat_values) > 0.0:
        collapse_retreat_corr: Optional[float] = float(np.corrcoef(collapse_values, retreat_values)[0, 1])
    else:
        collapse_retreat_corr = None
    return {
        "mean_planning_cns": mean_planning_cns,
        "mean_trust_cns": mean_trust_cns,
        "mean_cns_delta_trust_vs_planning": mean_trust_cns - mean_planning_cns,
        "mean_cns_reduction_trust_vs_planning": mean_planning_cns - mean_trust_cns,
        "trust_retreat_rate_mean": float(np.mean([_to_float(row.get("retreat_rate")) for row in trust_rows])) if trust_rows else 0.0,
        "planning_retreat_rate_mean": float(np.mean([_to_float(row.get("retreat_rate")) for row in planning_rows])) if planning_rows else 0.0,
        "phase3_frustration_decoy_is_best": frustration.get("scenario") == best_trust.get("scenario"),
        "best_trust_policy": best_trust.get("scenario"),
        "trust_collapse_rate_mean": float(np.mean(collapse_values)) if len(collapse_values) > 0 else 0.0,
        "trust_collapse_occurred": bool(np.any(collapse_values > 0.0)) if len(collapse_values) > 0 else False,
        "trust_collapse_retreat_correlation": collapse_retreat_corr,
        "trust_attacker_stronger_than_planning": mean_trust_cns < mean_planning_cns,
        "path_aware_decoy_effective": (
            _to_float(frustration.get("critical_compromise_rate")) <= 0.0
            and _to_float(frustration.get("retreat_rate")) >= 1.0
        ),
    }


def _write_phase3_trust_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "trust_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE3_TRUST_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "trust_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase3_trust_metric(rows: List[Dict[str, object]], key: str, title: str, save_path: str) -> None:
    if not rows:
        return
    scenarios = list(dict.fromkeys(str(row.get("scenario")) for row in rows))
    modes = ["static", "adaptive_memory", "adaptive_preference", "adaptive_path_preference", "adaptive_planning", "trust_aware_planning"]
    colors = {
        "static": "#4c78a8",
        "adaptive_memory": "#f58518",
        "adaptive_preference": "#59a14f",
        "adaptive_path_preference": "#e45756",
        "adaptive_planning": "#7f3c8d",
        "trust_aware_planning": "#b279a2",
    }
    x = np.arange(len(scenarios))
    width = 0.13
    fig, ax = plt.subplots(figsize=(16, 6))
    for idx, mode in enumerate(modes):
        values = []
        for scenario in scenarios:
            row = next((candidate for candidate in rows if candidate.get("scenario") == scenario and candidate.get("attacker_mode") == mode), {})
            values.append(_to_float(row.get(key)))
        ax.bar(x + (idx - 2.5) * width, values, width=width, color=colors[mode], label=mode)
    labels = [scenario.replace("phase3_trust_", "") for scenario in scenarios]
    ax.set_title(title)
    ax.set_ylabel(key)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase3_trust_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    correlation = analysis.get("trust_collapse_retreat_correlation")
    correlation_text = "undefined" if correlation is None else f"{_to_float(correlation):.3f}"
    lines = [
        "# Phase3 Trust-Aware Planning Attacker Report",
        "",
        "## Questions",
        f"1. Trust-aware attacker CNS reduction vs planning attacker: `{_to_float(analysis.get('mean_cns_reduction_trust_vs_planning')):.3f}` (planning `{_to_float(analysis.get('mean_planning_cns')):.3f}`, trust-aware `{_to_float(analysis.get('mean_trust_cns')):.3f}`).",
        f"2. retreat_rate maintained: trust-aware `{_to_float(analysis.get('trust_retreat_rate_mean')):.3f}` vs planning `{_to_float(analysis.get('planning_retreat_rate_mean')):.3f}`.",
        f"3. phase2_frustration_decoy lineage is still strongest: `{analysis.get('phase3_frustration_decoy_is_best')}`.",
        f"4. trust collapse occurred: `{analysis.get('trust_collapse_occurred')}` (mean collapse rate `{_to_float(analysis.get('trust_collapse_rate_mean')):.3f}`).",
        f"5. trust collapse / retreat correlation: `{correlation_text}`.",
        f"6. Trust-aware attacker stronger than planning attacker: `{analysis.get('trust_attacker_stronger_than_planning')}`.",
        f"7. Path-aware decoy effective against trust-aware attacker: `{analysis.get('path_aware_decoy_effective')}`.",
        "",
        "## Rows",
        "| scenario | mode | CNS | retreat_rate | effectiveness | trust_mean | trust_min | trust_collapse_rate | planned_path |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('scenario')} | {row.get('attacker_mode')} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('retreat_rate')):.3f} | "
            f"{_to_float(row.get('policy_effectiveness_score')):.3f} | "
            f"{_to_float(row.get('trust_mean')):.3f} | "
            f"{_to_float(row.get('trust_min')):.3f} | "
            f"{_to_float(row.get('trust_collapse_rate')):.3f} | "
            f"{row.get('planned_path') or ''} |"
        )
    with open(os.path.join(output_dir, "PHASE3_TRUST_ATTACKER_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE3_EXPECTED_SCENARIO_NAMES = [
    "phase3_expected_reference",
    "phase3_expected_frustration_decoy",
    "phase3_expected_ai_balanced",
    "phase3_expected_gated_count2",
]

PHASE3_EXPECTED_COLUMNS = [
    "scenario",
    "attacker_mode",
    "num_runs",
    "policy_effectiveness_score",
    "cognitive_neutralization_score",
    "cns_delta_vs_static",
    "cns_delta_vs_planning",
    "cns_delta_vs_trust",
    "retreat_rate",
    "retreat_score",
    "critical_protection_score",
    "critical_compromise_rate",
    "planning_score_mean",
    "planning_score_max",
    "trust_mean",
    "trust_min",
    "trust_collapse_rate",
    "expected_utility_final",
    "expected_utility_mean",
    "expected_gain_estimate",
    "expected_detection_risk",
    "expected_search_cost",
    "target_switch_count",
    "planned_path",
    "planned_path_is_critical_rate",
]


def run_phase3_expected_utility_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase3_expected_utility"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for name in PHASE3_EXPECTED_SCENARIO_NAMES:
        base = SCENARIOS[name]
        shared_adaptive = {
            "adaptive_success_weight": 1.0,
            "adaptive_decoy_weight": 2.0,
            "adaptive_detection_weight": 1.5,
            "adaptive_preference_weight": 2.0,
            "adaptive_success_reward": 1.0,
            "adaptive_critical_reward": 3.0,
            "adaptive_decoy_penalty": 2.0,
            "adaptive_detection_penalty": 1.5,
            "path_preference_weight": 3.0,
            "path_success_reward": 1.0,
            "path_critical_reward": 5.0,
            "path_decoy_penalty": 2.0,
            "path_detection_penalty": 1.5,
            "planning_depth": 2,
            "planning_success_weight": 1.0,
            "planning_critical_weight": 5.0,
            "planning_decoy_penalty": 2.0,
            "planning_detection_penalty": 1.5,
        }
        shared_trust = {
            "trust_enabled": True,
            "trust_decoy_penalty": 0.20,
            "trust_credential_penalty": 0.30,
            "trust_detection_penalty": 0.15,
            "trust_success_reward": 0.05,
        }
        scenarios[f"{name}__static"] = {
            **base,
            "adaptive_attacker_enabled": False,
            "adaptive_preference_enabled": False,
            "adaptive_path_enabled": False,
            "adaptive_planning_enabled": False,
            "trust_enabled": False,
            "expected_utility_enabled": False,
            "attacker_target_selection": "greedy",
        }
        scenarios[f"{name}__planning"] = {
            **base,
            **shared_adaptive,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "adaptive_path_enabled": True,
            "adaptive_planning_enabled": True,
            "trust_enabled": False,
            "expected_utility_enabled": False,
            "attacker_target_selection": "adaptive",
        }
        scenarios[f"{name}__trust"] = {
            **base,
            **shared_adaptive,
            **shared_trust,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "adaptive_path_enabled": True,
            "adaptive_planning_enabled": True,
            "expected_utility_enabled": False,
            "attacker_target_selection": "adaptive",
        }
        scenarios[f"{name}__expected"] = {
            **base,
            **shared_adaptive,
            **shared_trust,
            "adaptive_attacker_enabled": True,
            "adaptive_preference_enabled": True,
            "adaptive_path_enabled": True,
            "adaptive_planning_enabled": True,
            "expected_utility_enabled": True,
            "expected_gain_weight": 1.0,
            "expected_success_weight": 1.0,
            "expected_detection_cost": 1.0,
            "expected_search_cost": 1.0,
            "expected_trust_weight": 1.0,
            "attacker_target_selection": "adaptive",
        }

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase3_expected_row(row) for row in stats_rows]
    _add_phase3_expected_deltas(summary_rows)
    summary_rows.sort(key=lambda row: (str(row.get("scenario")), str(row.get("attacker_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase3_expected_rows(summary_rows)
    _write_phase3_expected_summary(summary_rows, analysis, output_dir)
    _plot_phase3_expected_metric(summary_rows, "cognitive_neutralization_score", "Expected Utility Attacker CNS", os.path.join(output_dir, "expected_cns.png"))
    _plot_phase3_expected_metric(summary_rows, "retreat_rate", "Expected Utility Attacker Retreat Rate", os.path.join(output_dir, "expected_retreat_rate.png"))
    _plot_phase3_expected_metric(summary_rows, "target_switch_count", "Expected Utility Target Switch Count", os.path.join(output_dir, "expected_target_switch.png"))
    _write_phase3_expected_report(summary_rows, analysis, output_dir)
    return summary_rows


def _build_phase3_expected_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario_name = str(row.get("scenario") or "")
    if scenario_name.endswith("__expected"):
        attacker_mode = "expected_utility"
    elif scenario_name.endswith("__trust"):
        attacker_mode = "trust_aware_planning"
    elif scenario_name.endswith("__planning"):
        attacker_mode = "adaptive_planning"
    else:
        attacker_mode = "static"
    base_scenario = (
        scenario_name
        .replace("__static", "")
        .replace("__planning", "")
        .replace("__trust", "")
        .replace("__expected", "")
    )
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    critical = _to_float(row.get("critical_protection_score_mean"))
    retreat = _to_float(row.get("retreat_score_mean"))
    effectiveness = float(np.clip(0.5 * cns + 0.3 * critical + 0.2 * retreat, 0.0, 1.0))
    return {
        "scenario": base_scenario,
        "attacker_mode": attacker_mode,
        "num_runs": row.get("num_runs"),
        "policy_effectiveness_score": effectiveness,
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_delta_vs_static": 0.0,
        "cns_delta_vs_planning": 0.0,
        "cns_delta_vs_trust": 0.0,
        "retreat_rate": row.get("retreat_rate"),
        "retreat_score": row.get("retreat_score_mean"),
        "critical_protection_score": row.get("critical_protection_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "planning_score_mean": row.get("planning_score_mean"),
        "planning_score_max": row.get("planning_score_max_mean"),
        "trust_mean": row.get("trust_mean_mean"),
        "trust_min": row.get("trust_min_mean"),
        "trust_collapse_rate": row.get("trust_collapse_rate_mean"),
        "expected_utility_final": row.get("expected_utility_final_mean"),
        "expected_utility_mean": row.get("expected_utility_mean_mean"),
        "expected_gain_estimate": row.get("expected_gain_estimate_mean"),
        "expected_detection_risk": row.get("expected_detection_risk_mean"),
        "expected_search_cost": row.get("expected_search_cost_mean"),
        "target_switch_count": row.get("target_switch_count_mean"),
        "planned_path": row.get("planned_path"),
        "planned_path_is_critical_rate": row.get("planned_path_is_critical_rate"),
    }


def _add_phase3_expected_deltas(rows: List[Dict[str, object]]) -> None:
    by_mode: Dict[str, Dict[str, float]] = {}
    for mode in ["static", "adaptive_planning", "trust_aware_planning"]:
        by_mode[mode] = {
            str(row.get("scenario")): _to_float(row.get("cognitive_neutralization_score"))
            for row in rows
            if row.get("attacker_mode") == mode
        }
    for row in rows:
        scenario = str(row.get("scenario"))
        cns = _to_float(row.get("cognitive_neutralization_score"))
        row["cns_delta_vs_static"] = cns - by_mode["static"].get(scenario, 0.0)
        row["cns_delta_vs_planning"] = cns - by_mode["adaptive_planning"].get(scenario, 0.0)
        row["cns_delta_vs_trust"] = cns - by_mode["trust_aware_planning"].get(scenario, 0.0)


def _analyze_phase3_expected_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    expected_rows = [row for row in rows if row.get("attacker_mode") == "expected_utility"]
    trust_rows = [row for row in rows if row.get("attacker_mode") == "trust_aware_planning"]
    planning_rows = [row for row in rows if row.get("attacker_mode") == "adaptive_planning"]
    mean_expected_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in expected_rows])) if expected_rows else 0.0
    mean_trust_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in trust_rows])) if trust_rows else 0.0
    mean_planning_cns = float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in planning_rows])) if planning_rows else 0.0
    best_expected = max(expected_rows, key=lambda row: _to_float(row.get("policy_effectiveness_score"))) if expected_rows else {}
    frustration = next((row for row in expected_rows if row.get("scenario") == "phase3_expected_frustration_decoy"), {})
    collapse_values = np.asarray([_to_float(row.get("trust_collapse_rate")) for row in expected_rows], dtype=float)
    return {
        "mean_planning_cns": mean_planning_cns,
        "mean_trust_cns": mean_trust_cns,
        "mean_expected_cns": mean_expected_cns,
        "mean_cns_delta_expected_vs_trust": mean_expected_cns - mean_trust_cns,
        "mean_cns_reduction_expected_vs_trust": mean_trust_cns - mean_expected_cns,
        "expected_retreat_rate_mean": float(np.mean([_to_float(row.get("retreat_rate")) for row in expected_rows])) if expected_rows else 0.0,
        "trust_retreat_rate_mean": float(np.mean([_to_float(row.get("retreat_rate")) for row in trust_rows])) if trust_rows else 0.0,
        "phase3_frustration_decoy_is_best": frustration.get("scenario") == best_expected.get("scenario"),
        "best_expected_policy": best_expected.get("scenario"),
        "target_switch_count_mean": float(np.mean([_to_float(row.get("target_switch_count")) for row in expected_rows])) if expected_rows else 0.0,
        "target_switch_occurred": any(_to_float(row.get("target_switch_count")) > 0.0 for row in expected_rows),
        "trust_collapse_rate_mean": float(np.mean(collapse_values)) if len(collapse_values) > 0 else 0.0,
        "trust_collapse_occurred": bool(np.any(collapse_values > 0.0)) if len(collapse_values) > 0 else False,
        "expected_attacker_stronger_than_trust": mean_expected_cns < mean_trust_cns,
        "expected_critical_compromise_rate_mean": float(np.mean([_to_float(row.get("critical_compromise_rate")) for row in expected_rows])) if expected_rows else 0.0,
        "expected_planned_critical_rate_mean": float(np.mean([_to_float(row.get("planned_path_is_critical_rate")) for row in expected_rows])) if expected_rows else 0.0,
    }


def _write_phase3_expected_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "expected_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE3_EXPECTED_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "expected_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase3_expected_metric(rows: List[Dict[str, object]], key: str, title: str, save_path: str) -> None:
    if not rows:
        return
    scenarios = list(dict.fromkeys(str(row.get("scenario")) for row in rows))
    modes = ["static", "adaptive_planning", "trust_aware_planning", "expected_utility"]
    colors = {
        "static": "#4c78a8",
        "adaptive_planning": "#7f3c8d",
        "trust_aware_planning": "#b279a2",
        "expected_utility": "#e45756",
    }
    x = np.arange(len(scenarios))
    width = 0.18
    fig, ax = plt.subplots(figsize=(14, 6))
    for idx, mode in enumerate(modes):
        values = []
        for scenario in scenarios:
            row = next((candidate for candidate in rows if candidate.get("scenario") == scenario and candidate.get("attacker_mode") == mode), {})
            values.append(_to_float(row.get(key)))
        ax.bar(x + (idx - 1.5) * width, values, width=width, color=colors[mode], label=mode)
    labels = [scenario.replace("phase3_expected_", "") for scenario in scenarios]
    ax.set_title(title)
    ax.set_ylabel(key)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase3_expected_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    lines = [
        "# Phase3 Expected Utility Attacker Report",
        "",
        "## Questions",
        f"1. Expected Utility attacker CNS reduction vs Trust-Aware attacker: `{_to_float(analysis.get('mean_cns_reduction_expected_vs_trust')):.3f}` (trust `{_to_float(analysis.get('mean_trust_cns')):.3f}`, expected `{_to_float(analysis.get('mean_expected_cns')):.3f}`).",
        f"2. retreat_rate maintained: expected `{_to_float(analysis.get('expected_retreat_rate_mean')):.3f}` vs trust `{_to_float(analysis.get('trust_retreat_rate_mean')):.3f}`.",
        f"3. phase2_frustration_decoy lineage is still strongest: `{analysis.get('phase3_frustration_decoy_is_best')}`.",
        f"4. target_switch occurred: `{analysis.get('target_switch_occurred')}` (mean switch count `{_to_float(analysis.get('target_switch_count_mean')):.3f}`).",
        f"5. trust collapse remains observable: `{analysis.get('trust_collapse_occurred')}` (mean collapse rate `{_to_float(analysis.get('trust_collapse_rate_mean')):.3f}`).",
        f"6. Expected Utility attacker stronger than Trust-Aware attacker: `{analysis.get('expected_attacker_stronger_than_trust')}`.",
        f"7. Critical asset movement: critical compromise rate `{_to_float(analysis.get('expected_critical_compromise_rate_mean')):.3f}`, planned critical path rate `{_to_float(analysis.get('expected_planned_critical_rate_mean')):.3f}`.",
        "",
        "## Rows",
        "| scenario | mode | CNS | retreat_rate | effectiveness | expected_utility_mean | trust_collapse_rate | target_switch_count | critical_compromise_rate |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('scenario')} | {row.get('attacker_mode')} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('retreat_rate')):.3f} | "
            f"{_to_float(row.get('policy_effectiveness_score')):.3f} | "
            f"{_to_float(row.get('expected_utility_mean')):.3f} | "
            f"{_to_float(row.get('trust_collapse_rate')):.3f} | "
            f"{_to_float(row.get('target_switch_count')):.3f} | "
            f"{_to_float(row.get('critical_compromise_rate')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE3_EXPECTED_UTILITY_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE2_CNS_OBJECTIVE_SCENARIO_NAMES = [
    "phase2_frustration_decoy",
    "phase2_frustration_credential",
    "phase2_ai_balanced",
    "phase2_ai_high_trust_degradation",
    "gated_edge_pressure_count_2",
    "gated_edge_pressure_duration_2",
    "credential_aware_mtd_window5",
]

PHASE2_CNS_OBJECTIVE_COLUMNS = [
    "policy",
    "num_runs",
    "phase1_neutralization_score",
    "cognitive_neutralization_score",
    "cns_objective_score",
    "cns_human_contribution",
    "cns_ai_contribution",
    "cns_protection_contribution",
    "cognitive_human_score",
    "cognitive_ai_score",
    "critical_protection_score",
    "critical_compromise_rate",
    "retreat_rate",
]


def run_phase2_cns_objective_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase2_cns_objective"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios = {name: SCENARIOS[name] for name in PHASE2_CNS_OBJECTIVE_SCENARIO_NAMES}
    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase2_cns_objective_row(row) for row in stats_rows]
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase2_cns_objective(summary_rows)
    sensitivity_rows = _run_phase2_cns_weight_sensitivity(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=output_dir,
        config_path=config_path,
    )
    _write_phase2_cns_objective_summary(summary_rows, analysis, sensitivity_rows, output_dir)
    _plot_cns_objective_ranking(summary_rows, os.path.join(output_dir, "cns_objective_ranking.png"))
    _plot_phase1_vs_cns_vs_objective(summary_rows, os.path.join(output_dir, "phase1_vs_cns_vs_objective.png"))
    _plot_cns_contribution_breakdown(summary_rows, os.path.join(output_dir, "cns_contribution_breakdown.png"))
    _plot_cns_weight_sensitivity(sensitivity_rows, os.path.join(output_dir, "cns_weight_sensitivity.png"))
    _write_phase2_objective_report(summary_rows, analysis, sensitivity_rows, output_dir)
    return summary_rows


def _build_phase2_cns_objective_row(row: Dict[str, object]) -> Dict[str, object]:
    return {
        "policy": row.get("scenario"),
        "num_runs": row.get("num_runs"),
        "phase1_neutralization_score": row.get("neutralization_score_mean"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_objective_score": row.get("cns_objective_score_mean"),
        "cns_human_contribution": row.get("cns_human_contribution_mean"),
        "cns_ai_contribution": row.get("cns_ai_contribution_mean"),
        "cns_protection_contribution": row.get("cns_protection_contribution_mean"),
        "cognitive_human_score": row.get("cognitive_human_score_mean"),
        "cognitive_ai_score": row.get("cognitive_ai_score_mean"),
        "critical_protection_score": row.get("critical_protection_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
    }


def _analyze_phase2_cns_objective(rows: List[Dict[str, object]]) -> Dict[str, object]:
    if not rows:
        return {}
    best_phase1 = max(rows, key=lambda row: _to_float(row.get("phase1_neutralization_score")))
    best_cns = max(rows, key=lambda row: _to_float(row.get("cognitive_neutralization_score")))
    best_objective = max(rows, key=lambda row: _to_float(row.get("cns_objective_score")))
    best_human = max(rows, key=lambda row: _to_float(row.get("cns_human_contribution")))
    best_ai = max(rows, key=lambda row: _to_float(row.get("cns_ai_contribution")))
    protection_best = max(rows, key=lambda row: _to_float(row.get("critical_protection_score")))
    return {
        "best_phase1_policy": best_phase1.get("policy"),
        "best_cns_policy": best_cns.get("policy"),
        "best_cns_objective_policy": best_objective.get("policy"),
        "best_human_contribution_policy": best_human.get("policy"),
        "best_ai_contribution_policy": best_ai.get("policy"),
        "best_protection_policy": protection_best.get("policy"),
        "rankings_match": (
            best_phase1.get("policy") == best_cns.get("policy") == best_objective.get("policy")
        ),
        "dominant_contribution": (
            "human"
            if sum(_to_float(row.get("cns_human_contribution")) for row in rows)
            >= sum(_to_float(row.get("cns_ai_contribution")) for row in rows)
            else "ai"
        ),
        "protection_best_is_objective_best": protection_best.get("policy") == best_objective.get("policy"),
        "recommended_decision_neutralization_policy": best_objective.get("policy"),
    }


def _run_phase2_cns_weight_sensitivity(
    scenarios: Dict[str, Dict[str, object]],
    seeds: Optional[List[int]],
    output_dir: str,
    config_path: str,
) -> List[Dict[str, object]]:
    sensitivity_rows = []
    sensitivity_seeds = list(seeds or MULTI_SEED_VALUES)[:3]
    for human_weight in [0.2, 0.4, 0.6]:
        for ai_weight in [0.2, 0.4, 0.6]:
            protection_weight = max(0.0, 1.0 - human_weight - ai_weight)
            weighted_scenarios = {
                name: {
                    **overrides,
                    "cns_weight_human": human_weight,
                    "cns_weight_ai": ai_weight,
                    "cns_weight_protection": protection_weight,
                }
                for name, overrides in scenarios.items()
            }
            stats_rows = run_scenarios_multi_seed(
                scenarios=weighted_scenarios,
                seeds=sensitivity_seeds,
                output_dir=os.path.join(output_dir, "sensitivity", f"h{human_weight:.1f}_a{ai_weight:.1f}"),
                config_path=config_path,
            )
            rows = [_build_phase2_cns_objective_row(row) for row in stats_rows]
            best = max(rows, key=lambda row: _to_float(row.get("cns_objective_score")))
            sensitivity_rows.append(
                {
                    "human_weight": human_weight,
                    "ai_weight": ai_weight,
                    "protection_weight": protection_weight,
                    "best_policy": best.get("policy"),
                    "best_cns_objective_score": best.get("cns_objective_score"),
                }
            )
    return sensitivity_rows


def _write_phase2_cns_objective_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    sensitivity_rows: List[Dict[str, object]],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "cns_objective_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE2_CNS_OBJECTIVE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "cns_objective_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis, "sensitivity": sensitivity_rows}, f, indent=4, ensure_ascii=False)


def _plot_cns_objective_ranking(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    ranked = sorted(rows, key=lambda row: _to_float(row.get("cns_objective_score")), reverse=True)
    labels = [str(row["policy"]).replace("phase2_", "") for row in ranked]
    values = np.array([_to_float(row.get("cns_objective_score")) for row in ranked], dtype=float)
    plt.figure(figsize=(14, 6))
    plt.bar(labels, values, color="#4c78a8")
    plt.ylim(0.0, 1.0)
    plt.title("Phase2.6 CNS Objective Ranking")
    plt.ylabel("CNS Objective Score")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_phase1_vs_cns_vs_objective(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    labels = [str(row["policy"]).replace("phase2_", "") for row in rows]
    x = np.arange(len(labels))
    width = 0.27
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(x - width, [_to_float(row.get("phase1_neutralization_score")) for row in rows], width=width, label="Phase1")
    ax.bar(x, [_to_float(row.get("cognitive_neutralization_score")) for row in rows], width=width, label="CNS")
    ax.bar(x + width, [_to_float(row.get("cns_objective_score")) for row in rows], width=width, label="CNS objective")
    ax.set_ylim(0.0, 1.0)
    ax.set_ylabel("Score")
    ax.set_title("Phase2.6 Phase1 vs CNS vs CNS Objective")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_cns_contribution_breakdown(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    labels = [str(row["policy"]).replace("phase2_", "") for row in rows]
    human = np.array([_to_float(row.get("cns_human_contribution")) for row in rows], dtype=float)
    ai = np.array([_to_float(row.get("cns_ai_contribution")) for row in rows], dtype=float)
    protection = np.array([_to_float(row.get("cns_protection_contribution")) for row in rows], dtype=float)
    x = np.arange(len(labels))
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(x, human, color="#4c78a8", label="Human")
    ax.bar(x, ai, bottom=human, color="#f58518", label="AI")
    ax.bar(x, protection, bottom=human + ai, color="#59a14f", label="Protection")
    ax.set_ylim(0.0, 1.0)
    ax.set_ylabel("Contribution")
    ax.set_title("Phase2.6 CNS Objective Contribution Breakdown")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_cns_weight_sensitivity(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    human_values = sorted({float(row["human_weight"]) for row in rows})
    ai_values = sorted({float(row["ai_weight"]) for row in rows})
    grid = np.zeros((len(human_values), len(ai_values)), dtype=float)
    for row in rows:
        i = human_values.index(float(row["human_weight"]))
        j = ai_values.index(float(row["ai_weight"]))
        grid[i, j] = _to_float(row.get("best_cns_objective_score"))
    fig, ax = plt.subplots(figsize=(8, 6))
    image = ax.imshow(grid, cmap="viridis", vmin=0.0, vmax=1.0)
    ax.set_xticks(np.arange(len(ai_values)))
    ax.set_xticklabels([f"{value:.1f}" for value in ai_values])
    ax.set_yticks(np.arange(len(human_values)))
    ax.set_yticklabels([f"{value:.1f}" for value in human_values])
    ax.set_xlabel("AI Weight")
    ax.set_ylabel("Human Weight")
    ax.set_title("Phase2.6 CNS Weight Sensitivity")
    for i, human_weight in enumerate(human_values):
        for j, ai_weight in enumerate(ai_values):
            match = next(
                row
                for row in rows
                if float(row["human_weight"]) == human_weight and float(row["ai_weight"]) == ai_weight
            )
            ax.text(j, i, str(match.get("best_policy", "")).replace("phase2_", "")[:10], ha="center", va="center", color="white", fontsize=8)
    fig.colorbar(image, ax=ax, label="Best CNS Objective Score")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase2_objective_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    sensitivity_rows: List[Dict[str, object]],
    output_dir: str,
) -> None:
    human_top = sorted(rows, key=lambda row: _to_float(row.get("cns_human_contribution")), reverse=True)[:3]
    ai_top = sorted(rows, key=lambda row: _to_float(row.get("cns_ai_contribution")), reverse=True)[:3]
    sensitivity_best_counts: Dict[str, int] = {}
    for row in sensitivity_rows:
        policy = str(row.get("best_policy"))
        sensitivity_best_counts[policy] = sensitivity_best_counts.get(policy, 0) + 1
    stable_best = max(sensitivity_best_counts, key=sensitivity_best_counts.get) if sensitivity_best_counts else None
    lines = [
        "# Phase2.6 CNS Driven Defense Objective",
        "",
        "## Definition",
        "cns_objective_score = clip(cns_weight_human * cognitive_human_score + cns_weight_ai * cognitive_ai_score + cns_weight_protection * critical_protection_score, 0, 1).",
        "",
        "## Best Policies",
        f"- Phase1 Best: `{analysis.get('best_phase1_policy')}`",
        f"- CNS Best: `{analysis.get('best_cns_policy')}`",
        f"- CNS Objective Best: `{analysis.get('best_cns_objective_policy')}`",
        f"- Decision Neutralization Policy: `{analysis.get('recommended_decision_neutralization_policy')}`",
        "",
        "## Questions",
        f"- Q1 rankings all match: `{analysis.get('rankings_match')}`",
        f"- Q2 dominant contribution: `{analysis.get('dominant_contribution')}`",
        f"- Q3 protection best is objective best: `{analysis.get('protection_best_is_objective_best')}`",
        f"- Q4 recommended policy: `{analysis.get('recommended_decision_neutralization_policy')}`",
        "",
        "## Human Contribution Top 3",
        *[f"- `{row.get('policy')}`: {_to_float(row.get('cns_human_contribution')):.3f}" for row in human_top],
        "",
        "## AI Contribution Top 3",
        *[f"- `{row.get('policy')}`: {_to_float(row.get('cns_ai_contribution')):.3f}" for row in ai_top],
        "",
        "## Sensitivity",
        f"- Most frequent best policy across sweep: `{stable_best}` ({sensitivity_best_counts.get(stable_best, 0) if stable_best else 0}/{len(sensitivity_rows)})",
    ]
    with open(os.path.join(output_dir, "PHASE2_OBJECTIVE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _plot_visible_log_multiseed_summary(rows: List[Dict[str, object]], save_path: str) -> None:
    modes = {"target_frequency", "selection_score", "defender_visible_log", "hybrid_visible"}
    filtered = [
        row
        for row in rows
        if row.get("defender_belief_observation_mode") in modes
        and row.get("post_decoy_defense_belief_source") == "estimated"
    ]
    if not filtered:
        return
    labels = [str(row["scenario"]).replace("adaptive_decoy_defense_estimated_belief_", "") for row in filtered]
    means = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("post_decoy_compromised_std") or 0.0) for row in filtered])
    errors = np.array([float(row.get("defender_estimation_error_l1_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4

    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.bar(x - width / 2, means, width=width, yerr=stds, capsize=4, color="#59a14f", label="Post-decoy compromised mean")
    ax1.set_ylabel("Post-Decoy Compromised Value Mean")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, errors, width=width, color="#e45756", label="Estimation error L1 mean")
    ax2.set_ylabel("Defender Estimation Error L1 Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Visible Log Belief Estimation Mean +/- Std")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_mtd_multiseed_summary(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = [row for row in rows if str(row.get("scenario", "")).startswith("mtd_")]
    if not filtered:
        return
    labels = [str(row["scenario"]).replace("mtd_", "") for row in filtered]
    means = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("post_decoy_compromised_std") or 0.0) for row in filtered])
    costs = np.array([float(row.get("mtd_total_cost_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.bar(x - width / 2, means, width=width, yerr=stds, capsize=4, color="#59a14f", label="Post-decoy compromised")
    ax1.set_ylabel("Post-Decoy Compromised Value Mean")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, costs, width=width, color="#e45756", label="MTD cost")
    ax2.set_ylabel("MTD Total Cost Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("MTD Effect Mean +/- Std")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _mtd_sweep_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    return [row for row in rows if str(row.get("scenario", "")).startswith("mtd_sweep_")]


def _plot_mtd_sweep_compromised(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _mtd_sweep_rows(rows)
    if not filtered:
        return
    labels = [str(row["scenario"]).replace("mtd_sweep_", "") for row in filtered]
    means = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("post_decoy_compromised_std") or 0.0) for row in filtered])

    plt.figure(figsize=(14, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#4c78a8")
    plt.title("MTD Sweep Post-Decoy Compromised Mean +/- Std")
    plt.ylabel("Post-Decoy Compromised Value Mean")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_mtd_sweep_cost_adjusted(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _mtd_sweep_rows(rows)
    if not filtered:
        return
    labels = [str(row["scenario"]).replace("mtd_sweep_", "") for row in filtered]
    deltas = np.array([float(row.get("mtd_cost_adjusted_delta") or 0.0) for row in filtered])
    colors = ["#59a14f" if value < 0 else "#e45756" for value in deltas]

    plt.figure(figsize=(14, 6))
    plt.axhline(0.0, color="#333333", linewidth=1)
    plt.bar(labels, deltas, color=colors)
    plt.title("MTD Sweep Cost-Adjusted Delta vs Reference")
    plt.ylabel("Compromised Delta + MTD Cost Mean")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_mtd_estimator_compatibility(rows: List[Dict[str, object]], save_path: str) -> None:
    wanted = {"mtd_sweep_target_frequency", "mtd_sweep_visible_log", "mtd_sweep_hybrid_visible"}
    filtered = [row for row in rows if row.get("scenario") in wanted]
    if not filtered:
        return
    labels = [str(row.get("defender_belief_observation_mode")) for row in filtered]
    compromised = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    errors = np.array([float(row.get("defender_estimation_error_l1_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4

    fig, ax1 = plt.subplots(figsize=(10, 6))
    ax1.bar(x - width / 2, compromised, width=width, color="#4c78a8", label="Post-decoy compromised mean")
    ax1.set_ylabel("Post-Decoy Compromised Value Mean")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, errors, width=width, color="#f58518", label="Estimation error L1 mean")
    ax2.set_ylabel("Defender Estimation Error L1 Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=20, ha="right")
    ax1.set_title("MTD Estimator Compatibility")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _lateral_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    return [row for row in rows if str(row.get("scenario", "")).startswith("lateral_")]


def _plot_lateral_compromise_rate(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _lateral_rows(rows)
    if not filtered:
        return
    labels = [str(row["scenario"]).replace("lateral_", "") for row in filtered]
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    plt.figure(figsize=(10, 6))
    plt.bar(labels, rates, color="#4c78a8")
    plt.ylim(0.0, 1.0)
    plt.title("Lateral Movement Critical Compromise Rate")
    plt.ylabel("Critical Compromise Rate")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_lateral_compromise_step(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _lateral_rows(rows)
    if not filtered:
        return
    labels = [str(row["scenario"]).replace("lateral_", "") for row in filtered]
    means = np.array([float(row.get("critical_compromise_step_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("critical_compromise_step_std") or 0.0) for row in filtered])
    plt.figure(figsize=(10, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#59a14f")
    plt.title("Lateral Movement Critical Compromise Step")
    plt.ylabel("Critical Compromise Step Mean")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _path_aware_lateral_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    wanted = {
        "lateral_baseline",
        "lateral_decoy",
        "lateral_decoy_on_chokepoint",
        "lateral_decoy_on_server_path",
        "lateral_multi_decoy_path",
        "lateral_edge_mtd_chokepoint",
        "lateral_edge_mtd_interval5",
        "lateral_path_decoy_edge_mtd",
    }
    return [row for row in rows if row.get("scenario") in wanted]


def _plot_lateral_path_aware_compromise_rate(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _path_aware_lateral_rows(rows)
    if not filtered:
        return
    labels = [str(row["scenario"]).replace("lateral_", "") for row in filtered]
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    colors = ["#e45756" if not bool(row.get("decoy_on_critical_path")) else "#4c78a8" for row in filtered]
    plt.figure(figsize=(12, 6))
    plt.bar(labels, rates, color=colors)
    plt.ylim(0.0, 1.0)
    plt.title("Path-Aware Lateral Critical Compromise Rate")
    plt.ylabel("Critical Compromise Rate")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_lateral_path_aware_step(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _path_aware_lateral_rows(rows)
    if not filtered:
        return
    labels = [str(row["scenario"]).replace("lateral_", "") for row in filtered]
    means = np.array([float(row.get("critical_compromise_step_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("critical_compromise_step_std") or 0.0) for row in filtered])
    plt.figure(figsize=(12, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#59a14f")
    plt.title("Path-Aware Lateral Critical Compromise Step")
    plt.ylabel("Critical Compromise Step Mean")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_lateral_edge_mtd(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _path_aware_lateral_rows(rows)
    if not filtered:
        return
    labels = [str(row["scenario"]).replace("lateral_", "") for row in filtered]
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    events = np.array([float(row.get("mtd_edge_block_events_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.bar(x - width / 2, rates, width=width, color="#4c78a8", label="Critical compromise rate")
    ax1.set_ylim(0.0, 1.0)
    ax1.set_ylabel("Critical Compromise Rate")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, events, width=width, color="#f58518", label="Edge block events")
    ax2.set_ylabel("MTD Edge Block Events Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Lateral Edge MTD Comparison")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _bayesian_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    return [row for row in rows if str(row.get("scenario", "")).startswith("bayesian_")]


def _plot_bayesian_compromise_rate(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _bayesian_rows(rows)
    if not filtered:
        return
    labels = [str(row["scenario"]).replace("bayesian_", "") for row in filtered]
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    plt.figure(figsize=(12, 6))
    plt.bar(labels, rates, color="#4c78a8")
    plt.ylim(0.0, 1.0)
    plt.title("Bayesian Defender Critical Compromise Rate")
    plt.ylabel("Critical Compromise Rate")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_bayesian_post_decoy_compromised(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _bayesian_rows(rows)
    if not filtered:
        return
    labels = [str(row["scenario"]).replace("bayesian_", "") for row in filtered]
    means = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("post_decoy_compromised_std") or 0.0) for row in filtered])
    plt.figure(figsize=(12, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#59a14f")
    plt.title("Bayesian Defender Post-Decoy Compromised Value")
    plt.ylabel("Post-Decoy Compromised Mean")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_bayesian_error(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _bayesian_rows(rows)
    if not filtered:
        return
    labels = [str(row["scenario"]).replace("bayesian_", "") for row in filtered]
    bayes = np.array([float(row.get("defender_bayesian_error_l1_mean") or 0.0) for row in filtered])
    estimated = np.array([float(row.get("defender_estimation_error_l1_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    plt.figure(figsize=(12, 6))
    plt.bar(x - width / 2, bayes, width=width, color="#4c78a8", label="Bayesian error L1")
    plt.bar(x + width / 2, estimated, width=width, color="#f58518", label="Estimated error L1")
    plt.title("Bayesian Defender Belief Error")
    plt.ylabel("Error L1 Mean")
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _bayesian_sweep_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    comparison = {
        "bayesian_vs_target_frequency_reference",
        "bayesian_lateral_path_decoy",
        "bayesian_lateral_path_decoy_edge_mtd",
    }
    return [
        row
        for row in rows
        if row.get("scenario") in comparison or str(row.get("scenario", "")).startswith("bayesian_sweep_")
    ]


def _bayesian_sweep_labels(rows: List[Dict[str, object]]) -> List[str]:
    return [
        str(row["scenario"])
        .replace("bayesian_sweep_", "")
        .replace("bayesian_", "")
        for row in rows
    ]


def _plot_bayesian_sweep_compromise_rate(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _bayesian_sweep_rows(rows)
    if not filtered:
        return
    labels = _bayesian_sweep_labels(filtered)
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    plt.figure(figsize=(14, 6))
    plt.bar(labels, rates, color="#4c78a8")
    plt.ylim(0.0, 1.0)
    plt.title("Bayesian Sweep Critical Compromise Rate")
    plt.ylabel("Critical Compromise Rate")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_bayesian_sweep_post_decoy(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _bayesian_sweep_rows(rows)
    if not filtered:
        return
    labels = _bayesian_sweep_labels(filtered)
    means = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("post_decoy_compromised_std") or 0.0) for row in filtered])
    plt.figure(figsize=(14, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#59a14f")
    plt.title("Bayesian Sweep Post-Decoy Compromised")
    plt.ylabel("Post-Decoy Compromised Mean")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_bayesian_sweep_error(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _bayesian_sweep_rows(rows)
    if not filtered:
        return
    labels = _bayesian_sweep_labels(filtered)
    errors = np.array([float(row.get("defender_bayesian_error_l1_mean") or 0.0) for row in filtered])
    plt.figure(figsize=(14, 6))
    plt.bar(labels, errors, color="#f58518")
    plt.title("Bayesian Sweep Belief Error")
    plt.ylabel("Bayesian Error L1 Mean")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_bayesian_vs_target_frequency_delta(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = [
        row
        for row in _bayesian_sweep_rows(rows)
        if row.get("scenario") != "bayesian_vs_target_frequency_reference"
    ]
    if not filtered:
        return
    labels = _bayesian_sweep_labels(filtered)
    compromise = np.array([float(row.get("bayesian_compromise_delta_vs_target_frequency") or 0.0) for row in filtered])
    post_decoy = np.array([float(row.get("bayesian_post_decoy_delta_vs_target_frequency") or 0.0) for row in filtered])
    error = np.array([float(row.get("bayesian_error_delta_vs_target_frequency") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.25
    plt.figure(figsize=(14, 6))
    plt.axhline(0.0, color="#333333", linewidth=1)
    plt.bar(x - width, compromise, width=width, color="#4c78a8", label="Compromise delta")
    plt.bar(x, post_decoy, width=width, color="#59a14f", label="Post-decoy delta")
    plt.bar(x + width, error, width=width, color="#f58518", label="Bayesian error delta")
    plt.title("Bayesian Delta vs Target Frequency")
    plt.ylabel("Delta vs Target Frequency")
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _defense_objective_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    wanted = {
        "bayesian_vs_target_frequency_reference",
        "bayesian_lateral_path_decoy",
        "bayesian_lateral_path_decoy_edge_mtd",
        "bayesian_defense_objective_default",
        "bayesian_defense_objective_high_critical_weight",
        "bayesian_defense_objective_high_delay_reward",
        "bayesian_defense_objective_low_post_decoy_weight",
        "bayesian_defense_objective_edge_mtd",
    }
    return [row for row in rows if row.get("scenario") in wanted]


def _defense_objective_labels(rows: List[Dict[str, object]]) -> List[str]:
    return [
        str(row["scenario"])
        .replace("bayesian_defense_objective_", "")
        .replace("bayesian_", "")
        for row in rows
    ]


def _plot_defense_objective_score(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _defense_objective_rows(rows)
    if not filtered:
        return
    labels = _defense_objective_labels(filtered)
    means = np.array([float(row.get("defense_objective_score_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("defense_objective_score_std") or 0.0) for row in filtered])
    plt.figure(figsize=(14, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#4c78a8")
    plt.title("Defense Objective Score")
    plt.ylabel("Score Mean (Lower is Better)")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_defense_objective_tradeoff(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _defense_objective_rows(rows)
    if not filtered:
        return
    labels = _defense_objective_labels(filtered)
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    post_decoy = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(14, 6))
    ax1.bar(x - width / 2, rates, width=width, color="#e45756", label="Critical compromise rate")
    ax1.set_ylim(0.0, 1.0)
    ax1.set_ylabel("Critical Compromise Rate")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, post_decoy, width=width, color="#59a14f", label="Post-decoy compromised")
    ax2.set_ylabel("Post-Decoy Compromised Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Defense Objective Trade-off")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _policy_selection_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    return [row for row in rows if row.get("scenario") in POLICY_SELECTION_SCENARIO_NAMES]


def _policy_selection_labels(rows: List[Dict[str, object]]) -> List[str]:
    return [str(row["scenario"]).replace("policy_", "") for row in rows]


def _plot_policy_selection_objective(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _policy_selection_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _policy_selection_labels(filtered)
    means = np.array([float(row.get("defense_objective_score_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("defense_objective_score_std") or 0.0) for row in filtered])
    plt.figure(figsize=(14, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#4c78a8")
    plt.title("Policy Selection Defense Objective Score")
    plt.ylabel("Score Mean (Lower is Better)")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_policy_selection_tradeoff(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _policy_selection_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _policy_selection_labels(filtered)
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    post_decoy = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(14, 6))
    ax1.bar(x - width / 2, rates, width=width, color="#e45756", label="Critical compromise rate")
    ax1.set_ylim(0.0, 1.0)
    ax1.set_ylabel("Critical Compromise Rate")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, post_decoy, width=width, color="#59a14f", label="Post-decoy compromised")
    ax2.set_ylabel("Post-Decoy Compromised Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Policy Selection Trade-off")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _gated_mtd_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    return [row for row in rows if str(row.get("scenario", "")).startswith("policy_gated_edge_mtd_")]


def _gated_mtd_labels(rows: List[Dict[str, object]]) -> List[str]:
    return [str(row["scenario"]).replace("policy_gated_edge_mtd_", "") for row in rows]


def _plot_gated_mtd_objective(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _gated_mtd_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _gated_mtd_labels(filtered)
    means = np.array([float(row.get("defense_objective_score_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("defense_objective_score_std") or 0.0) for row in filtered])
    plt.figure(figsize=(12, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#4c78a8")
    plt.title("Gated Edge MTD Defense Objective")
    plt.ylabel("Score Mean (Lower is Better)")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_gated_mtd_tradeoff(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _gated_mtd_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _gated_mtd_labels(filtered)
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    post_decoy = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.bar(x - width / 2, rates, width=width, color="#e45756", label="Critical compromise rate")
    ax1.set_ylim(0.0, 1.0)
    ax1.set_ylabel("Critical Compromise Rate")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, post_decoy, width=width, color="#59a14f", label="Post-decoy compromised")
    ax2.set_ylabel("Post-Decoy Compromised Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Gated Edge MTD Trade-off")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_gated_mtd_fire_count(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _gated_mtd_rows(rows)
    if not filtered:
        return
    labels = _gated_mtd_labels(filtered)
    fires = np.array([float(row.get("mtd_risk_gate_fire_count_mean") or 0.0) for row in filtered])
    suppressed = np.array([float(row.get("mtd_risk_gate_suppressed_count_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    plt.figure(figsize=(12, 6))
    plt.bar(x - width / 2, fires, width=width, color="#4c78a8", label="Fired")
    plt.bar(x + width / 2, suppressed, width=width, color="#f58518", label="Suppressed")
    plt.title("Gated Edge MTD Fire/Suppression Count")
    plt.ylabel("Mean Count")
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _gated_mtd_sweep_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    wanted = set(GATED_EDGE_PRESSURE_SWEEP_SCENARIO_NAMES) | {"policy_gated_edge_mtd_edge_pressure"}
    return [row for row in rows if row.get("scenario") in wanted]


def _gated_mtd_sweep_labels(rows: List[Dict[str, object]]) -> List[str]:
    return [
        str(row["scenario"])
        .replace("policy_gated_edge_mtd_", "policy_")
        .replace("gated_edge_pressure_", "")
        for row in rows
    ]


def _reference_policy_values(rows: List[Dict[str, object]]) -> tuple:
    reference = next((row for row in rows if row.get("scenario") == "policy_target_frequency_path_decoy"), None)
    if reference is None:
        return 0.0, 0.0
    return (
        _to_float(reference.get("post_decoy_compromised_mean")),
        _to_float(reference.get("critical_compromise_rate")),
    )


def _plot_gated_mtd_sweep_objective(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _gated_mtd_sweep_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _gated_mtd_sweep_labels(filtered)
    means = np.array([float(row.get("defense_objective_score_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("defense_objective_score_std") or 0.0) for row in filtered])
    plt.figure(figsize=(14, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#4c78a8")
    plt.title("Gated Edge Pressure Sweep Objective")
    plt.ylabel("Score Mean (Lower is Better)")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_gated_mtd_sweep_cost_effectiveness(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _gated_mtd_sweep_rows(rows)
    if not filtered:
        return
    reference_post_decoy, _ = _reference_policy_values(rows)
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _gated_mtd_sweep_labels(filtered)
    costs = []
    for row in filtered:
        reduction = reference_post_decoy - _to_float(row.get("post_decoy_compromised_mean"))
        costs.append(_to_float(row.get("mtd_total_cost_mean")) / max(reduction, 1e-6))
    plt.figure(figsize=(14, 6))
    plt.bar(labels, np.array(costs, dtype=float), color="#f58518")
    plt.title("Gated Edge Pressure Cost per Post-Decoy Reduction")
    plt.ylabel("MTD Cost / Reduction")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_gated_mtd_threshold_tradeoff(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _gated_mtd_sweep_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _gated_mtd_sweep_labels(filtered)
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    post_decoy = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(14, 6))
    ax1.bar(x - width / 2, rates, width=width, color="#e45756", label="Critical compromise rate")
    ax1.set_ylim(0.0, 1.0)
    ax1.set_ylabel("Critical Compromise Rate")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, post_decoy, width=width, color="#59a14f", label="Post-decoy compromised")
    ax2.set_ylabel("Post-Decoy Compromised Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Gated Edge Pressure Sweep Trade-off")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _gated_mtd_hybrid_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    wanted = set(GATED_EDGE_PRESSURE_HYBRID_SCENARIO_NAMES)
    return [row for row in rows if row.get("scenario") in wanted]


def _gated_mtd_hybrid_labels(rows: List[Dict[str, object]]) -> List[str]:
    return [str(row["scenario"]).replace("gated_edge_pressure_", "") for row in rows]


def _plot_gated_mtd_hybrid_objective(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _gated_mtd_hybrid_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _gated_mtd_hybrid_labels(filtered)
    means = np.array([float(row.get("defense_objective_score_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("defense_objective_score_std") or 0.0) for row in filtered])
    plt.figure(figsize=(14, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#4c78a8")
    plt.title("Hybrid Gated Edge MTD Objective")
    plt.ylabel("Score Mean (Lower is Better)")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_gated_mtd_hybrid_tradeoff(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _gated_mtd_hybrid_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _gated_mtd_hybrid_labels(filtered)
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    post_decoy = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(14, 6))
    ax1.bar(x - width / 2, rates, width=width, color="#e45756", label="Critical compromise rate")
    ax1.set_ylim(0.0, 1.0)
    ax1.set_ylabel("Critical Compromise Rate")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, post_decoy, width=width, color="#59a14f", label="Post-decoy compromised")
    ax2.set_ylabel("Post-Decoy Compromised Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Hybrid Gated Edge MTD Trade-off")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_gated_mtd_hybrid_cost_effectiveness(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _gated_mtd_hybrid_rows(rows)
    if not filtered:
        return
    reference_post_decoy, _ = _reference_policy_values(rows)
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _gated_mtd_hybrid_labels(filtered)
    costs = []
    for row in filtered:
        reduction = reference_post_decoy - _to_float(row.get("post_decoy_compromised_mean"))
        costs.append(_to_float(row.get("mtd_total_cost_mean")) / max(reduction, 1e-6))
    plt.figure(figsize=(14, 6))
    plt.bar(labels, np.array(costs, dtype=float), color="#f58518")
    plt.title("Hybrid Gated Edge MTD Cost per Post-Decoy Reduction")
    plt.ylabel("MTD Cost / Reduction")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _conditional_mtd_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    wanted = set(CONDITIONAL_MTD_SCENARIO_NAMES)
    return [row for row in rows if row.get("scenario") in wanted]


def _conditional_mtd_labels(rows: List[Dict[str, object]]) -> List[str]:
    return [str(row["scenario"]).replace("gated_edge_conditional_", "") for row in rows]


def _plot_conditional_mtd_objective(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _conditional_mtd_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _conditional_mtd_labels(filtered)
    means = np.array([float(row.get("defense_objective_score_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("defense_objective_score_std") or 0.0) for row in filtered])
    plt.figure(figsize=(12, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#4c78a8")
    plt.title("Conditional Gated MTD Objective")
    plt.ylabel("Score Mean (Lower is Better)")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_conditional_mtd_tradeoff(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _conditional_mtd_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _conditional_mtd_labels(filtered)
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    post_decoy = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.bar(x - width / 2, rates, width=width, color="#e45756", label="Critical compromise rate")
    ax1.set_ylim(0.0, 1.0)
    ax1.set_ylabel("Critical Compromise Rate")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, post_decoy, width=width, color="#59a14f", label="Post-decoy compromised")
    ax2.set_ylabel("Post-Decoy Compromised Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Conditional Gated MTD Trade-off")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_conditional_mtd_actions(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _conditional_mtd_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _conditional_mtd_labels(filtered)
    count2 = np.array([float(row.get("mtd_conditional_count2_action_count_mean") or 0.0) for row in filtered])
    duration2 = np.array([float(row.get("mtd_conditional_duration2_action_count_mean") or 0.0) for row in filtered])
    suppress = np.array([float(row.get("mtd_conditional_suppress_count_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.25
    plt.figure(figsize=(12, 6))
    plt.bar(x - width, count2, width=width, color="#4c78a8", label="count2")
    plt.bar(x, duration2, width=width, color="#59a14f", label="duration2")
    plt.bar(x + width, suppress, width=width, color="#f58518", label="suppress")
    plt.title("Conditional Gated MTD Action Counts")
    plt.ylabel("Mean Count")
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _honeypot_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    wanted = set(HONEYPOT_CREDENTIAL_SCENARIO_NAMES)
    return [row for row in rows if row.get("scenario") in wanted]


def _honeypot_labels(rows: List[Dict[str, object]]) -> List[str]:
    return [str(row["scenario"]).replace("honeypot_credential_", "") for row in rows]


def _plot_honeypot_objective(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _honeypot_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _honeypot_labels(filtered)
    means = np.array([float(row.get("defense_objective_score_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("defense_objective_score_std") or 0.0) for row in filtered])
    plt.figure(figsize=(12, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#4c78a8")
    plt.title("Honeypot Credential Defense Objective")
    plt.ylabel("Score Mean (Lower is Better)")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_honeypot_tradeoff(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _honeypot_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _honeypot_labels(filtered)
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    post_decoy = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.bar(x - width / 2, rates, width=width, color="#e45756", label="Critical compromise rate")
    ax1.set_ylim(0.0, 1.0)
    ax1.set_ylabel("Critical Compromise Rate")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, post_decoy, width=width, color="#59a14f", label="Post-decoy compromised")
    ax2.set_ylabel("Post-Decoy Compromised Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Honeypot Credential Trade-off")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_honeypot_trigger_rate(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _honeypot_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _honeypot_labels(filtered)
    trigger_rates = np.array([float(row.get("credential_trigger_rate_mean") or 0.0) for row in filtered])
    triggers = np.array([float(row.get("credential_decoy_trigger_count_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.bar(x - width / 2, trigger_rates, width=width, color="#4c78a8", label="Trigger rate")
    ax1.set_ylim(0.0, 1.0)
    ax1.set_ylabel("Credential Trigger Rate")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, triggers, width=width, color="#f58518", label="Trigger count")
    ax2.set_ylabel("Credential Trigger Count Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Honeypot Credential Trigger Rate")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _credential_aware_mtd_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    wanted = set(CREDENTIAL_AWARE_MTD_SCENARIO_NAMES)
    return [row for row in rows if row.get("scenario") in wanted]


def _credential_aware_mtd_labels(rows: List[Dict[str, object]]) -> List[str]:
    return [str(row["scenario"]).replace("credential_aware_mtd_", "") for row in rows]


def _plot_credential_aware_mtd_objective(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _credential_aware_mtd_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _credential_aware_mtd_labels(filtered)
    means = np.array([float(row.get("defense_objective_score_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("defense_objective_score_std") or 0.0) for row in filtered])
    plt.figure(figsize=(12, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#4c78a8")
    plt.title("Credential-Aware MTD Defense Objective")
    plt.ylabel("Score Mean (Lower is Better)")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_credential_aware_mtd_tradeoff(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _credential_aware_mtd_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _credential_aware_mtd_labels(filtered)
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    post_decoy = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.bar(x - width / 2, rates, width=width, color="#e45756", label="Critical compromise rate")
    ax1.set_ylim(0.0, 1.0)
    ax1.set_ylabel("Critical Compromise Rate")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, post_decoy, width=width, color="#59a14f", label="Post-decoy compromised")
    ax2.set_ylabel("Post-Decoy Compromised Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Credential-Aware MTD Trade-off")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_credential_aware_mtd_events(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _credential_aware_mtd_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _credential_aware_mtd_labels(filtered)
    credential_events = np.array([float(row.get("credential_trigger_mtd_event_count_mean") or 0.0) for row in filtered])
    total_events = np.array([float(row.get("mtd_event_count_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    plt.figure(figsize=(12, 6))
    plt.bar(x - width / 2, credential_events, width=width, color="#4c78a8", label="Credential-aware MTD")
    plt.bar(x + width / 2, total_events, width=width, color="#f58518", label="Total MTD")
    plt.title("Credential-Aware MTD Events")
    plt.ylabel("Mean Event Count")
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _credential_staged_mtd_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    wanted = set(CREDENTIAL_STAGED_MTD_SCENARIO_NAMES)
    return [row for row in rows if row.get("scenario") in wanted]


def _credential_staged_mtd_labels(rows: List[Dict[str, object]]) -> List[str]:
    return [str(row["scenario"]).replace("credential_staged_mtd_", "") for row in rows]


def _plot_credential_staged_mtd_objective(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _credential_staged_mtd_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _credential_staged_mtd_labels(filtered)
    means = np.array([float(row.get("defense_objective_score_mean") or 0.0) for row in filtered])
    stds = np.array([float(row.get("defense_objective_score_std") or 0.0) for row in filtered])
    plt.figure(figsize=(12, 6))
    plt.bar(labels, means, yerr=stds, capsize=4, color="#4c78a8")
    plt.title("Staged Credential-Aware MTD Defense Objective")
    plt.ylabel("Score Mean (Lower is Better)")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


def _plot_credential_staged_mtd_tradeoff(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _credential_staged_mtd_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _credential_staged_mtd_labels(filtered)
    rates = np.array([float(row.get("critical_compromise_rate") or 0.0) for row in filtered])
    post_decoy = np.array([float(row.get("post_decoy_compromised_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.4
    fig, ax1 = plt.subplots(figsize=(12, 6))
    ax1.bar(x - width / 2, rates, width=width, color="#e45756", label="Critical compromise rate")
    ax1.set_ylim(0.0, 1.0)
    ax1.set_ylabel("Critical Compromise Rate")
    ax2 = ax1.twinx()
    ax2.bar(x + width / 2, post_decoy, width=width, color="#59a14f", label="Post-decoy compromised")
    ax2.set_ylabel("Post-Decoy Compromised Mean")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=30, ha="right")
    ax1.set_title("Staged Credential-Aware MTD Trade-off")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_credential_staged_mtd_actions(rows: List[Dict[str, object]], save_path: str) -> None:
    filtered = _credential_staged_mtd_rows(rows)
    if not filtered:
        return
    filtered = sorted(filtered, key=lambda row: _to_float(row.get("defense_objective_score_mean")))
    labels = _credential_staged_mtd_labels(filtered)
    stage1 = np.array([float(row.get("credential_stage1_action_count_mean") or 0.0) for row in filtered])
    stage2 = np.array([float(row.get("credential_stage2_action_count_mean") or 0.0) for row in filtered])
    none = np.array([float(row.get("credential_stage_none_count_mean") or 0.0) for row in filtered])
    x = np.arange(len(labels))
    width = 0.25
    plt.figure(figsize=(12, 6))
    plt.bar(x - width, stage1, width=width, color="#4c78a8", label="stage1")
    plt.bar(x, stage2, width=width, color="#59a14f", label="stage2")
    plt.bar(x + width, none, width=width, color="#f58518", label="none")
    plt.title("Staged Credential-Aware MTD Actions")
    plt.ylabel("Mean Count")
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()


if __name__ == "__main__":
    rows = run_scenarios()
    print(f"Completed {len(rows)} scenarios. Summary written to output/scenarios.")
    if RUN_MULTI_SEED:
        stats = run_scenarios_multi_seed(seeds=MULTI_SEED_VALUES)
        print(f"Completed multi-seed evaluation for {len(stats)} scenarios. Summary written to output/scenarios_multiseed.")
        ai_cost_rows = run_phase2_ai_cost_evaluation(seeds=MULTI_SEED_VALUES)
        print(f"Completed Phase2.3 AI cost evaluation for {len(ai_cost_rows)} scenarios. Summary written to output/phase2_ai_cost.")
        ai_weight_rows = run_phase2_ai_weight_sweep_evaluation(seeds=MULTI_SEED_VALUES)
        print(f"Completed Phase2.3 AI weight sweep for {len(ai_weight_rows)} scenarios. Summary written to output/phase2_ai_weight_sweep.")
        cognitive_rows = run_phase2_cognitive_neutralization_evaluation(seeds=MULTI_SEED_VALUES)
        print(f"Completed Phase2.4 cognitive neutralization for {len(cognitive_rows)} scenarios. Summary written to output/phase2_cognitive_neutralization.")
        policy_rows = run_phase2_policy_selection_evaluation(seeds=MULTI_SEED_VALUES)
        print(f"Completed Phase2.5 CNS-driven policy selection for {len(policy_rows)} policies. Summary written to output/phase2_policy_selection.")
        objective_rows = run_phase2_cns_objective_evaluation(seeds=MULTI_SEED_VALUES)
        print(f"Completed Phase2.6 CNS objective evaluation for {len(objective_rows)} policies. Summary written to output/phase2_cns_objective.")
        adaptive_rows = run_phase3_adaptive_attacker_evaluation(seeds=MULTI_SEED_VALUES)
        print(f"Completed Phase3.1 adaptive attacker evaluation for {len(adaptive_rows)} rows. Summary written to output/phase3_adaptive_attacker.")
        preference_rows = run_phase3_preference_attacker_evaluation(seeds=MULTI_SEED_VALUES)
        print(f"Completed Phase3.2 preference attacker evaluation for {len(preference_rows)} rows. Summary written to output/phase3_preference_attacker.")
        path_rows = run_phase3_path_attacker_evaluation(seeds=MULTI_SEED_VALUES)
        print(f"Completed Phase3.3 path preference attacker evaluation for {len(path_rows)} rows. Summary written to output/phase3_path_attacker.")
        planning_rows = run_phase3_planning_attacker_evaluation(seeds=MULTI_SEED_VALUES)
        print(f"Completed Phase3.4 planning attacker evaluation for {len(planning_rows)} rows. Summary written to output/phase3_planning_attacker.")
        trust_rows = run_phase3_trust_attacker_evaluation(seeds=MULTI_SEED_VALUES)
        print(f"Completed Phase3.5 trust-aware planning attacker evaluation for {len(trust_rows)} rows. Summary written to output/phase3_trust_attacker.")
        expected_rows = run_phase3_expected_utility_evaluation(seeds=MULTI_SEED_VALUES)
        print(f"Completed Phase3.6 expected utility attacker evaluation for {len(expected_rows)} rows. Summary written to output/phase3_expected_utility.")
