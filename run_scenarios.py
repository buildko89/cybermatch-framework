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
    }
)

SUMMARY_COLUMNS = [
    "scenario",
    "steps",
    "attacker_enabled",
    "attacker_retreated",
    "attacker_retreat_step",
    "attacker_utility_final",
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
    "attacker_utility_final",
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
        "retreat_rate": float(np.mean(retreated)) if rows else 0.0,
        "retreat_step_mean": _mean_or_none(retreat_steps),
        "retreat_step_std": _std_or_none(retreat_steps),
    }

    for key in [
        "attacker_utility_final",
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
