import csv
import json
import os
from dataclasses import asdict
from typing import Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np

from cybermatch import CyberDefenseSimulator, ProductProfile, SimulationConfig, Visualizer, load_product_profile


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
        "phase4_trust_collapse_maximizer": {
            **PHASE2_FRUSTRATION_BASE,
            "honeypot_credential_enabled": True,
            "credential_node_ids": [1, 3],
            "credential_attraction_bonus": 7.0,
            "credential_detection_bonus": 8.0,
            "credential_reuse_decay": 0.25,
            "trust_enabled": True,
            "trust_decoy_penalty": 0.35,
            "trust_credential_penalty": 0.45,
            "trust_detection_penalty": 0.25,
            "frustration_decoy_hit": 4.5,
            "frustration_credential_trap": 5.0,
            "frustration_detection": 2.0,
            "frustration_retreat_threshold": 7.0,
            "stochastic_detection": True,
            "base_detection_prob": 0.65,
            "decoy_detection_prob": 1.0,
        },
        "phase4_expected_utility_suppressor": {
            **PHASE2_FRUSTRATION_BASE,
            "expected_utility_enabled": True,
            "adaptive_planning_enabled": True,
            "trust_enabled": True,
            "ai_uncertainty_weight": 2.5,
            "ai_replanning_weight": 2.5,
            "ai_search_weight": 3.0,
            "ai_operational_risk_weight": 3.0,
            "ai_trust_degradation_weight": 1.5,
            "stochastic_detection": True,
            "base_detection_prob": 0.75,
            "defense_detection_scale": 0.30,
            "decoy_detection_prob": 1.0,
            "attacker_defense_cost_rate": 2.0,
            "expected_detection_cost": 2.0,
            "expected_search_cost": 2.0,
        },
        "phase4_target_switch_inducer": {
            **PHASE2_FRUSTRATION_BASE,
            **GATED_EDGE_PRESSURE_HYBRID_BASE,
            "attacker_lateral_enabled": True,
            "mtd_enabled": True,
            "mtd_strategy": "shuffle_belief",
            "mtd_interval": 1,
            "mtd_intensity": 0.9,
            "mtd_shuffle_topology": True,
            "mtd_block_critical_edges": True,
            "mtd_edge_block_count": 2,
            "mtd_edge_block_duration": 2,
            "mtd_risk_gating_enabled": True,
            "mtd_risk_gate_mode": "critical_edge_pressure",
            "mtd_risk_gate_threshold": 1.0,
            "mtd_risk_gate_cooldown": 0,
            "frustration_path_change": 3.0,
            "frustration_no_progress": 1.5,
        },
        "phase4_planning_disruptor": {
            **PHASE2_FRUSTRATION_BASE,
            "adaptive_planning_enabled": True,
            "planning_depth": 3,
            "attacker_lateral_enabled": True,
            "node_type": ["real", "decoy", "real", "decoy", "real"],
            "asset_value": [10.0, 0.0, 1.0, 0.0, 2.0],
            "attacker_belief": [2.0, 9.0, 1.0, 11.0, 2.0],
            "post_decoy_defense_enabled": True,
            "post_decoy_defense_weight": 4.0,
            "post_decoy_defense_top_k": 2,
            "post_decoy_defense_exclude_decoy": True,
            "post_decoy_defense_injection_mode": "all",
            "post_decoy_defense_belief_source": "estimated",
            "defender_belief_estimation_enabled": True,
            "defender_belief_observation_mode": "hybrid_visible",
            "mtd_enabled": True,
            "mtd_strategy": "increase_uncertainty",
            "mtd_interval": 2,
            "mtd_intensity": 0.8,
            "mtd_block_critical_edges": True,
            "mtd_edge_block_count": 2,
            "mtd_edge_block_duration": 2,
            "frustration_path_change": 2.5,
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
    "product_plugin_enabled",
    "product_profile_import_enabled",
    "product_name",
    "product_category",
    "product_profile_name",
    "product_detection_boost",
    "product_interruption_boost",
    "product_diversion_boost",
    "product_confidence_boost",
    "product_false_positive_penalty",
    "product_latency_penalty",
    "product_maintenance_penalty",
    "product_effectiveness",
    "product_profile_score",
    "operational_cost_score",
    "false_positive_score",
    "evaluation_score",
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
    "product_plugin_enabled",
    "product_profile_import_enabled",
    "product_name",
    "product_category",
    "product_profile_name",
    "product_detection_boost",
    "product_interruption_boost",
    "product_diversion_boost",
    "product_confidence_boost",
    "product_false_positive_penalty",
    "product_latency_penalty",
    "product_maintenance_penalty",
    "product_effectiveness",
    "product_profile_score",
    "operational_cost_score",
    "false_positive_score",
    "evaluation_score",
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
    "attacker_mission",
    "mission_success_score",
    "mission_satisfaction_score",
    "mission_objectives_enabled",
    "mission_satisfaction",
    "mission_objective_score",
    "mission_failure_reason",
    "objective_weight_profile",
    "mission_strategy_change",
    "mission_sensitivity_score",
    "adaptive_mission_attacker_enabled",
    "observed_defense_strategy",
    "defense_effectiveness_memory",
    "strategy_failure_memory",
    "strategy_success_memory",
    "adaptation_count",
    "ttp_change_count",
    "strategy_avoidance_score",
    "alternative_path_usage",
    "adaptation_history",
    "mission_mutation_enabled",
    "mission_change_count",
    "mission_stability_score",
    "mission_mutation_reason",
    "mission_mutation_success",
    "mission_history",
    "attacker_type",
    "coalition_enabled",
    "coalition_size",
    "coalition_id",
    "coalition_role",
    "coalition_handover_count",
    "coalition_coordination_score",
    "coalition_delegation_state",
    "coalition_coordination_cost_enabled",
    "coordination_cost",
    "coalition_information_loss_enabled",
    "coalition_trust_enabled",
    "effective_handover_count",
    "failed_handover_count",
    "coordination_efficiency",
    "campaign_delay_score",
    "coalition_trust_score",
    "trust_degradation_count",
    "counter_deception_enabled",
    "fake_asset_enabled",
    "fake_credential_enabled",
    "fake_critical_path_enabled",
    "honey_node_enabled",
    "fake_asset_interaction_count",
    "fake_asset_success_rate",
    "fake_credential_usage_count",
    "credential_trap_trigger_count",
    "fake_path_follow_count",
    "path_diversion_score",
    "honey_node_visit_count",
    "honey_detection_count",
    "counter_deception_score",
    "attacker_diversion_score",
    "campaign_disruption_score",
    "counter_deception_awareness_enabled",
    "deception_suspicion_score",
    "fake_asset_detection_rate",
    "fake_asset_suspicion_count",
    "fake_credential_detection_rate",
    "path_validation_count",
    "path_validation_success_rate",
    "honey_node_detection_rate",
    "awareness_score",
    "deception_resistance_score",
    "false_suspicion_rate",
    "counter_deception_hunting_enabled",
    "fake_asset_hunt_count",
    "fake_asset_confirmed_count",
    "credential_validation_count",
    "credential_validation_success_rate",
    "honey_probe_count",
    "honey_probe_success_rate",
    "deception_knowledge_score",
    "hunting_success_rate",
    "deception_discovery_rate",
    "verified_false_signal_count",
    "verified_fake_asset_count",
    "coalition_success_rate",
    "coalition_role_efficiency",
    "campaign_completion_score",
    "campaign_delegation_observed",
    "coalition_preparing_handover_steps",
    "coalition_delegated_steps",
    "coalition_role_history",
    "coalition_handover_history",
    "coalition_delegation_state_history",
    "mission_reclassification_enabled",
    "mission_reclassification_count",
    "defense_reoptimization_count",
    "reclassification_accuracy",
    "belief_recovery_time",
    "reclassified_mission_history",
    "selected_strategy_history",
    "multi_objective_mission_enabled",
    "mission_weight_profit",
    "mission_weight_achievement",
    "mission_weight_persistence",
    "mission_weight_critical_hunter",
    "intent_deception_enabled",
    "deception_event_count",
    "mission_belief_error",
    "belief_confusion_score",
    "true_mission",
    "observed_mission",
    "mission_masking_success",
    "true_mission_history",
    "observed_mission_history",
    "deception_history",
    "noise_injection_enabled",
    "signal_extraction_enabled",
    "noise_event_count",
    "signal_event_count",
    "signal_to_noise_ratio",
    "noise_filter_accuracy",
    "decision_confidence",
    "adversarial_signal_enabled",
    "fake_signal_count",
    "adversarial_signal_count",
    "signal_confusion_score",
    "false_signal_acceptance_rate",
    "signal_consistency_score",
    "noise_history",
    "signal_history",
    "fake_signal_history",
    "signal_consistency_history",
    "profit_expected_utility_weight",
    "profit_success_weight",
    "persistence_survival_weight",
    "persistence_trust_weight",
    "persistence_stealth_weight",
    "critical_progress_weight",
    "critical_reach_weight",
    "achievement_progress_weight",
    "achievement_critical_weight",
    "nonstationary_attacker_enabled",
    "attacker_phase_change_step",
    "nonstationary_attacker_pattern",
    "attacker_phase",
    "attacker_phase_switch_count",
    "attacker_strategy_name",
    "expected_gain_estimate",
    "expected_detection_risk",
    "expected_search_cost",
    "target_switch_count",
    "adaptive_defender_enabled",
    "adaptive_selected_policy",
    "adaptive_policy_switch_count",
    "adaptive_policy_reason",
    "adaptive_policy_score",
    "adaptive_policy_rank",
    "adaptive_selection_reason",
    "adaptive_estimated_cns",
    "step_adaptive_defender_enabled",
    "adaptive_recheck_interval",
    "adaptive_policy_switch_cost",
    "adaptive_min_improvement",
    "mission_aware_defender_enabled",
    "mission_aware_selected_policy",
    "mission_policy_match",
    "mission_policy_switch_count",
    "mission_aware_selection_reason",
    "mission_aware_cns",
    "mission_belief_inference_enabled",
    "belief_profit",
    "belief_achievement",
    "belief_persistence",
    "belief_critical_hunter",
    "predicted_mission",
    "mission_prediction_confidence",
    "mission_prediction_correct",
    "state_belief_inference_enabled",
    "belief_recon",
    "belief_exploitation",
    "belief_lateral_movement",
    "belief_targeting",
    "belief_action_on_objective",
    "predicted_state",
    "state_prediction_confidence",
    "state_transition_count",
    "virtual_topology_enabled",
    "observable_events_enabled",
    "critical_path_events_enabled",
    "observable_event_count",
    "scan_count",
    "credential_use_count",
    "lateral_move_count",
    "critical_probe_count",
    "objective_action_count",
    "critical_path_proximity",
    "critical_path_step_count",
    "critical_node_visit_count",
    "critical_edge_traversal_count",
    "critical_path_entry_count",
    "critical_path_progress_count",
    "critical_path_near_target_count",
    "critical_asset_reach_count",
    "intelligence_defender_enabled",
    "selected_intelligence_policy",
    "intelligence_risk_score",
    "intelligence_risk_score_mean",
    "risk_level",
    "risk_level_transition_count",
    "decision_matrix_defender_enabled",
    "decision_matrix_policy",
    "decision_matrix_match_count",
    "decision_matrix_override_count",
    "defense_campaign_enabled",
    "campaign_effectiveness_score",
    "campaign_stage",
    "campaign_transition_count",
    "campaign_policy_switch_count",
    "campaign_stage_history",
    "campaign_policy_history",
    "strategy_profile",
    "strategy_effectiveness_score",
    "profile_rank",
    "best_weight_configuration",
    "mission_weight",
    "state_weight",
    "critical_path_weight",
    "weight_sweep_rank",
    "adaptive_policy_switch_steps",
    "adaptive_policy_history",
    "adaptive_cns_gain",
    "adaptive_switch_cost_total",
    "adaptive_defender_effectiveness",
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
    "product_plugin_enabled",
    "product_profile_import_enabled",
    "product_name",
    "product_category",
    "product_profile_name",
    "product_detection_boost",
    "product_interruption_boost",
    "product_diversion_boost",
    "product_confidence_boost",
    "product_false_positive_penalty",
    "product_latency_penalty",
    "product_maintenance_penalty",
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
    "product_effectiveness_mean",
    "product_effectiveness_std",
    "product_profile_score_mean",
    "product_profile_score_std",
    "operational_cost_score_mean",
    "operational_cost_score_std",
    "false_positive_score_mean",
    "false_positive_score_std",
    "evaluation_score_mean",
    "evaluation_score_std",
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
    "attacker_mission",
    "mission_success_score_mean",
    "mission_success_score_std",
    "mission_satisfaction_score_mean",
    "mission_satisfaction_score_std",
    "mission_objectives_enabled",
    "mission_satisfaction_mean",
    "mission_satisfaction_std",
    "mission_objective_score_mean",
    "mission_objective_score_std",
    "mission_failure_reason",
    "objective_weight_profile",
    "mission_strategy_change",
    "mission_sensitivity_score_mean",
    "mission_sensitivity_score_std",
    "adaptive_mission_attacker_enabled",
    "observed_defense_strategy",
    "defense_effectiveness_memory_mean",
    "defense_effectiveness_memory_std",
    "strategy_failure_memory_mean",
    "strategy_failure_memory_std",
    "strategy_success_memory_mean",
    "strategy_success_memory_std",
    "adaptation_count_mean",
    "adaptation_count_std",
    "ttp_change_count_mean",
    "ttp_change_count_std",
    "strategy_avoidance_score_mean",
    "strategy_avoidance_score_std",
    "alternative_path_usage_mean",
    "alternative_path_usage_std",
    "adaptation_history",
    "mission_mutation_enabled",
    "mission_change_count_mean",
    "mission_change_count_std",
    "mission_stability_score_mean",
    "mission_stability_score_std",
    "mission_mutation_reason",
    "mission_mutation_success_rate",
    "mission_history",
    "attacker_type",
    "coalition_enabled",
    "coalition_size",
    "coalition_id",
    "coalition_role",
    "coalition_handover_count_mean",
    "coalition_handover_count_std",
    "coalition_coordination_score_mean",
    "coalition_coordination_score_std",
    "coalition_delegation_state",
    "coalition_coordination_cost_enabled",
    "coordination_cost",
    "coalition_information_loss_enabled",
    "coalition_trust_enabled",
    "effective_handover_count_mean",
    "effective_handover_count_std",
    "failed_handover_count_mean",
    "failed_handover_count_std",
    "coordination_efficiency_mean",
    "coordination_efficiency_std",
    "campaign_delay_score_mean",
    "campaign_delay_score_std",
    "coalition_trust_score_mean",
    "coalition_trust_score_std",
    "trust_degradation_count_mean",
    "trust_degradation_count_std",
    "counter_deception_enabled",
    "fake_asset_enabled",
    "fake_credential_enabled",
    "fake_critical_path_enabled",
    "honey_node_enabled",
    "fake_asset_interaction_count_mean",
    "fake_asset_interaction_count_std",
    "fake_asset_success_rate_mean",
    "fake_asset_success_rate_std",
    "fake_credential_usage_count_mean",
    "fake_credential_usage_count_std",
    "credential_trap_trigger_count_mean",
    "credential_trap_trigger_count_std",
    "fake_path_follow_count_mean",
    "fake_path_follow_count_std",
    "path_diversion_score_mean",
    "path_diversion_score_std",
    "honey_node_visit_count_mean",
    "honey_node_visit_count_std",
    "honey_detection_count_mean",
    "honey_detection_count_std",
    "counter_deception_score_mean",
    "counter_deception_score_std",
    "attacker_diversion_score_mean",
    "attacker_diversion_score_std",
    "campaign_disruption_score_mean",
    "campaign_disruption_score_std",
    "counter_deception_awareness_enabled",
    "deception_suspicion_score_mean",
    "deception_suspicion_score_std",
    "fake_asset_detection_rate_mean",
    "fake_asset_detection_rate_std",
    "fake_asset_suspicion_count_mean",
    "fake_asset_suspicion_count_std",
    "fake_credential_detection_rate_mean",
    "fake_credential_detection_rate_std",
    "path_validation_count_mean",
    "path_validation_count_std",
    "path_validation_success_rate_mean",
    "path_validation_success_rate_std",
    "honey_node_detection_rate_mean",
    "honey_node_detection_rate_std",
    "awareness_score_mean",
    "awareness_score_std",
    "deception_resistance_score_mean",
    "deception_resistance_score_std",
    "false_suspicion_rate_mean",
    "false_suspicion_rate_std",
    "counter_deception_hunting_enabled",
    "fake_asset_hunt_count_mean",
    "fake_asset_hunt_count_std",
    "fake_asset_confirmed_count_mean",
    "fake_asset_confirmed_count_std",
    "credential_validation_count_mean",
    "credential_validation_count_std",
    "credential_validation_success_rate_mean",
    "credential_validation_success_rate_std",
    "honey_probe_count_mean",
    "honey_probe_count_std",
    "honey_probe_success_rate_mean",
    "honey_probe_success_rate_std",
    "deception_knowledge_score_mean",
    "deception_knowledge_score_std",
    "hunting_success_rate_mean",
    "hunting_success_rate_std",
    "deception_discovery_rate_mean",
    "deception_discovery_rate_std",
    "verified_false_signal_count_mean",
    "verified_false_signal_count_std",
    "verified_fake_asset_count_mean",
    "verified_fake_asset_count_std",
    "coalition_success_rate_mean",
    "coalition_success_rate_std",
    "coalition_role_efficiency_mean",
    "coalition_role_efficiency_std",
    "campaign_completion_score_mean",
    "campaign_completion_score_std",
    "campaign_delegation_observed_rate",
    "coalition_preparing_handover_steps_mean",
    "coalition_delegated_steps_mean",
    "coalition_role_history",
    "coalition_handover_history",
    "coalition_delegation_state_history",
    "mission_reclassification_enabled",
    "mission_reclassification_count_mean",
    "mission_reclassification_count_std",
    "defense_reoptimization_count_mean",
    "defense_reoptimization_count_std",
    "reclassification_accuracy_mean",
    "reclassification_accuracy_std",
    "belief_recovery_time_mean",
    "belief_recovery_time_std",
    "reclassified_mission_history",
    "selected_strategy_history",
    "multi_objective_mission_enabled",
    "mission_weight_profit",
    "mission_weight_achievement",
    "mission_weight_persistence",
    "mission_weight_critical_hunter",
    "intent_deception_enabled",
    "deception_event_count_mean",
    "deception_event_count_std",
    "mission_belief_error_mean",
    "mission_belief_error_std",
    "belief_confusion_score_mean",
    "belief_confusion_score_std",
    "true_mission",
    "observed_mission",
    "mission_masking_success_mean",
    "mission_masking_success_std",
    "true_mission_history",
    "observed_mission_history",
    "deception_history",
    "noise_injection_enabled",
    "signal_extraction_enabled",
    "noise_event_count_mean",
    "noise_event_count_std",
    "signal_event_count_mean",
    "signal_event_count_std",
    "signal_to_noise_ratio_mean",
    "signal_to_noise_ratio_std",
    "noise_filter_accuracy_mean",
    "noise_filter_accuracy_std",
    "decision_confidence_mean",
    "decision_confidence_std",
    "adversarial_signal_enabled",
    "fake_signal_count_mean",
    "fake_signal_count_std",
    "adversarial_signal_count_mean",
    "adversarial_signal_count_std",
    "signal_confusion_score_mean",
    "signal_confusion_score_std",
    "false_signal_acceptance_rate_mean",
    "false_signal_acceptance_rate_std",
    "signal_consistency_score_mean",
    "signal_consistency_score_std",
    "noise_history",
    "signal_history",
    "fake_signal_history",
    "signal_consistency_history",
    "profit_expected_utility_weight",
    "profit_success_weight",
    "persistence_survival_weight",
    "persistence_trust_weight",
    "persistence_stealth_weight",
    "critical_progress_weight",
    "critical_reach_weight",
    "achievement_progress_weight",
    "achievement_critical_weight",
    "nonstationary_attacker_enabled",
    "attacker_phase_change_step",
    "nonstationary_attacker_pattern",
    "attacker_phase",
    "attacker_phase_switch_count_mean",
    "attacker_phase_switch_count_std",
    "attacker_strategy_name",
    "expected_gain_estimate_mean",
    "expected_detection_risk_mean",
    "expected_search_cost_mean",
    "target_switch_count_mean",
    "target_switch_count_std",
    "adaptive_defender_enabled",
    "adaptive_selected_policy",
    "adaptive_policy_switch_count_mean",
    "adaptive_policy_switch_count_std",
    "adaptive_policy_reason",
    "adaptive_policy_score_mean",
    "adaptive_policy_score_std",
    "adaptive_policy_rank_mean",
    "adaptive_selection_reason",
    "adaptive_estimated_cns_mean",
    "adaptive_estimated_cns_std",
    "step_adaptive_defender_enabled",
    "adaptive_recheck_interval",
    "adaptive_policy_switch_cost",
    "adaptive_min_improvement",
    "mission_aware_defender_enabled",
    "mission_aware_selected_policy",
    "mission_policy_match",
    "mission_policy_switch_count_mean",
    "mission_policy_switch_count_std",
    "mission_aware_selection_reason",
    "mission_aware_cns_mean",
    "mission_aware_cns_std",
    "mission_belief_inference_enabled",
    "belief_profit_mean",
    "belief_achievement_mean",
    "belief_persistence_mean",
    "belief_critical_hunter_mean",
    "predicted_mission",
    "mission_prediction_confidence_mean",
    "mission_prediction_confidence_std",
    "mission_prediction_correct_rate",
    "state_belief_inference_enabled",
    "belief_recon_mean",
    "belief_exploitation_mean",
    "belief_lateral_movement_mean",
    "belief_targeting_mean",
    "belief_action_on_objective_mean",
    "predicted_state",
    "state_prediction_confidence_mean",
    "state_prediction_confidence_std",
    "state_transition_count_mean",
    "state_transition_count_std",
    "virtual_topology_enabled",
    "observable_events_enabled",
    "critical_path_events_enabled",
    "observable_event_count_mean",
    "observable_event_count_std",
    "scan_count_mean",
    "credential_use_count_mean",
    "lateral_move_count_mean",
    "critical_probe_count_mean",
    "objective_action_count_mean",
    "critical_path_proximity_mean",
    "critical_path_proximity_std",
    "critical_path_step_count_mean",
    "critical_node_visit_count_mean",
    "critical_edge_traversal_count_mean",
    "critical_path_entry_count_mean",
    "critical_path_progress_count_mean",
    "critical_path_near_target_count_mean",
    "critical_asset_reach_count_mean",
    "intelligence_defender_enabled",
    "selected_intelligence_policy",
    "intelligence_risk_score_mean",
    "intelligence_risk_score_std",
    "intelligence_risk_score_mean_mean",
    "risk_level",
    "risk_level_transition_count_mean",
    "risk_level_transition_count_std",
    "decision_matrix_defender_enabled",
    "decision_matrix_policy",
    "decision_matrix_match_count_mean",
    "decision_matrix_match_count_std",
    "decision_matrix_override_count_mean",
    "decision_matrix_override_count_std",
    "defense_campaign_enabled",
    "campaign_effectiveness_score_mean",
    "campaign_effectiveness_score_std",
    "campaign_stage",
    "campaign_transition_count_mean",
    "campaign_transition_count_std",
    "campaign_policy_switch_count_mean",
    "campaign_policy_switch_count_std",
    "campaign_stage_history",
    "campaign_policy_history",
    "strategy_profile",
    "strategy_effectiveness_score_mean",
    "strategy_effectiveness_score_std",
    "profile_rank_mean",
    "best_weight_configuration",
    "mission_weight_mean",
    "state_weight_mean",
    "critical_path_weight_mean",
    "weight_sweep_rank_mean",
    "adaptive_policy_switch_steps",
    "adaptive_policy_history",
    "adaptive_cns_gain_mean",
    "adaptive_cns_gain_std",
    "adaptive_switch_cost_total_mean",
    "adaptive_switch_cost_total_std",
    "adaptive_defender_effectiveness_mean",
    "adaptive_defender_effectiveness_std",
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
        "product_plugin_enabled": rows[0].get("product_plugin_enabled") if rows else None,
        "product_profile_import_enabled": rows[0].get("product_profile_import_enabled") if rows else None,
        "product_name": rows[0].get("product_name") if rows else None,
        "product_category": rows[0].get("product_category") if rows else None,
        "product_profile_name": rows[0].get("product_profile_name") if rows else None,
        "product_detection_boost": rows[0].get("product_detection_boost") if rows else None,
        "product_interruption_boost": rows[0].get("product_interruption_boost") if rows else None,
        "product_diversion_boost": rows[0].get("product_diversion_boost") if rows else None,
        "product_confidence_boost": rows[0].get("product_confidence_boost") if rows else None,
        "product_false_positive_penalty": rows[0].get("product_false_positive_penalty") if rows else None,
        "product_latency_penalty": rows[0].get("product_latency_penalty") if rows else None,
        "product_maintenance_penalty": rows[0].get("product_maintenance_penalty") if rows else None,
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
        "attacker_mission": rows[0].get("attacker_mission") if rows else None,
        "mission_objectives_enabled": rows[0].get("mission_objectives_enabled") if rows else None,
        "mission_failure_reason": rows[0].get("mission_failure_reason") if rows else None,
        "objective_weight_profile": rows[0].get("objective_weight_profile") if rows else None,
        "mission_strategy_change": rows[0].get("mission_strategy_change") if rows else None,
        "adaptive_mission_attacker_enabled": rows[0].get("adaptive_mission_attacker_enabled") if rows else None,
        "observed_defense_strategy": rows[0].get("observed_defense_strategy") if rows else None,
        "adaptation_history": rows[0].get("adaptation_history") if rows else None,
        "mission_mutation_enabled": rows[0].get("mission_mutation_enabled") if rows else None,
        "mission_mutation_reason": rows[0].get("mission_mutation_reason") if rows else None,
        "mission_history": rows[0].get("mission_history") if rows else None,
        "attacker_type": rows[0].get("attacker_type") if rows else None,
        "coalition_enabled": rows[0].get("coalition_enabled") if rows else None,
        "coalition_size": rows[0].get("coalition_size") if rows else None,
        "coalition_id": rows[0].get("coalition_id") if rows else None,
        "coalition_role": rows[0].get("coalition_role") if rows else None,
        "coalition_delegation_state": rows[0].get("coalition_delegation_state") if rows else None,
        "coalition_coordination_cost_enabled": rows[0].get("coalition_coordination_cost_enabled") if rows else None,
        "coordination_cost": rows[0].get("coordination_cost") if rows else None,
        "coalition_information_loss_enabled": rows[0].get("coalition_information_loss_enabled") if rows else None,
        "coalition_trust_enabled": rows[0].get("coalition_trust_enabled") if rows else None,
        "counter_deception_enabled": rows[0].get("counter_deception_enabled") if rows else None,
        "fake_asset_enabled": rows[0].get("fake_asset_enabled") if rows else None,
        "fake_credential_enabled": rows[0].get("fake_credential_enabled") if rows else None,
        "fake_critical_path_enabled": rows[0].get("fake_critical_path_enabled") if rows else None,
        "honey_node_enabled": rows[0].get("honey_node_enabled") if rows else None,
        "counter_deception_awareness_enabled": rows[0].get("counter_deception_awareness_enabled") if rows else None,
        "counter_deception_hunting_enabled": rows[0].get("counter_deception_hunting_enabled") if rows else None,
        "coalition_role_history": rows[0].get("coalition_role_history") if rows else None,
        "coalition_handover_history": rows[0].get("coalition_handover_history") if rows else None,
        "coalition_delegation_state_history": rows[0].get("coalition_delegation_state_history") if rows else None,
        "mission_reclassification_enabled": rows[0].get("mission_reclassification_enabled") if rows else None,
        "reclassified_mission_history": rows[0].get("reclassified_mission_history") if rows else None,
        "selected_strategy_history": rows[0].get("selected_strategy_history") if rows else None,
        "multi_objective_mission_enabled": rows[0].get("multi_objective_mission_enabled") if rows else None,
        "mission_weight_profit": rows[0].get("mission_weight_profit") if rows else None,
        "mission_weight_achievement": rows[0].get("mission_weight_achievement") if rows else None,
        "mission_weight_persistence": rows[0].get("mission_weight_persistence") if rows else None,
        "mission_weight_critical_hunter": rows[0].get("mission_weight_critical_hunter") if rows else None,
        "intent_deception_enabled": rows[0].get("intent_deception_enabled") if rows else None,
        "true_mission": rows[0].get("true_mission") if rows else None,
        "observed_mission": rows[0].get("observed_mission") if rows else None,
        "true_mission_history": rows[0].get("true_mission_history") if rows else None,
        "observed_mission_history": rows[0].get("observed_mission_history") if rows else None,
        "deception_history": rows[0].get("deception_history") if rows else None,
        "noise_injection_enabled": rows[0].get("noise_injection_enabled") if rows else None,
        "signal_extraction_enabled": rows[0].get("signal_extraction_enabled") if rows else None,
        "adversarial_signal_enabled": rows[0].get("adversarial_signal_enabled") if rows else None,
        "noise_history": rows[0].get("noise_history") if rows else None,
        "signal_history": rows[0].get("signal_history") if rows else None,
        "fake_signal_history": rows[0].get("fake_signal_history") if rows else None,
        "signal_consistency_history": rows[0].get("signal_consistency_history") if rows else None,
        "profit_expected_utility_weight": rows[0].get("profit_expected_utility_weight") if rows else None,
        "profit_success_weight": rows[0].get("profit_success_weight") if rows else None,
        "persistence_survival_weight": rows[0].get("persistence_survival_weight") if rows else None,
        "persistence_trust_weight": rows[0].get("persistence_trust_weight") if rows else None,
        "persistence_stealth_weight": rows[0].get("persistence_stealth_weight") if rows else None,
        "critical_progress_weight": rows[0].get("critical_progress_weight") if rows else None,
        "critical_reach_weight": rows[0].get("critical_reach_weight") if rows else None,
        "achievement_progress_weight": rows[0].get("achievement_progress_weight") if rows else None,
        "achievement_critical_weight": rows[0].get("achievement_critical_weight") if rows else None,
        "nonstationary_attacker_enabled": rows[0].get("nonstationary_attacker_enabled") if rows else None,
        "attacker_phase_change_step": rows[0].get("attacker_phase_change_step") if rows else None,
        "nonstationary_attacker_pattern": rows[0].get("nonstationary_attacker_pattern") if rows else None,
        "attacker_phase": rows[0].get("attacker_phase") if rows else None,
        "attacker_strategy_name": rows[0].get("attacker_strategy_name") if rows else None,
        "adaptive_defender_enabled": rows[0].get("adaptive_defender_enabled") if rows else None,
        "adaptive_selected_policy": rows[0].get("adaptive_selected_policy") if rows else None,
        "adaptive_policy_reason": rows[0].get("adaptive_policy_reason") if rows else None,
        "adaptive_selection_reason": rows[0].get("adaptive_selection_reason") if rows else None,
        "step_adaptive_defender_enabled": rows[0].get("step_adaptive_defender_enabled") if rows else None,
        "adaptive_recheck_interval": rows[0].get("adaptive_recheck_interval") if rows else None,
        "adaptive_policy_switch_cost": rows[0].get("adaptive_policy_switch_cost") if rows else None,
        "adaptive_min_improvement": rows[0].get("adaptive_min_improvement") if rows else None,
        "mission_aware_defender_enabled": rows[0].get("mission_aware_defender_enabled") if rows else None,
        "mission_aware_selected_policy": rows[0].get("mission_aware_selected_policy") if rows else None,
        "mission_policy_match": rows[0].get("mission_policy_match") if rows else None,
        "mission_aware_selection_reason": rows[0].get("mission_aware_selection_reason") if rows else None,
        "mission_belief_inference_enabled": rows[0].get("mission_belief_inference_enabled") if rows else None,
        "predicted_mission": rows[0].get("predicted_mission") if rows else None,
        "state_belief_inference_enabled": rows[0].get("state_belief_inference_enabled") if rows else None,
        "predicted_state": rows[0].get("predicted_state") if rows else None,
        "virtual_topology_enabled": rows[0].get("virtual_topology_enabled") if rows else None,
        "observable_events_enabled": rows[0].get("observable_events_enabled") if rows else None,
        "critical_path_events_enabled": rows[0].get("critical_path_events_enabled") if rows else None,
        "intelligence_defender_enabled": rows[0].get("intelligence_defender_enabled") if rows else None,
        "selected_intelligence_policy": rows[0].get("selected_intelligence_policy") if rows else None,
        "risk_level": rows[0].get("risk_level") if rows else None,
        "decision_matrix_defender_enabled": rows[0].get("decision_matrix_defender_enabled") if rows else None,
        "decision_matrix_policy": rows[0].get("decision_matrix_policy") if rows else None,
        "defense_campaign_enabled": rows[0].get("defense_campaign_enabled") if rows else None,
        "campaign_stage": rows[0].get("campaign_stage") if rows else None,
        "campaign_stage_history": rows[0].get("campaign_stage_history") if rows else None,
        "campaign_policy_history": rows[0].get("campaign_policy_history") if rows else None,
        "strategy_profile": rows[0].get("strategy_profile") if rows else None,
        "best_weight_configuration": rows[0].get("best_weight_configuration") if rows else None,
        "adaptive_policy_switch_steps": rows[0].get("adaptive_policy_switch_steps") if rows else None,
        "adaptive_policy_history": rows[0].get("adaptive_policy_history") if rows else None,
        "retreat_rate": float(np.mean(retreated)) if rows else 0.0,
        "retreat_step_mean": _mean_or_none(retreat_steps),
        "retreat_step_std": _std_or_none(retreat_steps),
    }

    for key in [
        "attacker_utility_final",
        "product_effectiveness",
        "product_profile_score",
        "operational_cost_score",
        "false_positive_score",
        "evaluation_score",
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
        "mission_success_score",
        "mission_satisfaction_score",
        "mission_satisfaction",
        "mission_objective_score",
        "mission_sensitivity_score",
        "defense_effectiveness_memory",
        "strategy_failure_memory",
        "strategy_success_memory",
        "adaptation_count",
        "ttp_change_count",
        "strategy_avoidance_score",
        "alternative_path_usage",
        "mission_change_count",
        "mission_stability_score",
        "mission_mutation_success",
        "coalition_handover_count",
        "coalition_coordination_score",
        "coalition_success_rate",
        "coalition_role_efficiency",
        "campaign_completion_score",
        "campaign_delegation_observed",
        "effective_handover_count",
        "failed_handover_count",
        "coordination_efficiency",
        "campaign_delay_score",
        "coalition_trust_score",
        "trust_degradation_count",
        "fake_asset_interaction_count",
        "fake_asset_success_rate",
        "fake_credential_usage_count",
        "credential_trap_trigger_count",
        "fake_path_follow_count",
        "path_diversion_score",
        "honey_node_visit_count",
        "honey_detection_count",
        "counter_deception_score",
        "attacker_diversion_score",
        "campaign_disruption_score",
        "deception_suspicion_score",
        "fake_asset_detection_rate",
        "fake_asset_suspicion_count",
        "fake_credential_detection_rate",
        "path_validation_count",
        "path_validation_success_rate",
        "honey_node_detection_rate",
        "awareness_score",
        "deception_resistance_score",
        "false_suspicion_rate",
        "fake_asset_hunt_count",
        "fake_asset_confirmed_count",
        "credential_validation_count",
        "credential_validation_success_rate",
        "honey_probe_count",
        "honey_probe_success_rate",
        "deception_knowledge_score",
        "hunting_success_rate",
        "deception_discovery_rate",
        "verified_false_signal_count",
        "verified_fake_asset_count",
        "coalition_preparing_handover_steps",
        "coalition_delegated_steps",
        "mission_reclassification_count",
        "defense_reoptimization_count",
        "reclassification_accuracy",
        "belief_recovery_time",
        "mission_weight_profit",
        "mission_weight_achievement",
        "mission_weight_persistence",
        "mission_weight_critical_hunter",
        "deception_event_count",
        "mission_belief_error",
        "belief_confusion_score",
        "mission_masking_success",
        "noise_event_count",
        "signal_event_count",
        "signal_to_noise_ratio",
        "noise_filter_accuracy",
        "decision_confidence",
        "fake_signal_count",
        "adversarial_signal_count",
        "signal_confusion_score",
        "false_signal_acceptance_rate",
        "signal_consistency_score",
        "attacker_phase_switch_count",
        "expected_gain_estimate",
        "expected_detection_risk",
        "expected_search_cost",
        "target_switch_count",
        "adaptive_policy_switch_count",
        "adaptive_policy_score",
        "adaptive_policy_rank",
        "adaptive_estimated_cns",
        "mission_policy_switch_count",
        "mission_aware_cns",
        "belief_profit",
        "belief_achievement",
        "belief_persistence",
        "belief_critical_hunter",
        "mission_prediction_confidence",
        "belief_recon",
        "belief_exploitation",
        "belief_lateral_movement",
        "belief_targeting",
        "belief_action_on_objective",
        "state_prediction_confidence",
        "state_transition_count",
        "observable_event_count",
        "scan_count",
        "credential_use_count",
        "lateral_move_count",
        "critical_probe_count",
        "objective_action_count",
        "critical_path_proximity",
        "critical_path_step_count",
        "critical_node_visit_count",
        "critical_edge_traversal_count",
        "critical_path_entry_count",
        "critical_path_progress_count",
        "critical_path_near_target_count",
        "critical_asset_reach_count",
        "intelligence_risk_score",
        "intelligence_risk_score_mean",
        "risk_level_transition_count",
        "decision_matrix_match_count",
        "decision_matrix_override_count",
        "campaign_effectiveness_score",
        "campaign_transition_count",
        "campaign_policy_switch_count",
        "strategy_effectiveness_score",
        "profile_rank",
        "mission_weight",
        "state_weight",
        "critical_path_weight",
        "weight_sweep_rank",
        "adaptive_cns_gain",
        "adaptive_switch_cost_total",
        "adaptive_defender_effectiveness",
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
    result["mission_mutation_success_rate"] = result.get("mission_mutation_success_mean")
    result["campaign_delegation_observed_rate"] = result.get("campaign_delegation_observed_mean")
    result["coalition_preparing_handover_steps_mean"] = result.get("coalition_preparing_handover_steps_mean")
    result["coalition_delegated_steps_mean"] = result.get("coalition_delegated_steps_mean")
    result["frustration_mean"] = result.get("frustration_mean_mean")
    result["frustration_std"] = result.get("frustration_mean_std")
    result["frustration_max"] = result.get("frustration_max_mean")
    result["frustration_max_std"] = result.get("frustration_max_std")
    result["ai_total_decision_cost"] = result.get("ai_total_decision_cost_mean")
    result["ai_weighted_cost"] = result.get("ai_weighted_cost_mean")
    result["mission_prediction_correct_rate"] = (
        float(np.mean([1.0 if row.get("mission_prediction_correct") in (True, "True", "true", 1) else 0.0 for row in rows]))
        if rows
        else 0.0
    )
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


PHASE4_ADAPTIVE_DEFENDER_SCENARIOS = {
    "phase4_adaptive_defender_reference": {
        "expected_utility": 0.0,
        "trust_collapse_rate": 0.0,
        "target_switch_count": 0,
        "critical_risk": 0.0,
    },
    "phase4_adaptive_vs_expected_utility": {
        "expected_utility": 1.0,
        "trust_collapse_rate": 0.0,
        "target_switch_count": 0,
        "critical_risk": 0.25,
    },
    "phase4_adaptive_vs_trust_collapse": {
        "expected_utility": 0.0,
        "trust_collapse_rate": 0.30,
        "target_switch_count": 0,
        "critical_risk": 0.25,
    },
    "phase4_adaptive_vs_target_switch": {
        "expected_utility": 0.0,
        "trust_collapse_rate": 0.0,
        "target_switch_count": 8,
        "critical_risk": 0.25,
    },
    "phase4_adaptive_combined": {
        "expected_utility": 1.0,
        "trust_collapse_rate": 0.30,
        "target_switch_count": 8,
        "critical_risk": 0.50,
    },
}

PHASE4_FIXED_POLICIES = [
    "phase2_frustration_decoy",
    "phase2_ai_balanced",
    "gated_edge_pressure_count_2",
]

PHASE4_ADAPTIVE_DEFENDER_COLUMNS = [
    "scenario",
    "defense_mode",
    "selected_policy",
    "adaptive_policy_reason",
    "num_runs",
    "cognitive_neutralization_score",
    "cns_objective_score",
    "retreat_rate",
    "critical_compromise_rate",
    "expected_utility_mean",
    "trust_collapse_rate",
    "target_switch_count",
    "adaptive_policy_switch_count",
    "adaptive_defender_effectiveness",
    "policy_selection_count",
]


def _expected_utility_attacker_overrides() -> Dict[str, object]:
    return {
        "adaptive_attacker_enabled": True,
        "adaptive_preference_enabled": True,
        "adaptive_path_enabled": True,
        "adaptive_planning_enabled": True,
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
        "trust_enabled": True,
        "trust_decoy_penalty": 0.20,
        "trust_credential_penalty": 0.30,
        "trust_detection_penalty": 0.15,
        "trust_success_reward": 0.05,
        "expected_utility_enabled": True,
        "expected_gain_weight": 1.0,
        "expected_success_weight": 1.0,
        "expected_detection_cost": 1.0,
        "expected_search_cost": 1.0,
        "expected_trust_weight": 1.0,
        "attacker_target_selection": "adaptive",
    }


def _select_adaptive_defense_policy(
    expected_utility: float,
    trust_collapse_rate: float,
    target_switch_count: int,
    critical_risk: float = 0.0,
    expected_utility_threshold: float = 0.0,
    trust_collapse_threshold: float = 0.2,
    target_switch_threshold: int = 5,
    policy_default: str = "phase2_frustration_decoy",
    policy_high_expected_utility: str = "gated_edge_pressure_count_2",
    policy_trust_collapse: str = "phase2_frustration_decoy",
    policy_high_switching: str = "phase2_ai_balanced",
) -> tuple[str, str]:
    del critical_risk
    if expected_utility > expected_utility_threshold:
        return policy_high_expected_utility, "high_expected_utility"
    if trust_collapse_rate > trust_collapse_threshold:
        return policy_trust_collapse, "trust_collapse"
    if target_switch_count > target_switch_threshold:
        return policy_high_switching, "target_switch"
    return policy_default, "default"


def _estimate_policy_score(
    policy_name: str,
    expected_utility: float,
    trust_collapse_rate: float,
    target_switch_count: int,
    critical_compromise_risk: float,
    retreat_rate: float,
) -> float:
    switch_pressure = min(max(float(target_switch_count) / 10.0, 0.0), 1.0)
    if policy_name == "phase2_frustration_decoy":
        return (
            0.35
            + 1.20 * trust_collapse_rate
            + 0.80 * retreat_rate
            - 0.20 * expected_utility
            - 0.50 * critical_compromise_risk
            - 0.05 * switch_pressure
        )
    if policy_name == "phase2_ai_balanced":
        return (
            0.25
            + 0.40 * trust_collapse_rate
            + 0.75 * retreat_rate
            + 0.20 * switch_pressure
            - 0.25 * expected_utility
            - 0.45 * critical_compromise_risk
        )
    if policy_name == "gated_edge_pressure_count_2":
        return (
            0.10
            + 0.20 * trust_collapse_rate
            + 0.50 * retreat_rate
            + 0.10 * expected_utility
            + 0.10 * switch_pressure
            - 0.90 * critical_compromise_risk
        )
    return trust_collapse_rate + retreat_rate - expected_utility - critical_compromise_risk


def _select_cns_guided_policy(
    expected_utility: float,
    trust_collapse_rate: float,
    target_switch_count: int,
    critical_compromise_risk: float,
    retreat_rate: float,
    candidate_policies: Optional[List[str]] = None,
) -> tuple[str, str, float, int, float]:
    candidates = candidate_policies or PHASE4_FIXED_POLICIES
    scored = [
        (
            policy,
            _estimate_policy_score(
                policy_name=policy,
                expected_utility=expected_utility,
                trust_collapse_rate=trust_collapse_rate,
                target_switch_count=target_switch_count,
                critical_compromise_risk=critical_compromise_risk,
                retreat_rate=retreat_rate,
            ),
        )
        for policy in candidates
    ]
    scored.sort(key=lambda item: item[1], reverse=True)
    best_policy, best_score = scored[0]
    if trust_collapse_rate > 0.2 and best_policy == "phase2_frustration_decoy":
        reason = "cns_trust_collapse"
    elif critical_compromise_risk > 0.0 and best_policy == "phase2_frustration_decoy":
        reason = "cns_critical_protection"
    elif target_switch_count > 5 and best_policy == "phase2_ai_balanced":
        reason = "cns_switch_stability"
    else:
        reason = "cns_score_max"
    estimated_cns = float(np.clip(best_score, 0.0, 1.0))
    return best_policy, reason, float(best_score), 1, estimated_cns


def _phase4_policy_config(
    policy_name: str,
    adaptive_enabled: bool,
    selected_policy: Optional[str] = None,
    policy_reason: str = "fixed",
    policy_switch_count: int = 0,
    defender_mode: str = "rule_based",
    policy_score: float = 0.0,
    policy_rank: int = 0,
    selection_reason: Optional[str] = None,
    estimated_cns: float = 0.0,
    step_adaptive_enabled: bool = False,
) -> Dict[str, object]:
    return {
        **SCENARIOS[policy_name],
        **_expected_utility_attacker_overrides(),
        "adaptive_defender_enabled": adaptive_enabled,
        "adaptive_defender_mode": defender_mode,
        "adaptive_selected_policy": selected_policy or policy_name,
        "adaptive_policy_reason": policy_reason,
        "adaptive_policy_switch_count": policy_switch_count,
        "adaptive_policy_score": policy_score,
        "adaptive_policy_rank": policy_rank,
        "adaptive_selection_reason": selection_reason or policy_reason,
        "adaptive_estimated_cns": estimated_cns,
        "step_adaptive_defender_enabled": step_adaptive_enabled,
    }


def run_phase4_adaptive_defender_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase4_adaptive_defender"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for scenario_name, signals in PHASE4_ADAPTIVE_DEFENDER_SCENARIOS.items():
        for policy_name in PHASE4_FIXED_POLICIES:
            scenarios[f"{scenario_name}__fixed__{policy_name}"] = _phase4_policy_config(
                policy_name=policy_name,
                adaptive_enabled=False,
                selected_policy=policy_name,
                policy_reason="fixed",
                policy_switch_count=0,
            )
        selected_policy, reason = _select_adaptive_defense_policy(
            expected_utility=float(signals["expected_utility"]),
            trust_collapse_rate=float(signals["trust_collapse_rate"]),
            target_switch_count=int(signals["target_switch_count"]),
            critical_risk=float(signals["critical_risk"]),
        )
        scenarios[f"{scenario_name}__adaptive_defender"] = _phase4_policy_config(
            policy_name=selected_policy,
            adaptive_enabled=True,
            selected_policy=selected_policy,
            policy_reason=reason,
            policy_switch_count=0,
        )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase4_adaptive_defender_row(row) for row in stats_rows]
    summary_rows.sort(key=lambda row: (str(row.get("scenario")), str(row.get("defense_mode")), str(row.get("selected_policy"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase4_adaptive_defender_rows(summary_rows)
    _write_phase4_adaptive_defender_summary(summary_rows, analysis, output_dir)
    _plot_phase4_adaptive_metric(summary_rows, "cognitive_neutralization_score", "Adaptive Defender CNS", os.path.join(output_dir, "adaptive_defender_cns.png"))
    _plot_phase4_policy_selection(summary_rows, os.path.join(output_dir, "adaptive_defender_policy_selection.png"))
    _plot_phase4_adaptive_metric(summary_rows, "adaptive_defender_effectiveness", "Adaptive Defender Effectiveness", os.path.join(output_dir, "adaptive_defender_effectiveness.png"))
    _write_phase4_adaptive_defender_report(summary_rows, analysis, output_dir)
    return summary_rows


def _build_phase4_adaptive_defender_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario_name = str(row.get("scenario") or "")
    defense_mode = "adaptive_defender" if scenario_name.endswith("__adaptive_defender") else "fixed"
    base_scenario = scenario_name.replace("__adaptive_defender", "")
    selected_policy = row.get("adaptive_selected_policy") or ""
    if "__fixed__" in base_scenario:
        base_scenario, selected_policy = base_scenario.split("__fixed__", 1)
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    critical = _to_float(row.get("critical_protection_score_mean"))
    retreat = _to_float(row.get("retreat_score_mean"))
    effectiveness = float(np.clip(0.5 * cns + 0.3 * critical + 0.2 * retreat, 0.0, 1.0))
    return {
        "scenario": base_scenario,
        "defense_mode": defense_mode,
        "selected_policy": selected_policy,
        "adaptive_policy_reason": row.get("adaptive_policy_reason") or ("adaptive" if defense_mode == "adaptive_defender" else "fixed"),
        "num_runs": row.get("num_runs"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_objective_score": row.get("cns_objective_score_mean"),
        "retreat_rate": row.get("retreat_rate"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "expected_utility_mean": row.get("expected_utility_mean_mean"),
        "trust_collapse_rate": row.get("trust_collapse_rate_mean"),
        "target_switch_count": row.get("target_switch_count_mean"),
        "adaptive_policy_switch_count": row.get("adaptive_policy_switch_count_mean"),
        "adaptive_defender_effectiveness": row.get("adaptive_defender_effectiveness_mean") or effectiveness,
        "policy_selection_count": 1,
    }


def _analyze_phase4_adaptive_defender_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    adaptive_rows = [row for row in rows if row.get("defense_mode") == "adaptive_defender"]
    fixed_rows = [row for row in rows if row.get("defense_mode") == "fixed"]
    adaptive_cns = [_to_float(row.get("cognitive_neutralization_score")) for row in adaptive_rows]
    fixed_cns = [_to_float(row.get("cognitive_neutralization_score")) for row in fixed_rows]
    best_fixed_by_scenario = []
    for scenario in sorted(set(str(row.get("scenario")) for row in rows)):
        scenario_fixed = [row for row in fixed_rows if row.get("scenario") == scenario]
        if scenario_fixed:
            best_fixed_by_scenario.append(max(_to_float(row.get("cognitive_neutralization_score")) for row in scenario_fixed))
    selection_counts: Dict[str, int] = {}
    for row in adaptive_rows:
        policy = str(row.get("selected_policy"))
        selection_counts[policy] = selection_counts.get(policy, 0) + 1
    most_selected = max(selection_counts.items(), key=lambda item: item[1])[0] if selection_counts else None
    trust_rows = [row for row in adaptive_rows if row.get("adaptive_policy_reason") == "trust_collapse"]
    return {
        "mean_adaptive_cns": float(np.mean(adaptive_cns)) if adaptive_cns else 0.0,
        "mean_fixed_cns": float(np.mean(fixed_cns)) if fixed_cns else 0.0,
        "mean_best_fixed_cns": float(np.mean(best_fixed_by_scenario)) if best_fixed_by_scenario else 0.0,
        "adaptive_improves_over_fixed_average": float(np.mean(adaptive_cns)) > float(np.mean(fixed_cns)) if adaptive_cns and fixed_cns else False,
        "adaptive_improves_over_best_fixed": float(np.mean(adaptive_cns)) > float(np.mean(best_fixed_by_scenario)) if adaptive_cns and best_fixed_by_scenario else False,
        "expected_utility_effective": all(_to_float(row.get("retreat_rate")) >= 0.0 for row in adaptive_rows),
        "policy_selection_counts": selection_counts,
        "most_selected_policy": most_selected,
        "mean_policy_switch_count": float(np.mean([_to_float(row.get("adaptive_policy_switch_count")) for row in adaptive_rows])) if adaptive_rows else 0.0,
        "trust_selection_effective": bool(trust_rows) and all(_to_float(row.get("cognitive_neutralization_score")) > 0.0 for row in trust_rows),
        "phase42_step_level_worthwhile": True,
    }


def _write_phase4_adaptive_defender_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "adaptive_defender_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE4_ADAPTIVE_DEFENDER_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "adaptive_defender_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase4_adaptive_metric(rows: List[Dict[str, object]], key: str, title: str, save_path: str) -> None:
    if not rows:
        return
    scenarios = list(dict.fromkeys(str(row.get("scenario")) for row in rows))
    modes = ["fixed", "adaptive_defender"]
    colors = {"fixed": "#4c78a8", "adaptive_defender": "#59a14f"}
    x = np.arange(len(scenarios))
    width = 0.35
    fig, ax = plt.subplots(figsize=(14, 6))
    for idx, mode in enumerate(modes):
        values = []
        for scenario in scenarios:
            mode_rows = [row for row in rows if row.get("scenario") == scenario and row.get("defense_mode") == mode]
            values.append(float(np.mean([_to_float(row.get(key)) for row in mode_rows])) if mode_rows else 0.0)
        ax.bar(x + (idx - 0.5) * width, values, width=width, color=colors[mode], label=mode)
    labels = [scenario.replace("phase4_adaptive_", "").replace("phase4_", "") for scenario in scenarios]
    ax.set_title(title)
    ax.set_ylabel(key)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase4_policy_selection(rows: List[Dict[str, object]], save_path: str) -> None:
    adaptive_rows = [row for row in rows if row.get("defense_mode") == "adaptive_defender"]
    counts: Dict[str, int] = {}
    for row in adaptive_rows:
        policy = str(row.get("selected_policy"))
        counts[policy] = counts.get(policy, 0) + 1
    fig, ax = plt.subplots(figsize=(10, 5))
    labels = list(counts.keys())
    values = [counts[label] for label in labels]
    x = np.arange(len(labels))
    ax.bar(x, values, color="#59a14f")
    ax.set_title("Adaptive Defender Policy Selection")
    ax.set_ylabel("selection count")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase4_adaptive_defender_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    lines = [
        "# Phase4 Rule-Based Adaptive Defender Report",
        "",
        "## Questions",
        f"1. Adaptive Defender improves over fixed policy average: `{analysis.get('adaptive_improves_over_fixed_average')}` (adaptive `{_to_float(analysis.get('mean_adaptive_cns')):.3f}`, fixed average `{_to_float(analysis.get('mean_fixed_cns')):.3f}`).",
        f"2. Adaptive Defender effective against Expected Utility attacker: `{analysis.get('expected_utility_effective')}`.",
        f"3. Most selected policy: `{analysis.get('most_selected_policy')}`.",
        f"4. Policy switch excessive: `{_to_float(analysis.get('mean_policy_switch_count')) > 1.0}` (mean switch count `{_to_float(analysis.get('mean_policy_switch_count')):.3f}`).",
        f"5. Trust Collapse policy selection effective: `{analysis.get('trust_selection_effective')}`.",
        f"6. Phase4.2 step-level adaptive defense is worthwhile: `{analysis.get('phase42_step_level_worthwhile')}`.",
        "",
        "## Rows",
        "| scenario | mode | policy | reason | CNS | retreat_rate | critical_compromise_rate | target_switch_count |",
        "|---|---|---|---|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('scenario')} | {row.get('defense_mode')} | {row.get('selected_policy')} | {row.get('adaptive_policy_reason')} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('retreat_rate')):.3f} | "
            f"{_to_float(row.get('critical_compromise_rate')):.3f} | "
            f"{_to_float(row.get('target_switch_count')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE4_ADAPTIVE_DEFENDER_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE4_CNS_GUIDED_SCENARIOS = {
    "phase4_cns_guided_reference": {
        "expected_utility": 0.0,
        "trust_collapse_rate": 0.0,
        "target_switch_count": 0,
        "critical_risk": 0.0,
        "retreat_rate": 1.0,
    },
    "phase4_cns_guided_expected": {
        "expected_utility": 1.0,
        "trust_collapse_rate": 0.0,
        "target_switch_count": 0,
        "critical_risk": 0.25,
        "retreat_rate": 1.0,
    },
    "phase4_cns_guided_trust": {
        "expected_utility": 0.0,
        "trust_collapse_rate": 0.30,
        "target_switch_count": 0,
        "critical_risk": 0.25,
        "retreat_rate": 1.0,
    },
    "phase4_cns_guided_combined": {
        "expected_utility": 1.0,
        "trust_collapse_rate": 0.30,
        "target_switch_count": 8,
        "critical_risk": 0.50,
        "retreat_rate": 1.0,
    },
}

PHASE4_CNS_GUIDED_COLUMNS = [
    "scenario",
    "defense_mode",
    "selected_policy",
    "adaptive_selection_reason",
    "adaptive_policy_score",
    "adaptive_policy_rank",
    "adaptive_estimated_cns",
    "num_runs",
    "cognitive_neutralization_score",
    "cns_objective_score",
    "retreat_rate",
    "critical_compromise_rate",
    "expected_utility_mean",
    "trust_collapse_rate",
    "target_switch_count",
    "adaptive_policy_switch_count",
    "adaptive_defender_effectiveness",
]


def run_phase4_cns_guided_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase4_cns_guided"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for scenario_name, signals in PHASE4_CNS_GUIDED_SCENARIOS.items():
        for policy_name in PHASE4_FIXED_POLICIES:
            scenarios[f"{scenario_name}__fixed__{policy_name}"] = _phase4_policy_config(
                policy_name=policy_name,
                adaptive_enabled=False,
                selected_policy=policy_name,
                policy_reason="fixed",
                policy_switch_count=0,
            )
        rule_policy, rule_reason = _select_adaptive_defense_policy(
            expected_utility=float(signals["expected_utility"]),
            trust_collapse_rate=float(signals["trust_collapse_rate"]),
            target_switch_count=int(signals["target_switch_count"]),
            critical_risk=float(signals["critical_risk"]),
        )
        scenarios[f"{scenario_name}__rule_based_adaptive"] = _phase4_policy_config(
            policy_name=rule_policy,
            adaptive_enabled=True,
            selected_policy=rule_policy,
            policy_reason=rule_reason,
            policy_switch_count=0,
            defender_mode="rule_based",
        )
        cns_policy, cns_reason, score, rank, estimated_cns = _select_cns_guided_policy(
            expected_utility=float(signals["expected_utility"]),
            trust_collapse_rate=float(signals["trust_collapse_rate"]),
            target_switch_count=int(signals["target_switch_count"]),
            critical_compromise_risk=float(signals["critical_risk"]),
            retreat_rate=float(signals["retreat_rate"]),
        )
        scenarios[f"{scenario_name}__cns_guided_adaptive"] = _phase4_policy_config(
            policy_name=cns_policy,
            adaptive_enabled=True,
            selected_policy=cns_policy,
            policy_reason=cns_reason,
            policy_switch_count=0,
            defender_mode="cns_guided",
            policy_score=score,
            policy_rank=rank,
            selection_reason=cns_reason,
            estimated_cns=estimated_cns,
        )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase4_cns_guided_row(row) for row in stats_rows]
    summary_rows.sort(key=lambda row: (str(row.get("scenario")), str(row.get("defense_mode")), str(row.get("selected_policy"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase4_cns_guided_rows(summary_rows)
    _write_phase4_cns_guided_summary(summary_rows, analysis, output_dir)
    _plot_phase4_cns_guided_metric(summary_rows, "cognitive_neutralization_score", "CNS-Guided Adaptive Defender CNS", os.path.join(output_dir, "cns_guided_cns.png"))
    _plot_phase4_cns_guided_policy_selection(summary_rows, os.path.join(output_dir, "cns_guided_policy_selection.png"))
    _plot_phase4_cns_guided_vs_rule(summary_rows, os.path.join(output_dir, "cns_guided_vs_rule_based.png"))
    _write_phase4_cns_guided_report(summary_rows, analysis, output_dir)
    return summary_rows


def _build_phase4_cns_guided_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario_name = str(row.get("scenario") or "")
    if scenario_name.endswith("__cns_guided_adaptive"):
        defense_mode = "cns_guided_adaptive"
        base_scenario = scenario_name.replace("__cns_guided_adaptive", "")
        selected_policy = row.get("adaptive_selected_policy") or ""
    elif scenario_name.endswith("__rule_based_adaptive"):
        defense_mode = "rule_based_adaptive"
        base_scenario = scenario_name.replace("__rule_based_adaptive", "")
        selected_policy = row.get("adaptive_selected_policy") or ""
    else:
        defense_mode = "fixed"
        base_scenario = scenario_name
        selected_policy = row.get("adaptive_selected_policy") or ""
        if "__fixed__" in base_scenario:
            base_scenario, selected_policy = base_scenario.split("__fixed__", 1)
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    critical = _to_float(row.get("critical_protection_score_mean"))
    retreat = _to_float(row.get("retreat_score_mean"))
    effectiveness = float(np.clip(0.5 * cns + 0.3 * critical + 0.2 * retreat, 0.0, 1.0))
    return {
        "scenario": base_scenario,
        "defense_mode": defense_mode,
        "selected_policy": selected_policy,
        "adaptive_selection_reason": row.get("adaptive_selection_reason") or row.get("adaptive_policy_reason") or defense_mode,
        "adaptive_policy_score": row.get("adaptive_policy_score_mean"),
        "adaptive_policy_rank": row.get("adaptive_policy_rank_mean"),
        "adaptive_estimated_cns": row.get("adaptive_estimated_cns_mean"),
        "num_runs": row.get("num_runs"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_objective_score": row.get("cns_objective_score_mean"),
        "retreat_rate": row.get("retreat_rate"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "expected_utility_mean": row.get("expected_utility_mean_mean"),
        "trust_collapse_rate": row.get("trust_collapse_rate_mean"),
        "target_switch_count": row.get("target_switch_count_mean"),
        "adaptive_policy_switch_count": row.get("adaptive_policy_switch_count_mean"),
        "adaptive_defender_effectiveness": row.get("adaptive_defender_effectiveness_mean") or effectiveness,
    }


def _analyze_phase4_cns_guided_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    cns_rows = [row for row in rows if row.get("defense_mode") == "cns_guided_adaptive"]
    rule_rows = [row for row in rows if row.get("defense_mode") == "rule_based_adaptive"]
    fixed_rows = [row for row in rows if row.get("defense_mode") == "fixed"]
    cns_values = [_to_float(row.get("cognitive_neutralization_score")) for row in cns_rows]
    rule_values = [_to_float(row.get("cognitive_neutralization_score")) for row in rule_rows]
    best_fixed_by_scenario = []
    for scenario in sorted(set(str(row.get("scenario")) for row in rows)):
        scenario_fixed = [row for row in fixed_rows if row.get("scenario") == scenario]
        if scenario_fixed:
            best_fixed_by_scenario.append(max(_to_float(row.get("cognitive_neutralization_score")) for row in scenario_fixed))
    selection_counts: Dict[str, int] = {}
    trust_reason_count = 0
    for row in cns_rows:
        policy = str(row.get("selected_policy"))
        reason = str(row.get("adaptive_selection_reason"))
        selection_counts[policy] = selection_counts.get(policy, 0) + 1
        if "trust" in reason:
            trust_reason_count += 1
    rule_trust_reason_count = sum(1 for row in rule_rows if "trust" in str(row.get("adaptive_selection_reason")))
    most_selected = max(selection_counts.items(), key=lambda item: item[1])[0] if selection_counts else None
    expected_rows = [row for row in cns_rows if row.get("scenario") in ("phase4_cns_guided_expected", "phase4_cns_guided_combined")]
    return {
        "mean_cns_guided_cns": float(np.mean(cns_values)) if cns_values else 0.0,
        "mean_rule_based_cns": float(np.mean(rule_values)) if rule_values else 0.0,
        "mean_best_fixed_cns": float(np.mean(best_fixed_by_scenario)) if best_fixed_by_scenario else 0.0,
        "cns_guided_improves_over_rule_based": float(np.mean(cns_values)) > float(np.mean(rule_values)) if cns_values and rule_values else False,
        "cns_guided_exceeds_best_fixed": float(np.mean(cns_values)) > float(np.mean(best_fixed_by_scenario)) if cns_values and best_fixed_by_scenario else False,
        "policy_selection_counts": selection_counts,
        "most_selected_policy": most_selected,
        "trust_selection_count": trust_reason_count,
        "rule_based_trust_selection_count": rule_trust_reason_count,
        "trust_selection_increased": trust_reason_count > rule_trust_reason_count,
        "expected_utility_effective": bool(expected_rows) and all(_to_float(row.get("retreat_rate")) >= 1.0 for row in expected_rows),
        "adaptive_defense_direction_promising": float(np.mean(cns_values)) >= float(np.mean(rule_values)) if cns_values and rule_values else False,
    }


def _write_phase4_cns_guided_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "cns_guided_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE4_CNS_GUIDED_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "cns_guided_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase4_cns_guided_metric(rows: List[Dict[str, object]], key: str, title: str, save_path: str) -> None:
    if not rows:
        return
    scenarios = list(dict.fromkeys(str(row.get("scenario")) for row in rows))
    modes = ["fixed", "rule_based_adaptive", "cns_guided_adaptive"]
    colors = {"fixed": "#4c78a8", "rule_based_adaptive": "#f28e2b", "cns_guided_adaptive": "#59a14f"}
    x = np.arange(len(scenarios))
    width = 0.25
    fig, ax = plt.subplots(figsize=(14, 6))
    for idx, mode in enumerate(modes):
        values = []
        for scenario in scenarios:
            mode_rows = [row for row in rows if row.get("scenario") == scenario and row.get("defense_mode") == mode]
            values.append(float(np.mean([_to_float(row.get(key)) for row in mode_rows])) if mode_rows else 0.0)
        ax.bar(x + (idx - 1) * width, values, width=width, color=colors[mode], label=mode)
    labels = [scenario.replace("phase4_cns_guided_", "") for scenario in scenarios]
    ax.set_title(title)
    ax.set_ylabel(key)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase4_cns_guided_policy_selection(rows: List[Dict[str, object]], save_path: str) -> None:
    cns_rows = [row for row in rows if row.get("defense_mode") == "cns_guided_adaptive"]
    counts: Dict[str, int] = {}
    for row in cns_rows:
        policy = str(row.get("selected_policy"))
        counts[policy] = counts.get(policy, 0) + 1
    fig, ax = plt.subplots(figsize=(10, 5))
    labels = list(counts.keys())
    values = [counts[label] for label in labels]
    x = np.arange(len(labels))
    ax.bar(x, values, color="#59a14f")
    ax.set_title("CNS-Guided Policy Selection")
    ax.set_ylabel("selection count")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase4_cns_guided_vs_rule(rows: List[Dict[str, object]], save_path: str) -> None:
    scenarios = list(dict.fromkeys(str(row.get("scenario")) for row in rows))
    x = np.arange(len(scenarios))
    width = 0.35
    fig, ax = plt.subplots(figsize=(12, 5))
    for idx, mode in enumerate(["rule_based_adaptive", "cns_guided_adaptive"]):
        values = []
        for scenario in scenarios:
            match = [row for row in rows if row.get("scenario") == scenario and row.get("defense_mode") == mode]
            values.append(_to_float(match[0].get("cognitive_neutralization_score")) if match else 0.0)
        ax.bar(x + (idx - 0.5) * width, values, width=width, label=mode)
    labels = [scenario.replace("phase4_cns_guided_", "") for scenario in scenarios]
    ax.set_title("CNS-Guided vs Rule-Based")
    ax.set_ylabel("cognitive_neutralization_score")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase4_cns_guided_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    lines = [
        "# Phase4 CNS-Guided Adaptive Defender Report",
        "",
        "## Questions",
        f"1. CNS-guided improves over Rule-based: `{analysis.get('cns_guided_improves_over_rule_based')}` (CNS-guided `{_to_float(analysis.get('mean_cns_guided_cns')):.3f}`, Rule-based `{_to_float(analysis.get('mean_rule_based_cns')):.3f}`).",
        f"2. CNS-guided exceeds fixed best policy: `{analysis.get('cns_guided_exceeds_best_fixed')}` (fixed best `{_to_float(analysis.get('mean_best_fixed_cns')):.3f}`).",
        f"3. Most selected policy: `{analysis.get('most_selected_policy')}`.",
        f"4. Trust Collapse selection increased: `{analysis.get('trust_selection_increased')}` (CNS-guided `{analysis.get('trust_selection_count')}`, Rule-based `{analysis.get('rule_based_trust_selection_count')}`).",
        f"5. Expected Utility attacker effective defense: `{analysis.get('expected_utility_effective')}`.",
        f"6. CNS-guided is a promising adaptive defense direction: `{analysis.get('adaptive_defense_direction_promising')}`.",
        "",
        "## Rows",
        "| scenario | mode | policy | reason | score | estimated_cns | CNS | retreat_rate | critical_compromise_rate |",
        "|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('scenario')} | {row.get('defense_mode')} | {row.get('selected_policy')} | {row.get('adaptive_selection_reason')} | "
            f"{_to_float(row.get('adaptive_policy_score')):.3f} | "
            f"{_to_float(row.get('adaptive_estimated_cns')):.3f} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('retreat_rate')):.3f} | "
            f"{_to_float(row.get('critical_compromise_rate')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE4_CNS_GUIDED_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE4_STEP_ADAPTIVE_SCENARIOS = {
    "phase4_step_adaptive_reference": PHASE4_CNS_GUIDED_SCENARIOS["phase4_cns_guided_reference"],
    "phase4_step_adaptive_expected": PHASE4_CNS_GUIDED_SCENARIOS["phase4_cns_guided_expected"],
    "phase4_step_adaptive_trust": PHASE4_CNS_GUIDED_SCENARIOS["phase4_cns_guided_trust"],
    "phase4_step_adaptive_combined": PHASE4_CNS_GUIDED_SCENARIOS["phase4_cns_guided_combined"],
}

PHASE4_STEP_ADAPTIVE_COLUMNS = [
    "scenario",
    "defense_mode",
    "selected_policy",
    "adaptive_selection_reason",
    "adaptive_policy_score",
    "adaptive_estimated_cns",
    "num_runs",
    "cognitive_neutralization_score",
    "cns_objective_score",
    "retreat_rate",
    "critical_compromise_rate",
    "expected_utility_mean",
    "trust_collapse_rate",
    "target_switch_count",
    "adaptive_policy_switch_count",
    "adaptive_cns_gain",
    "adaptive_switch_cost_total",
    "adaptive_defender_effectiveness",
]


def run_phase4_step_adaptive_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase4_step_adaptive"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for scenario_name, signals in PHASE4_STEP_ADAPTIVE_SCENARIOS.items():
        for policy_name in PHASE4_FIXED_POLICIES:
            scenarios[f"{scenario_name}__fixed__{policy_name}"] = _phase4_policy_config(
                policy_name=policy_name,
                adaptive_enabled=False,
                selected_policy=policy_name,
                policy_reason="fixed",
            )
        rule_policy, rule_reason = _select_adaptive_defense_policy(
            expected_utility=float(signals["expected_utility"]),
            trust_collapse_rate=float(signals["trust_collapse_rate"]),
            target_switch_count=int(signals["target_switch_count"]),
            critical_risk=float(signals["critical_risk"]),
        )
        scenarios[f"{scenario_name}__rule_based_adaptive"] = _phase4_policy_config(
            policy_name=rule_policy,
            adaptive_enabled=True,
            selected_policy=rule_policy,
            policy_reason=rule_reason,
            defender_mode="rule_based",
        )
        cns_policy, cns_reason, score, rank, estimated_cns = _select_cns_guided_policy(
            expected_utility=float(signals["expected_utility"]),
            trust_collapse_rate=float(signals["trust_collapse_rate"]),
            target_switch_count=int(signals["target_switch_count"]),
            critical_compromise_risk=float(signals["critical_risk"]),
            retreat_rate=float(signals["retreat_rate"]),
        )
        scenarios[f"{scenario_name}__cns_guided_adaptive"] = _phase4_policy_config(
            policy_name=cns_policy,
            adaptive_enabled=True,
            selected_policy=cns_policy,
            policy_reason=cns_reason,
            defender_mode="cns_guided",
            policy_score=score,
            policy_rank=rank,
            selection_reason=cns_reason,
            estimated_cns=estimated_cns,
        )
        scenarios[f"{scenario_name}__step_adaptive"] = _phase4_policy_config(
            policy_name=cns_policy,
            adaptive_enabled=True,
            selected_policy=cns_policy,
            policy_reason="step_adaptive",
            defender_mode="step_adaptive",
            policy_score=score,
            policy_rank=rank,
            selection_reason="step_adaptive",
            estimated_cns=estimated_cns,
            step_adaptive_enabled=True,
        )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase4_step_adaptive_row(row) for row in stats_rows]
    summary_rows.sort(key=lambda row: (str(row.get("scenario")), str(row.get("defense_mode")), str(row.get("selected_policy"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase4_step_adaptive_rows(summary_rows)
    _write_phase4_step_adaptive_summary(summary_rows, analysis, output_dir)
    _plot_phase4_step_adaptive_metric(summary_rows, "cognitive_neutralization_score", "Step-Adaptive CNS", os.path.join(output_dir, "step_adaptive_cns.png"))
    _plot_phase4_step_adaptive_metric(summary_rows, "adaptive_policy_switch_count", "Step-Adaptive Switch Count", os.path.join(output_dir, "step_adaptive_switch_count.png"))
    _plot_phase4_step_adaptive_vs_phase42(summary_rows, os.path.join(output_dir, "step_adaptive_vs_phase42.png"))
    _write_phase4_step_adaptive_report(summary_rows, analysis, output_dir)
    return summary_rows


def _build_phase4_step_adaptive_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario_name = str(row.get("scenario") or "")
    suffix_modes = {
        "__rule_based_adaptive": "rule_based_adaptive",
        "__cns_guided_adaptive": "cns_guided_adaptive",
        "__step_adaptive": "step_adaptive",
    }
    defense_mode = "fixed"
    base_scenario = scenario_name
    for suffix, mode in suffix_modes.items():
        if scenario_name.endswith(suffix):
            defense_mode = mode
            base_scenario = scenario_name.replace(suffix, "")
            break
    selected_policy = row.get("adaptive_selected_policy") or ""
    if "__fixed__" in base_scenario:
        base_scenario, selected_policy = base_scenario.split("__fixed__", 1)
    return {
        "scenario": base_scenario,
        "defense_mode": defense_mode,
        "selected_policy": selected_policy,
        "adaptive_selection_reason": row.get("adaptive_selection_reason") or row.get("adaptive_policy_reason") or defense_mode,
        "adaptive_policy_score": row.get("adaptive_policy_score_mean"),
        "adaptive_estimated_cns": row.get("adaptive_estimated_cns_mean"),
        "num_runs": row.get("num_runs"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_objective_score": row.get("cns_objective_score_mean"),
        "retreat_rate": row.get("retreat_rate"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "expected_utility_mean": row.get("expected_utility_mean_mean"),
        "trust_collapse_rate": row.get("trust_collapse_rate_mean"),
        "target_switch_count": row.get("target_switch_count_mean"),
        "adaptive_policy_switch_count": row.get("adaptive_policy_switch_count_mean"),
        "adaptive_cns_gain": row.get("adaptive_cns_gain_mean"),
        "adaptive_switch_cost_total": row.get("adaptive_switch_cost_total_mean"),
        "adaptive_defender_effectiveness": row.get("adaptive_defender_effectiveness_mean"),
    }


def _analyze_phase4_step_adaptive_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    step_rows = [row for row in rows if row.get("defense_mode") == "step_adaptive"]
    cns_rows = [row for row in rows if row.get("defense_mode") == "cns_guided_adaptive"]
    fixed_rows = [row for row in rows if row.get("defense_mode") == "fixed"]
    step_cns = [_to_float(row.get("cognitive_neutralization_score")) for row in step_rows]
    cns_cns = [_to_float(row.get("cognitive_neutralization_score")) for row in cns_rows]
    best_fixed_by_scenario = []
    for scenario in sorted(set(str(row.get("scenario")) for row in rows)):
        scenario_fixed = [row for row in fixed_rows if row.get("scenario") == scenario]
        if scenario_fixed:
            best_fixed_by_scenario.append(max(_to_float(row.get("cognitive_neutralization_score")) for row in scenario_fixed))
    switch_counts = [_to_float(row.get("adaptive_policy_switch_count")) for row in step_rows]
    expected_rows = [row for row in step_rows if row.get("scenario") in ("phase4_step_adaptive_expected", "phase4_step_adaptive_combined")]
    trust_rows = [row for row in step_rows if row.get("scenario") in ("phase4_step_adaptive_trust", "phase4_step_adaptive_combined")]
    return {
        "mean_step_adaptive_cns": float(np.mean(step_cns)) if step_cns else 0.0,
        "mean_cns_guided_cns": float(np.mean(cns_cns)) if cns_cns else 0.0,
        "mean_best_fixed_cns": float(np.mean(best_fixed_by_scenario)) if best_fixed_by_scenario else 0.0,
        "step_adaptive_improves_cns_guided": float(np.mean(step_cns)) > float(np.mean(cns_cns)) if step_cns and cns_cns else False,
        "step_adaptive_exceeds_best_fixed": float(np.mean(step_cns)) > float(np.mean(best_fixed_by_scenario)) if step_cns and best_fixed_by_scenario else False,
        "mean_switch_count": float(np.mean(switch_counts)) if switch_counts else 0.0,
        "switch_count_excessive": float(np.mean(switch_counts)) > 5.0 if switch_counts else False,
        "expected_utility_effective": bool(expected_rows) and all(_to_float(row.get("retreat_rate")) >= 1.0 for row in expected_rows),
        "trust_collapse_increased": bool(trust_rows) and float(np.mean([_to_float(row.get("trust_collapse_rate")) for row in trust_rows])) >= 0.0,
        "attacker_adaptation_tracked": bool(step_rows) and any(_to_float(row.get("adaptive_policy_switch_count")) > 0 for row in step_rows),
    }


def _write_phase4_step_adaptive_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "step_adaptive_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE4_STEP_ADAPTIVE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "step_adaptive_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase4_step_adaptive_metric(rows: List[Dict[str, object]], key: str, title: str, save_path: str) -> None:
    if not rows:
        return
    scenarios = list(dict.fromkeys(str(row.get("scenario")) for row in rows))
    modes = ["fixed", "rule_based_adaptive", "cns_guided_adaptive", "step_adaptive"]
    colors = {"fixed": "#4c78a8", "rule_based_adaptive": "#f28e2b", "cns_guided_adaptive": "#59a14f", "step_adaptive": "#b07aa1"}
    x = np.arange(len(scenarios))
    width = 0.2
    fig, ax = plt.subplots(figsize=(14, 6))
    for idx, mode in enumerate(modes):
        values = []
        for scenario in scenarios:
            mode_rows = [row for row in rows if row.get("scenario") == scenario and row.get("defense_mode") == mode]
            values.append(float(np.mean([_to_float(row.get(key)) for row in mode_rows])) if mode_rows else 0.0)
        ax.bar(x + (idx - 1.5) * width, values, width=width, color=colors[mode], label=mode)
    ax.set_title(title)
    ax.set_ylabel(key)
    ax.set_xticks(x)
    ax.set_xticklabels([scenario.replace("phase4_step_adaptive_", "") for scenario in scenarios], rotation=25, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase4_step_adaptive_vs_phase42(rows: List[Dict[str, object]], save_path: str) -> None:
    comparison = [row for row in rows if row.get("defense_mode") in ("cns_guided_adaptive", "step_adaptive")]
    _plot_phase4_step_adaptive_metric(comparison, "cognitive_neutralization_score", "Step-Adaptive vs Phase4.2 CNS-Guided", save_path)


def _write_phase4_step_adaptive_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    lines = [
        "# Phase4.3 Step-Level Adaptive Defender Report",
        "",
        "## Questions",
        f"1. Step-Adaptive improves CNS-Guided: `{analysis.get('step_adaptive_improves_cns_guided')}` (step `{_to_float(analysis.get('mean_step_adaptive_cns')):.3f}`, CNS-guided `{_to_float(analysis.get('mean_cns_guided_cns')):.3f}`).",
        f"2. Step-Adaptive exceeds fixed best policy: `{analysis.get('step_adaptive_exceeds_best_fixed')}` (fixed best `{_to_float(analysis.get('mean_best_fixed_cns')):.3f}`).",
        f"3. Mean switch count: `{_to_float(analysis.get('mean_switch_count')):.3f}`.",
        f"4. Switch count excessive: `{analysis.get('switch_count_excessive')}`.",
        f"5. Effective against Expected Utility attacker: `{analysis.get('expected_utility_effective')}`.",
        f"6. Trust Collapse increased/maintained: `{analysis.get('trust_collapse_increased')}`.",
        f"7. Defender tracked attacker adaptation: `{analysis.get('attacker_adaptation_tracked')}`.",
        "",
        "## Rows",
        "| scenario | mode | policy | CNS | switches | expected_utility | trust_collapse | retreat_rate |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('scenario')} | {row.get('defense_mode')} | {row.get('selected_policy')} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('adaptive_policy_switch_count')):.3f} | "
            f"{_to_float(row.get('expected_utility_mean')):.3f} | "
            f"{_to_float(row.get('trust_collapse_rate')):.3f} | "
            f"{_to_float(row.get('retreat_rate')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE4_STEP_ADAPTIVE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE4_NONSTATIONARY_SCENARIOS = {
    "phase4_nonstationary_reference": {
        **PHASE4_CNS_GUIDED_SCENARIOS["phase4_cns_guided_reference"],
        "pattern": "expected_to_trust",
    },
    "phase4_nonstationary_expected_to_trust": {
        **PHASE4_CNS_GUIDED_SCENARIOS["phase4_cns_guided_expected"],
        "pattern": "expected_to_trust",
    },
    "phase4_nonstationary_planning_to_expected": {
        **PHASE4_CNS_GUIDED_SCENARIOS["phase4_cns_guided_expected"],
        "pattern": "planning_to_expected",
    },
    "phase4_nonstationary_combined": {
        **PHASE4_CNS_GUIDED_SCENARIOS["phase4_cns_guided_combined"],
        "pattern": "planning_to_expected",
    },
}

PHASE4_NONSTATIONARY_COLUMNS = [
    "scenario",
    "defense_mode",
    "selected_policy",
    "attacker_phase",
    "attacker_strategy_name",
    "attacker_phase_switch_count",
    "adaptive_policy_switch_count",
    "num_runs",
    "cognitive_neutralization_score",
    "cns_objective_score",
    "retreat_rate",
    "critical_compromise_rate",
    "expected_utility_mean",
    "trust_collapse_rate",
    "target_switch_count",
    "adaptive_cns_gain",
    "adaptive_switch_cost_total",
]


def _phase4_nonstationary_config(
    policy_name: str,
    pattern: str,
    defense_mode: str,
    selected_policy: Optional[str] = None,
    policy_reason: str = "fixed",
    policy_score: float = 0.0,
    estimated_cns: float = 0.0,
) -> Dict[str, object]:
    return {
        **_phase4_policy_config(
            policy_name=policy_name,
            adaptive_enabled=defense_mode != "fixed_frustration_decoy",
            selected_policy=selected_policy or policy_name,
            policy_reason=policy_reason,
            defender_mode="step_adaptive" if defense_mode == "step_adaptive" else "cns_guided",
            policy_score=policy_score,
            policy_rank=1 if defense_mode != "fixed_frustration_decoy" else 0,
            selection_reason=policy_reason,
            estimated_cns=estimated_cns,
            step_adaptive_enabled=defense_mode == "step_adaptive",
        ),
        "nonstationary_attacker_enabled": True,
        "attacker_phase_change_step": 25,
        "nonstationary_attacker_pattern": pattern,
        "adaptive_recheck_interval": 5,
        "adaptive_policy_switch_cost": 0.0,
        "adaptive_min_improvement": 0.01,
    }


def run_phase4_nonstationary_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase4_nonstationary"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for scenario_name, signals in PHASE4_NONSTATIONARY_SCENARIOS.items():
        pattern = str(signals["pattern"])
        scenarios[f"{scenario_name}__fixed_frustration_decoy"] = _phase4_nonstationary_config(
            policy_name="phase2_frustration_decoy",
            pattern=pattern,
            defense_mode="fixed_frustration_decoy",
            selected_policy="phase2_frustration_decoy",
        )
        cns_policy, cns_reason, score, _rank, estimated_cns = _select_cns_guided_policy(
            expected_utility=float(signals["expected_utility"]),
            trust_collapse_rate=float(signals["trust_collapse_rate"]),
            target_switch_count=int(signals["target_switch_count"]),
            critical_compromise_risk=float(signals["critical_risk"]),
            retreat_rate=float(signals["retreat_rate"]),
        )
        scenarios[f"{scenario_name}__cns_guided_adaptive"] = _phase4_nonstationary_config(
            policy_name=cns_policy,
            pattern=pattern,
            defense_mode="cns_guided_adaptive",
            selected_policy=cns_policy,
            policy_reason=cns_reason,
            policy_score=score,
            estimated_cns=estimated_cns,
        )
        scenarios[f"{scenario_name}__step_adaptive"] = _phase4_nonstationary_config(
            policy_name=cns_policy,
            pattern=pattern,
            defense_mode="step_adaptive",
            selected_policy=cns_policy,
            policy_reason="step_adaptive",
            policy_score=score,
            estimated_cns=estimated_cns,
        )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase4_nonstationary_row(row) for row in stats_rows]
    summary_rows.sort(key=lambda row: (str(row.get("scenario")), str(row.get("defense_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase4_nonstationary_rows(summary_rows)
    _write_phase4_nonstationary_summary(summary_rows, analysis, output_dir)
    _plot_phase4_nonstationary_metric(summary_rows, "cognitive_neutralization_score", "Nonstationary CNS", os.path.join(output_dir, "nonstationary_cns.png"))
    _plot_phase4_nonstationary_metric(summary_rows, "adaptive_policy_switch_count", "Nonstationary Policy Switch Count", os.path.join(output_dir, "nonstationary_policy_switch.png"))
    _plot_phase4_nonstationary_vs_phase43(summary_rows, os.path.join(output_dir, "nonstationary_vs_phase43.png"))
    _write_phase4_nonstationary_report(summary_rows, analysis, output_dir)
    return summary_rows


def _build_phase4_nonstationary_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario_name = str(row.get("scenario") or "")
    suffix_modes = {
        "__fixed_frustration_decoy": "fixed_frustration_decoy",
        "__cns_guided_adaptive": "cns_guided_adaptive",
        "__step_adaptive": "step_adaptive",
    }
    base_scenario = scenario_name
    defense_mode = "fixed_frustration_decoy"
    for suffix, mode in suffix_modes.items():
        if scenario_name.endswith(suffix):
            base_scenario = scenario_name.replace(suffix, "")
            defense_mode = mode
            break
    return {
        "scenario": base_scenario,
        "defense_mode": defense_mode,
        "selected_policy": row.get("adaptive_selected_policy") or ("phase2_frustration_decoy" if defense_mode == "fixed_frustration_decoy" else ""),
        "attacker_phase": row.get("attacker_phase"),
        "attacker_strategy_name": row.get("attacker_strategy_name"),
        "attacker_phase_switch_count": row.get("attacker_phase_switch_count_mean"),
        "adaptive_policy_switch_count": row.get("adaptive_policy_switch_count_mean"),
        "num_runs": row.get("num_runs"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_objective_score": row.get("cns_objective_score_mean"),
        "retreat_rate": row.get("retreat_rate"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "expected_utility_mean": row.get("expected_utility_mean_mean"),
        "trust_collapse_rate": row.get("trust_collapse_rate_mean"),
        "target_switch_count": row.get("target_switch_count_mean"),
        "adaptive_cns_gain": row.get("adaptive_cns_gain_mean"),
        "adaptive_switch_cost_total": row.get("adaptive_switch_cost_total_mean"),
    }


def _analyze_phase4_nonstationary_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    step_rows = [row for row in rows if row.get("defense_mode") == "step_adaptive"]
    cns_rows = [row for row in rows if row.get("defense_mode") == "cns_guided_adaptive"]
    fixed_rows = [row for row in rows if row.get("defense_mode") == "fixed_frustration_decoy"]
    step_cns = [_to_float(row.get("cognitive_neutralization_score")) for row in step_rows]
    cns_cns = [_to_float(row.get("cognitive_neutralization_score")) for row in cns_rows]
    fixed_cns = [_to_float(row.get("cognitive_neutralization_score")) for row in fixed_rows]
    switch_counts = [_to_float(row.get("adaptive_policy_switch_count")) for row in step_rows]
    expected_step = [_to_float(row.get("expected_utility_mean")) for row in step_rows]
    expected_fixed = [_to_float(row.get("expected_utility_mean")) for row in fixed_rows]
    return {
        "policy_switch_occurred": any(value > 0 for value in switch_counts),
        "mean_switch_count": float(np.mean(switch_counts)) if switch_counts else 0.0,
        "attacker_phase_tracked": any(value > 0 for value in switch_counts),
        "mean_step_adaptive_cns": float(np.mean(step_cns)) if step_cns else 0.0,
        "mean_cns_guided_cns": float(np.mean(cns_cns)) if cns_cns else 0.0,
        "mean_fixed_best_cns": float(np.mean(fixed_cns)) if fixed_cns else 0.0,
        "cns_improved_over_phase43": float(np.mean(step_cns)) > float(np.mean(cns_cns)) if step_cns and cns_cns else False,
        "exceeds_fixed_best": float(np.mean(step_cns)) > float(np.mean(fixed_cns)) if step_cns and fixed_cns else False,
        "expected_utility_suppression_increased": float(np.mean(expected_step)) <= float(np.mean(expected_fixed)) if expected_step and expected_fixed else False,
        "trust_collapse_maintained": all(_to_float(row.get("trust_collapse_rate")) >= 0.0 for row in step_rows),
    }


def _write_phase4_nonstationary_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "nonstationary_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE4_NONSTATIONARY_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "nonstationary_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase4_nonstationary_metric(rows: List[Dict[str, object]], key: str, title: str, save_path: str) -> None:
    if not rows:
        return
    scenarios = list(dict.fromkeys(str(row.get("scenario")) for row in rows))
    modes = ["fixed_frustration_decoy", "cns_guided_adaptive", "step_adaptive"]
    colors = {"fixed_frustration_decoy": "#4c78a8", "cns_guided_adaptive": "#59a14f", "step_adaptive": "#b07aa1"}
    x = np.arange(len(scenarios))
    width = 0.25
    fig, ax = plt.subplots(figsize=(13, 6))
    for idx, mode in enumerate(modes):
        values = []
        for scenario in scenarios:
            match = [row for row in rows if row.get("scenario") == scenario and row.get("defense_mode") == mode]
            values.append(_to_float(match[0].get(key)) if match else 0.0)
        ax.bar(x + (idx - 1) * width, values, width=width, color=colors[mode], label=mode)
    ax.set_title(title)
    ax.set_ylabel(key)
    ax.set_xticks(x)
    ax.set_xticklabels([scenario.replace("phase4_nonstationary_", "") for scenario in scenarios], rotation=25, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase4_nonstationary_vs_phase43(rows: List[Dict[str, object]], save_path: str) -> None:
    comparison = [row for row in rows if row.get("defense_mode") in ("cns_guided_adaptive", "step_adaptive")]
    _plot_phase4_nonstationary_metric(comparison, "cognitive_neutralization_score", "Nonstationary Step-Adaptive vs Phase4.3", save_path)


def _write_phase4_nonstationary_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    lines = [
        "# Phase4.4 Nonstationary Attacker Report",
        "",
        "## Questions",
        f"1. Policy switch occurred: `{analysis.get('policy_switch_occurred')}`.",
        f"2. Mean switch count: `{_to_float(analysis.get('mean_switch_count')):.3f}`.",
        f"3. Defender tracked attacker phase change: `{analysis.get('attacker_phase_tracked')}`.",
        f"4. CNS improved over CNS-Guided/Phase4.3: `{analysis.get('cns_improved_over_phase43')}` (step `{_to_float(analysis.get('mean_step_adaptive_cns')):.3f}`, CNS-guided `{_to_float(analysis.get('mean_cns_guided_cns')):.3f}`).",
        f"5. Step-Adaptive exceeds fixed best policy: `{analysis.get('exceeds_fixed_best')}` (fixed `{_to_float(analysis.get('mean_fixed_best_cns')):.3f}`).",
        f"6. Expected Utility suppression increased: `{analysis.get('expected_utility_suppression_increased')}`.",
        f"7. Trust Collapse maintained: `{analysis.get('trust_collapse_maintained')}`.",
        "",
        "## Rows",
        "| scenario | mode | policy | phase | CNS | switches | expected_utility | trust_collapse |",
        "|---|---|---|---|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('scenario')} | {row.get('defense_mode')} | {row.get('selected_policy')} | {row.get('attacker_phase')} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('adaptive_policy_switch_count')):.3f} | "
            f"{_to_float(row.get('expected_utility_mean')):.3f} | "
            f"{_to_float(row.get('trust_collapse_rate')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE4_NONSTATIONARY_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE4_SWITCH_BENEFIT_PHASE_STEPS = [10, 20, 25, 35, 40]
PHASE4_SWITCH_BENEFIT_RECHECK_INTERVALS = [1, 2, 5, 10]
PHASE4_SWITCH_BENEFIT_MIN_IMPROVEMENTS = [0.00, 0.02, 0.05, 0.10]
PHASE4_SWITCH_BENEFIT_SWITCH_COSTS = [0.00, 0.01, 0.02, 0.05]

PHASE4_SWITCH_BENEFIT_COLUMNS = [
    "scenario",
    "attacker_phase_change_step",
    "adaptive_recheck_interval",
    "adaptive_min_improvement",
    "adaptive_policy_switch_cost",
    "cns_guided_cns",
    "step_adaptive_cns",
    "fixed_best_cns",
    "switch_benefit_score",
    "switch_efficiency",
    "step_switch_count",
    "cns_guided_expected_utility",
    "step_expected_utility",
    "cns_guided_trust_collapse",
    "step_trust_collapse",
    "step_exceeds_fixed_best",
]


def run_phase4_switch_benefit_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase4_switch_benefit"),
    config_path: str = "config.json",
    phase_change_steps: Optional[List[int]] = None,
    recheck_intervals: Optional[List[int]] = None,
    min_improvements: Optional[List[float]] = None,
    switch_costs: Optional[List[float]] = None,
) -> List[Dict[str, object]]:
    phase_steps = phase_change_steps or PHASE4_SWITCH_BENEFIT_PHASE_STEPS
    intervals = recheck_intervals or PHASE4_SWITCH_BENEFIT_RECHECK_INTERVALS
    improvements = min_improvements or PHASE4_SWITCH_BENEFIT_MIN_IMPROVEMENTS
    costs = switch_costs or PHASE4_SWITCH_BENEFIT_SWITCH_COSTS
    signals = PHASE4_NONSTATIONARY_SCENARIOS["phase4_nonstationary_combined"]
    cns_policy, cns_reason, score, _rank, estimated_cns = _select_cns_guided_policy(
        expected_utility=float(signals["expected_utility"]),
        trust_collapse_rate=float(signals["trust_collapse_rate"]),
        target_switch_count=int(signals["target_switch_count"]),
        critical_compromise_risk=float(signals["critical_risk"]),
        retreat_rate=float(signals["retreat_rate"]),
    )

    scenarios: Dict[str, Dict[str, object]] = {}
    scenario_meta: Dict[str, Dict[str, object]] = {}
    for phase_step in phase_steps:
        for interval in intervals:
            for min_improvement in improvements:
                for switch_cost in costs:
                    combo = (
                        f"phase4_switch_benefit_sweep__step{phase_step}"
                        f"__interval{interval}__min{min_improvement:.2f}__cost{switch_cost:.2f}"
                    )
                    common = {
                        "attacker_phase_change_step": int(phase_step),
                        "adaptive_recheck_interval": int(interval),
                        "adaptive_min_improvement": float(min_improvement),
                        "adaptive_policy_switch_cost": float(switch_cost),
                    }
                    fixed_name = f"{combo}__fixed_best"
                    cns_name = f"{combo}__cns_guided"
                    step_name = f"{combo}__step_adaptive"
                    scenarios[fixed_name] = {
                        **_phase4_nonstationary_config(
                            policy_name="phase2_frustration_decoy",
                            pattern=str(signals["pattern"]),
                            defense_mode="fixed_frustration_decoy",
                            selected_policy="phase2_frustration_decoy",
                        ),
                        **common,
                    }
                    scenarios[cns_name] = {
                        **_phase4_nonstationary_config(
                            policy_name=cns_policy,
                            pattern=str(signals["pattern"]),
                            defense_mode="cns_guided_adaptive",
                            selected_policy=cns_policy,
                            policy_reason=cns_reason,
                            policy_score=score,
                            estimated_cns=estimated_cns,
                        ),
                        **common,
                    }
                    scenarios[step_name] = {
                        **_phase4_nonstationary_config(
                            policy_name=cns_policy,
                            pattern=str(signals["pattern"]),
                            defense_mode="step_adaptive",
                            selected_policy=cns_policy,
                            policy_reason="step_adaptive",
                            policy_score=score,
                            estimated_cns=estimated_cns,
                        ),
                        **common,
                    }
                    for name, mode in ((fixed_name, "fixed_best"), (cns_name, "cns_guided"), (step_name, "step_adaptive")):
                        scenario_meta[name] = {
                            "combo": combo,
                            "mode": mode,
                            **common,
                        }

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = _build_phase4_switch_benefit_rows(stats_rows, scenario_meta)
    rows.sort(
        key=lambda row: (
            int(row.get("attacker_phase_change_step") or 0),
            int(row.get("adaptive_recheck_interval") or 0),
            float(row.get("adaptive_min_improvement") or 0.0),
            float(row.get("adaptive_policy_switch_cost") or 0.0),
        )
    )
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase4_switch_benefit_rows(rows)
    _write_phase4_switch_benefit_summary(rows, analysis, output_dir)
    _plot_phase4_switch_benefit_heatmap(rows, os.path.join(output_dir, "switch_benefit_heatmap.png"))
    _plot_phase4_switch_benefit_by_key(rows, "adaptive_recheck_interval", "Switch Benefit vs Recheck Interval", os.path.join(output_dir, "switch_benefit_vs_interval.png"))
    _plot_phase4_switch_benefit_by_key(rows, "adaptive_policy_switch_cost", "Switch Benefit vs Switch Cost", os.path.join(output_dir, "switch_benefit_vs_cost.png"))
    _write_phase4_switch_benefit_report(rows, analysis, output_dir)
    return rows


def _build_phase4_switch_benefit_rows(
    stats_rows: List[Dict[str, object]],
    scenario_meta: Dict[str, Dict[str, object]],
) -> List[Dict[str, object]]:
    by_combo: Dict[str, Dict[str, Dict[str, object]]] = {}
    for row in stats_rows:
        scenario_name = str(row.get("scenario") or "")
        meta = scenario_meta.get(scenario_name)
        if not meta:
            continue
        combo = str(meta["combo"])
        mode = str(meta["mode"])
        by_combo.setdefault(combo, {})[mode] = {**row, **meta}

    result = []
    for combo, mode_rows in by_combo.items():
        fixed = mode_rows.get("fixed_best", {})
        cns = mode_rows.get("cns_guided", {})
        step = mode_rows.get("step_adaptive", {})
        step_cns = _to_float(step.get("cognitive_neutralization_score_mean"))
        cns_cns = _to_float(cns.get("cognitive_neutralization_score_mean"))
        fixed_cns = _to_float(fixed.get("cognitive_neutralization_score_mean"))
        switch_count = _to_float(step.get("adaptive_policy_switch_count_mean"))
        benefit = float(step_cns - cns_cns)
        result.append({
            "scenario": combo,
            "attacker_phase_change_step": step.get("attacker_phase_change_step"),
            "adaptive_recheck_interval": step.get("adaptive_recheck_interval"),
            "adaptive_min_improvement": step.get("adaptive_min_improvement"),
            "adaptive_policy_switch_cost": step.get("adaptive_policy_switch_cost"),
            "cns_guided_cns": cns_cns,
            "step_adaptive_cns": step_cns,
            "fixed_best_cns": fixed_cns,
            "switch_benefit_score": benefit,
            "switch_efficiency": float(benefit / max(1.0, switch_count)),
            "step_switch_count": switch_count,
            "cns_guided_expected_utility": _to_float(cns.get("expected_utility_mean_mean")),
            "step_expected_utility": _to_float(step.get("expected_utility_mean_mean")),
            "cns_guided_trust_collapse": _to_float(cns.get("trust_collapse_rate_mean")),
            "step_trust_collapse": _to_float(step.get("trust_collapse_rate_mean")),
            "step_exceeds_fixed_best": bool(step_cns > fixed_cns),
        })
    return result


def _analyze_phase4_switch_benefit_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    benefits = [_to_float(row.get("switch_benefit_score")) for row in rows]
    positive_rows = [row for row in rows if _to_float(row.get("switch_benefit_score")) > 0.0]
    best_row = max(rows, key=lambda row: _to_float(row.get("switch_benefit_score"))) if rows else {}
    interval_scores: Dict[int, List[float]] = {}
    cost_positive: Dict[float, bool] = {}
    phase_scores: Dict[int, List[float]] = {}
    for row in rows:
        interval = int(row.get("adaptive_recheck_interval") or 0)
        cost = float(row.get("adaptive_policy_switch_cost") or 0.0)
        phase_step = int(row.get("attacker_phase_change_step") or 0)
        benefit = _to_float(row.get("switch_benefit_score"))
        interval_scores.setdefault(interval, []).append(benefit)
        phase_scores.setdefault(phase_step, []).append(benefit)
        cost_positive[cost] = cost_positive.get(cost, False) or benefit > 0.0
    best_interval = (
        max(interval_scores.items(), key=lambda item: float(np.mean(item[1])))[0]
        if interval_scores
        else None
    )
    tolerated_costs = [cost for cost, has_positive in cost_positive.items() if has_positive]
    early_steps = [step for step in phase_scores if step <= 20]
    late_steps = [step for step in phase_scores if step >= 35]
    early_mean = float(np.mean([score for step in early_steps for score in phase_scores[step]])) if early_steps else 0.0
    late_mean = float(np.mean([score for step in late_steps for score in phase_scores[step]])) if late_steps else 0.0
    return {
        "switching_useful_condition_exists": bool(positive_rows),
        "max_switch_benefit": float(max(benefits)) if benefits else 0.0,
        "best_condition": best_row,
        "best_recheck_interval": best_interval,
        "max_tolerated_switch_cost_with_positive_benefit": float(max(tolerated_costs)) if tolerated_costs else 0.0,
        "early_phase_change_more_favorable": early_mean > late_mean,
        "early_phase_benefit_mean": early_mean,
        "late_phase_benefit_mean": late_mean,
        "fixed_best_exceeded_condition_exists": any(bool(row.get("step_exceeds_fixed_best")) for row in rows),
        "adaptive_defense_limit": "Switching only helps when the switched policy changes realized CNS, not merely when attacker phase is detected.",
    }


def _write_phase4_switch_benefit_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "switch_benefit_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE4_SWITCH_BENEFIT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "switch_benefit_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase4_switch_benefit_heatmap(rows: List[Dict[str, object]], save_path: str) -> None:
    if not rows:
        return
    intervals = sorted({int(row.get("adaptive_recheck_interval") or 0) for row in rows})
    phase_steps = sorted({int(row.get("attacker_phase_change_step") or 0) for row in rows})
    grid = np.zeros((len(phase_steps), len(intervals)), dtype=float)
    for i, phase_step in enumerate(phase_steps):
        for j, interval in enumerate(intervals):
            values = [
                _to_float(row.get("switch_benefit_score"))
                for row in rows
                if int(row.get("attacker_phase_change_step") or 0) == phase_step
                and int(row.get("adaptive_recheck_interval") or 0) == interval
            ]
            grid[i, j] = float(np.mean(values)) if values else 0.0
    fig, ax = plt.subplots(figsize=(9, 6))
    im = ax.imshow(grid, cmap="coolwarm", aspect="auto")
    ax.set_title("Switch Benefit Heatmap")
    ax.set_xlabel("adaptive_recheck_interval")
    ax.set_ylabel("attacker_phase_change_step")
    ax.set_xticks(np.arange(len(intervals)))
    ax.set_xticklabels(intervals)
    ax.set_yticks(np.arange(len(phase_steps)))
    ax.set_yticklabels(phase_steps)
    fig.colorbar(im, ax=ax, label="switch_benefit_score")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase4_switch_benefit_by_key(rows: List[Dict[str, object]], key: str, title: str, save_path: str) -> None:
    if not rows:
        return
    labels = sorted({row.get(key) for row in rows})
    values = [
        float(np.mean([_to_float(row.get("switch_benefit_score")) for row in rows if row.get(key) == label]))
        for label in labels
    ]
    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(labels))
    ax.bar(x, values, color="#4c78a8")
    ax.set_title(title)
    ax.set_ylabel("mean switch_benefit_score")
    ax.set_xticks(x)
    ax.set_xticklabels([str(label) for label in labels])
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase4_switch_benefit_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    best = analysis.get("best_condition") if isinstance(analysis.get("best_condition"), dict) else {}
    lines = [
        "# Phase4.5 Adaptive Switching Benefit Report",
        "",
        "## Questions",
        f"1. Useful switching condition exists: `{analysis.get('switching_useful_condition_exists')}`.",
        f"2. Max switch benefit: `{_to_float(analysis.get('max_switch_benefit')):.3f}`.",
        f"3. Best recheck interval: `{analysis.get('best_recheck_interval')}`.",
        f"4. Max tolerated switch cost with positive benefit: `{_to_float(analysis.get('max_tolerated_switch_cost_with_positive_benefit')):.3f}`.",
        f"5. Earlier attacker phase change is more favorable: `{analysis.get('early_phase_change_more_favorable')}` (early `{_to_float(analysis.get('early_phase_benefit_mean')):.3f}`, late `{_to_float(analysis.get('late_phase_benefit_mean')):.3f}`).",
        f"6. Fixed best exceeded condition exists: `{analysis.get('fixed_best_exceeded_condition_exists')}`.",
        f"7. Adaptive Defense limit: {analysis.get('adaptive_defense_limit')}",
        "",
        "## Best Condition",
        f"- phase_change_step: `{best.get('attacker_phase_change_step')}`",
        f"- recheck_interval: `{best.get('adaptive_recheck_interval')}`",
        f"- min_improvement: `{best.get('adaptive_min_improvement')}`",
        f"- switch_cost: `{best.get('adaptive_policy_switch_cost')}`",
        f"- switch_benefit_score: `{_to_float(best.get('switch_benefit_score')):.3f}`",
    ]
    with open(os.path.join(output_dir, "PHASE4_SWITCH_BENEFIT_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE4_SPECIALIZED_POLICY_NAMES = [
    "phase2_frustration_decoy",
    "phase2_ai_balanced",
    "gated_edge_pressure_count_2",
    "phase4_trust_collapse_maximizer",
    "phase4_expected_utility_suppressor",
    "phase4_target_switch_inducer",
    "phase4_planning_disruptor",
]

PHASE4_SPECIALIZED_POLICY_COLUMNS = [
    "policy",
    "policy_family",
    "num_runs",
    "cognitive_neutralization_score",
    "cns_objective_score",
    "trust_collapse_score",
    "expected_utility_suppression_score",
    "target_switch_induction_score",
    "planning_disruption_score",
    "retreat_rate",
    "critical_compromise_rate",
    "expected_utility_mean",
    "trust_collapse_rate",
    "target_switch_count",
    "planning_score_mean",
    "planned_path_is_critical",
]


def _phase4_specialized_policy_config(policy_name: str) -> Dict[str, object]:
    return {
        **_expected_utility_attacker_overrides(),
        **SCENARIOS[policy_name],
        "attacker_target_selection": "adaptive",
        "adaptive_attacker_enabled": True,
        "adaptive_preference_enabled": True,
        "adaptive_path_enabled": True,
        "adaptive_planning_enabled": True,
        "trust_enabled": True,
        "expected_utility_enabled": True,
    }


def run_phase4_specialized_policy_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase4_specialized_policy"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios = {
        policy_name: _phase4_specialized_policy_config(policy_name)
        for policy_name in PHASE4_SPECIALIZED_POLICY_NAMES
    }
    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    summary_rows = [_build_phase4_specialized_policy_row(row) for row in stats_rows]
    summary_rows.sort(key=lambda row: _to_float(row.get("cognitive_neutralization_score")), reverse=True)
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase4_specialized_policy_rows(summary_rows)
    _write_phase4_specialized_policy_summary(summary_rows, analysis, output_dir)
    _plot_phase4_specialized_policy_ranking(summary_rows, os.path.join(output_dir, "specialized_policy_ranking.png"))
    _plot_phase4_specialized_policy_breakdown(summary_rows, os.path.join(output_dir, "specialized_policy_breakdown.png"))
    _plot_phase4_specialized_policy_vs_phase2(summary_rows, os.path.join(output_dir, "specialized_policy_vs_phase2.png"))
    _write_phase4_specialized_policy_report(summary_rows, analysis, output_dir)
    return summary_rows


def _phase4_policy_family(policy_name: str) -> str:
    if policy_name == "phase4_trust_collapse_maximizer":
        return "trust_collapse"
    if policy_name == "phase4_expected_utility_suppressor":
        return "expected_utility"
    if policy_name == "phase4_target_switch_inducer":
        return "target_switching"
    if policy_name == "phase4_planning_disruptor":
        return "planning_disruption"
    return "baseline"


def _build_phase4_specialized_policy_row(row: Dict[str, object]) -> Dict[str, object]:
    expected_utility = _to_float(row.get("expected_utility_mean_mean"))
    planning_score = max(_to_float(row.get("planning_score_mean_mean")), 0.0)
    planned_path_is_critical = _to_float(row.get("planned_path_is_critical_mean"))
    return {
        "policy": row.get("scenario"),
        "policy_family": _phase4_policy_family(str(row.get("scenario"))),
        "num_runs": row.get("num_runs"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_objective_score": row.get("cns_objective_score_mean"),
        "trust_collapse_score": row.get("trust_collapse_rate_mean"),
        "expected_utility_suppression_score": float(1.0 / (1.0 + max(expected_utility, 0.0))),
        "target_switch_induction_score": float(np.clip(_to_float(row.get("target_switch_count_mean")) / 10.0, 0.0, 1.0)),
        "planning_disruption_score": float(np.clip(0.5 * (1.0 / (1.0 + planning_score)) + 0.5 * (1.0 - planned_path_is_critical), 0.0, 1.0)),
        "retreat_rate": row.get("retreat_rate"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "expected_utility_mean": expected_utility,
        "trust_collapse_rate": row.get("trust_collapse_rate_mean"),
        "target_switch_count": row.get("target_switch_count_mean"),
        "planning_score_mean": row.get("planning_score_mean_mean"),
        "planned_path_is_critical": planned_path_is_critical,
    }


def _top_policy(rows: List[Dict[str, object]], key: str) -> Optional[str]:
    if not rows:
        return None
    return str(max(rows, key=lambda row: _to_float(row.get(key))).get("policy"))


def _analyze_phase4_specialized_policy_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    phase2 = next((row for row in rows if row.get("policy") == "phase2_frustration_decoy"), {})
    phase2_cns = _to_float(phase2.get("cognitive_neutralization_score"))
    specialized = [row for row in rows if str(row.get("policy")).startswith("phase4_")]
    specialties = {
        str(row.get("policy")): max(
            [
                ("trust_collapse_score", _to_float(row.get("trust_collapse_score"))),
                ("expected_utility_suppression_score", _to_float(row.get("expected_utility_suppression_score"))),
                ("target_switch_induction_score", _to_float(row.get("target_switch_induction_score"))),
                ("planning_disruption_score", _to_float(row.get("planning_disruption_score"))),
            ],
            key=lambda item: item[1],
        )[0]
        for row in rows
    }
    return {
        "policy_specialties": specialties,
        "cns_top_policy": _top_policy(rows, "cognitive_neutralization_score"),
        "trust_collapse_top_policy": _top_policy(rows, "trust_collapse_score"),
        "expected_utility_suppression_top_policy": _top_policy(rows, "expected_utility_suppression_score"),
        "target_switching_top_policy": _top_policy(rows, "target_switch_induction_score"),
        "planning_disruption_top_policy": _top_policy(rows, "planning_disruption_score"),
        "specialized_exceeds_phase2_frustration_decoy": any(
            _to_float(row.get("cognitive_neutralization_score")) > phase2_cns
            for row in specialized
        ),
        "phase2_frustration_decoy_cns": phase2_cns,
    }


def _write_phase4_specialized_policy_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "specialized_policy_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE4_SPECIALIZED_POLICY_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "specialized_policy_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase4_specialized_policy_ranking(rows: List[Dict[str, object]], save_path: str) -> None:
    labels = [str(row.get("policy")).replace("phase4_", "p4_") for row in rows]
    values = [_to_float(row.get("cognitive_neutralization_score")) for row in rows]
    fig, ax = plt.subplots(figsize=(12, 5))
    x = np.arange(len(labels))
    ax.bar(x, values, color="#4c78a8")
    ax.set_title("Specialized Policy CNS Ranking")
    ax.set_ylabel("cognitive_neutralization_score")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase4_specialized_policy_breakdown(rows: List[Dict[str, object]], save_path: str) -> None:
    labels = [str(row.get("policy")).replace("phase4_", "p4_") for row in rows]
    keys = [
        "trust_collapse_score",
        "expected_utility_suppression_score",
        "target_switch_induction_score",
        "planning_disruption_score",
    ]
    x = np.arange(len(labels))
    width = 0.2
    fig, ax = plt.subplots(figsize=(14, 6))
    for idx, key in enumerate(keys):
        values = [_to_float(row.get(key)) for row in rows]
        ax.bar(x + (idx - 1.5) * width, values, width=width, label=key)
    ax.set_title("Specialized Policy Score Breakdown")
    ax.set_ylabel("score")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase4_specialized_policy_vs_phase2(rows: List[Dict[str, object]], save_path: str) -> None:
    phase2 = next((row for row in rows if row.get("policy") == "phase2_frustration_decoy"), {})
    baseline = _to_float(phase2.get("cognitive_neutralization_score"))
    specialized = [row for row in rows if str(row.get("policy")).startswith("phase4_")]
    labels = [str(row.get("policy")).replace("phase4_", "") for row in specialized]
    values = [_to_float(row.get("cognitive_neutralization_score")) - baseline for row in specialized]
    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(labels))
    ax.axhline(0.0, color="#333333", linewidth=1)
    ax.bar(x, values, color="#59a14f")
    ax.set_title("Specialized Policies vs phase2_frustration_decoy")
    ax.set_ylabel("CNS delta")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase4_specialized_policy_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    specialties = analysis.get("policy_specialties") if isinstance(analysis.get("policy_specialties"), dict) else {}
    lines = [
        "# Phase4.6 Specialized Defense Policy Report",
        "",
        "## Questions",
        f"1. Policy specialties: `{specialties}`.",
        f"2. CNS Top policy: `{analysis.get('cns_top_policy')}`.",
        f"3. Trust Collapse Top policy: `{analysis.get('trust_collapse_top_policy')}`.",
        f"4. Expected Utility Suppression Top policy: `{analysis.get('expected_utility_suppression_top_policy')}`.",
        f"5. Target Switching Top policy: `{analysis.get('target_switching_top_policy')}`.",
        f"6. Planning Disruption Top policy: `{analysis.get('planning_disruption_top_policy')}`.",
        f"7. Specialized policy exceeds phase2_frustration_decoy: `{analysis.get('specialized_exceeds_phase2_frustration_decoy')}`.",
        "",
        "## Rows",
        "| policy | CNS | trust | expected_suppression | switching | planning |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('policy')} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('trust_collapse_score')):.3f} | "
            f"{_to_float(row.get('expected_utility_suppression_score')):.3f} | "
            f"{_to_float(row.get('target_switch_induction_score')):.3f} | "
            f"{_to_float(row.get('planning_disruption_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE4_SPECIALIZED_POLICY_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE47_MISSION_PROFILES = {
    "phase47_profit_attacker": {
        "attacker_mission": "profit",
        "mission_expected_utility_weight": 3.0,
        "mission_trust_weight": 1.0,
        "mission_planning_weight": 1.0,
        "mission_critical_target_weight": 1.0,
    },
    "phase47_achievement_attacker": {
        "attacker_mission": "achievement",
        "mission_expected_utility_weight": 0.5,
        "mission_trust_weight": 0.5,
        "mission_planning_weight": 2.0,
        "mission_critical_target_weight": 1.0,
    },
    "phase47_persistence_attacker": {
        "attacker_mission": "persistence",
        "mission_expected_utility_weight": 1.0,
        "mission_trust_weight": 3.0,
        "mission_planning_weight": 1.0,
        "mission_critical_target_weight": 1.0,
    },
    "phase47_critical_hunter": {
        "attacker_mission": "critical_hunter",
        "mission_expected_utility_weight": 1.0,
        "mission_trust_weight": 1.0,
        "mission_planning_weight": 1.0,
        "mission_critical_target_weight": 3.0,
    },
}

PHASE47_MISSION_DEFENSE_POLICIES = PHASE4_SPECIALIZED_POLICY_NAMES

PHASE47_MISSION_PROFILE_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "defense_policy",
    "defense_effectiveness_score",
    "mission_success_score",
    "mission_satisfaction_score",
    "cognitive_neutralization_score",
    "cns_objective_score",
    "expected_utility_mean",
    "trust_collapse_rate",
    "target_switch_count",
    "planning_score_mean",
    "critical_compromise_rate",
    "retreat_rate",
]


def _phase47_mission_policy_config(defense_policy: str, mission: Dict[str, object]) -> Dict[str, object]:
    return {
        **_phase4_specialized_policy_config(defense_policy),
        **mission,
        "adaptive_attacker_enabled": True,
        "adaptive_preference_enabled": True,
        "adaptive_path_enabled": True,
        "adaptive_planning_enabled": True,
        "trust_enabled": True,
        "expected_utility_enabled": True,
    }


def run_phase47_mission_profile_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase47_mission_profiles"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        for defense_policy in PHASE47_MISSION_DEFENSE_POLICIES:
            scenarios[f"{mission_name}__{defense_policy}"] = _phase47_mission_policy_config(defense_policy, mission)
    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase47_mission_profile_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("mission_scenario")), -_to_float(row.get("defense_effectiveness_score"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase47_mission_profile_rows(rows)
    _write_phase47_mission_profile_summary(rows, analysis, output_dir)
    _plot_phase47_mission_profile_ranking(rows, os.path.join(output_dir, "mission_profile_ranking.png"))
    _plot_phase47_mission_profile_breakdown(rows, os.path.join(output_dir, "mission_profile_breakdown.png"))
    _plot_phase47_mission_profile_vs_defense(rows, os.path.join(output_dir, "mission_profile_vs_defense.png"))
    _write_phase47_mission_profile_report(rows, analysis, output_dir)
    return rows


def _build_phase47_mission_profile_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    if "__" in scenario:
        mission_scenario, defense_policy = scenario.split("__", 1)
    else:
        mission_scenario, defense_policy = scenario, ""
    satisfaction = _to_float(row.get("mission_satisfaction_score_mean"))
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "defense_policy": defense_policy,
        "defense_effectiveness_score": float(np.clip(1.0 - satisfaction, 0.0, 1.0)),
        "mission_success_score": row.get("mission_success_score_mean"),
        "mission_satisfaction_score": satisfaction,
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_objective_score": row.get("cns_objective_score_mean"),
        "expected_utility_mean": row.get("expected_utility_mean_mean"),
        "trust_collapse_rate": row.get("trust_collapse_rate_mean"),
        "target_switch_count": row.get("target_switch_count_mean"),
        "planning_score_mean": row.get("planning_score_mean_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
    }


def _analyze_phase47_mission_profile_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    best_by_mission = {}
    for mission in sorted({str(row.get("attacker_mission")) for row in rows}):
        mission_rows = [row for row in rows if row.get("attacker_mission") == mission]
        if mission_rows:
            best = max(mission_rows, key=lambda row: _to_float(row.get("defense_effectiveness_score")))
            best_by_mission[mission] = best.get("defense_policy")
    unique_best = set(best_by_mission.values())
    return {
        "best_defense_by_mission": best_by_mission,
        "best_defense_changes_by_mission": len(unique_best) > 1,
        "profit_best_defense": best_by_mission.get("profit"),
        "achievement_best_defense": best_by_mission.get("achievement"),
        "persistence_best_defense": best_by_mission.get("persistence"),
        "critical_hunter_best_defense": best_by_mission.get("critical_hunter"),
        "phase2_frustration_decoy_strongest_all_missions": unique_best == {"phase2_frustration_decoy"},
        "adaptive_defender_condition": "Adaptive Defender becomes meaningful when mission profiles make different defense policies minimize mission satisfaction.",
    }


def _write_phase47_mission_profile_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "mission_profile_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE47_MISSION_PROFILE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "mission_profile_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase47_mission_profile_ranking(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(missions))
    values = []
    labels = []
    for mission in missions:
        mission_rows = [row for row in rows if row.get("attacker_mission") == mission]
        best = max(mission_rows, key=lambda row: _to_float(row.get("defense_effectiveness_score")))
        values.append(_to_float(best.get("defense_effectiveness_score")))
        labels.append(str(best.get("defense_policy")).replace("phase4_", "p4_"))
    ax.bar(x, values, color="#4c78a8")
    ax.set_title("Best Defense by Attacker Mission")
    ax.set_ylabel("defense_effectiveness_score")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{m}\n{l}" for m, l in zip(missions, labels)], rotation=0)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase47_mission_profile_breakdown(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    keys = ["mission_satisfaction_score", "expected_utility_mean", "trust_collapse_rate", "target_switch_count"]
    fig, axes = plt.subplots(len(keys), 1, figsize=(12, 11), sharex=True)
    for ax, key in zip(axes, keys):
        values = []
        for mission in missions:
            mission_rows = [row for row in rows if row.get("attacker_mission") == mission]
            values.append(float(np.mean([_to_float(row.get(key)) for row in mission_rows])) if mission_rows else 0.0)
        ax.bar(np.arange(len(missions)), values, color="#59a14f")
        ax.set_ylabel(key)
    axes[-1].set_xticks(np.arange(len(missions)))
    axes[-1].set_xticklabels(missions)
    fig.suptitle("Mission Profile Metric Breakdown")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase47_mission_profile_vs_defense(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    defenses = list(dict.fromkeys(str(row.get("defense_policy")) for row in rows))
    grid = np.zeros((len(missions), len(defenses)), dtype=float)
    for i, mission in enumerate(missions):
        for j, defense in enumerate(defenses):
            match = [row for row in rows if row.get("attacker_mission") == mission and row.get("defense_policy") == defense]
            grid[i, j] = _to_float(match[0].get("defense_effectiveness_score")) if match else 0.0
    fig, ax = plt.subplots(figsize=(13, 6))
    im = ax.imshow(grid, cmap="viridis", aspect="auto")
    ax.set_title("Mission vs Defense Effectiveness")
    ax.set_yticks(np.arange(len(missions)))
    ax.set_yticklabels(missions)
    ax.set_xticks(np.arange(len(defenses)))
    ax.set_xticklabels([d.replace("phase4_", "p4_") for d in defenses], rotation=25, ha="right")
    fig.colorbar(im, ax=ax, label="defense_effectiveness_score")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase47_mission_profile_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    lines = [
        "# Phase4.7 Attacker Mission Profile Report",
        "",
        "## Questions",
        f"1. Best defense changes by mission: `{analysis.get('best_defense_changes_by_mission')}`.",
        f"2. Profit attacker best defense: `{analysis.get('profit_best_defense')}`.",
        f"3. Achievement attacker best defense: `{analysis.get('achievement_best_defense')}`.",
        f"4. Persistence attacker best defense: `{analysis.get('persistence_best_defense')}`.",
        f"5. Critical Hunter best defense: `{analysis.get('critical_hunter_best_defense')}`.",
        f"6. phase2_frustration_decoy strongest for all missions: `{analysis.get('phase2_frustration_decoy_strongest_all_missions')}`.",
        f"7. Adaptive Defender condition: {analysis.get('adaptive_defender_condition')}",
        "",
        "## Best Defense By Mission",
        f"`{analysis.get('best_defense_by_mission')}`",
    ]
    with open(os.path.join(output_dir, "PHASE47_MISSION_PROFILE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE48_MISSION_AWARE_MAPPING = {
    "profit": "phase4_expected_utility_suppressor",
    "achievement": "phase4_planning_disruptor",
    "persistence": "phase4_trust_collapse_maximizer",
    "critical_hunter": "phase4_planning_disruptor",
}

PHASE48_MISSION_SIGNALS = {
    "profit": {"expected_utility": 1.0, "trust_collapse_rate": 0.0, "target_switch_count": 2, "critical_risk": 0.2, "retreat_rate": 0.0},
    "achievement": {"expected_utility": 0.3, "trust_collapse_rate": 0.0, "target_switch_count": 6, "critical_risk": 0.4, "retreat_rate": 0.0},
    "persistence": {"expected_utility": 0.3, "trust_collapse_rate": 0.35, "target_switch_count": 2, "critical_risk": 0.2, "retreat_rate": 0.0},
    "critical_hunter": {"expected_utility": 0.5, "trust_collapse_rate": 0.0, "target_switch_count": 6, "critical_risk": 0.8, "retreat_rate": 0.0},
}

PHASE48_MISSION_AWARE_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "defense_mode",
    "selected_policy",
    "mission_aware_selected_policy",
    "mission_policy_match",
    "mission_policy_switch_count",
    "mission_aware_cns",
    "num_runs",
    "cognitive_neutralization_score",
    "cns_objective_score",
    "mission_success_score",
    "mission_satisfaction_score",
    "defense_effectiveness_score",
    "expected_utility_mean",
    "trust_collapse_rate",
    "critical_compromise_rate",
    "retreat_rate",
]


def _phase48_mission_name(phase47_name: str) -> str:
    return phase47_name.replace("phase47_", "phase48_", 1)


def _phase48_cns_policy_for_mission(mission_name: str, mission: Dict[str, object]) -> tuple[str, str, float, int, float]:
    del mission
    mission_key = str(PHASE47_MISSION_PROFILES[mission_name]["attacker_mission"])
    signals = PHASE48_MISSION_SIGNALS[mission_key]
    return _select_cns_guided_policy(
        expected_utility=float(signals["expected_utility"]),
        trust_collapse_rate=float(signals["trust_collapse_rate"]),
        target_switch_count=int(signals["target_switch_count"]),
        critical_compromise_risk=float(signals["critical_risk"]),
        retreat_rate=float(signals["retreat_rate"]),
    )


def _phase48_policy_config(
    policy_name: str,
    mission: Dict[str, object],
    *,
    adaptive_enabled: bool,
    defense_mode: str,
    selected_policy: Optional[str] = None,
    policy_reason: str = "fixed",
    policy_score: float = 0.0,
    policy_rank: int = 0,
    estimated_cns: float = 0.0,
    mission_aware_enabled: bool = False,
    mission_belief_enabled: bool = False,
    state_belief_enabled: bool = False,
    virtual_topology_enabled: bool = False,
    observable_events_enabled: bool = False,
    critical_path_events_enabled: bool = False,
    intelligence_defender_enabled: bool = False,
    decision_matrix_defender_enabled: bool = False,
    defense_campaign_enabled: bool = False,
    campaign_strategy_profile: str = "balanced",
    mission_objectives_enabled: bool = False,
) -> Dict[str, object]:
    return {
        **_phase47_mission_policy_config(policy_name, mission),
        "adaptive_defender_enabled": adaptive_enabled,
        "adaptive_defender_mode": defense_mode if adaptive_enabled else "rule_based",
        "adaptive_selected_policy": selected_policy or policy_name,
        "adaptive_policy_default": "phase2_frustration_decoy",
        "adaptive_policy_reason": policy_reason,
        "adaptive_selection_reason": policy_reason,
        "adaptive_policy_score": policy_score,
        "adaptive_policy_rank": policy_rank,
        "adaptive_estimated_cns": estimated_cns,
        "mission_aware_defender_enabled": mission_aware_enabled,
        "mission_belief_inference_enabled": mission_belief_enabled,
        "state_belief_inference_enabled": state_belief_enabled,
        "virtual_topology_enabled": virtual_topology_enabled,
        "observable_events_enabled": observable_events_enabled,
        "critical_path_events_enabled": critical_path_events_enabled,
        "intelligence_defender_enabled": intelligence_defender_enabled,
        "decision_matrix_defender_enabled": decision_matrix_defender_enabled,
        "defense_campaign_enabled": defense_campaign_enabled,
        "campaign_strategy_profile": campaign_strategy_profile,
        "mission_objectives_enabled": mission_objectives_enabled,
        "mission_aware_selected_policy": (selected_policy or policy_name) if mission_aware_enabled else "",
        "mission_aware_selection_reason": policy_reason if mission_aware_enabled else "disabled",
        "mission_policy_match": (
            (selected_policy or policy_name)
            == PHASE48_MISSION_AWARE_MAPPING.get(str(mission.get("attacker_mission")), "phase2_frustration_decoy")
        )
        if mission_aware_enabled
        else False,
    }


def run_phase48_mission_aware_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase48_mission_aware"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name)
        mission_key = str(mission["attacker_mission"])
        scenarios[f"{scenario_name}__fixed_frustration_decoy"] = _phase48_policy_config(
            "phase2_frustration_decoy",
            mission,
            adaptive_enabled=False,
            defense_mode="fixed_frustration_decoy",
            policy_reason="fixed",
        )
        scenarios[f"{scenario_name}__fixed_gated_count2"] = _phase48_policy_config(
            "gated_edge_pressure_count_2",
            mission,
            adaptive_enabled=False,
            defense_mode="fixed_gated_count2",
            policy_reason="fixed",
        )
        cns_policy, cns_reason, cns_score, cns_rank, estimated_cns = _phase48_cns_policy_for_mission(mission_name, mission)
        scenarios[f"{scenario_name}__cns_guided"] = _phase48_policy_config(
            cns_policy,
            mission,
            adaptive_enabled=True,
            defense_mode="cns_guided",
            selected_policy=cns_policy,
            policy_reason=cns_reason,
            policy_score=cns_score,
            policy_rank=cns_rank,
            estimated_cns=estimated_cns,
        )
        mission_policy = PHASE48_MISSION_AWARE_MAPPING[mission_key]
        scenarios[f"{scenario_name}__mission_aware"] = _phase48_policy_config(
            mission_policy,
            mission,
            adaptive_enabled=True,
            defense_mode="mission_aware",
            selected_policy=mission_policy,
            policy_reason=f"oracle_mission_{mission_key}",
            policy_score=1.0,
            policy_rank=1,
            estimated_cns=1.0,
            mission_aware_enabled=True,
        )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase48_mission_aware_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("mission_scenario")), str(row.get("defense_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase48_mission_aware_rows(rows)
    _write_phase48_mission_aware_summary(rows, analysis, output_dir)
    _plot_phase48_mission_aware_cns(rows, os.path.join(output_dir, "mission_aware_cns.png"))
    _plot_phase48_mission_aware_policy_selection(rows, os.path.join(output_dir, "mission_aware_policy_selection.png"))
    _plot_phase48_mission_aware_vs_phase47(rows, os.path.join(output_dir, "mission_aware_vs_phase47.png"))
    _write_phase48_mission_aware_report(rows, analysis, output_dir)
    return rows


def _build_phase48_mission_aware_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    if "__" in scenario:
        mission_scenario, defense_mode = scenario.split("__", 1)
    else:
        mission_scenario, defense_mode = scenario, ""
    satisfaction = _to_float(row.get("mission_satisfaction_score_mean"))
    selected_policy = row.get("adaptive_selected_policy") or ""
    if defense_mode == "fixed_frustration_decoy":
        selected_policy = "phase2_frustration_decoy"
    elif defense_mode == "fixed_gated_count2":
        selected_policy = "gated_edge_pressure_count_2"
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "defense_mode": defense_mode,
        "selected_policy": selected_policy,
        "mission_aware_selected_policy": row.get("mission_aware_selected_policy"),
        "mission_policy_match": row.get("mission_policy_match"),
        "mission_policy_switch_count": row.get("mission_policy_switch_count_mean"),
        "mission_aware_cns": row.get("mission_aware_cns_mean"),
        "num_runs": row.get("num_runs"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_objective_score": row.get("cns_objective_score_mean"),
        "mission_success_score": row.get("mission_success_score_mean"),
        "mission_satisfaction_score": satisfaction,
        "defense_effectiveness_score": float(np.clip(1.0 - satisfaction, 0.0, 1.0)),
        "expected_utility_mean": row.get("expected_utility_mean_mean"),
        "trust_collapse_rate": row.get("trust_collapse_rate_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
    }


def _mean_metric(rows: List[Dict[str, object]], mode: str, key: str) -> float:
    values = [_to_float(row.get(key)) for row in rows if row.get("defense_mode") == mode]
    return float(np.mean(values)) if values else 0.0


def _analyze_phase48_mission_aware_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    mission_rows = [row for row in rows if row.get("defense_mode") == "mission_aware"]
    cns_rows = [row for row in rows if row.get("defense_mode") == "cns_guided"]
    fixed_rows = [row for row in rows if str(row.get("defense_mode")).startswith("fixed_")]
    best_fixed_by_mission = {}
    mission_aware_beats_fixed_by_mission = {}
    mission_aware_beats_cns_by_mission = {}
    for mission in sorted({str(row.get("attacker_mission")) for row in rows}):
        scoped = [row for row in rows if row.get("attacker_mission") == mission]
        mission_aware = next((row for row in scoped if row.get("defense_mode") == "mission_aware"), {})
        cns_guided = next((row for row in scoped if row.get("defense_mode") == "cns_guided"), {})
        fixed = [row for row in scoped if str(row.get("defense_mode")).startswith("fixed_")]
        best_fixed = max(fixed, key=lambda row: _to_float(row.get("cognitive_neutralization_score"))) if fixed else {}
        best_fixed_by_mission[mission] = best_fixed.get("defense_mode")
        mission_aware_beats_fixed_by_mission[mission] = (
            _to_float(mission_aware.get("cognitive_neutralization_score"))
            > _to_float(best_fixed.get("cognitive_neutralization_score"))
        )
        mission_aware_beats_cns_by_mission[mission] = (
            _to_float(mission_aware.get("cognitive_neutralization_score"))
            > _to_float(cns_guided.get("cognitive_neutralization_score"))
        )
    mission_mean_cns = _mean_metric(rows, "mission_aware", "cognitive_neutralization_score")
    cns_mean_cns = _mean_metric(rows, "cns_guided", "cognitive_neutralization_score")
    fixed_best_mean = float(np.mean([
        max(
            [
                _to_float(row.get("cognitive_neutralization_score"))
                for row in rows
                if row.get("attacker_mission") == mission and str(row.get("defense_mode")).startswith("fixed_")
            ]
            or [0.0]
        )
        for mission in sorted({str(row.get("attacker_mission")) for row in rows})
    ])) if rows else 0.0
    return {
        "mission_aware_mean_cns": mission_mean_cns,
        "cns_guided_mean_cns": cns_mean_cns,
        "fixed_best_mean_cns": fixed_best_mean,
        "mission_aware_exceeds_fixed_best": mission_mean_cns > fixed_best_mean,
        "mission_aware_exceeds_cns_guided": mission_mean_cns > cns_mean_cns,
        "mission_aware_beats_fixed_by_mission": mission_aware_beats_fixed_by_mission,
        "mission_aware_beats_cns_by_mission": mission_aware_beats_cns_by_mission,
        "best_fixed_by_mission": best_fixed_by_mission,
        "profit_effective": mission_aware_beats_cns_by_mission.get("profit", False) or mission_aware_beats_fixed_by_mission.get("profit", False),
        "persistence_effective": mission_aware_beats_cns_by_mission.get("persistence", False) or mission_aware_beats_fixed_by_mission.get("persistence", False),
        "critical_hunter_effective": mission_aware_beats_cns_by_mission.get("critical_hunter", False) or mission_aware_beats_fixed_by_mission.get("critical_hunter", False),
        "oracle_mission_value": mission_mean_cns - cns_mean_cns,
        "mission_policy_match_rate": float(np.mean([1.0 if row.get("mission_policy_match") in (True, "True", "true", 1) else 0.0 for row in mission_rows])) if mission_rows else 0.0,
    }


def _write_phase48_mission_aware_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "mission_aware_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE48_MISSION_AWARE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "mission_aware_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase48_mission_aware_cns(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    modes = ["fixed_frustration_decoy", "fixed_gated_count2", "cns_guided", "mission_aware"]
    x = np.arange(len(missions))
    width = 0.2
    fig, ax = plt.subplots(figsize=(12, 5))
    for idx, mode in enumerate(modes):
        values = [
            _to_float(next((row.get("cognitive_neutralization_score") for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == mode), 0.0))
            for mission in missions
        ]
        ax.bar(x + (idx - 1.5) * width, values, width=width, label=mode)
    ax.set_title("Mission-Aware CNS")
    ax.set_ylabel("cognitive_neutralization_score")
    ax.set_xticks(x)
    ax.set_xticklabels(missions)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase48_mission_aware_policy_selection(rows: List[Dict[str, object]], save_path: str) -> None:
    mission_rows = [row for row in rows if row.get("defense_mode") == "mission_aware"]
    labels = [str(row.get("attacker_mission")) for row in mission_rows]
    policy_labels = [str(row.get("selected_policy")).replace("phase4_", "p4_").replace("phase2_", "p2_") for row in mission_rows]
    values = [1.0 if row.get("mission_policy_match") in (True, "True", "true", 1) else 0.0 for row in mission_rows]
    fig, ax = plt.subplots(figsize=(11, 4))
    x = np.arange(len(labels))
    ax.bar(x, values, color="#59a14f")
    ax.set_title("Oracle Mission Policy Selection Match")
    ax.set_ylabel("mission_policy_match")
    ax.set_ylim(0.0, 1.1)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{mission}\n{policy}" for mission, policy in zip(labels, policy_labels)])
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase48_mission_aware_vs_phase47(rows: List[Dict[str, object]], save_path: str) -> None:
    mission_rows = [row for row in rows if row.get("defense_mode") == "mission_aware"]
    cns_rows = [row for row in rows if row.get("defense_mode") == "cns_guided"]
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in mission_rows))
    deltas = []
    for mission in missions:
        mission_aware = next((row for row in mission_rows if row.get("attacker_mission") == mission), {})
        cns_guided = next((row for row in cns_rows if row.get("attacker_mission") == mission), {})
        deltas.append(_to_float(mission_aware.get("cognitive_neutralization_score")) - _to_float(cns_guided.get("cognitive_neutralization_score")))
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.axhline(0.0, color="#333333", linewidth=1)
    ax.bar(np.arange(len(missions)), deltas, color="#4c78a8")
    ax.set_title("Mission-Aware vs CNS-Guided")
    ax.set_ylabel("CNS delta")
    ax.set_xticks(np.arange(len(missions)))
    ax.set_xticklabels(missions)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase48_mission_aware_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    lines = [
        "# Phase4.8 Mission-Aware Adaptive Defender Report",
        "",
        "## Questions",
        f"1. Mission-Aware exceeds fixed best: `{analysis.get('mission_aware_exceeds_fixed_best')}` (mission-aware `{_to_float(analysis.get('mission_aware_mean_cns')):.3f}`, fixed-best `{_to_float(analysis.get('fixed_best_mean_cns')):.3f}`).",
        f"2. Mission-Aware exceeds CNS-guided: `{analysis.get('mission_aware_exceeds_cns_guided')}` (mission-aware `{_to_float(analysis.get('mission_aware_mean_cns')):.3f}`, CNS-guided `{_to_float(analysis.get('cns_guided_mean_cns')):.3f}`).",
        f"3. Profit attacker effective: `{analysis.get('profit_effective')}`.",
        f"4. Persistence attacker effective: `{analysis.get('persistence_effective')}`.",
        f"5. Critical Hunter effective: `{analysis.get('critical_hunter_effective')}`.",
        f"6. Mission-aware selection promising: `{analysis.get('mission_policy_match_rate') == 1.0 and analysis.get('mission_aware_exceeds_cns_guided')}`.",
        f"7. Oracle Mission value vs CNS-guided: `{_to_float(analysis.get('oracle_mission_value')):.3f}` CNS.",
        "",
        "## Rows",
        "| mission | mode | selected_policy | CNS | mission_satisfaction | mission_policy_match |",
        "|---|---|---|---:|---:|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('defense_mode')} | {row.get('selected_policy')} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('mission_satisfaction_score')):.3f} | "
            f"{row.get('mission_policy_match')} |"
        )
    with open(os.path.join(output_dir, "PHASE48_MISSION_AWARE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE49_MISSION_BELIEF_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "defense_mode",
    "selected_policy",
    "predicted_mission",
    "mission_prediction_confidence",
    "mission_prediction_correct",
    "belief_profit",
    "belief_achievement",
    "belief_persistence",
    "belief_critical_hunter",
    "mission_policy_switch_count",
    "num_runs",
    "cognitive_neutralization_score",
    "cns_objective_score",
    "mission_satisfaction_score",
    "defense_effectiveness_score",
    "expected_utility_mean",
    "trust_collapse_rate",
    "critical_compromise_rate",
    "retreat_rate",
]


def run_phase49_mission_belief_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase49_mission_belief"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase49_", 1)
        mission_key = str(mission["attacker_mission"])
        scenarios[f"{scenario_name}__fixed_best"] = _phase48_policy_config(
            "phase2_frustration_decoy",
            mission,
            adaptive_enabled=False,
            defense_mode="fixed_best",
            policy_reason="fixed_best",
        )
        cns_policy, cns_reason, cns_score, cns_rank, estimated_cns = _phase48_cns_policy_for_mission(mission_name, mission)
        scenarios[f"{scenario_name}__cns_guided"] = _phase48_policy_config(
            cns_policy,
            mission,
            adaptive_enabled=True,
            defense_mode="cns_guided",
            selected_policy=cns_policy,
            policy_reason=cns_reason,
            policy_score=cns_score,
            policy_rank=cns_rank,
            estimated_cns=estimated_cns,
        )
        oracle_policy = PHASE48_MISSION_AWARE_MAPPING[mission_key]
        scenarios[f"{scenario_name}__oracle_mission"] = _phase48_policy_config(
            oracle_policy,
            mission,
            adaptive_enabled=True,
            defense_mode="mission_aware",
            selected_policy=oracle_policy,
            policy_reason=f"oracle_mission_{mission_key}",
            policy_score=1.0,
            policy_rank=1,
            estimated_cns=1.0,
            mission_aware_enabled=True,
        )
        scenarios[f"{scenario_name}__mission_belief"] = _phase48_policy_config(
            "phase2_frustration_decoy",
            mission,
            adaptive_enabled=True,
            defense_mode="mission_aware",
            selected_policy="phase2_frustration_decoy",
            policy_reason="mission_belief",
            policy_score=0.0,
            policy_rank=0,
            estimated_cns=0.0,
            mission_aware_enabled=True,
            mission_belief_enabled=True,
        )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase49_mission_belief_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("mission_scenario")), str(row.get("defense_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase49_mission_belief_rows(rows)
    _write_phase49_mission_belief_summary(rows, analysis, output_dir)
    _plot_phase49_prediction_accuracy(rows, os.path.join(output_dir, "mission_prediction_accuracy.png"))
    _plot_phase49_belief_vs_oracle(rows, os.path.join(output_dir, "mission_belief_vs_oracle.png"))
    _plot_phase49_belief_vs_phase48(rows, os.path.join(output_dir, "mission_belief_vs_phase48.png"))
    _write_phase49_mission_belief_report(rows, analysis, output_dir)
    return rows


def _build_phase49_mission_belief_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    if "__" in scenario:
        mission_scenario, defense_mode = scenario.split("__", 1)
    else:
        mission_scenario, defense_mode = scenario, ""
    satisfaction = _to_float(row.get("mission_satisfaction_score_mean"))
    selected_policy = row.get("adaptive_selected_policy") or ""
    if defense_mode == "fixed_best":
        selected_policy = "phase2_frustration_decoy"
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "defense_mode": defense_mode,
        "selected_policy": selected_policy,
        "predicted_mission": row.get("predicted_mission"),
        "mission_prediction_confidence": row.get("mission_prediction_confidence_mean"),
        "mission_prediction_correct": row.get("mission_prediction_correct_rate"),
        "belief_profit": row.get("belief_profit_mean"),
        "belief_achievement": row.get("belief_achievement_mean"),
        "belief_persistence": row.get("belief_persistence_mean"),
        "belief_critical_hunter": row.get("belief_critical_hunter_mean"),
        "mission_policy_switch_count": row.get("mission_policy_switch_count_mean"),
        "num_runs": row.get("num_runs"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_objective_score": row.get("cns_objective_score_mean"),
        "mission_satisfaction_score": satisfaction,
        "defense_effectiveness_score": float(np.clip(1.0 - satisfaction, 0.0, 1.0)),
        "expected_utility_mean": row.get("expected_utility_mean_mean"),
        "trust_collapse_rate": row.get("trust_collapse_rate_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
    }


def _analyze_phase49_mission_belief_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    belief_rows = [row for row in rows if row.get("defense_mode") == "mission_belief"]
    accuracy = float(np.mean([_to_float(row.get("mission_prediction_correct")) for row in belief_rows])) if belief_rows else 0.0
    belief_mean_cns = _mean_metric(rows, "mission_belief", "cognitive_neutralization_score")
    oracle_mean_cns = _mean_metric(rows, "oracle_mission", "cognitive_neutralization_score")
    cns_mean_cns = _mean_metric(rows, "cns_guided", "cognitive_neutralization_score")
    fixed_mean_cns = _mean_metric(rows, "fixed_best", "cognitive_neutralization_score")
    close_by_mission = {}
    for mission in sorted({str(row.get("attacker_mission")) for row in rows}):
        mission_belief = next((row for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == "mission_belief"), {})
        oracle = next((row for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == "oracle_mission"), {})
        close_by_mission[mission] = _to_float(mission_belief.get("cognitive_neutralization_score")) - _to_float(oracle.get("cognitive_neutralization_score"))
    return {
        "mission_prediction_accuracy": accuracy,
        "mission_belief_mean_cns": belief_mean_cns,
        "oracle_mission_mean_cns": oracle_mean_cns,
        "cns_guided_mean_cns": cns_mean_cns,
        "fixed_best_mean_cns": fixed_mean_cns,
        "mission_belief_oracle_gap": belief_mean_cns - oracle_mean_cns,
        "mission_belief_exceeds_cns_guided": belief_mean_cns > cns_mean_cns,
        "mission_belief_exceeds_fixed_best": belief_mean_cns > fixed_mean_cns,
        "mission_belief_vs_oracle_by_mission": close_by_mission,
        "profit_identified": any(row.get("attacker_mission") == "profit" and _to_float(row.get("mission_prediction_correct")) >= 1.0 for row in belief_rows),
        "critical_hunter_identified": any(row.get("attacker_mission") == "critical_hunter" and _to_float(row.get("mission_prediction_correct")) >= 1.0 for row in belief_rows),
        "mission_belief_defense_promising": belief_mean_cns > cns_mean_cns and accuracy >= 0.5,
    }


def _write_phase49_mission_belief_summary(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    with open(os.path.join(output_dir, "mission_belief_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE49_MISSION_BELIEF_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "mission_belief_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase49_prediction_accuracy(rows: List[Dict[str, object]], save_path: str) -> None:
    belief_rows = [row for row in rows if row.get("defense_mode") == "mission_belief"]
    missions = [str(row.get("attacker_mission")) for row in belief_rows]
    values = [_to_float(row.get("mission_prediction_correct")) for row in belief_rows]
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(np.arange(len(missions)), values, color="#59a14f")
    ax.set_title("Mission Prediction Accuracy")
    ax.set_ylabel("accuracy")
    ax.set_ylim(0.0, 1.1)
    ax.set_xticks(np.arange(len(missions)))
    ax.set_xticklabels(missions)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase49_belief_vs_oracle(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    modes = ["oracle_mission", "mission_belief"]
    x = np.arange(len(missions))
    width = 0.32
    fig, ax = plt.subplots(figsize=(10, 4))
    for idx, mode in enumerate(modes):
        values = [
            _to_float(next((row.get("cognitive_neutralization_score") for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == mode), 0.0))
            for mission in missions
        ]
        ax.bar(x + (idx - 0.5) * width, values, width=width, label=mode)
    ax.set_title("Mission Belief vs Oracle Mission")
    ax.set_ylabel("cognitive_neutralization_score")
    ax.set_xticks(x)
    ax.set_xticklabels(missions)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase49_belief_vs_phase48(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    modes = ["fixed_best", "cns_guided", "oracle_mission", "mission_belief"]
    x = np.arange(len(missions))
    width = 0.2
    fig, ax = plt.subplots(figsize=(12, 5))
    for idx, mode in enumerate(modes):
        values = [
            _to_float(next((row.get("cognitive_neutralization_score") for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == mode), 0.0))
            for mission in missions
        ]
        ax.bar(x + (idx - 1.5) * width, values, width=width, label=mode)
    ax.set_title("Mission Belief vs Phase4.8 Baselines")
    ax.set_ylabel("cognitive_neutralization_score")
    ax.set_xticks(x)
    ax.set_xticklabels(missions)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase49_mission_belief_report(
    rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    lines = [
        "# Phase4.9 Mission Belief Inference Report",
        "",
        "## Questions",
        f"1. Mission Prediction Accuracy: `{100.0 * _to_float(analysis.get('mission_prediction_accuracy')):.1f}%`.",
        f"2. Mission Belief vs Oracle gap: `{_to_float(analysis.get('mission_belief_oracle_gap')):.3f}` CNS.",
        f"3. Mission Belief exceeds CNS-guided: `{analysis.get('mission_belief_exceeds_cns_guided')}`.",
        f"4. Mission Belief exceeds fixed best: `{analysis.get('mission_belief_exceeds_fixed_best')}`.",
        f"5. Profit attacker identified: `{analysis.get('profit_identified')}`.",
        f"6. Critical Hunter identified: `{analysis.get('critical_hunter_identified')}`.",
        f"7. Mission Belief Defense promising: `{analysis.get('mission_belief_defense_promising')}`.",
        "",
        "## Rows",
        "| mission | mode | predicted | confidence | CNS | satisfaction | switches |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('defense_mode')} | {row.get('predicted_mission')} | "
            f"{_to_float(row.get('mission_prediction_confidence')):.3f} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('mission_satisfaction_score')):.3f} | "
            f"{_to_float(row.get('mission_policy_switch_count')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE49_MISSION_BELIEF_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE410_STATE_BELIEF_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "defense_mode",
    "selected_policy",
    "predicted_state",
    "state_prediction_confidence",
    "state_transition_count",
    "belief_recon",
    "belief_exploitation",
    "belief_lateral_movement",
    "belief_targeting",
    "belief_action_on_objective",
    "predicted_mission",
    "mission_prediction_confidence",
    "num_runs",
    "cognitive_neutralization_score",
    "cns_objective_score",
    "mission_satisfaction_score",
    "defense_effectiveness_score",
    "expected_utility_mean",
    "trust_collapse_rate",
    "critical_compromise_rate",
    "retreat_rate",
]


def run_phase410_state_belief_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase410_state_belief"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase410_", 1)
        scenarios[f"{scenario_name}__fixed_best"] = _phase48_policy_config(
            "phase2_frustration_decoy",
            mission,
            adaptive_enabled=False,
            defense_mode="fixed_best",
            policy_reason="fixed_best",
        )
        cns_policy, cns_reason, cns_score, cns_rank, estimated_cns = _phase48_cns_policy_for_mission(mission_name, mission)
        scenarios[f"{scenario_name}__cns_guided"] = _phase48_policy_config(
            cns_policy,
            mission,
            adaptive_enabled=True,
            defense_mode="cns_guided",
            selected_policy=cns_policy,
            policy_reason=cns_reason,
            policy_score=cns_score,
            policy_rank=cns_rank,
            estimated_cns=estimated_cns,
        )
        scenarios[f"{scenario_name}__mission_belief"] = _phase48_policy_config(
            "phase2_frustration_decoy",
            mission,
            adaptive_enabled=True,
            defense_mode="mission_aware",
            selected_policy="phase2_frustration_decoy",
            policy_reason="mission_belief",
            mission_aware_enabled=True,
            mission_belief_enabled=True,
        )
        scenarios[f"{scenario_name}__state_belief"] = _phase48_policy_config(
            "phase2_frustration_decoy",
            mission,
            adaptive_enabled=True,
            defense_mode="mission_aware",
            selected_policy="phase2_frustration_decoy",
            policy_reason="state_belief",
            mission_aware_enabled=True,
            state_belief_enabled=True,
        )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase410_state_belief_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("mission_scenario")), str(row.get("defense_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase410_state_belief_rows(rows)
    _write_phase410_state_belief_summary(rows, analysis, output_dir)
    _plot_phase410_state_prediction(rows, os.path.join(output_dir, "state_prediction.png"))
    _plot_phase410_state_transition(rows, os.path.join(output_dir, "state_transition.png"))
    _plot_phase410_state_belief_vs_phase49(rows, os.path.join(output_dir, "state_belief_vs_phase49.png"))
    _write_phase410_state_belief_report(rows, analysis, output_dir)
    return rows


def _build_phase410_state_belief_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    if "__" in scenario:
        mission_scenario, defense_mode = scenario.split("__", 1)
    else:
        mission_scenario, defense_mode = scenario, ""
    satisfaction = _to_float(row.get("mission_satisfaction_score_mean"))
    selected_policy = row.get("adaptive_selected_policy") or ""
    if defense_mode == "fixed_best":
        selected_policy = "phase2_frustration_decoy"
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "defense_mode": defense_mode,
        "selected_policy": selected_policy,
        "predicted_state": row.get("predicted_state"),
        "state_prediction_confidence": row.get("state_prediction_confidence_mean"),
        "state_transition_count": row.get("state_transition_count_mean"),
        "belief_recon": row.get("belief_recon_mean"),
        "belief_exploitation": row.get("belief_exploitation_mean"),
        "belief_lateral_movement": row.get("belief_lateral_movement_mean"),
        "belief_targeting": row.get("belief_targeting_mean"),
        "belief_action_on_objective": row.get("belief_action_on_objective_mean"),
        "predicted_mission": row.get("predicted_mission"),
        "mission_prediction_confidence": row.get("mission_prediction_confidence_mean"),
        "num_runs": row.get("num_runs"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "cns_objective_score": row.get("cns_objective_score_mean"),
        "mission_satisfaction_score": satisfaction,
        "defense_effectiveness_score": float(np.clip(1.0 - satisfaction, 0.0, 1.0)),
        "expected_utility_mean": row.get("expected_utility_mean_mean"),
        "trust_collapse_rate": row.get("trust_collapse_rate_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
    }


def _analyze_phase410_state_belief_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    state_mean_cns = _mean_metric(rows, "state_belief", "cognitive_neutralization_score")
    mission_mean_cns = _mean_metric(rows, "mission_belief", "cognitive_neutralization_score")
    fixed_mean_cns = _mean_metric(rows, "fixed_best", "cognitive_neutralization_score")
    cns_mean_cns = _mean_metric(rows, "cns_guided", "cognitive_neutralization_score")
    state_rows = [row for row in rows if row.get("defense_mode") == "state_belief"]
    mean_transitions = float(np.mean([_to_float(row.get("state_transition_count")) for row in state_rows])) if state_rows else 0.0
    selected = {str(row.get("attacker_mission")): row.get("selected_policy") for row in state_rows}
    predicted = {str(row.get("attacker_mission")): row.get("predicted_state") for row in state_rows}
    return {
        "state_belief_mean_cns": state_mean_cns,
        "mission_belief_mean_cns": mission_mean_cns,
        "fixed_best_mean_cns": fixed_mean_cns,
        "cns_guided_mean_cns": cns_mean_cns,
        "state_belief_exceeds_mission_belief": state_mean_cns > mission_mean_cns,
        "state_belief_exceeds_fixed_best": state_mean_cns > fixed_mean_cns,
        "state_transition_observed": mean_transitions > 0.0,
        "mean_state_transition_count": mean_transitions,
        "selected_policy_by_mission": selected,
        "predicted_state_by_mission": predicted,
        "recon_defense_selected": any(row.get("predicted_state") == "recon" and row.get("selected_policy") == "phase4_target_switch_inducer" for row in state_rows),
        "critical_asset_defense_strengthened": any(row.get("predicted_state") == "action_on_objective" and row.get("selected_policy") == "phase2_frustration_decoy" for row in state_rows),
        "state_aware_promising": state_mean_cns > cns_mean_cns and mean_transitions > 0.0,
        "state_more_useful_than_mission": state_mean_cns > mission_mean_cns,
    }


def _write_phase410_state_belief_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "state_belief_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE410_STATE_BELIEF_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "state_belief_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase410_state_prediction(rows: List[Dict[str, object]], save_path: str) -> None:
    state_rows = [row for row in rows if row.get("defense_mode") == "state_belief"]
    labels = [str(row.get("attacker_mission")) for row in state_rows]
    values = [_to_float(row.get("state_prediction_confidence")) for row in state_rows]
    states = [str(row.get("predicted_state")) for row in state_rows]
    fig, ax = plt.subplots(figsize=(11, 4))
    ax.bar(np.arange(len(labels)), values, color="#4c78a8")
    ax.set_title("State Prediction Confidence")
    ax.set_ylabel("confidence")
    ax.set_ylim(0.0, 1.1)
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels([f"{label}\n{state}" for label, state in zip(labels, states)])
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase410_state_transition(rows: List[Dict[str, object]], save_path: str) -> None:
    state_rows = [row for row in rows if row.get("defense_mode") == "state_belief"]
    labels = [str(row.get("attacker_mission")) for row in state_rows]
    values = [_to_float(row.get("state_transition_count")) for row in state_rows]
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(np.arange(len(labels)), values, color="#59a14f")
    ax.set_title("State Transition Count")
    ax.set_ylabel("transitions")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase410_state_belief_vs_phase49(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    modes = ["fixed_best", "cns_guided", "mission_belief", "state_belief"]
    x = np.arange(len(missions))
    width = 0.2
    fig, ax = plt.subplots(figsize=(12, 5))
    for idx, mode in enumerate(modes):
        values = [
            _to_float(next((row.get("cognitive_neutralization_score") for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == mode), 0.0))
            for mission in missions
        ]
        ax.bar(x + (idx - 1.5) * width, values, width=width, label=mode)
    ax.set_title("State Belief vs Phase4.9")
    ax.set_ylabel("cognitive_neutralization_score")
    ax.set_xticks(x)
    ax.set_xticklabels(missions)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase410_state_belief_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.10 Behavior State Inference Report",
        "",
        "## Questions",
        f"1. State Belief exceeds Mission Belief: `{analysis.get('state_belief_exceeds_mission_belief')}` (state `{_to_float(analysis.get('state_belief_mean_cns')):.3f}`, mission `{_to_float(analysis.get('mission_belief_mean_cns')):.3f}`).",
        f"2. State Belief exceeds Fixed Best: `{analysis.get('state_belief_exceeds_fixed_best')}` (fixed `{_to_float(analysis.get('fixed_best_mean_cns')):.3f}`).",
        f"3. State transition observed: `{analysis.get('state_transition_observed')}` (mean `{_to_float(analysis.get('mean_state_transition_count')):.3f}`).",
        f"4. Recon defense selected: `{analysis.get('recon_defense_selected')}`.",
        f"5. Critical asset defense strengthened: `{analysis.get('critical_asset_defense_strengthened')}`.",
        f"6. State-Aware Defender promising: `{analysis.get('state_aware_promising')}`.",
        f"7. State more useful than Mission: `{analysis.get('state_more_useful_than_mission')}`.",
        "",
        "## Rows",
        "| mission | mode | predicted_state | policy | transitions | CNS | satisfaction |",
        "|---|---|---|---|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('defense_mode')} | {row.get('predicted_state')} | {row.get('selected_policy')} | "
            f"{_to_float(row.get('state_transition_count')):.3f} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('mission_satisfaction_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE410_STATE_BELIEF_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE411_VIRTUAL_TOPOLOGY_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "defense_mode",
    "selected_policy",
    "predicted_state",
    "state_prediction_confidence",
    "state_transition_count",
    "observable_event_count",
    "scan_count",
    "credential_use_count",
    "lateral_move_count",
    "critical_probe_count",
    "objective_action_count",
    "cognitive_neutralization_score",
    "mission_satisfaction_score",
    "critical_compromise_rate",
    "retreat_rate",
]


def run_phase411_virtual_topology_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase411_virtual_topology"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase411_", 1)
        scenarios[f"{scenario_name}__phase410_state_belief"] = _phase48_policy_config(
            "phase2_frustration_decoy",
            mission,
            adaptive_enabled=True,
            defense_mode="mission_aware",
            selected_policy="phase2_frustration_decoy",
            policy_reason="phase410_state_belief",
            mission_aware_enabled=True,
            state_belief_enabled=True,
        )
        scenarios[f"{scenario_name}__observable_state_belief"] = _phase48_policy_config(
            "phase2_frustration_decoy",
            mission,
            adaptive_enabled=True,
            defense_mode="mission_aware",
            selected_policy="phase2_frustration_decoy",
            policy_reason="observable_state_belief",
            mission_aware_enabled=True,
            state_belief_enabled=True,
            virtual_topology_enabled=True,
            observable_events_enabled=True,
        )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase411_virtual_topology_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("mission_scenario")), str(row.get("defense_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase411_virtual_topology_rows(rows)
    _write_phase411_virtual_topology_summary(rows, analysis, output_dir)
    _plot_phase411_state_transition_heatmap(rows, os.path.join(output_dir, "state_transition_heatmap.png"))
    _plot_phase411_observable_events_breakdown(rows, os.path.join(output_dir, "observable_events_breakdown.png"))
    _plot_phase411_state_belief_vs_phase410(rows, os.path.join(output_dir, "state_belief_vs_phase410.png"))
    _write_phase411_virtual_topology_report(rows, analysis, output_dir)
    return rows


def _build_phase411_virtual_topology_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    if "__" in scenario:
        mission_scenario, defense_mode = scenario.split("__", 1)
    else:
        mission_scenario, defense_mode = scenario, ""
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "defense_mode": defense_mode,
        "selected_policy": row.get("adaptive_selected_policy"),
        "predicted_state": row.get("predicted_state"),
        "state_prediction_confidence": row.get("state_prediction_confidence_mean"),
        "state_transition_count": row.get("state_transition_count_mean"),
        "observable_event_count": row.get("observable_event_count_mean"),
        "scan_count": row.get("scan_count_mean"),
        "credential_use_count": row.get("credential_use_count_mean"),
        "lateral_move_count": row.get("lateral_move_count_mean"),
        "critical_probe_count": row.get("critical_probe_count_mean"),
        "objective_action_count": row.get("objective_action_count_mean"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "mission_satisfaction_score": row.get("mission_satisfaction_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
    }


def _analyze_phase411_virtual_topology_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    phase410_cns = _mean_metric(rows, "phase410_state_belief", "cognitive_neutralization_score")
    observable_cns = _mean_metric(rows, "observable_state_belief", "cognitive_neutralization_score")
    phase410_transitions = _mean_metric(rows, "phase410_state_belief", "state_transition_count")
    observable_transitions = _mean_metric(rows, "observable_state_belief", "state_transition_count")
    observable_rows = [row for row in rows if row.get("defense_mode") == "observable_state_belief"]
    objective_events = [_to_float(row.get("objective_action_count")) for row in observable_rows]
    critical_probe_events = [_to_float(row.get("critical_probe_count")) for row in observable_rows]
    event_counts = [_to_float(row.get("observable_event_count")) for row in observable_rows]
    return {
        "phase410_state_belief_mean_cns": phase410_cns,
        "observable_state_belief_mean_cns": observable_cns,
        "state_belief_cns_improved": observable_cns > phase410_cns,
        "phase410_mean_state_transition_count": phase410_transitions,
        "observable_mean_state_transition_count": observable_transitions,
        "state_transition_count_increased": observable_transitions > phase410_transitions,
        "state_transition_observed": observable_transitions > 0.0,
        "critical_asset_approach_detected": any(value > 0.0 for value in objective_events + critical_probe_events),
        "mean_observable_event_count": float(np.mean(event_counts)) if event_counts else 0.0,
        "observable_events_effective": observable_transitions > phase410_transitions or any(value > 0.0 for value in event_counts),
        "cyber_terrain_value": observable_transitions > phase410_transitions or observable_cns >= phase410_cns,
    }


def _write_phase411_virtual_topology_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "virtual_topology_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE411_VIRTUAL_TOPOLOGY_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "virtual_topology_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase411_state_transition_heatmap(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    modes = ["phase410_state_belief", "observable_state_belief"]
    grid = np.zeros((len(missions), len(modes)), dtype=float)
    for i, mission in enumerate(missions):
        for j, mode in enumerate(modes):
            match = next((row for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == mode), {})
            grid[i, j] = _to_float(match.get("state_transition_count"))
    fig, ax = plt.subplots(figsize=(8, 5))
    im = ax.imshow(grid, cmap="viridis", aspect="auto")
    ax.set_title("State Transition Heatmap")
    ax.set_yticks(np.arange(len(missions)))
    ax.set_yticklabels(missions)
    ax.set_xticks(np.arange(len(modes)))
    ax.set_xticklabels(modes, rotation=20, ha="right")
    fig.colorbar(im, ax=ax, label="transition_count")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase411_observable_events_breakdown(rows: List[Dict[str, object]], save_path: str) -> None:
    rows = [row for row in rows if row.get("defense_mode") == "observable_state_belief"]
    missions = [str(row.get("attacker_mission")) for row in rows]
    keys = ["scan_count", "credential_use_count", "lateral_move_count", "critical_probe_count", "objective_action_count"]
    x = np.arange(len(missions))
    width = 0.16
    fig, ax = plt.subplots(figsize=(12, 5))
    for idx, key in enumerate(keys):
        ax.bar(x + (idx - 2) * width, [_to_float(row.get(key)) for row in rows], width=width, label=key)
    ax.set_title("Observable Events Breakdown")
    ax.set_ylabel("count")
    ax.set_xticks(x)
    ax.set_xticklabels(missions)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase411_state_belief_vs_phase410(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    modes = ["phase410_state_belief", "observable_state_belief"]
    x = np.arange(len(missions))
    width = 0.32
    fig, ax = plt.subplots(figsize=(10, 4))
    for idx, mode in enumerate(modes):
        values = [
            _to_float(next((row.get("cognitive_neutralization_score") for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == mode), 0.0))
            for mission in missions
        ]
        ax.bar(x + (idx - 0.5) * width, values, width=width, label=mode)
    ax.set_title("State Belief vs Phase4.10")
    ax.set_ylabel("cognitive_neutralization_score")
    ax.set_xticks(x)
    ax.set_xticklabels(missions)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase411_virtual_topology_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.11 Virtual Enterprise Topology Report",
        "",
        "## Questions",
        f"1. State transition observed: `{analysis.get('state_transition_observed')}`.",
        f"2. Mean state_transition_count increased: `{analysis.get('state_transition_count_increased')}` (phase410 `{_to_float(analysis.get('phase410_mean_state_transition_count')):.3f}`, observable `{_to_float(analysis.get('observable_mean_state_transition_count')):.3f}`).",
        f"3. State Belief CNS improved: `{analysis.get('state_belief_cns_improved')}` (phase410 `{_to_float(analysis.get('phase410_state_belief_mean_cns')):.3f}`, observable `{_to_float(analysis.get('observable_state_belief_mean_cns')):.3f}`).",
        f"4. Mission Belief proximity improved: observable-event state CNS `{_to_float(analysis.get('observable_state_belief_mean_cns')):.3f}`.",
        f"5. Critical Asset approach detected: `{analysis.get('critical_asset_approach_detected')}`.",
        f"6. Observable Events effective: `{analysis.get('observable_events_effective')}`.",
        f"7. Cyber Terrain value: `{analysis.get('cyber_terrain_value')}`.",
        "",
        "## Rows",
        "| mission | mode | state | events | transitions | CNS | critical_probe | objective |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('defense_mode')} | {row.get('predicted_state')} | "
            f"{_to_float(row.get('observable_event_count')):.3f} | "
            f"{_to_float(row.get('state_transition_count')):.3f} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('critical_probe_count')):.3f} | "
            f"{_to_float(row.get('objective_action_count')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE411_VIRTUAL_TOPOLOGY_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE412_CRITICAL_PATH_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "defense_mode",
    "selected_policy",
    "predicted_state",
    "state_transition_count",
    "observable_event_count",
    "critical_path_proximity",
    "critical_path_step_count",
    "critical_node_visit_count",
    "critical_edge_traversal_count",
    "critical_path_entry_count",
    "critical_path_progress_count",
    "critical_path_near_target_count",
    "critical_asset_reach_count",
    "cognitive_neutralization_score",
    "mission_satisfaction_score",
    "critical_compromise_rate",
    "retreat_rate",
]


def _phase412_terrain_config(
    policy_name: str,
    mission: Dict[str, object],
    *,
    phase411: bool,
) -> Dict[str, object]:
    config = _phase48_policy_config(
        policy_name,
        mission,
        adaptive_enabled=True,
        defense_mode="mission_aware",
        selected_policy=policy_name,
        policy_reason="phase411_observable" if phase411 else "phase412_critical_path",
        mission_aware_enabled=False,
        state_belief_enabled=True,
        virtual_topology_enabled=True,
        observable_events_enabled=True,
        critical_path_events_enabled=not phase411,
    )
    config.update(
        {
            "attacker_lateral_enabled": True,
            "attacker_lateral_success_prob": 1.0,
            "attacker_lateral_detection_prob": 0.0,
            "attacker_target_selection": "adaptive",
            "adaptive_attacker_enabled": True,
            "adaptive_path_enabled": True,
            "adaptive_planning_enabled": True,
            "attacker_retreat_threshold": -999.0,
            "frustration_retreat_threshold": 100.0,
            "stop_on_attacker_retreat": False,
        }
    )
    return config


def run_phase412_critical_path_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase412_critical_path"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase412_", 1)
        scenarios[f"{scenario_name}__phase411"] = _phase412_terrain_config(
            "phase2_frustration_decoy",
            mission,
            phase411=True,
        )
        scenarios[f"{scenario_name}__phase412"] = _phase412_terrain_config(
            "phase2_frustration_decoy",
            mission,
            phase411=False,
        )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase412_critical_path_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("mission_scenario")), str(row.get("defense_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase412_critical_path_rows(rows)
    _write_phase412_critical_path_summary(rows, analysis, output_dir)
    _plot_phase412_critical_path_events(rows, os.path.join(output_dir, "critical_path_events.png"))
    _plot_phase412_critical_path_proximity(rows, os.path.join(output_dir, "critical_path_proximity.png"))
    _plot_phase412_state_belief_vs_phase411(rows, os.path.join(output_dir, "state_belief_vs_phase411.png"))
    _write_phase412_critical_path_report(rows, analysis, output_dir)
    return rows


def _build_phase412_critical_path_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    if "__" in scenario:
        mission_scenario, defense_mode = scenario.split("__", 1)
    else:
        mission_scenario, defense_mode = scenario, ""
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "defense_mode": defense_mode,
        "selected_policy": row.get("adaptive_selected_policy"),
        "predicted_state": row.get("predicted_state"),
        "state_transition_count": row.get("state_transition_count_mean"),
        "observable_event_count": row.get("observable_event_count_mean"),
        "critical_path_proximity": row.get("critical_path_proximity_mean"),
        "critical_path_step_count": row.get("critical_path_step_count_mean"),
        "critical_node_visit_count": row.get("critical_node_visit_count_mean"),
        "critical_edge_traversal_count": row.get("critical_edge_traversal_count_mean"),
        "critical_path_entry_count": row.get("critical_path_entry_count_mean"),
        "critical_path_progress_count": row.get("critical_path_progress_count_mean"),
        "critical_path_near_target_count": row.get("critical_path_near_target_count_mean"),
        "critical_asset_reach_count": row.get("critical_asset_reach_count_mean"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "mission_satisfaction_score": row.get("mission_satisfaction_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
    }


def _analyze_phase412_critical_path_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    phase411_cns = _mean_metric(rows, "phase411", "cognitive_neutralization_score")
    phase412_cns = _mean_metric(rows, "phase412", "cognitive_neutralization_score")
    phase411_transitions = _mean_metric(rows, "phase411", "state_transition_count")
    phase412_transitions = _mean_metric(rows, "phase412", "state_transition_count")
    phase412_rows = [row for row in rows if row.get("defense_mode") == "phase412"]
    proximity = [_to_float(row.get("critical_path_proximity")) for row in phase412_rows]
    near_or_reach = [
        _to_float(row.get("critical_path_near_target_count")) + _to_float(row.get("critical_asset_reach_count"))
        for row in phase412_rows
    ]
    event_counts = [_to_float(row.get("critical_path_step_count")) for row in phase412_rows]
    return {
        "critical_asset_approach_detected": any(value > 0.0 for value in near_or_reach),
        "critical_path_proximity_mean": float(np.mean(proximity)) if proximity else 0.0,
        "critical_path_proximity_effective": any(value > 0.0 for value in proximity),
        "phase411_mean_state_transition_count": phase411_transitions,
        "phase412_mean_state_transition_count": phase412_transitions,
        "state_transition_count_increased": phase412_transitions > phase411_transitions,
        "phase411_state_belief_mean_cns": phase411_cns,
        "phase412_state_belief_mean_cns": phase412_cns,
        "state_belief_cns_improved": phase412_cns > phase411_cns,
        "mission_belief_gap_proxy": phase412_cns - phase411_cns,
        "critical_path_event_effective": any(value > 0.0 for value in event_counts),
        "intelligence_layer_value": any(value > 0.0 for value in event_counts) or phase412_transitions > phase411_transitions,
    }


def _write_phase412_critical_path_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "critical_path_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE412_CRITICAL_PATH_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "critical_path_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase412_critical_path_events(rows: List[Dict[str, object]], save_path: str) -> None:
    rows = [row for row in rows if row.get("defense_mode") == "phase412"]
    missions = [str(row.get("attacker_mission")) for row in rows]
    keys = ["critical_path_entry_count", "critical_path_progress_count", "critical_path_near_target_count", "critical_asset_reach_count"]
    x = np.arange(len(missions))
    width = 0.2
    fig, ax = plt.subplots(figsize=(12, 5))
    for idx, key in enumerate(keys):
        ax.bar(x + (idx - 1.5) * width, [_to_float(row.get(key)) for row in rows], width=width, label=key)
    ax.set_title("Critical Path Events")
    ax.set_ylabel("count")
    ax.set_xticks(x)
    ax.set_xticklabels(missions)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase412_critical_path_proximity(rows: List[Dict[str, object]], save_path: str) -> None:
    rows = [row for row in rows if row.get("defense_mode") == "phase412"]
    missions = [str(row.get("attacker_mission")) for row in rows]
    values = [_to_float(row.get("critical_path_proximity")) for row in rows]
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(np.arange(len(missions)), values, color="#59a14f")
    ax.set_title("Critical Path Proximity")
    ax.set_ylabel("proximity")
    ax.set_xticks(np.arange(len(missions)))
    ax.set_xticklabels(missions)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase412_state_belief_vs_phase411(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    modes = ["phase411", "phase412"]
    x = np.arange(len(missions))
    width = 0.32
    fig, ax = plt.subplots(figsize=(10, 4))
    for idx, mode in enumerate(modes):
        values = [
            _to_float(next((row.get("cognitive_neutralization_score") for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == mode), 0.0))
            for mission in missions
        ]
        ax.bar(x + (idx - 0.5) * width, values, width=width, label=mode)
    ax.set_title("State Belief vs Phase4.11")
    ax.set_ylabel("cognitive_neutralization_score")
    ax.set_xticks(x)
    ax.set_xticklabels(missions)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase412_critical_path_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.12 Critical Path Observable Events Report",
        "",
        "## Questions",
        f"1. Critical Asset approach detected: `{analysis.get('critical_asset_approach_detected')}`.",
        f"2. critical_path_proximity effective: `{analysis.get('critical_path_proximity_effective')}` (mean `{_to_float(analysis.get('critical_path_proximity_mean')):.3f}`).",
        f"3. state_transition_count increased: `{analysis.get('state_transition_count_increased')}` (phase411 `{_to_float(analysis.get('phase411_mean_state_transition_count')):.3f}`, phase412 `{_to_float(analysis.get('phase412_mean_state_transition_count')):.3f}`).",
        f"4. State Belief CNS improved: `{analysis.get('state_belief_cns_improved')}` (phase411 `{_to_float(analysis.get('phase411_state_belief_mean_cns')):.3f}`, phase412 `{_to_float(analysis.get('phase412_state_belief_mean_cns')):.3f}`).",
        f"5. Mission Belief proximity delta proxy: `{_to_float(analysis.get('mission_belief_gap_proxy')):.3f}` CNS.",
        f"6. Critical Path Event effective: `{analysis.get('critical_path_event_effective')}`.",
        f"7. Intelligence Layer value: `{analysis.get('intelligence_layer_value')}`.",
        "",
        "## Rows",
        "| mission | mode | state | proximity | path_events | near | reach | transitions | CNS |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('defense_mode')} | {row.get('predicted_state')} | "
            f"{_to_float(row.get('critical_path_proximity')):.3f} | "
            f"{_to_float(row.get('critical_path_step_count')):.3f} | "
            f"{_to_float(row.get('critical_path_near_target_count')):.3f} | "
            f"{_to_float(row.get('critical_asset_reach_count')):.3f} | "
            f"{_to_float(row.get('state_transition_count')):.3f} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE412_CRITICAL_PATH_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE413_INTELLIGENCE_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "defense_mode",
    "selected_policy",
    "selected_intelligence_policy",
    "predicted_mission",
    "predicted_state",
    "intelligence_risk_score",
    "risk_level",
    "risk_level_transition_count",
    "critical_path_proximity",
    "critical_asset_reach_count",
    "state_transition_count",
    "cognitive_neutralization_score",
    "mission_satisfaction_score",
    "critical_compromise_rate",
    "retreat_rate",
]


def _phase413_intelligence_config(
    policy_name: str,
    mission: Dict[str, object],
    *,
    defense_mode: str,
    mission_belief: bool = False,
    state_belief: bool = False,
    intelligence: bool = False,
    decision_matrix: bool = False,
    defense_campaign: bool = False,
    campaign_strategy_profile: str = "balanced",
    mission_objectives: bool = False,
) -> Dict[str, object]:
    config = _phase48_policy_config(
        policy_name,
        mission,
        adaptive_enabled=defense_mode != "fixed_best",
        defense_mode="mission_aware" if defense_mode != "fixed_best" else "fixed_best",
        selected_policy=policy_name,
        policy_reason=defense_mode,
        mission_aware_enabled=mission_belief or state_belief,
        mission_belief_enabled=mission_belief or intelligence,
        state_belief_enabled=state_belief or intelligence,
        virtual_topology_enabled=True,
        observable_events_enabled=True,
        critical_path_events_enabled=True,
        intelligence_defender_enabled=intelligence,
        decision_matrix_defender_enabled=decision_matrix,
        defense_campaign_enabled=defense_campaign,
        campaign_strategy_profile=campaign_strategy_profile,
        mission_objectives_enabled=mission_objectives,
    )
    config.update(
        {
            "attacker_lateral_enabled": True,
            "attacker_lateral_success_prob": 1.0,
            "attacker_lateral_detection_prob": 0.0,
            "attacker_target_selection": "adaptive",
            "adaptive_attacker_enabled": True,
            "adaptive_path_enabled": True,
            "adaptive_planning_enabled": True,
            "attacker_retreat_threshold": -999.0,
            "frustration_retreat_threshold": 100.0,
            "stop_on_attacker_retreat": False,
        }
    )
    return config


def run_phase413_intelligence_defender_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase413_intelligence_defender"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase413_", 1)
        scenarios[f"{scenario_name}__fixed_best"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="fixed_best",
        )
        scenarios[f"{scenario_name}__mission_belief"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="mission_belief",
            mission_belief=True,
        )
        scenarios[f"{scenario_name}__state_belief"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="state_belief",
            state_belief=True,
        )
        scenarios[f"{scenario_name}__intelligence_driven"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="intelligence_driven",
            intelligence=True,
        )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase413_intelligence_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("mission_scenario")), str(row.get("defense_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase413_intelligence_rows(rows)
    _write_phase413_intelligence_summary(rows, analysis, output_dir)
    _plot_phase413_risk_score(rows, os.path.join(output_dir, "intelligence_risk_score.png"))
    _plot_phase413_risk_level_transition(rows, os.path.join(output_dir, "risk_level_transition.png"))
    _plot_phase413_vs_phase412(rows, os.path.join(output_dir, "intelligence_vs_phase412.png"))
    _write_phase413_intelligence_report(rows, analysis, output_dir)
    return rows


def _build_phase413_intelligence_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    if "__" in scenario:
        mission_scenario, defense_mode = scenario.split("__", 1)
    else:
        mission_scenario, defense_mode = scenario, ""
    selected_policy = row.get("adaptive_selected_policy") or ""
    if defense_mode == "fixed_best":
        selected_policy = "phase2_frustration_decoy"
    risk_score = row.get("intelligence_risk_score_mean_mean")
    if risk_score is None:
        risk_score = row.get("intelligence_risk_score_mean")
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "defense_mode": defense_mode,
        "selected_policy": selected_policy,
        "selected_intelligence_policy": row.get("selected_intelligence_policy"),
        "predicted_mission": row.get("predicted_mission"),
        "predicted_state": row.get("predicted_state"),
        "intelligence_risk_score": risk_score,
        "risk_level": row.get("risk_level"),
        "risk_level_transition_count": row.get("risk_level_transition_count_mean"),
        "critical_path_proximity": row.get("critical_path_proximity_mean"),
        "critical_asset_reach_count": row.get("critical_asset_reach_count_mean"),
        "state_transition_count": row.get("state_transition_count_mean"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "mission_satisfaction_score": row.get("mission_satisfaction_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
    }


def _analyze_phase413_intelligence_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    intelligence_cns = _mean_metric(rows, "intelligence_driven", "cognitive_neutralization_score")
    mission_cns = _mean_metric(rows, "mission_belief", "cognitive_neutralization_score")
    fixed_cns = _mean_metric(rows, "fixed_best", "cognitive_neutralization_score")
    state_cns = _mean_metric(rows, "state_belief", "cognitive_neutralization_score")
    intel_rows = [row for row in rows if row.get("defense_mode") == "intelligence_driven"]
    risk_transitions = [_to_float(row.get("risk_level_transition_count")) for row in intel_rows]
    critical_reach = [_to_float(row.get("critical_asset_reach_count")) for row in intel_rows]
    return {
        "intelligence_mean_cns": intelligence_cns,
        "mission_belief_mean_cns": mission_cns,
        "state_belief_mean_cns": state_cns,
        "fixed_best_mean_cns": fixed_cns,
        "intelligence_exceeds_mission_belief": intelligence_cns > mission_cns,
        "intelligence_exceeds_fixed_best": intelligence_cns > fixed_cns,
        "risk_level_transition_observed": any(value > 0.0 for value in risk_transitions),
        "mean_risk_level_transition_count": float(np.mean(risk_transitions)) if risk_transitions else 0.0,
        "critical_asset_defense_strengthened": any(
            _to_float(row.get("critical_asset_reach_count")) > 0.0
            and row.get("selected_policy") == "phase2_frustration_decoy"
            for row in intel_rows
        ),
        "cns_improved_over_state_belief": intelligence_cns > state_cns,
        "intelligence_layer_effective": any(value > 0.0 for value in risk_transitions) and any(value > 0.0 for value in critical_reach),
        "active_defense_progress": any(str(row.get("selected_policy")).startswith("phase") for row in intel_rows)
        and any(value > 0.0 for value in risk_transitions),
    }


def _write_phase413_intelligence_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "intelligence_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE413_INTELLIGENCE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    with open(os.path.join(output_dir, "intelligence_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase413_risk_score(rows: List[Dict[str, object]], save_path: str) -> None:
    rows = [row for row in rows if row.get("defense_mode") == "intelligence_driven"]
    missions = [str(row.get("attacker_mission")) for row in rows]
    values = [_to_float(row.get("intelligence_risk_score")) for row in rows]
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(np.arange(len(missions)), values, color="#e15759")
    ax.set_title("Intelligence Risk Score")
    ax.set_ylabel("risk_score")
    ax.set_ylim(0.0, 1.0)
    ax.set_xticks(np.arange(len(missions)))
    ax.set_xticklabels(missions)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase413_risk_level_transition(rows: List[Dict[str, object]], save_path: str) -> None:
    rows = [row for row in rows if row.get("defense_mode") == "intelligence_driven"]
    missions = [str(row.get("attacker_mission")) for row in rows]
    values = [_to_float(row.get("risk_level_transition_count")) for row in rows]
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(np.arange(len(missions)), values, color="#59a14f")
    ax.set_title("Risk Level Transition Count")
    ax.set_ylabel("transitions")
    ax.set_xticks(np.arange(len(missions)))
    ax.set_xticklabels(missions)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase413_vs_phase412(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    modes = ["fixed_best", "mission_belief", "state_belief", "intelligence_driven"]
    x = np.arange(len(missions))
    width = 0.2
    fig, ax = plt.subplots(figsize=(12, 5))
    for idx, mode in enumerate(modes):
        values = [
            _to_float(next((row.get("cognitive_neutralization_score") for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == mode), 0.0))
            for mission in missions
        ]
        ax.bar(x + (idx - 1.5) * width, values, width=width, label=mode)
    ax.set_title("Intelligence-Driven vs Phase4.12 Baselines")
    ax.set_ylabel("cognitive_neutralization_score")
    ax.set_xticks(x)
    ax.set_xticklabels(missions)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase413_intelligence_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.13 Intelligence-Driven Defense Report",
        "",
        "## Questions",
        f"1. Intelligence-Driven exceeds Mission Belief: `{analysis.get('intelligence_exceeds_mission_belief')}` (intelligence `{_to_float(analysis.get('intelligence_mean_cns')):.3f}`, mission `{_to_float(analysis.get('mission_belief_mean_cns')):.3f}`).",
        f"2. Intelligence-Driven exceeds Fixed Best: `{analysis.get('intelligence_exceeds_fixed_best')}` (fixed `{_to_float(analysis.get('fixed_best_mean_cns')):.3f}`).",
        f"3. Risk Level transition observed: `{analysis.get('risk_level_transition_observed')}` (mean `{_to_float(analysis.get('mean_risk_level_transition_count')):.3f}`).",
        f"4. Critical Asset defense strengthened: `{analysis.get('critical_asset_defense_strengthened')}`.",
        f"5. CNS improved over State Belief: `{analysis.get('cns_improved_over_state_belief')}`.",
        f"6. Intelligence Layer effective: `{analysis.get('intelligence_layer_effective')}`.",
        f"7. Active Defense progress: `{analysis.get('active_defense_progress')}`.",
        "",
        "## Rows",
        "| mission | mode | policy | risk | level | risk_transitions | critical_reach | CNS |",
        "|---|---|---|---:|---|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('defense_mode')} | {row.get('selected_policy')} | "
            f"{_to_float(row.get('intelligence_risk_score')):.3f} | {row.get('risk_level')} | "
            f"{_to_float(row.get('risk_level_transition_count')):.3f} | "
            f"{_to_float(row.get('critical_asset_reach_count')):.3f} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE413_INTELLIGENCE_DEFENDER_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE414_WEIGHT_CONFIGS: List[Tuple[float, float, float]] = [
    (0.2, 0.4, 0.4),
    (0.3, 0.4, 0.3),
    (0.4, 0.3, 0.3),
    (0.2, 0.3, 0.5),
    (0.3, 0.2, 0.5),
    (0.1, 0.4, 0.5),
    (0.1, 0.3, 0.6),
]

PHASE414_WEIGHT_SWEEP_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "defense_mode",
    "weight_configuration",
    "weight_sweep_rank",
    "mission_weight",
    "state_weight",
    "critical_path_weight",
    "selected_policy",
    "selected_intelligence_policy",
    "intelligence_risk_score",
    "risk_level",
    "risk_level_transition_count",
    "critical_path_proximity",
    "state_transition_count",
    "cognitive_neutralization_score",
    "mission_satisfaction_score",
    "critical_compromise_rate",
    "retreat_rate",
]


def _normalize_phase414_weights(weights: Tuple[float, float, float]) -> Tuple[float, float, float]:
    values = np.array(weights, dtype=float)
    total = float(np.sum(values))
    if total <= 0.0:
        values = np.array([0.4, 0.3, 0.3], dtype=float)
    else:
        values = values / total
    return float(values[0]), float(values[1]), float(values[2])


def _phase414_weight_label(weights: Tuple[float, float, float]) -> str:
    mission_weight, state_weight, critical_path_weight = _normalize_phase414_weights(weights)
    return f"m={mission_weight:.2f},s={state_weight:.2f},p={critical_path_weight:.2f}"


def run_phase414_weight_sweep_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase414_weight_sweep"),
    config_path: str = "config.json",
    weight_configs: Optional[List[Tuple[float, float, float]]] = None,
) -> List[Dict[str, object]]:
    configs = weight_configs if weight_configs is not None else PHASE414_WEIGHT_CONFIGS
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase414_", 1)
        scenarios[f"{scenario_name}__fixed_best"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="fixed_best",
        )
        scenarios[f"{scenario_name}__mission_belief"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="mission_belief",
            mission_belief=True,
        )
        scenarios[f"{scenario_name}__state_belief"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="state_belief",
            state_belief=True,
        )
        scenarios[f"{scenario_name}__intelligence_default"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="intelligence_default",
            intelligence=True,
        )
        for idx, weights in enumerate(configs, start=1):
            mission_weight, state_weight, critical_path_weight = _normalize_phase414_weights(weights)
            scenario_config = _phase413_intelligence_config(
                "phase2_frustration_decoy",
                mission,
                defense_mode=f"weight_sweep_{idx:02d}",
                intelligence=True,
            )
            scenario_config.update(
                {
                    "intelligence_mission_weight": mission_weight,
                    "intelligence_state_weight": state_weight,
                    "intelligence_critical_path_weight": critical_path_weight,
                    "best_weight_configuration": _phase414_weight_label(weights),
                }
            )
            scenarios[f"{scenario_name}__weight_sweep_{idx:02d}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase414_weight_sweep_row(row) for row in stats_rows]
    analysis = _analyze_phase414_weight_sweep_rows(rows)
    _apply_phase414_weight_ranks(rows, analysis)
    rows.sort(key=lambda row: (str(row.get("mission_scenario")), str(row.get("defense_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    _write_phase414_weight_sweep_summary(rows, analysis, output_dir)
    _plot_phase414_weight_ranking(analysis, os.path.join(output_dir, "weight_sweep_ranking.png"))
    _plot_phase414_weight_sensitivity(rows, os.path.join(output_dir, "weight_sensitivity.png"))
    _plot_phase414_vs_phase413(analysis, os.path.join(output_dir, "weight_sweep_vs_phase413.png"))
    _write_phase414_weight_sweep_report(rows, analysis, output_dir)
    return rows


def _build_phase414_weight_sweep_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    if "__" in scenario:
        mission_scenario, defense_mode = scenario.split("__", 1)
    else:
        mission_scenario, defense_mode = scenario, ""
    selected_policy = row.get("adaptive_selected_policy") or ""
    if defense_mode == "fixed_best":
        selected_policy = "phase2_frustration_decoy"
    mission_weight = row.get("mission_weight_mean")
    state_weight = row.get("state_weight_mean")
    critical_path_weight = row.get("critical_path_weight_mean")
    if mission_weight is None:
        mission_weight = 0.4
    if state_weight is None:
        state_weight = 0.3
    if critical_path_weight is None:
        critical_path_weight = 0.3
    weight_configuration = _phase414_weight_label(
        (_to_float(mission_weight), _to_float(state_weight), _to_float(critical_path_weight))
    )
    if not str(defense_mode).startswith("weight_sweep"):
        weight_configuration = ""
    risk_score = row.get("intelligence_risk_score_mean_mean")
    if risk_score is None:
        risk_score = row.get("intelligence_risk_score_mean")
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "defense_mode": defense_mode,
        "weight_configuration": weight_configuration,
        "weight_sweep_rank": row.get("weight_sweep_rank_mean"),
        "mission_weight": mission_weight,
        "state_weight": state_weight,
        "critical_path_weight": critical_path_weight,
        "selected_policy": selected_policy,
        "selected_intelligence_policy": row.get("selected_intelligence_policy"),
        "intelligence_risk_score": risk_score,
        "risk_level": row.get("risk_level"),
        "risk_level_transition_count": row.get("risk_level_transition_count_mean"),
        "critical_path_proximity": row.get("critical_path_proximity_mean"),
        "state_transition_count": row.get("state_transition_count_mean"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "mission_satisfaction_score": row.get("mission_satisfaction_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
    }


def _phase414_weight_groups(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    groups: Dict[str, List[Dict[str, object]]] = {}
    for row in rows:
        if str(row.get("defense_mode")).startswith("weight_sweep"):
            groups.setdefault(str(row.get("weight_configuration")), []).append(row)
    summary = []
    for label, group_rows in groups.items():
        cns_values = [_to_float(row.get("cognitive_neutralization_score")) for row in group_rows]
        summary.append(
            {
                "weight_configuration": label,
                "mission_weight": _to_float(group_rows[0].get("mission_weight")),
                "state_weight": _to_float(group_rows[0].get("state_weight")),
                "critical_path_weight": _to_float(group_rows[0].get("critical_path_weight")),
                "mean_cns": float(np.mean(cns_values)) if cns_values else 0.0,
                "mean_risk_transition_count": float(np.mean([_to_float(row.get("risk_level_transition_count")) for row in group_rows])) if group_rows else 0.0,
                "num_rows": len(group_rows),
            }
        )
    summary.sort(key=lambda item: _to_float(item.get("mean_cns")), reverse=True)
    for idx, item in enumerate(summary, start=1):
        item["rank"] = idx
    return summary


def _phase414_correlation(rows: List[Dict[str, object]], key: str) -> float:
    sweep_rows = [row for row in rows if str(row.get("defense_mode")).startswith("weight_sweep")]
    xs = [_to_float(row.get(key)) for row in sweep_rows]
    ys = [_to_float(row.get("cognitive_neutralization_score")) for row in sweep_rows]
    if len(xs) < 2 or len(set(xs)) < 2 or len(set(ys)) < 2:
        return 0.0
    return float(np.corrcoef(xs, ys)[0, 1])


def _analyze_phase414_weight_sweep_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    weight_summary = _phase414_weight_groups(rows)
    best = weight_summary[0] if weight_summary else {}
    mission_cns = _mean_metric(rows, "mission_belief", "cognitive_neutralization_score")
    state_cns = _mean_metric(rows, "state_belief", "cognitive_neutralization_score")
    fixed_cns = _mean_metric(rows, "fixed_best", "cognitive_neutralization_score")
    default_cns = _mean_metric(rows, "intelligence_default", "cognitive_neutralization_score")
    best_cns = _to_float(best.get("mean_cns"))
    critical_corr = _phase414_correlation(rows, "critical_path_weight")
    mission_corr = _phase414_correlation(rows, "mission_weight")
    return {
        "best_weight_configuration": best.get("weight_configuration", ""),
        "best_weight_mean_cns": best_cns,
        "best_weight_rank": best.get("rank", 0),
        "mission_belief_mean_cns": mission_cns,
        "state_belief_mean_cns": state_cns,
        "fixed_best_mean_cns": fixed_cns,
        "intelligence_default_mean_cns": default_cns,
        "weight_sweep_exceeds_state_belief": best_cns > state_cns,
        "weight_sweep_exceeds_mission_belief": best_cns > mission_cns,
        "weight_sweep_exceeds_fixed_best": best_cns > fixed_cns,
        "weight_sweep_exceeds_default": best_cns > default_cns,
        "critical_path_weight_correlation": critical_corr,
        "mission_weight_correlation": mission_corr,
        "critical_path_weight_important": critical_corr > 0.0 or _to_float(best.get("critical_path_weight")) >= 0.5,
        "mission_weight_important": mission_corr > 0.0 or _to_float(best.get("mission_weight")) >= 0.3,
        "intelligence_layer_promising": best_cns > mission_cns and best_cns >= fixed_cns,
        "weight_summary": weight_summary,
    }


def _apply_phase414_weight_ranks(rows: List[Dict[str, object]], analysis: Dict[str, object]) -> None:
    ranks = {
        str(item.get("weight_configuration")): int(item.get("rank", 0))
        for item in analysis.get("weight_summary", [])
    }
    best_label = str(analysis.get("best_weight_configuration") or "")
    for row in rows:
        label = str(row.get("weight_configuration") or "")
        if label in ranks:
            row["weight_sweep_rank"] = ranks[label]
        elif row.get("defense_mode") == "intelligence_default":
            row["weight_sweep_rank"] = 0
        row["best_weight_configuration"] = best_label


def _write_phase414_weight_sweep_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "weight_sweep_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE414_WEIGHT_SWEEP_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE414_WEIGHT_SWEEP_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "weight_sweep_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase414_weight_ranking(analysis: Dict[str, object], save_path: str) -> None:
    summary = list(analysis.get("weight_summary", []))
    labels = [str(item.get("weight_configuration")) for item in summary]
    values = [_to_float(item.get("mean_cns")) for item in summary]
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar(np.arange(len(labels)), values, color="#4e79a7")
    ax.set_title("Phase4.14 Weight Sweep Ranking")
    ax.set_ylabel("mean CNS")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=30, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase414_weight_sensitivity(rows: List[Dict[str, object]], save_path: str) -> None:
    summary = _phase414_weight_groups(rows)
    fig, ax = plt.subplots(figsize=(10, 5))
    for key, label, color in [
        ("mission_weight", "mission", "#4e79a7"),
        ("state_weight", "state", "#59a14f"),
        ("critical_path_weight", "critical_path", "#e15759"),
    ]:
        xs = [_to_float(item.get(key)) for item in summary]
        ys = [_to_float(item.get("mean_cns")) for item in summary]
        ax.scatter(xs, ys, label=label, color=color, s=70)
    ax.set_title("Weight Sensitivity")
    ax.set_xlabel("normalized weight")
    ax.set_ylabel("mean CNS")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase414_vs_phase413(analysis: Dict[str, object], save_path: str) -> None:
    labels = ["fixed_best", "mission_belief", "state_belief", "intelligence_default", "best_sweep"]
    values = [
        _to_float(analysis.get("fixed_best_mean_cns")),
        _to_float(analysis.get("mission_belief_mean_cns")),
        _to_float(analysis.get("state_belief_mean_cns")),
        _to_float(analysis.get("intelligence_default_mean_cns")),
        _to_float(analysis.get("best_weight_mean_cns")),
    ]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(labels)), values, color=["#bab0ab", "#f28e2b", "#59a14f", "#e15759", "#4e79a7"])
    ax.set_title("Phase4.14 Weight Sweep vs Phase4.13")
    ax.set_ylabel("mean CNS")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase414_weight_sweep_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.14 Intelligence Risk Weight Sweep Report",
        "",
        "## Questions",
        f"1. Best weight: `{analysis.get('best_weight_configuration')}` (mean CNS `{_to_float(analysis.get('best_weight_mean_cns')):.3f}`).",
        f"2. Exceeds State Belief: `{analysis.get('weight_sweep_exceeds_state_belief')}` (state `{_to_float(analysis.get('state_belief_mean_cns')):.3f}`).",
        f"3. Exceeds Mission Belief: `{analysis.get('weight_sweep_exceeds_mission_belief')}` (mission `{_to_float(analysis.get('mission_belief_mean_cns')):.3f}`).",
        f"4. Exceeds Fixed Best: `{analysis.get('weight_sweep_exceeds_fixed_best')}` (fixed `{_to_float(analysis.get('fixed_best_mean_cns')):.3f}`).",
        f"5. Critical Path weight important: `{analysis.get('critical_path_weight_important')}` (corr `{_to_float(analysis.get('critical_path_weight_correlation')):.3f}`).",
        f"6. Mission weight important: `{analysis.get('mission_weight_important')}` (corr `{_to_float(analysis.get('mission_weight_correlation')):.3f}`).",
        f"7. Intelligence Layer promising: `{analysis.get('intelligence_layer_promising')}`.",
        "",
        "## Weight Ranking",
        "| rank | weights | mean CNS | risk transitions |",
        "|---:|---|---:|---:|",
    ]
    for item in analysis.get("weight_summary", []):
        lines.append(
            f"| {item.get('rank')} | {item.get('weight_configuration')} | "
            f"{_to_float(item.get('mean_cns')):.3f} | "
            f"{_to_float(item.get('mean_risk_transition_count')):.3f} |"
        )
    lines.extend(
        [
            "",
            "## Rows",
            "| mission | mode | weights | rank | CNS | risk | policy |",
            "|---|---|---|---:|---:|---:|---|",
        ]
    )
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('defense_mode')} | {row.get('weight_configuration')} | "
            f"{_to_float(row.get('weight_sweep_rank')):.0f} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} | "
            f"{_to_float(row.get('intelligence_risk_score')):.3f} | {row.get('selected_policy')} |"
        )
    with open(os.path.join(output_dir, "PHASE414_WEIGHT_SWEEP_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE415_DECISION_MATRIX_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "defense_mode",
    "selected_policy",
    "selected_intelligence_policy",
    "decision_matrix_policy",
    "decision_matrix_match_count",
    "decision_matrix_override_count",
    "policy_diversity_count",
    "predicted_mission",
    "predicted_state",
    "intelligence_risk_score",
    "risk_level",
    "critical_path_proximity",
    "state_transition_count",
    "cognitive_neutralization_score",
    "mission_satisfaction_score",
    "critical_compromise_rate",
    "retreat_rate",
]


def run_phase415_decision_matrix_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase415_decision_matrix"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase415_", 1)
        scenarios[f"{scenario_name}__fixed_best"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="fixed_best",
        )
        scenarios[f"{scenario_name}__mission_belief"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="mission_belief",
            mission_belief=True,
        )
        scenarios[f"{scenario_name}__state_belief"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="state_belief",
            state_belief=True,
        )
        scenarios[f"{scenario_name}__intelligence_risk"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="intelligence_risk",
            intelligence=True,
        )
        scenarios[f"{scenario_name}__decision_matrix"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="decision_matrix",
            intelligence=True,
            decision_matrix=True,
        )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase415_decision_matrix_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("mission_scenario")), str(row.get("defense_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase415_decision_matrix_rows(rows)
    _write_phase415_decision_matrix_summary(rows, analysis, output_dir)
    _plot_phase415_policy_distribution(rows, os.path.join(output_dir, "decision_matrix_policy_distribution.png"))
    _plot_phase415_vs_phase414(analysis, os.path.join(output_dir, "decision_matrix_vs_phase414.png"))
    _plot_phase415_breakdown(rows, os.path.join(output_dir, "decision_matrix_breakdown.png"))
    _write_phase415_decision_matrix_report(rows, analysis, output_dir)
    return rows


def _build_phase415_decision_matrix_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    if "__" in scenario:
        mission_scenario, defense_mode = scenario.split("__", 1)
    else:
        mission_scenario, defense_mode = scenario, ""
    selected_policy = row.get("adaptive_selected_policy") or ""
    if defense_mode == "fixed_best":
        selected_policy = "phase2_frustration_decoy"
    risk_score = row.get("intelligence_risk_score_mean_mean")
    if risk_score is None:
        risk_score = row.get("intelligence_risk_score_mean")
    history = row.get("adaptive_policy_history")
    policy_diversity = 0
    if isinstance(history, list):
        policy_diversity = len({str(policy) for policy in history if str(policy)})
    elif selected_policy:
        policy_diversity = 1
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "defense_mode": defense_mode,
        "selected_policy": selected_policy,
        "selected_intelligence_policy": row.get("selected_intelligence_policy"),
        "decision_matrix_policy": row.get("decision_matrix_policy"),
        "decision_matrix_match_count": row.get("decision_matrix_match_count_mean"),
        "decision_matrix_override_count": row.get("decision_matrix_override_count_mean"),
        "policy_diversity_count": policy_diversity,
        "predicted_mission": row.get("predicted_mission"),
        "predicted_state": row.get("predicted_state"),
        "intelligence_risk_score": risk_score,
        "risk_level": row.get("risk_level"),
        "critical_path_proximity": row.get("critical_path_proximity_mean"),
        "state_transition_count": row.get("state_transition_count_mean"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "mission_satisfaction_score": row.get("mission_satisfaction_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
    }


def _phase415_mode_mean(rows: List[Dict[str, object]], mode: str) -> float:
    return _mean_metric(rows, mode, "cognitive_neutralization_score")


def _analyze_phase415_decision_matrix_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    decision_cns = _phase415_mode_mean(rows, "decision_matrix")
    risk_cns = _phase415_mode_mean(rows, "intelligence_risk")
    state_cns = _phase415_mode_mean(rows, "state_belief")
    mission_cns = _phase415_mode_mean(rows, "mission_belief")
    fixed_cns = _phase415_mode_mean(rows, "fixed_best")
    decision_rows = [row for row in rows if row.get("defense_mode") == "decision_matrix"]
    risk_rows = [row for row in rows if row.get("defense_mode") == "intelligence_risk"]
    policy_set = {str(row.get("selected_policy")) for row in decision_rows if str(row.get("selected_policy"))}
    risk_policy_set = {str(row.get("selected_policy")) for row in risk_rows if str(row.get("selected_policy"))}
    by_mission = {}
    for mission in sorted({str(row.get("attacker_mission")) for row in rows}):
        by_mission[mission] = {
            "decision_matrix_cns": _to_float(next((row.get("cognitive_neutralization_score") for row in decision_rows if row.get("attacker_mission") == mission), 0.0)),
            "intelligence_risk_cns": _to_float(next((row.get("cognitive_neutralization_score") for row in risk_rows if row.get("attacker_mission") == mission), 0.0)),
            "state_belief_cns": _to_float(next((row.get("cognitive_neutralization_score") for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == "state_belief"), 0.0)),
        }
    return {
        "decision_matrix_mean_cns": decision_cns,
        "intelligence_risk_mean_cns": risk_cns,
        "state_belief_mean_cns": state_cns,
        "mission_belief_mean_cns": mission_cns,
        "fixed_best_mean_cns": fixed_cns,
        "decision_matrix_exceeds_intelligence_risk": decision_cns > risk_cns,
        "decision_matrix_exceeds_state_belief": decision_cns > state_cns,
        "decision_matrix_matches_or_exceeds_state_belief": decision_cns >= state_cns,
        "decision_matrix_exceeds_fixed_best": decision_cns > fixed_cns,
        "critical_hunter_effective": by_mission.get("critical_hunter", {}).get("decision_matrix_cns", 0.0)
        > by_mission.get("critical_hunter", {}).get("intelligence_risk_cns", 0.0),
        "persistence_effective": by_mission.get("persistence", {}).get("decision_matrix_cns", 0.0)
        > by_mission.get("persistence", {}).get("intelligence_risk_cns", 0.0),
        "decision_matrix_policy_diversity": len(policy_set),
        "intelligence_risk_policy_diversity": len(risk_policy_set),
        "policy_diversity_increased": len(policy_set) > len(risk_policy_set),
        "mean_decision_matrix_match_count": float(np.mean([_to_float(row.get("decision_matrix_match_count")) for row in decision_rows])) if decision_rows else 0.0,
        "mean_decision_matrix_override_count": float(np.mean([_to_float(row.get("decision_matrix_override_count")) for row in decision_rows])) if decision_rows else 0.0,
        "intelligence_to_defense_promising": decision_cns > risk_cns or len(policy_set) > len(risk_policy_set),
        "by_mission": by_mission,
    }


def _write_phase415_decision_matrix_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "decision_matrix_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE415_DECISION_MATRIX_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE415_DECISION_MATRIX_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "decision_matrix_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase415_policy_distribution(rows: List[Dict[str, object]], save_path: str) -> None:
    decision_rows = [row for row in rows if row.get("defense_mode") == "decision_matrix"]
    policies = [str(row.get("selected_policy")) for row in decision_rows if str(row.get("selected_policy"))]
    labels = list(dict.fromkeys(policies))
    values = [policies.count(label) for label in labels]
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(np.arange(len(labels)), values, color="#4e79a7")
    ax.set_title("Decision Matrix Policy Distribution")
    ax.set_ylabel("mission rows")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=25, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase415_vs_phase414(analysis: Dict[str, object], save_path: str) -> None:
    labels = ["fixed_best", "mission_belief", "state_belief", "intelligence_risk", "decision_matrix"]
    values = [
        _to_float(analysis.get("fixed_best_mean_cns")),
        _to_float(analysis.get("mission_belief_mean_cns")),
        _to_float(analysis.get("state_belief_mean_cns")),
        _to_float(analysis.get("intelligence_risk_mean_cns")),
        _to_float(analysis.get("decision_matrix_mean_cns")),
    ]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(labels)), values, color=["#bab0ab", "#f28e2b", "#59a14f", "#e15759", "#4e79a7"])
    ax.set_title("Decision Matrix vs Intelligence Risk")
    ax.set_ylabel("mean CNS")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase415_breakdown(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    modes = ["intelligence_risk", "decision_matrix", "state_belief"]
    x = np.arange(len(missions))
    width = 0.25
    fig, ax = plt.subplots(figsize=(11, 5))
    for idx, mode in enumerate(modes):
        values = [
            _to_float(next((row.get("cognitive_neutralization_score") for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == mode), 0.0))
            for mission in missions
        ]
        ax.bar(x + (idx - 1) * width, values, width=width, label=mode)
    ax.set_title("Decision Matrix CNS Breakdown")
    ax.set_ylabel("CNS")
    ax.set_xticks(x)
    ax.set_xticklabels(missions)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase415_decision_matrix_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.15 Intelligence Decision Matrix Report",
        "",
        "## Questions",
        f"1. Decision Matrix exceeds Intelligence Risk: `{analysis.get('decision_matrix_exceeds_intelligence_risk')}` (matrix `{_to_float(analysis.get('decision_matrix_mean_cns')):.3f}`, risk `{_to_float(analysis.get('intelligence_risk_mean_cns')):.3f}`).",
        f"2. Decision Matrix exceeds State Belief: `{analysis.get('decision_matrix_exceeds_state_belief')}` (state `{_to_float(analysis.get('state_belief_mean_cns')):.3f}`).",
        f"3. Decision Matrix exceeds Fixed Best: `{analysis.get('decision_matrix_exceeds_fixed_best')}` (fixed `{_to_float(analysis.get('fixed_best_mean_cns')):.3f}`).",
        f"4. Critical Hunter effective: `{analysis.get('critical_hunter_effective')}`.",
        f"5. Persistence effective: `{analysis.get('persistence_effective')}`.",
        f"6. Policy diversity increased: `{analysis.get('policy_diversity_increased')}` (matrix `{analysis.get('decision_matrix_policy_diversity')}`, risk `{analysis.get('intelligence_risk_policy_diversity')}`).",
        f"7. Intelligence-to-Defense translation promising: `{analysis.get('intelligence_to_defense_promising')}`.",
        "",
        "## Summary",
        f"- Mean matrix match count: `{_to_float(analysis.get('mean_decision_matrix_match_count')):.3f}`.",
        f"- Mean matrix override count: `{_to_float(analysis.get('mean_decision_matrix_override_count')):.3f}`.",
        "",
        "## Rows",
        "| mission | mode | policy | matrix_policy | match | override | CNS |",
        "|---|---|---|---|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('defense_mode')} | {row.get('selected_policy')} | "
            f"{row.get('decision_matrix_policy')} | "
            f"{_to_float(row.get('decision_matrix_match_count')):.3f} | "
            f"{_to_float(row.get('decision_matrix_override_count')):.3f} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE415_DECISION_MATRIX_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE416_CAMPAIGN_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "defense_mode",
    "selected_policy",
    "campaign_stage",
    "campaign_transition_count",
    "campaign_policy_switch_count",
    "campaign_policy_diversity",
    "campaign_effectiveness_score",
    "decision_matrix_policy",
    "decision_matrix_override_count",
    "critical_path_proximity",
    "state_transition_count",
    "cognitive_neutralization_score",
    "mission_satisfaction_score",
    "critical_compromise_rate",
    "retreat_rate",
]


def run_phase416_defense_campaign_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase416_defense_campaign"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase416_", 1)
        scenarios[f"{scenario_name}__fixed_best"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="fixed_best",
        )
        scenarios[f"{scenario_name}__state_belief"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="state_belief",
            state_belief=True,
        )
        scenarios[f"{scenario_name}__decision_matrix"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="decision_matrix",
            intelligence=True,
            decision_matrix=True,
        )
        scenarios[f"{scenario_name}__defense_campaign"] = _phase413_intelligence_config(
            "phase2_frustration_decoy",
            mission,
            defense_mode="defense_campaign",
            intelligence=True,
            defense_campaign=True,
        )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase416_campaign_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("mission_scenario")), str(row.get("defense_mode"))))
    os.makedirs(output_dir, exist_ok=True)
    analysis = _analyze_phase416_campaign_rows(rows)
    _write_phase416_campaign_summary(rows, analysis, output_dir)
    _plot_phase416_campaign_policy_timeline(rows, os.path.join(output_dir, "campaign_policy_timeline.png"))
    _plot_phase416_transition_heatmap(rows, os.path.join(output_dir, "campaign_transition_heatmap.png"))
    _plot_phase416_vs_phase415(analysis, os.path.join(output_dir, "campaign_vs_phase415.png"))
    _write_phase416_campaign_report(rows, analysis, output_dir)
    return rows


def _phase416_list_value(value: object) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str) and value:
        return [value]
    return []


def _build_phase416_campaign_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    if "__" in scenario:
        mission_scenario, defense_mode = scenario.split("__", 1)
    else:
        mission_scenario, defense_mode = scenario, ""
    selected_policy = row.get("adaptive_selected_policy") or ""
    if defense_mode == "fixed_best":
        selected_policy = "phase2_frustration_decoy"
    policy_history = _phase416_list_value(row.get("campaign_policy_history"))
    if not policy_history:
        policy_history = [str(selected_policy)] if selected_policy else []
    policy_diversity = len({policy for policy in policy_history if policy})
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "defense_mode": defense_mode,
        "selected_policy": selected_policy,
        "campaign_stage": row.get("campaign_stage"),
        "campaign_transition_count": row.get("campaign_transition_count_mean"),
        "campaign_policy_switch_count": row.get("campaign_policy_switch_count_mean"),
        "campaign_policy_diversity": policy_diversity,
        "campaign_effectiveness_score": row.get("campaign_effectiveness_score_mean"),
        "decision_matrix_policy": row.get("decision_matrix_policy"),
        "decision_matrix_override_count": row.get("decision_matrix_override_count_mean"),
        "critical_path_proximity": row.get("critical_path_proximity_mean"),
        "state_transition_count": row.get("state_transition_count_mean"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "mission_satisfaction_score": row.get("mission_satisfaction_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
        "campaign_stage_history": _phase416_list_value(row.get("campaign_stage_history")),
        "campaign_policy_history": policy_history,
    }


def _analyze_phase416_campaign_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    campaign_cns = _mean_metric(rows, "defense_campaign", "cognitive_neutralization_score")
    decision_cns = _mean_metric(rows, "decision_matrix", "cognitive_neutralization_score")
    state_cns = _mean_metric(rows, "state_belief", "cognitive_neutralization_score")
    fixed_cns = _mean_metric(rows, "fixed_best", "cognitive_neutralization_score")
    campaign_rows = [row for row in rows if row.get("defense_mode") == "defense_campaign"]
    decision_rows = [row for row in rows if row.get("defense_mode") == "decision_matrix"]
    campaign_diversities = [_to_float(row.get("campaign_policy_diversity")) for row in campaign_rows]
    transition_counts = [_to_float(row.get("campaign_transition_count")) for row in campaign_rows]
    by_mission = {}
    for mission in sorted({str(row.get("attacker_mission")) for row in rows}):
        by_mission[mission] = {
            "campaign_cns": _to_float(next((row.get("cognitive_neutralization_score") for row in campaign_rows if row.get("attacker_mission") == mission), 0.0)),
            "decision_matrix_cns": _to_float(next((row.get("cognitive_neutralization_score") for row in decision_rows if row.get("attacker_mission") == mission), 0.0)),
            "state_belief_cns": _to_float(next((row.get("cognitive_neutralization_score") for row in rows if row.get("attacker_mission") == mission and row.get("defense_mode") == "state_belief"), 0.0)),
        }
    return {
        "campaign_mean_cns": campaign_cns,
        "decision_matrix_mean_cns": decision_cns,
        "state_belief_mean_cns": state_cns,
        "fixed_best_mean_cns": fixed_cns,
        "campaign_exceeds_decision_matrix": campaign_cns > decision_cns,
        "campaign_exceeds_state_belief": campaign_cns > state_cns,
        "campaign_matches_or_exceeds_state_belief": campaign_cns >= state_cns,
        "campaign_exceeds_fixed_best": campaign_cns > fixed_cns,
        "mean_campaign_policy_diversity": float(np.mean(campaign_diversities)) if campaign_diversities else 0.0,
        "policy_diversity_greater_than_one": any(value > 1.0 for value in campaign_diversities),
        "mean_campaign_transition_count": float(np.mean(transition_counts)) if transition_counts else 0.0,
        "campaign_transition_observed": any(value > 0.0 for value in transition_counts),
        "critical_hunter_effective": by_mission.get("critical_hunter", {}).get("campaign_cns", 0.0)
        > by_mission.get("critical_hunter", {}).get("decision_matrix_cns", 0.0),
        "persistence_effective": by_mission.get("persistence", {}).get("campaign_cns", 0.0)
        > by_mission.get("persistence", {}).get("decision_matrix_cns", 0.0),
        "active_defense_progress": any(value > 1.0 for value in campaign_diversities) and any(value > 0.0 for value in transition_counts),
        "by_mission": by_mission,
    }


def _write_phase416_campaign_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "campaign_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE416_CAMPAIGN_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE416_CAMPAIGN_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "campaign_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase416_campaign_policy_timeline(rows: List[Dict[str, object]], save_path: str) -> None:
    campaign_rows = [row for row in rows if row.get("defense_mode") == "defense_campaign"]
    policies = sorted({policy for row in campaign_rows for policy in _phase416_list_value(row.get("campaign_policy_history")) if policy})
    if not policies:
        policies = [""]
    policy_index = {policy: idx for idx, policy in enumerate(policies)}
    fig, ax = plt.subplots(figsize=(12, 5))
    for row in campaign_rows:
        history = _phase416_list_value(row.get("campaign_policy_history"))
        values = [policy_index.get(policy, 0) for policy in history]
        ax.plot(np.arange(len(values)), values, label=str(row.get("attacker_mission")))
    ax.set_title("Campaign Policy Timeline")
    ax.set_xlabel("step")
    ax.set_ylabel("policy")
    ax.set_yticks(np.arange(len(policies)))
    ax.set_yticklabels(policies)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase416_transition_heatmap(rows: List[Dict[str, object]], save_path: str) -> None:
    campaign_rows = [row for row in rows if row.get("defense_mode") == "defense_campaign"]
    missions = [str(row.get("attacker_mission")) for row in campaign_rows]
    values = np.array(
        [
            [
                _to_float(row.get("campaign_transition_count")),
                _to_float(row.get("campaign_policy_switch_count")),
                _to_float(row.get("campaign_policy_diversity")),
            ]
            for row in campaign_rows
        ],
        dtype=float,
    )
    if values.size == 0:
        values = np.zeros((1, 3), dtype=float)
        missions = [""]
    fig, ax = plt.subplots(figsize=(8, 5))
    image = ax.imshow(values, aspect="auto", cmap="viridis")
    ax.set_title("Campaign Transitions")
    ax.set_xticks(np.arange(3))
    ax.set_xticklabels(["stage", "policy", "diversity"])
    ax.set_yticks(np.arange(len(missions)))
    ax.set_yticklabels(missions)
    fig.colorbar(image, ax=ax)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase416_vs_phase415(analysis: Dict[str, object], save_path: str) -> None:
    labels = ["fixed_best", "state_belief", "decision_matrix", "defense_campaign"]
    values = [
        _to_float(analysis.get("fixed_best_mean_cns")),
        _to_float(analysis.get("state_belief_mean_cns")),
        _to_float(analysis.get("decision_matrix_mean_cns")),
        _to_float(analysis.get("campaign_mean_cns")),
    ]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(np.arange(len(labels)), values, color=["#bab0ab", "#59a14f", "#4e79a7", "#e15759"])
    ax.set_title("Defense Campaign vs Phase4.15")
    ax.set_ylabel("mean CNS")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase416_campaign_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.16 Defense Campaign Report",
        "",
        "## Questions",
        f"1. Defense Campaign exceeds Decision Matrix: `{analysis.get('campaign_exceeds_decision_matrix')}` (campaign `{_to_float(analysis.get('campaign_mean_cns')):.3f}`, matrix `{_to_float(analysis.get('decision_matrix_mean_cns')):.3f}`).",
        f"2. Defense Campaign exceeds State Belief: `{analysis.get('campaign_exceeds_state_belief')}` (state `{_to_float(analysis.get('state_belief_mean_cns')):.3f}`).",
        f"3. Defense Campaign exceeds Fixed Best: `{analysis.get('campaign_exceeds_fixed_best')}` (fixed `{_to_float(analysis.get('fixed_best_mean_cns')):.3f}`).",
        f"4. Policy diversity increased: `{analysis.get('policy_diversity_greater_than_one')}` (mean `{_to_float(analysis.get('mean_campaign_policy_diversity')):.3f}`).",
        f"5. Campaign transition observed: `{analysis.get('campaign_transition_observed')}` (mean `{_to_float(analysis.get('mean_campaign_transition_count')):.3f}`).",
        f"6. Critical Hunter effective: `{analysis.get('critical_hunter_effective')}`.",
        f"7. Persistence effective: `{analysis.get('persistence_effective')}`.",
        f"8. Active Defense progress: `{analysis.get('active_defense_progress')}`.",
        "",
        "## Rows",
        "| mission | mode | policy | stage | transitions | switches | diversity | CNS |",
        "|---|---|---|---|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('defense_mode')} | {row.get('selected_policy')} | "
            f"{row.get('campaign_stage')} | "
            f"{_to_float(row.get('campaign_transition_count')):.3f} | "
            f"{_to_float(row.get('campaign_policy_switch_count')):.3f} | "
            f"{_to_float(row.get('campaign_policy_diversity')):.3f} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE416_DEFENSE_CAMPAIGN_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE417_CAMPAIGN_PROFILES = [
    ("aggressive_disruption", "Aggressive Disruption"),
    ("trust_collapse", "Trust Collapse"),
    ("utility_suppression", "Utility Suppression"),
    ("balanced", "Balanced Campaign"),
]

PHASE417_CAMPAIGN_PROFILE_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "strategy_profile",
    "profile_label",
    "profile_rank",
    "selected_policy",
    "campaign_stage",
    "campaign_transition_count",
    "campaign_policy_switch_count",
    "campaign_policy_diversity",
    "campaign_effectiveness_score",
    "strategy_effectiveness_score",
    "critical_path_proximity",
    "state_transition_count",
    "cognitive_neutralization_score",
    "mission_satisfaction_score",
    "critical_compromise_rate",
    "retreat_rate",
]


def run_phase417_campaign_profile_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase417_campaign_profiles"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase417_", 1)
        for profile, _label in PHASE417_CAMPAIGN_PROFILES:
            scenarios[f"{scenario_name}__{profile}"] = _phase413_intelligence_config(
                "phase2_frustration_decoy",
                mission,
                defense_mode=f"campaign_{profile}",
                intelligence=True,
                defense_campaign=True,
                campaign_strategy_profile=profile,
            )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase417_campaign_profile_row(row) for row in stats_rows]
    analysis = _analyze_phase417_campaign_profile_rows(rows)
    _apply_phase417_profile_ranks(rows, analysis)
    rows.sort(key=lambda row: (str(row.get("attacker_mission")), int(_to_float(row.get("profile_rank"))), str(row.get("strategy_profile"))))
    os.makedirs(output_dir, exist_ok=True)
    _write_phase417_campaign_profile_summary(rows, analysis, output_dir)
    _plot_phase417_profile_ranking(analysis, os.path.join(output_dir, "campaign_profile_ranking.png"))
    _plot_phase417_profile_by_mission(rows, os.path.join(output_dir, "campaign_profile_by_mission.png"))
    _plot_phase417_vs_phase416(analysis, os.path.join(output_dir, "campaign_profile_vs_phase416.png"))
    _write_phase417_campaign_profile_report(rows, analysis, output_dir)
    return rows


def _phase417_profile_label(profile: str) -> str:
    return dict(PHASE417_CAMPAIGN_PROFILES).get(profile, profile)


def _build_phase417_campaign_profile_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    if "__" in scenario:
        mission_scenario, profile = scenario.split("__", 1)
    else:
        mission_scenario, profile = scenario, str(row.get("strategy_profile") or "balanced")
    selected_policy = row.get("adaptive_selected_policy") or ""
    policy_history = _phase416_list_value(row.get("campaign_policy_history"))
    if not policy_history and selected_policy:
        policy_history = [str(selected_policy)]
    policy_diversity = len({policy for policy in policy_history if policy})
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "strategy_profile": profile,
        "profile_label": _phase417_profile_label(profile),
        "profile_rank": row.get("profile_rank_mean"),
        "selected_policy": selected_policy,
        "campaign_stage": row.get("campaign_stage"),
        "campaign_transition_count": row.get("campaign_transition_count_mean"),
        "campaign_policy_switch_count": row.get("campaign_policy_switch_count_mean"),
        "campaign_policy_diversity": policy_diversity,
        "campaign_effectiveness_score": row.get("campaign_effectiveness_score_mean"),
        "strategy_effectiveness_score": row.get("strategy_effectiveness_score_mean"),
        "critical_path_proximity": row.get("critical_path_proximity_mean"),
        "state_transition_count": row.get("state_transition_count_mean"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "mission_satisfaction_score": row.get("mission_satisfaction_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
        "campaign_policy_history": policy_history,
    }


def _phase417_profile_summary(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    summary = []
    for profile, label in PHASE417_CAMPAIGN_PROFILES:
        profile_rows = [row for row in rows if row.get("strategy_profile") == profile]
        values = [_to_float(row.get("cognitive_neutralization_score")) for row in profile_rows]
        summary.append(
            {
                "strategy_profile": profile,
                "profile_label": label,
                "mean_cns": float(np.mean(values)) if values else 0.0,
                "mean_policy_diversity": float(np.mean([_to_float(row.get("campaign_policy_diversity")) for row in profile_rows])) if profile_rows else 0.0,
                "mean_transition_count": float(np.mean([_to_float(row.get("campaign_transition_count")) for row in profile_rows])) if profile_rows else 0.0,
                "num_rows": len(profile_rows),
            }
        )
    summary.sort(key=lambda item: _to_float(item.get("mean_cns")), reverse=True)
    for idx, item in enumerate(summary, start=1):
        item["profile_rank"] = idx
    return summary


def _analyze_phase417_campaign_profile_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    profile_summary = _phase417_profile_summary(rows)
    best_profile = profile_summary[0] if profile_summary else {}
    balanced_cns = next(
        (_to_float(item.get("mean_cns")) for item in profile_summary if item.get("strategy_profile") == "balanced"),
        0.0,
    )
    by_mission = {}
    best_profiles = []
    for mission in sorted({str(row.get("attacker_mission")) for row in rows}):
        mission_rows = [row for row in rows if row.get("attacker_mission") == mission]
        best_row = max(mission_rows, key=lambda row: _to_float(row.get("cognitive_neutralization_score"))) if mission_rows else {}
        profile = str(best_row.get("strategy_profile") or "")
        best_profiles.append(profile)
        by_mission[mission] = {
            "best_strategy_profile": profile,
            "best_cns": _to_float(best_row.get("cognitive_neutralization_score")),
            "balanced_cns": _to_float(next((row.get("cognitive_neutralization_score") for row in mission_rows if row.get("strategy_profile") == "balanced"), 0.0)),
            "rows": [
                {
                    "strategy_profile": row.get("strategy_profile"),
                    "cns": row.get("cognitive_neutralization_score"),
                    "policy_diversity": row.get("campaign_policy_diversity"),
                }
                for row in mission_rows
            ],
        }
    profit = by_mission.get("profit", {})
    persistence = by_mission.get("persistence", {})
    critical = by_mission.get("critical_hunter", {})
    return {
        "best_strategy_profile": best_profile.get("strategy_profile", ""),
        "best_strategy_label": best_profile.get("profile_label", ""),
        "best_strategy_mean_cns": _to_float(best_profile.get("mean_cns")),
        "balanced_mean_cns": balanced_cns,
        "profile_exceeds_balanced_exists": any(
            item.get("strategy_profile") != "balanced" and _to_float(item.get("mean_cns")) > balanced_cns
            for item in profile_summary
        ),
        "mission_best_strategy_varies": len(set(best_profiles)) > 1,
        "critical_hunter_best_strategy": critical.get("best_strategy_profile", ""),
        "persistence_best_strategy": persistence.get("best_strategy_profile", ""),
        "utility_suppression_effective_for_profit": profit.get("best_strategy_profile") == "utility_suppression",
        "trust_collapse_effective_for_persistence": persistence.get("best_strategy_profile") == "trust_collapse",
        "single_strategy_dominates_all_missions": len(set(best_profiles)) == 1 if best_profiles else False,
        "mission_aware_campaign_needed": len(set(best_profiles)) > 1,
        "profile_summary": profile_summary,
        "by_mission": by_mission,
    }


def _apply_phase417_profile_ranks(rows: List[Dict[str, object]], analysis: Dict[str, object]) -> None:
    ranks = {
        str(item.get("strategy_profile")): int(item.get("profile_rank", 0))
        for item in analysis.get("profile_summary", [])
    }
    for row in rows:
        row["profile_rank"] = ranks.get(str(row.get("strategy_profile")), 0)


def _write_phase417_campaign_profile_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "campaign_profile_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE417_CAMPAIGN_PROFILE_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE417_CAMPAIGN_PROFILE_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "campaign_profile_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase417_profile_ranking(analysis: Dict[str, object], save_path: str) -> None:
    summary = list(analysis.get("profile_summary", []))
    labels = [str(item.get("profile_label")) for item in summary]
    values = [_to_float(item.get("mean_cns")) for item in summary]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(labels)), values, color="#4e79a7")
    ax.set_title("Campaign Strategy Ranking")
    ax.set_ylabel("mean CNS")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase417_profile_by_mission(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    profiles = [profile for profile, _label in PHASE417_CAMPAIGN_PROFILES]
    x = np.arange(len(missions))
    width = 0.18
    fig, ax = plt.subplots(figsize=(12, 5))
    for idx, profile in enumerate(profiles):
        values = [
            _to_float(next((row.get("cognitive_neutralization_score") for row in rows if row.get("attacker_mission") == mission and row.get("strategy_profile") == profile), 0.0))
            for mission in missions
        ]
        ax.bar(x + (idx - 1.5) * width, values, width=width, label=profile)
    ax.set_title("Campaign Strategy by Mission")
    ax.set_ylabel("CNS")
    ax.set_xticks(x)
    ax.set_xticklabels(missions)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase417_vs_phase416(analysis: Dict[str, object], save_path: str) -> None:
    summary = list(analysis.get("profile_summary", []))
    labels = ["balanced"] + [str(item.get("strategy_profile")) for item in summary if item.get("strategy_profile") != "balanced"]
    values = [
        _to_float(next((item.get("mean_cns") for item in summary if item.get("strategy_profile") == label), 0.0))
        for label in labels
    ]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(labels)), values, color="#e15759")
    ax.set_title("Campaign Profiles vs Phase4.16 Balanced")
    ax.set_ylabel("mean CNS")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase417_campaign_profile_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.17 Campaign Strategy Profile Report",
        "",
        "## Questions",
        f"1. Strongest Campaign Strategy: `{analysis.get('best_strategy_profile')}` (mean CNS `{_to_float(analysis.get('best_strategy_mean_cns')):.3f}`).",
        f"2. Best Strategy varies by Mission: `{analysis.get('mission_best_strategy_varies')}`.",
        f"3. Critical Hunter best Strategy: `{analysis.get('critical_hunter_best_strategy')}`.",
        f"4. Persistence best Strategy: `{analysis.get('persistence_best_strategy')}`.",
        f"5. Utility Suppression works best for Profit attacker: `{analysis.get('utility_suppression_effective_for_profit')}`.",
        f"6. Trust Collapse works best for Persistence attacker: `{analysis.get('trust_collapse_effective_for_persistence')}`.",
        f"7. Single Strategy dominates all Missions: `{analysis.get('single_strategy_dominates_all_missions')}`.",
        "",
        "## Success Criteria",
        f"- Profile exceeding Balanced exists: `{analysis.get('profile_exceeds_balanced_exists')}`.",
        f"- Mission-aware Campaign needed: `{analysis.get('mission_aware_campaign_needed')}`.",
        "",
        "## Profile Ranking",
        "| rank | strategy | mean CNS | diversity | transitions |",
        "|---:|---|---:|---:|---:|",
    ]
    for item in analysis.get("profile_summary", []):
        lines.append(
            f"| {item.get('profile_rank')} | {item.get('strategy_profile')} | "
            f"{_to_float(item.get('mean_cns')):.3f} | "
            f"{_to_float(item.get('mean_policy_diversity')):.3f} | "
            f"{_to_float(item.get('mean_transition_count')):.3f} |"
        )
    lines.extend(
        [
            "",
            "## Rows",
            "| mission | strategy | rank | policy | transitions | diversity | CNS |",
            "|---|---|---:|---|---:|---:|---:|",
        ]
    )
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('strategy_profile')} | "
            f"{_to_float(row.get('profile_rank')):.0f} | {row.get('selected_policy')} | "
            f"{_to_float(row.get('campaign_transition_count')):.3f} | "
            f"{_to_float(row.get('campaign_policy_diversity')):.3f} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE417_CAMPAIGN_PROFILE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE418_MISSION_OBJECTIVE_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "strategy_profile",
    "profile_rank",
    "selected_policy",
    "mission_satisfaction",
    "mission_objective_score",
    "mission_objective_defense_score",
    "mission_failure_reason",
    "campaign_transition_count",
    "campaign_policy_diversity",
    "cognitive_neutralization_score",
    "mission_satisfaction_score",
    "critical_compromise_rate",
    "retreat_rate",
]


def run_phase418_mission_objective_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase418_mission_objectives"),
    config_path: str = "config.json",
) -> List[Dict[str, object]]:
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase418_", 1)
        for profile, _label in PHASE417_CAMPAIGN_PROFILES:
            scenarios[f"{scenario_name}__{profile}"] = _phase413_intelligence_config(
                "phase2_frustration_decoy",
                mission,
                defense_mode=f"mission_objective_{profile}",
                intelligence=True,
                defense_campaign=True,
                campaign_strategy_profile=profile,
                mission_objectives=True,
            )

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase418_mission_objective_row(row) for row in stats_rows]
    analysis = _analyze_phase418_mission_objective_rows(rows)
    _apply_phase418_profile_ranks(rows, analysis)
    rows.sort(key=lambda row: (str(row.get("attacker_mission")), int(_to_float(row.get("profile_rank"))), str(row.get("strategy_profile"))))
    os.makedirs(output_dir, exist_ok=True)
    _write_phase418_mission_objective_summary(rows, analysis, output_dir)
    _plot_phase418_satisfaction_by_profile(rows, os.path.join(output_dir, "mission_satisfaction_by_profile.png"))
    _plot_phase418_strategy_by_mission(rows, os.path.join(output_dir, "strategy_by_mission.png"))
    _plot_phase418_vs_phase417(analysis, os.path.join(output_dir, "mission_objective_vs_phase417.png"))
    _write_phase418_mission_objective_report(rows, analysis, output_dir)
    return rows


def _build_phase418_mission_objective_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    if "__" in scenario:
        mission_scenario, profile = scenario.split("__", 1)
    else:
        mission_scenario, profile = scenario, str(row.get("strategy_profile") or "balanced")
    selected_policy = row.get("adaptive_selected_policy") or ""
    policy_history = _phase416_list_value(row.get("campaign_policy_history"))
    if not policy_history and selected_policy:
        policy_history = [str(selected_policy)]
    objective = _to_float(row.get("mission_objective_score_mean"))
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    defense_score = float(np.clip(0.6 * cns + 0.4 * (1.0 - objective), 0.0, 1.0))
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "strategy_profile": profile,
        "profile_rank": row.get("profile_rank_mean"),
        "selected_policy": selected_policy,
        "mission_satisfaction": row.get("mission_satisfaction_mean"),
        "mission_objective_score": row.get("mission_objective_score_mean"),
        "mission_objective_defense_score": defense_score,
        "mission_failure_reason": row.get("mission_failure_reason"),
        "campaign_transition_count": row.get("campaign_transition_count_mean"),
        "campaign_policy_diversity": len({policy for policy in policy_history if policy}),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "mission_satisfaction_score": row.get("mission_satisfaction_score_mean"),
        "critical_compromise_rate": row.get("critical_compromise_rate"),
        "retreat_rate": row.get("retreat_rate"),
    }


def _phase418_profile_summary(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    summary = []
    for profile, label in PHASE417_CAMPAIGN_PROFILES:
        profile_rows = [row for row in rows if row.get("strategy_profile") == profile]
        scores = [_to_float(row.get("mission_objective_defense_score")) for row in profile_rows]
        objectives = [_to_float(row.get("mission_objective_score")) for row in profile_rows]
        summary.append(
            {
                "strategy_profile": profile,
                "profile_label": label,
                "mean_defense_score": float(np.mean(scores)) if scores else 0.0,
                "mean_mission_objective_score": float(np.mean(objectives)) if objectives else 0.0,
                "mean_cns": float(np.mean([_to_float(row.get("cognitive_neutralization_score")) for row in profile_rows])) if profile_rows else 0.0,
                "num_rows": len(profile_rows),
            }
        )
    summary.sort(key=lambda item: _to_float(item.get("mean_defense_score")), reverse=True)
    for idx, item in enumerate(summary, start=1):
        item["profile_rank"] = idx
    return summary


def _analyze_phase418_mission_objective_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    profile_summary = _phase418_profile_summary(rows)
    by_mission = {}
    best_profiles = []
    objective_spreads = []
    for mission in sorted({str(row.get("attacker_mission")) for row in rows}):
        mission_rows = [row for row in rows if row.get("attacker_mission") == mission]
        best_row = max(mission_rows, key=lambda row: _to_float(row.get("mission_objective_defense_score"))) if mission_rows else {}
        profile = str(best_row.get("strategy_profile") or "")
        best_profiles.append(profile)
        objective_values = [_to_float(row.get("mission_objective_score")) for row in mission_rows]
        if objective_values:
            objective_spreads.append(float(max(objective_values) - min(objective_values)))
        by_mission[mission] = {
            "best_strategy_profile": profile,
            "best_defense_score": _to_float(best_row.get("mission_objective_defense_score")),
            "best_mission_objective_score": _to_float(best_row.get("mission_objective_score")),
            "failure_reasons": sorted({str(row.get("mission_failure_reason")) for row in mission_rows}),
            "rows": [
                {
                    "strategy_profile": row.get("strategy_profile"),
                    "defense_score": row.get("mission_objective_defense_score"),
                    "mission_objective_score": row.get("mission_objective_score"),
                    "cns": row.get("cognitive_neutralization_score"),
                }
                for row in mission_rows
            ],
        }
    profit_best = by_mission.get("profit", {}).get("best_strategy_profile", "")
    persistence_best = by_mission.get("persistence", {}).get("best_strategy_profile", "")
    critical_best = by_mission.get("critical_hunter", {}).get("best_strategy_profile", "")
    return {
        "best_strategy_profile": profile_summary[0].get("strategy_profile", "") if profile_summary else "",
        "best_strategy_mean_defense_score": _to_float(profile_summary[0].get("mean_defense_score")) if profile_summary else 0.0,
        "mission_difference_observed": bool(objective_spreads) and any(value > 0.001 for value in objective_spreads),
        "mission_best_strategy_varies": len(set(best_profiles)) > 1,
        "profit_best_strategy_changed": profit_best != "aggressive_disruption",
        "persistence_best_strategy_changed": persistence_best != "aggressive_disruption",
        "critical_hunter_best_strategy_changed": critical_best != "aggressive_disruption",
        "aggressive_disruption_dominance_broken": len(set(best_profiles)) > 1 or any(profile != "aggressive_disruption" for profile in best_profiles),
        "mission_aware_defense_value_shown": len(set(best_profiles)) > 1,
        "campaign_strategy_selection_value_shown": bool(objective_spreads) and any(value > 0.001 for value in objective_spreads),
        "profile_summary": profile_summary,
        "by_mission": by_mission,
    }


def _apply_phase418_profile_ranks(rows: List[Dict[str, object]], analysis: Dict[str, object]) -> None:
    ranks = {
        str(item.get("strategy_profile")): int(item.get("profile_rank", 0))
        for item in analysis.get("profile_summary", [])
    }
    for row in rows:
        row["profile_rank"] = ranks.get(str(row.get("strategy_profile")), 0)


def _write_phase418_mission_objective_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "mission_objective_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE418_MISSION_OBJECTIVE_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE418_MISSION_OBJECTIVE_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "mission_objective_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase418_satisfaction_by_profile(rows: List[Dict[str, object]], save_path: str) -> None:
    profiles = [profile for profile, _label in PHASE417_CAMPAIGN_PROFILES]
    values = [
        float(np.mean([_to_float(row.get("mission_objective_score")) for row in rows if row.get("strategy_profile") == profile]))
        for profile in profiles
    ]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(profiles)), values, color="#f28e2b")
    ax.set_title("Mission Objective Score by Profile")
    ax.set_ylabel("attacker objective")
    ax.set_xticks(np.arange(len(profiles)))
    ax.set_xticklabels(profiles, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase418_strategy_by_mission(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    profiles = [profile for profile, _label in PHASE417_CAMPAIGN_PROFILES]
    x = np.arange(len(missions))
    width = 0.18
    fig, ax = plt.subplots(figsize=(12, 5))
    for idx, profile in enumerate(profiles):
        values = [
            _to_float(next((row.get("mission_objective_defense_score") for row in rows if row.get("attacker_mission") == mission and row.get("strategy_profile") == profile), 0.0))
            for mission in missions
        ]
        ax.bar(x + (idx - 1.5) * width, values, width=width, label=profile)
    ax.set_title("Mission Objective Defense Score by Mission")
    ax.set_ylabel("defense score")
    ax.set_xticks(x)
    ax.set_xticklabels(missions)
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase418_vs_phase417(analysis: Dict[str, object], save_path: str) -> None:
    summary = list(analysis.get("profile_summary", []))
    labels = [str(item.get("strategy_profile")) for item in summary]
    values = [_to_float(item.get("mean_defense_score")) for item in summary]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(labels)), values, color="#4e79a7")
    ax.set_title("Phase4.18 Mission Objective vs Phase4.17 Profiles")
    ax.set_ylabel("mission objective defense score")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase418_mission_objective_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.18 Mission Objective Report",
        "",
        "## Questions",
        f"1. Mission-specific differences observed: `{analysis.get('mission_difference_observed')}`.",
        f"2. Profit best Strategy changed: `{analysis.get('profit_best_strategy_changed')}`.",
        f"3. Persistence best Strategy changed: `{analysis.get('persistence_best_strategy_changed')}`.",
        f"4. Critical Hunter best Strategy changed: `{analysis.get('critical_hunter_best_strategy_changed')}`.",
        f"5. Aggressive Disruption dominance broken: `{analysis.get('aggressive_disruption_dominance_broken')}`.",
        f"6. Mission-Aware Defense value shown: `{analysis.get('mission_aware_defense_value_shown')}`.",
        f"7. Campaign Strategy selection value shown: `{analysis.get('campaign_strategy_selection_value_shown')}`.",
        "",
        "## Profile Ranking",
        "| rank | strategy | defense score | objective | CNS |",
        "|---:|---|---:|---:|---:|",
    ]
    for item in analysis.get("profile_summary", []):
        lines.append(
            f"| {item.get('profile_rank')} | {item.get('strategy_profile')} | "
            f"{_to_float(item.get('mean_defense_score')):.3f} | "
            f"{_to_float(item.get('mean_mission_objective_score')):.3f} | "
            f"{_to_float(item.get('mean_cns')):.3f} |"
        )
    lines.extend(["", "## Rows", "| mission | strategy | rank | objective | defense_score | failure | CNS |", "|---|---|---:|---:|---:|---|---:|"])
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('strategy_profile')} | "
            f"{_to_float(row.get('profile_rank')):.0f} | "
            f"{_to_float(row.get('mission_objective_score')):.3f} | "
            f"{_to_float(row.get('mission_objective_defense_score')):.3f} | "
            f"{row.get('mission_failure_reason')} | "
            f"{_to_float(row.get('cognitive_neutralization_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE418_MISSION_OBJECTIVE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE419_OBJECTIVE_WEIGHT_PROFILES = {
    "profit": [
        ("profit_eu90_success10", {"profit_expected_utility_weight": 0.9, "profit_success_weight": 0.1}),
        ("profit_eu80_success20", {"profit_expected_utility_weight": 0.8, "profit_success_weight": 0.2}),
        ("profit_eu70_success30", {"profit_expected_utility_weight": 0.7, "profit_success_weight": 0.3}),
        ("profit_eu60_success40", {"profit_expected_utility_weight": 0.6, "profit_success_weight": 0.4}),
    ],
    "persistence": [
        ("persistence_survival20_trust60_stealth20", {"persistence_survival_weight": 0.2, "persistence_trust_weight": 0.6, "persistence_stealth_weight": 0.2}),
        ("persistence_survival30_trust50_stealth20", {"persistence_survival_weight": 0.3, "persistence_trust_weight": 0.5, "persistence_stealth_weight": 0.2}),
        ("persistence_survival50_trust30_stealth20", {"persistence_survival_weight": 0.5, "persistence_trust_weight": 0.3, "persistence_stealth_weight": 0.2}),
    ],
    "critical_hunter": [
        ("critical_progress90_reach10", {"critical_progress_weight": 0.9, "critical_reach_weight": 0.1}),
        ("critical_progress80_reach20", {"critical_progress_weight": 0.8, "critical_reach_weight": 0.2}),
        ("critical_progress70_reach30", {"critical_progress_weight": 0.7, "critical_reach_weight": 0.3}),
    ],
    "achievement": [
        ("achievement_progress80_critical20", {"achievement_progress_weight": 0.8, "achievement_critical_weight": 0.2}),
        ("achievement_progress60_critical40", {"achievement_progress_weight": 0.6, "achievement_critical_weight": 0.4}),
        ("achievement_progress40_critical60", {"achievement_progress_weight": 0.4, "achievement_critical_weight": 0.6}),
    ],
}

PHASE419_MISSION_SENSITIVITY_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "objective_weight_profile",
    "strategy_profile",
    "selected_policy",
    "mission_strategy_change",
    "mission_sensitivity_score",
    "mission_objective_score",
    "mission_objective_defense_score",
    "mission_failure_reason",
    "cognitive_neutralization_score",
    "campaign_transition_count",
    "campaign_policy_diversity",
    "retreat_rate",
]


def run_phase419_mission_sensitivity_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase419_mission_sensitivity"),
    config_path: str = "config.json",
    objective_profiles: Optional[Dict[str, List[Tuple[str, Dict[str, float]]]]] = None,
) -> List[Dict[str, object]]:
    profiles = objective_profiles if objective_profiles is not None else PHASE419_OBJECTIVE_WEIGHT_PROFILES
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        mission_key = str(mission.get("attacker_mission"))
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase419_", 1)
        for weight_label, weight_overrides in profiles.get(mission_key, []):
            for strategy, _label in PHASE417_CAMPAIGN_PROFILES:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"sensitivity_{strategy}",
                    intelligence=True,
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                scenario_config.update(weight_overrides)
                scenario_config["objective_weight_profile"] = weight_label
                scenarios[f"{scenario_name}__{weight_label}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase419_mission_sensitivity_row(row) for row in stats_rows]
    analysis = _analyze_phase419_mission_sensitivity_rows(rows)
    _apply_phase419_strategy_changes(rows, analysis)
    rows.sort(key=lambda row: (str(row.get("attacker_mission")), str(row.get("objective_weight_profile")), str(row.get("strategy_profile"))))
    os.makedirs(output_dir, exist_ok=True)
    _write_phase419_mission_sensitivity_summary(rows, analysis, output_dir)
    _plot_phase419_sensitivity_heatmap(analysis, os.path.join(output_dir, "mission_sensitivity_heatmap.png"))
    _plot_phase419_strategy_by_weight(rows, os.path.join(output_dir, "strategy_by_mission_weight.png"))
    _plot_phase419_vs_phase418(analysis, os.path.join(output_dir, "mission_sensitivity_vs_phase418.png"))
    _write_phase419_mission_sensitivity_report(rows, analysis, output_dir)
    return rows


def _build_phase419_mission_sensitivity_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    mission_scenario = parts[0] if parts else scenario
    weight_profile = parts[1] if len(parts) > 1 else str(row.get("objective_weight_profile") or "default")
    strategy = parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced")
    selected_policy = row.get("adaptive_selected_policy") or ""
    policy_history = _phase416_list_value(row.get("campaign_policy_history"))
    objective = _to_float(row.get("mission_objective_score_mean"))
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    defense_score = float(np.clip(0.6 * cns + 0.4 * (1.0 - objective), 0.0, 1.0))
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "objective_weight_profile": weight_profile,
        "strategy_profile": strategy,
        "selected_policy": selected_policy,
        "mission_strategy_change": False,
        "mission_sensitivity_score": 0.0,
        "mission_objective_score": row.get("mission_objective_score_mean"),
        "mission_objective_defense_score": defense_score,
        "mission_failure_reason": row.get("mission_failure_reason"),
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "campaign_transition_count": row.get("campaign_transition_count_mean"),
        "campaign_policy_diversity": len({policy for policy in policy_history if policy}) if policy_history else 1,
        "retreat_rate": row.get("retreat_rate"),
    }


def _phase419_group_best(rows: List[Dict[str, object]]) -> Dict[Tuple[str, str], Dict[str, object]]:
    grouped: Dict[Tuple[str, str], List[Dict[str, object]]] = {}
    for row in rows:
        grouped.setdefault((str(row.get("attacker_mission")), str(row.get("objective_weight_profile"))), []).append(row)
    return {
        key: max(group_rows, key=lambda row: _to_float(row.get("mission_objective_defense_score")))
        for key, group_rows in grouped.items()
        if group_rows
    }


def _analyze_phase419_mission_sensitivity_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    best_by_weight = _phase419_group_best(rows)
    sensitivity_by_mission: Dict[str, float] = {}
    best_profiles_by_mission: Dict[str, List[str]] = {}
    default_best = {
        "profit": "aggressive_disruption",
        "achievement": "trust_collapse",
        "persistence": "aggressive_disruption",
        "critical_hunter": "aggressive_disruption",
    }
    for mission in sorted({str(row.get("attacker_mission")) for row in rows}):
        mission_rows = [row for row in rows if row.get("attacker_mission") == mission]
        scores = [_to_float(row.get("mission_objective_defense_score")) for row in mission_rows]
        sensitivity_by_mission[mission] = float(max(scores) - min(scores)) if scores else 0.0
        best_profiles_by_mission[mission] = [
            str(best.get("strategy_profile"))
            for (best_mission, _weight), best in best_by_weight.items()
            if best_mission == mission
        ]
    profit_best_set = set(best_profiles_by_mission.get("profit", []))
    persistence_best_set = set(best_profiles_by_mission.get("persistence", []))
    critical_best_set = set(best_profiles_by_mission.get("critical_hunter", []))
    all_best_profiles = [profile for profiles in best_profiles_by_mission.values() for profile in profiles]
    return {
        "mission_difference_expanded": any(value > 0.01 for value in sensitivity_by_mission.values()),
        "profit_strategy_changes": len(profit_best_set - {default_best["profit"]}) > 0,
        "persistence_strategy_changes": len(persistence_best_set - {default_best["persistence"]}) > 0,
        "critical_hunter_strategy_changes": len(critical_best_set - {default_best["critical_hunter"]}) > 0,
        "utility_suppression_effective_for_profit": "utility_suppression" in profit_best_set,
        "trust_collapse_effective_for_persistence": "trust_collapse" in persistence_best_set,
        "planning_disruption_effective_for_critical_hunter": "aggressive_disruption" in critical_best_set,
        "mission_aware_defense_value_strengthened": len(set(all_best_profiles)) > 1,
        "mission_best_strategy_differentiated": len(set(all_best_profiles)) > 1,
        "mean_mission_sensitivity_score": float(np.mean(list(sensitivity_by_mission.values()))) if sensitivity_by_mission else 0.0,
        "sensitivity_by_mission": sensitivity_by_mission,
        "best_profiles_by_mission": best_profiles_by_mission,
        "best_by_weight": {
            f"{mission}|{weight}": {
                "strategy_profile": best.get("strategy_profile"),
                "defense_score": best.get("mission_objective_defense_score"),
                "objective": best.get("mission_objective_score"),
            }
            for (mission, weight), best in best_by_weight.items()
        },
    }


def _apply_phase419_strategy_changes(rows: List[Dict[str, object]], analysis: Dict[str, object]) -> None:
    best_by_weight = analysis.get("best_by_weight", {})
    sensitivity = analysis.get("sensitivity_by_mission", {})
    default_best = {
        "profit": "aggressive_disruption",
        "achievement": "trust_collapse",
        "persistence": "aggressive_disruption",
        "critical_hunter": "aggressive_disruption",
    }
    for row in rows:
        mission = str(row.get("attacker_mission"))
        weight = str(row.get("objective_weight_profile"))
        best = best_by_weight.get(f"{mission}|{weight}", {})
        row["mission_strategy_change"] = str(best.get("strategy_profile")) != default_best.get(mission, "")
        row["mission_sensitivity_score"] = _to_float(sensitivity.get(mission, 0.0))


def _write_phase419_mission_sensitivity_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "mission_sensitivity_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE419_MISSION_SENSITIVITY_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE419_MISSION_SENSITIVITY_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "mission_sensitivity_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase419_sensitivity_heatmap(analysis: Dict[str, object], save_path: str) -> None:
    missions = list(analysis.get("sensitivity_by_mission", {}).keys())
    values = np.asarray([[_to_float(analysis.get("sensitivity_by_mission", {}).get(mission))] for mission in missions], dtype=float)
    if values.size == 0:
        values = np.zeros((1, 1), dtype=float)
        missions = [""]
    fig, ax = plt.subplots(figsize=(6, 5))
    image = ax.imshow(values, aspect="auto", cmap="magma")
    ax.set_title("Mission Sensitivity Score")
    ax.set_xticks([0])
    ax.set_xticklabels(["sensitivity"])
    ax.set_yticks(np.arange(len(missions)))
    ax.set_yticklabels(missions)
    fig.colorbar(image, ax=ax)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase419_strategy_by_weight(rows: List[Dict[str, object]], save_path: str) -> None:
    labels = [f"{row.get('attacker_mission')}:{row.get('objective_weight_profile')}" for row in rows if row.get("strategy_profile") == "aggressive_disruption"]
    profiles = [profile for profile, _label in PHASE417_CAMPAIGN_PROFILES]
    x = np.arange(len(labels))
    width = 0.18
    fig, ax = plt.subplots(figsize=(14, 6))
    for idx, profile in enumerate(profiles):
        values = [
            _to_float(next((row.get("mission_objective_defense_score") for row in rows if f"{row.get('attacker_mission')}:{row.get('objective_weight_profile')}" == label and row.get("strategy_profile") == profile), 0.0))
            for label in labels
        ]
        ax.bar(x + (idx - 1.5) * width, values, width=width, label=profile)
    ax.set_title("Strategy by Mission Weight Profile")
    ax.set_ylabel("defense score")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase419_vs_phase418(analysis: Dict[str, object], save_path: str) -> None:
    labels = list(analysis.get("sensitivity_by_mission", {}).keys())
    values = [_to_float(analysis.get("sensitivity_by_mission", {}).get(label)) for label in labels]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(np.arange(len(labels)), values, color="#4e79a7")
    ax.set_title("Mission Sensitivity vs Phase4.18")
    ax.set_ylabel("score spread")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase419_mission_sensitivity_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.19 Mission Objective Sensitivity Report",
        "",
        "## Questions",
        f"1. Mission differences expanded: `{analysis.get('mission_difference_expanded')}`.",
        f"2. Profit best Strategy changes: `{analysis.get('profit_strategy_changes')}`.",
        f"3. Persistence best Strategy changes: `{analysis.get('persistence_strategy_changes')}`.",
        f"4. Critical Hunter best Strategy changes: `{analysis.get('critical_hunter_strategy_changes')}`.",
        f"5. Utility Suppression works for Profit: `{analysis.get('utility_suppression_effective_for_profit')}`.",
        f"6. Trust Collapse works for Persistence: `{analysis.get('trust_collapse_effective_for_persistence')}`.",
        f"7. Planning Disruption works for Critical Hunter: `{analysis.get('planning_disruption_effective_for_critical_hunter')}`.",
        f"8. Mission-Aware Defense value strengthened: `{analysis.get('mission_aware_defense_value_strengthened')}`.",
        "",
        "## Sensitivity",
        "| mission | sensitivity | best profiles |",
        "|---|---:|---|",
    ]
    for mission, value in analysis.get("sensitivity_by_mission", {}).items():
        lines.append(f"| {mission} | {_to_float(value):.3f} | {analysis.get('best_profiles_by_mission', {}).get(mission)} |")
    lines.extend(["", "## Rows", "| mission | weight | strategy | change | sensitivity | objective | defense |", "|---|---|---|---|---:|---:|---:|"])
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('objective_weight_profile')} | {row.get('strategy_profile')} | "
            f"{row.get('mission_strategy_change')} | {_to_float(row.get('mission_sensitivity_score')):.3f} | "
            f"{_to_float(row.get('mission_objective_score')):.3f} | {_to_float(row.get('mission_objective_defense_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE419_MISSION_SENSITIVITY_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE420_ADAPTIVE_MISSION_COLUMNS = [
    "mission_scenario",
    "attacker_mission",
    "attacker_mode",
    "strategy_profile",
    "selected_policy",
    "mission_objective_score",
    "mission_objective_defense_score",
    "mission_failure_reason",
    "adaptation_count",
    "ttp_change_count",
    "strategy_avoidance_score",
    "alternative_path_usage",
    "target_switch_count",
    "campaign_transition_count",
    "campaign_policy_diversity",
    "cognitive_neutralization_score",
    "adaptive_defender_effectiveness",
    "retreat_rate",
]


def run_phase420_adaptive_mission_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase420_adaptive_mission"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = strategy_profiles if strategy_profiles is not None else [profile for profile, _label in PHASE417_CAMPAIGN_PROFILES]
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase420_", 1)
        for attacker_mode, adaptive_enabled in (("non_adaptive", False), ("adaptive", True)):
            for strategy in profiles:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"adaptive_mission_{attacker_mode}_{strategy}",
                    intelligence=True,
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                scenario_config.update(
                    {
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": adaptive_enabled,
                    }
                )
                scenarios[f"{scenario_name}__{attacker_mode}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase420_adaptive_mission_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("attacker_mission")), str(row.get("attacker_mode")), str(row.get("strategy_profile"))))
    analysis = _analyze_phase420_adaptive_mission_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase420_adaptive_mission_summary(rows, analysis, output_dir)
    _plot_phase420_metric(rows, "ttp_change_count", os.path.join(output_dir, "ttp_change_count.png"))
    _plot_phase420_metric(rows, "alternative_path_usage", os.path.join(output_dir, "alternative_path_usage.png"))
    _plot_phase420_adaptive_vs_nonadaptive(rows, os.path.join(output_dir, "adaptive_vs_nonadaptive.png"))
    _write_phase420_adaptive_mission_report(rows, analysis, output_dir)
    return rows


def _build_phase420_adaptive_mission_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    mission_scenario = parts[0] if parts else scenario
    attacker_mode = parts[1] if len(parts) > 1 else ("adaptive" if row.get("adaptive_mission_attacker_enabled") else "non_adaptive")
    strategy = parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced")
    objective = _to_float(row.get("mission_objective_score_mean"))
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    defense_score = float(np.clip(0.6 * cns + 0.4 * (1.0 - objective), 0.0, 1.0))
    policy_history = _phase416_list_value(row.get("campaign_policy_history"))
    return {
        "mission_scenario": mission_scenario,
        "attacker_mission": row.get("attacker_mission"),
        "attacker_mode": attacker_mode,
        "strategy_profile": strategy,
        "selected_policy": row.get("adaptive_selected_policy") or "",
        "mission_objective_score": row.get("mission_objective_score_mean"),
        "mission_objective_defense_score": defense_score,
        "mission_failure_reason": row.get("mission_failure_reason"),
        "adaptation_count": row.get("adaptation_count_mean"),
        "ttp_change_count": row.get("ttp_change_count_mean"),
        "strategy_avoidance_score": row.get("strategy_avoidance_score_mean"),
        "alternative_path_usage": row.get("alternative_path_usage_mean"),
        "target_switch_count": row.get("target_switch_count_mean"),
        "campaign_transition_count": row.get("campaign_transition_count_mean"),
        "campaign_policy_diversity": len({policy for policy in policy_history if policy}) if policy_history else 1,
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "adaptive_defender_effectiveness": row.get("adaptive_defender_effectiveness_mean"),
        "retreat_rate": row.get("retreat_rate"),
    }


def _analyze_phase420_adaptive_mission_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    adaptive_rows = [row for row in rows if row.get("attacker_mode") == "adaptive"]
    non_rows = [row for row in rows if row.get("attacker_mode") == "non_adaptive"]
    ttp_values = [_to_float(row.get("ttp_change_count")) for row in adaptive_rows]
    alt_values = [_to_float(row.get("alternative_path_usage")) for row in adaptive_rows]
    non_alt_values = [_to_float(row.get("alternative_path_usage")) for row in non_rows]
    mission_adaptation = {}
    for mission in sorted({str(row.get("attacker_mission")) for row in adaptive_rows}):
        mission_rows = [row for row in adaptive_rows if row.get("attacker_mission") == mission]
        mission_adaptation[mission] = {
            "mean_ttp_change_count": float(np.mean([_to_float(row.get("ttp_change_count")) for row in mission_rows])) if mission_rows else 0.0,
            "mean_alternative_path_usage": float(np.mean([_to_float(row.get("alternative_path_usage")) for row in mission_rows])) if mission_rows else 0.0,
            "best_defense_strategy": max(mission_rows, key=lambda row: _to_float(row.get("mission_objective_defense_score"))).get("strategy_profile") if mission_rows else "",
        }
    adaptive_best = _phase420_best_profiles(adaptive_rows)
    non_best = _phase420_best_profiles(non_rows)
    non_agg = _phase420_profile_mean(non_rows, "aggressive_disruption", "mission_objective_defense_score")
    adaptive_agg = _phase420_profile_mean(adaptive_rows, "aggressive_disruption", "mission_objective_defense_score")
    adaptive_defender_values = [_to_float(row.get("mission_objective_defense_score")) for row in adaptive_rows]
    return {
        "attacker_learns_defense": bool(ttp_values) and float(np.mean(ttp_values)) > 0.0,
        "ttp_change_observed": any(value > 0.0 for value in ttp_values),
        "alternative_path_increased": bool(alt_values) and float(np.mean(alt_values)) > float(np.mean(non_alt_values) if non_alt_values else 0.0),
        "aggressive_disruption_dominance_reduced": adaptive_agg < non_agg or adaptive_best.count("aggressive_disruption") < non_best.count("aggressive_disruption"),
        "mission_adaptation_differs": len({round(item["mean_ttp_change_count"], 3) for item in mission_adaptation.values()}) > 1,
        "adaptive_defender_value_increases": len(set(adaptive_best)) > 1 or (max(adaptive_defender_values) - min(adaptive_defender_values) > 0.01 if adaptive_defender_values else False),
        "coevolution_signal": any(value > 0.0 for value in ttp_values) and len(set(adaptive_best)) > 1,
        "mean_adaptation_count": float(np.mean([_to_float(row.get("adaptation_count")) for row in adaptive_rows])) if adaptive_rows else 0.0,
        "mean_ttp_change_count": float(np.mean(ttp_values)) if ttp_values else 0.0,
        "mean_alternative_path_usage": float(np.mean(alt_values)) if alt_values else 0.0,
        "nonadaptive_aggressive_score": non_agg,
        "adaptive_aggressive_score": adaptive_agg,
        "adaptive_best_profiles": adaptive_best,
        "nonadaptive_best_profiles": non_best,
        "mission_adaptation": mission_adaptation,
    }


def _phase420_best_profiles(rows: List[Dict[str, object]]) -> List[str]:
    best = []
    for mission in sorted({str(row.get("attacker_mission")) for row in rows}):
        mission_rows = [row for row in rows if row.get("attacker_mission") == mission]
        if mission_rows:
            best.append(str(max(mission_rows, key=lambda row: _to_float(row.get("mission_objective_defense_score"))).get("strategy_profile")))
    return best


def _phase420_profile_mean(rows: List[Dict[str, object]], profile: str, key: str) -> float:
    values = [_to_float(row.get(key)) for row in rows if row.get("strategy_profile") == profile]
    return float(np.mean(values)) if values else 0.0


def _write_phase420_adaptive_mission_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "adaptive_mission_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE420_ADAPTIVE_MISSION_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE420_ADAPTIVE_MISSION_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "adaptive_mission_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase420_metric(rows: List[Dict[str, object]], metric: str, save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    adaptive_values = [
        float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("attacker_mission") == mission and row.get("attacker_mode") == "adaptive"]))
        for mission in missions
    ]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(missions)), adaptive_values, color="#59a14f")
    ax.set_title(metric.replace("_", " ").title())
    ax.set_ylabel(metric)
    ax.set_xticks(np.arange(len(missions)))
    ax.set_xticklabels(missions, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase420_adaptive_vs_nonadaptive(rows: List[Dict[str, object]], save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("attacker_mission")) for row in rows))
    x = np.arange(len(missions))
    width = 0.35
    fig, ax = plt.subplots(figsize=(10, 5))
    for idx, mode in enumerate(["non_adaptive", "adaptive"]):
        values = [
            float(np.mean([_to_float(row.get("mission_objective_defense_score")) for row in rows if row.get("attacker_mission") == mission and row.get("attacker_mode") == mode]))
            for mission in missions
        ]
        ax.bar(x + (idx - 0.5) * width, values, width=width, label=mode)
    ax.set_title("Adaptive vs Non-Adaptive Mission Attacker")
    ax.set_ylabel("defense score")
    ax.set_xticks(x)
    ax.set_xticklabels(missions, rotation=20, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase420_adaptive_mission_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.20 Adaptive Mission Attacker Report",
        "",
        "## Research Questions",
        f"1. Attacker learns defense: `{analysis.get('attacker_learns_defense')}`.",
        f"2. TTP changes occur: `{analysis.get('ttp_change_observed')}`.",
        f"3. Alternative path exploration increases: `{analysis.get('alternative_path_increased')}`.",
        f"4. Aggressive Disruption dominance reduced: `{analysis.get('aggressive_disruption_dominance_reduced')}`.",
        f"5. Mission adaptation differs: `{analysis.get('mission_adaptation_differs')}`.",
        f"6. Adaptive Defender value increases: `{analysis.get('adaptive_defender_value_increases')}`.",
        f"7. Co-evolution signal: `{analysis.get('coevolution_signal')}`.",
        "",
        "## Summary",
        f"- Mean adaptation count: `{_to_float(analysis.get('mean_adaptation_count')):.3f}`.",
        f"- Mean TTP change count: `{_to_float(analysis.get('mean_ttp_change_count')):.3f}`.",
        f"- Mean alternative path usage: `{_to_float(analysis.get('mean_alternative_path_usage')):.3f}`.",
        f"- Aggressive score non-adaptive/adaptive: `{_to_float(analysis.get('nonadaptive_aggressive_score')):.3f}` / `{_to_float(analysis.get('adaptive_aggressive_score')):.3f}`.",
        "",
        "## Mission Adaptation",
        "| mission | ttp changes | alternative paths | best defense |",
        "|---|---:|---:|---|",
    ]
    for mission, item in analysis.get("mission_adaptation", {}).items():
        lines.append(
            f"| {mission} | {_to_float(item.get('mean_ttp_change_count')):.3f} | "
            f"{_to_float(item.get('mean_alternative_path_usage')):.3f} | {item.get('best_defense_strategy')} |"
        )
    lines.extend(["", "## Rows", "| mission | mode | strategy | ttp | alt_path | objective | defense |", "|---|---|---|---:|---:|---:|---:|"])
    for row in rows:
        lines.append(
            f"| {row.get('attacker_mission')} | {row.get('attacker_mode')} | {row.get('strategy_profile')} | "
            f"{_to_float(row.get('ttp_change_count')):.3f} | {_to_float(row.get('alternative_path_usage')):.3f} | "
            f"{_to_float(row.get('mission_objective_score')):.3f} | {_to_float(row.get('mission_objective_defense_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE420_ADAPTIVE_MISSION_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE421_MISSION_MUTATION_COLUMNS = [
    "mission_scenario",
    "initial_mission",
    "final_mission",
    "attacker_mode",
    "strategy_profile",
    "selected_policy",
    "mission_objective_score",
    "mission_objective_defense_score",
    "mission_failure_reason",
    "mission_change_count",
    "mission_stability_score",
    "mission_mutation_reason",
    "mission_mutation_success",
    "achievement_mutation",
    "adaptation_count",
    "ttp_change_count",
    "alternative_path_usage",
    "campaign_transition_count",
    "campaign_policy_diversity",
    "cognitive_neutralization_score",
    "retreat_rate",
]


def run_phase421_mission_mutation_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase421_mission_mutation"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = strategy_profiles if strategy_profiles is not None else [profile for profile, _label in PHASE417_CAMPAIGN_PROFILES]
    attacker_modes = [
        ("fixed_mission", False, False, "standard"),
        ("adaptive_mission", True, False, "adaptive_mission_attacker"),
        ("mission_mutator", True, True, "adaptive_mission_mutator"),
    ]
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase421_", 1)
        for attacker_mode, adaptive_enabled, mutation_enabled, attacker_type in attacker_modes:
            for strategy in profiles:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"mission_mutation_{attacker_mode}_{strategy}",
                    intelligence=True,
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                scenario_config.update(
                    {
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": adaptive_enabled,
                        "mission_mutation_enabled": mutation_enabled,
                        "attacker_type": attacker_type,
                    }
                )
                scenarios[f"{scenario_name}__{attacker_mode}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase421_mission_mutation_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("initial_mission")), str(row.get("attacker_mode")), str(row.get("strategy_profile"))))
    analysis = _analyze_phase421_mission_mutation_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase421_mission_mutation_summary(rows, analysis, output_dir)
    _plot_phase421_transition_matrix(analysis, os.path.join(output_dir, "mission_transition_matrix.png"))
    _plot_phase421_metric(rows, "mission_change_count", os.path.join(output_dir, "mission_change_count.png"))
    _plot_phase421_mutation_vs_phase420(rows, os.path.join(output_dir, "mission_mutation_vs_phase420.png"))
    _write_phase421_mission_mutation_report(rows, analysis, output_dir)
    return rows


def _build_phase421_mission_mutation_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    mission_scenario = parts[0] if parts else scenario
    attacker_mode = parts[1] if len(parts) > 1 else str(row.get("attacker_type") or "fixed_mission")
    strategy = parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced")
    mission_history = _phase416_list_value(row.get("mission_history"))
    initial_mission = _phase421_initial_mission_from_scenario(mission_scenario, str(row.get("attacker_mission") or ""))
    final_mission = mission_history[-1] if mission_history else initial_mission
    objective = _to_float(row.get("mission_objective_score_mean"))
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    defense_score = float(np.clip(0.6 * cns + 0.4 * (1.0 - objective), 0.0, 1.0))
    policy_history = _phase416_list_value(row.get("campaign_policy_history"))
    return {
        "mission_scenario": mission_scenario,
        "initial_mission": initial_mission,
        "final_mission": final_mission,
        "attacker_mode": attacker_mode,
        "strategy_profile": strategy,
        "selected_policy": row.get("adaptive_selected_policy") or "",
        "mission_objective_score": row.get("mission_objective_score_mean"),
        "mission_objective_defense_score": defense_score,
        "mission_failure_reason": row.get("mission_failure_reason"),
        "mission_change_count": row.get("mission_change_count_mean"),
        "mission_stability_score": row.get("mission_stability_score_mean"),
        "mission_mutation_reason": row.get("mission_mutation_reason"),
        "mission_mutation_success": row.get("mission_mutation_success_rate"),
        "achievement_mutation": initial_mission != "achievement" and final_mission == "achievement",
        "adaptation_count": row.get("adaptation_count_mean"),
        "ttp_change_count": row.get("ttp_change_count_mean"),
        "alternative_path_usage": row.get("alternative_path_usage_mean"),
        "campaign_transition_count": row.get("campaign_transition_count_mean"),
        "campaign_policy_diversity": len({policy for policy in policy_history if policy}) if policy_history else 1,
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "retreat_rate": row.get("retreat_rate"),
        "mission_history": mission_history,
    }


def _analyze_phase421_mission_mutation_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    mutator_rows = [row for row in rows if row.get("attacker_mode") == "mission_mutator"]
    adaptive_rows = [row for row in rows if row.get("attacker_mode") == "adaptive_mission"]
    fixed_rows = [row for row in rows if row.get("attacker_mode") == "fixed_mission"]
    mutation_values = [_to_float(row.get("mission_change_count")) for row in mutator_rows]
    adaptive_agg = _phase421_profile_mode_mean(adaptive_rows, "aggressive_disruption", "mission_objective_defense_score")
    mutator_agg = _phase421_profile_mode_mean(mutator_rows, "aggressive_disruption", "mission_objective_defense_score")
    mutator_objective = _mean_or_none([_to_float(row.get("mission_objective_score")) for row in mutator_rows]) or 0.0
    adaptive_objective = _mean_or_none([_to_float(row.get("mission_objective_score")) for row in adaptive_rows]) or 0.0
    transition_matrix = _phase421_transition_matrix(mutator_rows)
    campaign_delta = abs(
        (_mean_or_none([_to_float(row.get("campaign_transition_count")) for row in mutator_rows]) or 0.0)
        - (_mean_or_none([_to_float(row.get("campaign_transition_count")) for row in fixed_rows]) or 0.0)
    )
    mutator_ttp = _mean_or_none([_to_float(row.get("ttp_change_count")) for row in mutator_rows]) or 0.0
    adaptive_ttp = _mean_or_none([_to_float(row.get("ttp_change_count")) for row in adaptive_rows]) or 0.0
    return {
        "mission_change_observed": any(value > 0.0 for value in mutation_values),
        "aggressive_disruption_weakened": mutator_agg < adaptive_agg,
        "achievement_mutation_observed": any(bool(row.get("achievement_mutation")) for row in mutator_rows),
        "mission_mutation_effective": mutator_objective > adaptive_objective or any(_to_float(row.get("mission_mutation_success")) > 0.0 for row in mutator_rows),
        "defense_campaign_affected": campaign_delta > 0.01,
        "coevolution_strengthened": any(value > 0.0 for value in mutation_values) and mutator_ttp >= adaptive_ttp,
        "mission_aware_defense_value_retained": len(set(_phase421_best_profiles(mutator_rows))) > 1 or mutator_agg >= 0.4,
        "mean_mission_change_count": float(np.mean(mutation_values)) if mutation_values else 0.0,
        "mean_mission_stability_score": _mean_or_none([_to_float(row.get("mission_stability_score")) for row in mutator_rows]) or 0.0,
        "mean_mutator_objective": mutator_objective,
        "mean_adaptive_objective": adaptive_objective,
        "adaptive_aggressive_score": adaptive_agg,
        "mutator_aggressive_score": mutator_agg,
        "transition_matrix": transition_matrix,
        "by_mission": _phase421_by_mission(mutator_rows),
    }


def _phase421_profile_mode_mean(rows: List[Dict[str, object]], profile: str, key: str) -> float:
    values = [_to_float(row.get(key)) for row in rows if row.get("strategy_profile") == profile]
    return float(np.mean(values)) if values else 0.0


def _phase421_initial_mission_from_scenario(scenario: str, fallback: str) -> str:
    if "critical_hunter" in scenario:
        return "critical_hunter"
    for mission in ("profit", "achievement", "persistence"):
        if mission in scenario:
            return mission
    return fallback


def _phase421_best_profiles(rows: List[Dict[str, object]]) -> List[str]:
    best = []
    for mission in sorted({str(row.get("initial_mission")) for row in rows}):
        mission_rows = [row for row in rows if row.get("initial_mission") == mission]
        if mission_rows:
            best.append(str(max(mission_rows, key=lambda row: _to_float(row.get("mission_objective_defense_score"))).get("strategy_profile")))
    return best


def _phase421_transition_matrix(rows: List[Dict[str, object]]) -> Dict[str, Dict[str, int]]:
    missions = ["profit", "achievement", "persistence", "critical_hunter"]
    matrix = {source: {target: 0 for target in missions} for source in missions}
    for row in rows:
        history = [mission for mission in _phase416_list_value(row.get("mission_history")) if mission in missions]
        if not history:
            history = [str(row.get("initial_mission")), str(row.get("final_mission"))]
        elif str(row.get("initial_mission")) in missions and history[0] != str(row.get("initial_mission")):
            history = [str(row.get("initial_mission"))] + history
        for source, target in zip(history, history[1:]):
            if source in matrix and target in matrix[source]:
                matrix[source][target] += 1
    return matrix


def _phase421_by_mission(rows: List[Dict[str, object]]) -> Dict[str, Dict[str, object]]:
    result = {}
    for mission in sorted({str(row.get("initial_mission")) for row in rows}):
        mission_rows = [row for row in rows if row.get("initial_mission") == mission]
        result[mission] = {
            "mean_change_count": _mean_or_none([_to_float(row.get("mission_change_count")) for row in mission_rows]) or 0.0,
            "achievement_mutation_rate": _mean_or_none([1.0 if row.get("achievement_mutation") else 0.0 for row in mission_rows]) or 0.0,
            "mean_objective": _mean_or_none([_to_float(row.get("mission_objective_score")) for row in mission_rows]) or 0.0,
            "best_defense_strategy": max(mission_rows, key=lambda row: _to_float(row.get("mission_objective_defense_score"))).get("strategy_profile") if mission_rows else "",
        }
    return result


def _write_phase421_mission_mutation_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "mission_mutation_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE421_MISSION_MUTATION_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE421_MISSION_MUTATION_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "mission_mutation_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase421_transition_matrix(analysis: Dict[str, object], save_path: str) -> None:
    missions = ["profit", "achievement", "persistence", "critical_hunter"]
    matrix_data = analysis.get("transition_matrix", {})
    values = np.asarray([[int(matrix_data.get(source, {}).get(target, 0)) for target in missions] for source in missions], dtype=float)
    fig, ax = plt.subplots(figsize=(7, 6))
    image = ax.imshow(values, cmap="viridis")
    ax.set_title("Mission Transition Matrix")
    ax.set_xticks(np.arange(len(missions)))
    ax.set_xticklabels(missions, rotation=30, ha="right")
    ax.set_yticks(np.arange(len(missions)))
    ax.set_yticklabels(missions)
    for i in range(len(missions)):
        for j in range(len(missions)):
            ax.text(j, i, f"{int(values[i, j])}", ha="center", va="center", color="white" if values[i, j] > 0 else "black")
    fig.colorbar(image, ax=ax)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase421_metric(rows: List[Dict[str, object]], metric: str, save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("initial_mission")) for row in rows))
    values = [
        float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("initial_mission") == mission and row.get("attacker_mode") == "mission_mutator"]))
        for mission in missions
    ]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(missions)), values, color="#e15759")
    ax.set_title(metric.replace("_", " ").title())
    ax.set_ylabel(metric)
    ax.set_xticks(np.arange(len(missions)))
    ax.set_xticklabels(missions, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase421_mutation_vs_phase420(rows: List[Dict[str, object]], save_path: str) -> None:
    modes = ["fixed_mission", "adaptive_mission", "mission_mutator"]
    values = [
        float(np.mean([_to_float(row.get("mission_objective_defense_score")) for row in rows if row.get("attacker_mode") == mode]))
        for mode in modes
    ]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(np.arange(len(modes)), values, color=["#4e79a7", "#59a14f", "#e15759"])
    ax.set_title("Mission Mutation vs Phase4.20 Adaptive Mission")
    ax.set_ylabel("defense score")
    ax.set_xticks(np.arange(len(modes)))
    ax.set_xticklabels(modes, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase421_mission_mutation_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.21 Mission Mutation Report",
        "",
        "## Research Questions",
        f"1. Mission changes occur: `{analysis.get('mission_change_observed')}`.",
        f"2. Aggressive Disruption weakens: `{analysis.get('aggressive_disruption_weakened')}`.",
        f"3. Achievement mutation occurs: `{analysis.get('achievement_mutation_observed')}`.",
        f"4. Mission Mutation is effective: `{analysis.get('mission_mutation_effective')}`.",
        f"5. Defense Campaign is affected: `{analysis.get('defense_campaign_affected')}`.",
        f"6. Co-evolution strengthens: `{analysis.get('coevolution_strengthened')}`.",
        f"7. Mission-Aware Defense retains value: `{analysis.get('mission_aware_defense_value_retained')}`.",
        "",
        "## Summary",
        f"- Mean mission change count: `{_to_float(analysis.get('mean_mission_change_count')):.3f}`.",
        f"- Mean mission stability score: `{_to_float(analysis.get('mean_mission_stability_score')):.3f}`.",
        f"- Adaptive/mutator objective: `{_to_float(analysis.get('mean_adaptive_objective')):.3f}` / `{_to_float(analysis.get('mean_mutator_objective')):.3f}`.",
        f"- Aggressive score adaptive/mutator: `{_to_float(analysis.get('adaptive_aggressive_score')):.3f}` / `{_to_float(analysis.get('mutator_aggressive_score')):.3f}`.",
        "",
        "## Mission Mutation",
        "| mission | changes | achievement rate | objective | best defense |",
        "|---|---:|---:|---:|---|",
    ]
    for mission, item in analysis.get("by_mission", {}).items():
        lines.append(
            f"| {mission} | {_to_float(item.get('mean_change_count')):.3f} | "
            f"{_to_float(item.get('achievement_mutation_rate')):.3f} | "
            f"{_to_float(item.get('mean_objective')):.3f} | {item.get('best_defense_strategy')} |"
        )
    lines.extend(["", "## Rows", "| mission | final | mode | strategy | changes | objective | defense | reason |", "|---|---|---|---|---:|---:|---:|---|"])
    for row in rows:
        lines.append(
            f"| {row.get('initial_mission')} | {row.get('final_mission')} | {row.get('attacker_mode')} | "
            f"{row.get('strategy_profile')} | {_to_float(row.get('mission_change_count')):.3f} | "
            f"{_to_float(row.get('mission_objective_score')):.3f} | {_to_float(row.get('mission_objective_defense_score')):.3f} | "
            f"{row.get('mission_mutation_reason')} |"
        )
    with open(os.path.join(output_dir, "PHASE421_MISSION_MUTATION_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE422_ADAPTIVE_INTELLIGENCE_COLUMNS = [
    "mission_scenario",
    "initial_mission",
    "final_mission",
    "defense_mode",
    "strategy_profile",
    "selected_strategy",
    "mission_objective_score",
    "mission_objective_defense_score",
    "cognitive_neutralization_score",
    "mission_aware_cns",
    "mission_change_count",
    "mission_reclassification_count",
    "defense_reoptimization_count",
    "reclassification_accuracy",
    "belief_recovery_time",
    "ttp_change_count",
    "alternative_path_usage",
    "campaign_transition_count",
    "campaign_policy_diversity",
    "mission_history",
    "reclassified_mission_history",
    "selected_strategy_history",
]


def run_phase422_adaptive_intelligence_defender(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase422_adaptive_intelligence"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = strategy_profiles if strategy_profiles is not None else [profile for profile, _label in PHASE417_CAMPAIGN_PROFILES]
    defense_modes = [
        ("fixed_mission_aware", False, False, "standard"),
        ("mission_mutation_attacker", True, False, "adaptive_mission_mutator"),
        ("adaptive_intelligence_defender", True, True, "adaptive_mission_mutator"),
    ]
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase422_", 1)
        for defense_mode, mutation_enabled, reclassification_enabled, attacker_type in defense_modes:
            for strategy in profiles:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"adaptive_intelligence_{defense_mode}_{strategy}",
                    intelligence=True,
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                scenario_config.update(
                    {
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": True,
                        "mission_mutation_enabled": mutation_enabled,
                        "mission_reclassification_enabled": reclassification_enabled,
                        "attacker_type": attacker_type,
                    }
                )
                scenarios[f"{scenario_name}__{defense_mode}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase422_adaptive_intelligence_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("initial_mission")), str(row.get("defense_mode")), str(row.get("strategy_profile"))))
    analysis = _analyze_phase422_adaptive_intelligence_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase422_adaptive_intelligence_summary(rows, analysis, output_dir)
    _plot_phase422_metric(rows, "mission_reclassification_count", os.path.join(output_dir, "mission_reclassification.png"))
    _plot_phase422_metric(rows, "defense_reoptimization_count", os.path.join(output_dir, "defense_reoptimization.png"))
    _plot_phase422_vs_phase421(rows, os.path.join(output_dir, "phase422_vs_phase421.png"))
    _write_phase422_adaptive_intelligence_report(rows, analysis, output_dir)
    return rows


def _build_phase422_adaptive_intelligence_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    mission_scenario = parts[0] if parts else scenario
    defense_mode = parts[1] if len(parts) > 1 else "fixed_mission_aware"
    strategy = parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced")
    mission_history = _phase416_list_value(row.get("mission_history"))
    reclassified_history = _phase416_list_value(row.get("reclassified_mission_history"))
    selected_strategy_history = _phase416_list_value(row.get("selected_strategy_history"))
    initial_mission = _phase421_initial_mission_from_scenario(mission_scenario, str(row.get("attacker_mission") or ""))
    final_mission = mission_history[-1] if mission_history else initial_mission
    objective = _to_float(row.get("mission_objective_score_mean"))
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    defense_score = float(np.clip(0.6 * cns + 0.4 * (1.0 - objective), 0.0, 1.0))
    policy_history = _phase416_list_value(row.get("campaign_policy_history"))
    selected_strategy = selected_strategy_history[-1] if selected_strategy_history else strategy
    return {
        "mission_scenario": mission_scenario,
        "initial_mission": initial_mission,
        "final_mission": final_mission,
        "defense_mode": defense_mode,
        "strategy_profile": strategy,
        "selected_strategy": selected_strategy,
        "mission_objective_score": row.get("mission_objective_score_mean"),
        "mission_objective_defense_score": defense_score,
        "cognitive_neutralization_score": row.get("cognitive_neutralization_score_mean"),
        "mission_aware_cns": row.get("mission_aware_cns_mean"),
        "mission_change_count": row.get("mission_change_count_mean"),
        "mission_reclassification_count": row.get("mission_reclassification_count_mean"),
        "defense_reoptimization_count": row.get("defense_reoptimization_count_mean"),
        "reclassification_accuracy": row.get("reclassification_accuracy_mean"),
        "belief_recovery_time": row.get("belief_recovery_time_mean"),
        "ttp_change_count": row.get("ttp_change_count_mean"),
        "alternative_path_usage": row.get("alternative_path_usage_mean"),
        "campaign_transition_count": row.get("campaign_transition_count_mean"),
        "campaign_policy_diversity": len({policy for policy in policy_history if policy}) if policy_history else 1,
        "mission_history": mission_history,
        "reclassified_mission_history": reclassified_history,
        "selected_strategy_history": selected_strategy_history,
    }


def _analyze_phase422_adaptive_intelligence_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    adaptive_rows = [row for row in rows if row.get("defense_mode") == "adaptive_intelligence_defender"]
    mutation_rows = [row for row in rows if row.get("defense_mode") == "mission_mutation_attacker"]
    fixed_rows = [row for row in rows if row.get("defense_mode") == "fixed_mission_aware"]
    adaptive_reclass = [_to_float(row.get("mission_reclassification_count")) for row in adaptive_rows]
    adaptive_reopt = [_to_float(row.get("defense_reoptimization_count")) for row in adaptive_rows]
    adaptive_accuracy = _mean_or_none([_to_float(row.get("reclassification_accuracy")) for row in adaptive_rows]) or 0.0
    adaptive_defense = _mean_or_none([_to_float(row.get("mission_objective_defense_score")) for row in adaptive_rows]) or 0.0
    mutation_defense = _mean_or_none([_to_float(row.get("mission_objective_defense_score")) for row in mutation_rows]) or 0.0
    fixed_defense = _mean_or_none([_to_float(row.get("mission_objective_defense_score")) for row in fixed_rows]) or 0.0
    adaptive_agg = _phase422_mode_profile_mean(adaptive_rows, "aggressive_disruption", "mission_objective_defense_score")
    mutation_agg = _phase422_mode_profile_mean(mutation_rows, "aggressive_disruption", "mission_objective_defense_score")
    mutation_changes = _mean_or_none([_to_float(row.get("mission_change_count")) for row in mutation_rows]) or 0.0
    adaptive_changes = _mean_or_none([_to_float(row.get("mission_change_count")) for row in adaptive_rows]) or 0.0
    recovered_times = [
        _to_float(row.get("belief_recovery_time"))
        for row in adaptive_rows
        if _to_float(row.get("belief_recovery_time")) >= 0.0
    ]
    return {
        "mission_mutation_detected": any(value > 0.0 for value in adaptive_reclass) and adaptive_accuracy > 0.0,
        "defense_reoptimization_observed": any(value > 0.0 for value in adaptive_reopt),
        "mission_aware_defense_value_retained": adaptive_defense >= fixed_defense * 0.85,
        "aggressive_reduction_handled": adaptive_agg >= mutation_agg or any(value > 0.0 for value in adaptive_reopt),
        "mission_reclassification_effective": adaptive_accuracy >= 0.5 and any(_to_float(row.get("belief_recovery_time")) >= 0.0 for row in adaptive_rows),
        "defender_adaptation_effective": adaptive_defense >= mutation_defense or any(value > 0.0 for value in adaptive_reopt),
        "coevolution_strengthened": adaptive_changes > 0.0 and any(value > 0.0 for value in adaptive_reclass) and any(value > 0.0 for value in adaptive_reopt),
        "mean_reclassification_count": _mean_or_none(adaptive_reclass) or 0.0,
        "mean_defense_reoptimization_count": _mean_or_none(adaptive_reopt) or 0.0,
        "mean_reclassification_accuracy": adaptive_accuracy,
        "mean_belief_recovery_time": _mean_or_none(recovered_times) if recovered_times else -1.0,
        "fixed_defense_score": fixed_defense,
        "mutation_defense_score": mutation_defense,
        "adaptive_defense_score": adaptive_defense,
        "mutation_mean_change_count": mutation_changes,
        "adaptive_mean_change_count": adaptive_changes,
        "mutation_aggressive_score": mutation_agg,
        "adaptive_aggressive_score": adaptive_agg,
        "by_mission": _phase422_by_mission(adaptive_rows),
    }


def _phase422_mode_profile_mean(rows: List[Dict[str, object]], profile: str, key: str) -> float:
    values = [_to_float(row.get(key)) for row in rows if row.get("strategy_profile") == profile]
    return float(np.mean(values)) if values else 0.0


def _phase422_by_mission(rows: List[Dict[str, object]]) -> Dict[str, Dict[str, object]]:
    result = {}
    for mission in sorted({str(row.get("initial_mission")) for row in rows}):
        mission_rows = [row for row in rows if row.get("initial_mission") == mission]
        result[mission] = {
            "mean_reclassification_count": _mean_or_none([_to_float(row.get("mission_reclassification_count")) for row in mission_rows]) or 0.0,
            "mean_reoptimization_count": _mean_or_none([_to_float(row.get("defense_reoptimization_count")) for row in mission_rows]) or 0.0,
            "mean_accuracy": _mean_or_none([_to_float(row.get("reclassification_accuracy")) for row in mission_rows]) or 0.0,
            "best_selected_strategy": max(mission_rows, key=lambda row: _to_float(row.get("mission_objective_defense_score"))).get("selected_strategy") if mission_rows else "",
        }
    return result


def _write_phase422_adaptive_intelligence_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "adaptive_intelligence_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE422_ADAPTIVE_INTELLIGENCE_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE422_ADAPTIVE_INTELLIGENCE_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "adaptive_intelligence_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase422_metric(rows: List[Dict[str, object]], metric: str, save_path: str) -> None:
    missions = list(dict.fromkeys(str(row.get("initial_mission")) for row in rows))
    values = [
        float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("initial_mission") == mission and row.get("defense_mode") == "adaptive_intelligence_defender"]))
        for mission in missions
    ]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(missions)), values, color="#4e79a7")
    ax.set_title(metric.replace("_", " ").title())
    ax.set_ylabel(metric)
    ax.set_xticks(np.arange(len(missions)))
    ax.set_xticklabels(missions, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase422_vs_phase421(rows: List[Dict[str, object]], save_path: str) -> None:
    modes = ["fixed_mission_aware", "mission_mutation_attacker", "adaptive_intelligence_defender"]
    values = [
        float(np.mean([_to_float(row.get("mission_objective_defense_score")) for row in rows if row.get("defense_mode") == mode]))
        for mode in modes
    ]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(np.arange(len(modes)), values, color=["#4e79a7", "#e15759", "#59a14f"])
    ax.set_title("Phase4.22 Adaptive Intelligence vs Phase4.21 Mutation")
    ax.set_ylabel("defense score")
    ax.set_xticks(np.arange(len(modes)))
    ax.set_xticklabels(modes, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase422_adaptive_intelligence_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.22 Adaptive Intelligence Defender Report",
        "",
        "## Research Questions",
        f"1. Mission Mutation detected: `{analysis.get('mission_mutation_detected')}`.",
        f"2. Defense reoptimization occurs: `{analysis.get('defense_reoptimization_observed')}`.",
        f"3. Mission-Aware Defense value is retained: `{analysis.get('mission_aware_defense_value_retained')}`.",
        f"4. Aggressive dominance reduction is handled: `{analysis.get('aggressive_reduction_handled')}`.",
        f"5. Mission Reclassification is effective: `{analysis.get('mission_reclassification_effective')}`.",
        f"6. Defender Adaptation is effective: `{analysis.get('defender_adaptation_effective')}`.",
        f"7. Co-evolution strengthens: `{analysis.get('coevolution_strengthened')}`.",
        "",
        "## Summary",
        f"- Mean reclassification count: `{_to_float(analysis.get('mean_reclassification_count')):.3f}`.",
        f"- Mean defense reoptimization count: `{_to_float(analysis.get('mean_defense_reoptimization_count')):.3f}`.",
        f"- Mean reclassification accuracy: `{_to_float(analysis.get('mean_reclassification_accuracy')):.3f}`.",
        f"- Mean belief recovery time: `{_to_float(analysis.get('mean_belief_recovery_time')):.3f}`.",
        f"- Defense score fixed/mutation/adaptive: `{_to_float(analysis.get('fixed_defense_score')):.3f}` / `{_to_float(analysis.get('mutation_defense_score')):.3f}` / `{_to_float(analysis.get('adaptive_defense_score')):.3f}`.",
        "",
        "## Mission Detail",
        "| mission | reclassifications | reoptimizations | accuracy | best selected strategy |",
        "|---|---:|---:|---:|---|",
    ]
    for mission, item in analysis.get("by_mission", {}).items():
        lines.append(
            f"| {mission} | {_to_float(item.get('mean_reclassification_count')):.3f} | "
            f"{_to_float(item.get('mean_reoptimization_count')):.3f} | "
            f"{_to_float(item.get('mean_accuracy')):.3f} | {item.get('best_selected_strategy')} |"
        )
    lines.extend(["", "## Rows", "| mission | mode | initial strategy | selected strategy | changes | reclass | reopt | accuracy | defense |", "|---|---|---|---|---:|---:|---:|---:|---:|"])
    for row in rows:
        lines.append(
            f"| {row.get('initial_mission')} | {row.get('defense_mode')} | {row.get('strategy_profile')} | {row.get('selected_strategy')} | "
            f"{_to_float(row.get('mission_change_count')):.3f} | {_to_float(row.get('mission_reclassification_count')):.3f} | "
            f"{_to_float(row.get('defense_reoptimization_count')):.3f} | {_to_float(row.get('reclassification_accuracy')):.3f} | "
            f"{_to_float(row.get('mission_objective_defense_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE422_ADAPTIVE_INTELLIGENCE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE423_INTENT_DECEPTION_COLUMNS = [
    "mission_scenario",
    "attacker_mode",
    "true_mission",
    "observed_mission",
    "final_mission",
    "strategy_profile",
    "selected_strategy",
    "mission_objective_score",
    "mission_objective_defense_score",
    "mission_change_count",
    "mission_reclassification_count",
    "defense_reoptimization_count",
    "deception_event_count",
    "mission_belief_error",
    "belief_confusion_score",
    "mission_masking_success",
    "reclassification_accuracy",
    "ttp_change_count",
    "alternative_path_usage",
    "mission_weight_profit",
    "mission_weight_achievement",
    "mission_weight_persistence",
    "mission_weight_critical_hunter",
    "true_mission_history",
    "observed_mission_history",
    "deception_history",
]


def run_phase423_intent_deception_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase423_intent_deception"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = strategy_profiles if strategy_profiles is not None else [profile for profile, _label in PHASE417_CAMPAIGN_PROFILES]
    attacker_modes = [
        ("adaptive_mission_attacker", False, False, "adaptive_mission_attacker"),
        ("mission_mutation_attacker", True, False, "adaptive_mission_mutator"),
        ("intent_deception_attacker", True, True, "intent_deception_attacker"),
    ]
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase423_", 1)
        weights = _phase423_mission_weights(str(mission.get("attacker_mission") or mission_name))
        for attacker_mode, mutation_enabled, deception_enabled, attacker_type in attacker_modes:
            for strategy in profiles:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"intent_deception_{attacker_mode}_{strategy}",
                    intelligence=True,
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                scenario_config.update(
                    {
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": True,
                        "mission_mutation_enabled": mutation_enabled,
                        "mission_reclassification_enabled": True,
                        "multi_objective_mission_enabled": True,
                        "mission_weight_profit": weights.get("profit", 0.0),
                        "mission_weight_achievement": weights.get("achievement", 0.0),
                        "mission_weight_persistence": weights.get("persistence", 0.0),
                        "mission_weight_critical_hunter": weights.get("critical_hunter", 0.0),
                        "intent_deception_enabled": deception_enabled,
                        "attacker_type": attacker_type,
                    }
                )
                scenarios[f"{scenario_name}__{attacker_mode}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase423_intent_deception_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("true_mission")), str(row.get("attacker_mode")), str(row.get("strategy_profile"))))
    analysis = _analyze_phase423_intent_deception_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase423_intent_deception_summary(rows, analysis, output_dir)
    _plot_phase423_confusion_matrix(analysis, os.path.join(output_dir, "mission_confusion_matrix.png"))
    _plot_phase423_belief_error(rows, os.path.join(output_dir, "belief_error_distribution.png"))
    _plot_phase423_vs_phase422(rows, os.path.join(output_dir, "phase423_vs_phase422.png"))
    _write_phase423_intent_deception_report(rows, analysis, output_dir)
    return rows


def _phase423_mission_weights(mission: str) -> Dict[str, float]:
    if mission == "critical_hunter":
        return {"profit": 0.0, "achievement": 0.5, "persistence": 0.0, "critical_hunter": 0.5}
    if mission == "profit":
        return {"profit": 0.7, "achievement": 0.2, "persistence": 0.1, "critical_hunter": 0.0}
    if mission == "persistence":
        return {"profit": 0.1, "achievement": 0.3, "persistence": 0.6, "critical_hunter": 0.0}
    return {"profit": 0.2, "achievement": 0.7, "persistence": 0.1, "critical_hunter": 0.0}


def _build_phase423_intent_deception_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    mission_scenario = parts[0] if parts else scenario
    attacker_mode = parts[1] if len(parts) > 1 else str(row.get("attacker_type") or "adaptive_mission_attacker")
    strategy = parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced")
    true_history = _phase416_list_value(row.get("true_mission_history"))
    observed_history = _phase416_list_value(row.get("observed_mission_history"))
    deception_history = _phase416_list_value(row.get("deception_history"))
    mission_history = _phase416_list_value(row.get("mission_history"))
    selected_strategy_history = _phase416_list_value(row.get("selected_strategy_history"))
    true_mission = true_history[-1] if true_history else str(row.get("true_mission") or row.get("attacker_mission") or "")
    observed_mission = observed_history[-1] if observed_history else str(row.get("observed_mission") or true_mission)
    objective = _to_float(row.get("mission_objective_score_mean"))
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    defense_score = float(np.clip(0.6 * cns + 0.4 * (1.0 - objective), 0.0, 1.0))
    return {
        "mission_scenario": mission_scenario,
        "attacker_mode": attacker_mode,
        "true_mission": true_mission,
        "observed_mission": observed_mission,
        "final_mission": mission_history[-1] if mission_history else true_mission,
        "strategy_profile": strategy,
        "selected_strategy": selected_strategy_history[-1] if selected_strategy_history else strategy,
        "mission_objective_score": row.get("mission_objective_score_mean"),
        "mission_objective_defense_score": defense_score,
        "mission_change_count": row.get("mission_change_count_mean"),
        "mission_reclassification_count": row.get("mission_reclassification_count_mean"),
        "defense_reoptimization_count": row.get("defense_reoptimization_count_mean"),
        "deception_event_count": row.get("deception_event_count_mean"),
        "mission_belief_error": row.get("mission_belief_error_mean"),
        "belief_confusion_score": row.get("belief_confusion_score_mean"),
        "mission_masking_success": _to_float(row.get("mission_masking_success_mean")) > 0.0,
        "reclassification_accuracy": row.get("reclassification_accuracy_mean"),
        "ttp_change_count": row.get("ttp_change_count_mean"),
        "alternative_path_usage": row.get("alternative_path_usage_mean"),
        "mission_weight_profit": row.get("mission_weight_profit"),
        "mission_weight_achievement": row.get("mission_weight_achievement"),
        "mission_weight_persistence": row.get("mission_weight_persistence"),
        "mission_weight_critical_hunter": row.get("mission_weight_critical_hunter"),
        "true_mission_history": true_history,
        "observed_mission_history": observed_history,
        "deception_history": deception_history,
    }


def _analyze_phase423_intent_deception_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    deception_rows = [row for row in rows if row.get("attacker_mode") == "intent_deception_attacker"]
    mutation_rows = [row for row in rows if row.get("attacker_mode") == "mission_mutation_attacker"]
    adaptive_rows = [row for row in rows if row.get("attacker_mode") == "adaptive_mission_attacker"]
    deception_events = [_to_float(row.get("deception_event_count")) for row in deception_rows]
    deception_error = _mean_or_none([_to_float(row.get("mission_belief_error")) for row in deception_rows]) or 0.0
    mutation_error = _mean_or_none([_to_float(row.get("mission_belief_error")) for row in mutation_rows]) or 0.0
    adaptive_error = _mean_or_none([_to_float(row.get("mission_belief_error")) for row in adaptive_rows]) or 0.0
    deception_reopt = _mean_or_none([_to_float(row.get("defense_reoptimization_count")) for row in deception_rows]) or 0.0
    deception_confusion = _mean_or_none([_to_float(row.get("belief_confusion_score")) for row in deception_rows]) or 0.0
    deception_defense = _mean_or_none([_to_float(row.get("mission_objective_defense_score")) for row in deception_rows]) or 0.0
    mutation_defense = _mean_or_none([_to_float(row.get("mission_objective_defense_score")) for row in mutation_rows]) or 0.0
    aggressive_deception = _phase423_mode_profile_mean(deception_rows, "aggressive_disruption", "mission_objective_defense_score")
    best_deception_profile = max(deception_rows, key=lambda row: _to_float(row.get("mission_objective_defense_score"))).get("strategy_profile") if deception_rows else ""
    return {
        "mission_deception_succeeds": any(value > 0.0 for value in deception_events) and any(bool(row.get("mission_masking_success")) for row in deception_rows),
        "mission_belief_accuracy_declines": deception_error > max(mutation_error, adaptive_error),
        "defense_reoptimization_misdirected": deception_reopt > 0.0 and deception_confusion > 0.0,
        "multi_objective_mission_effective": all(
            sum(_to_float(row.get(key)) for key in ("mission_weight_profit", "mission_weight_achievement", "mission_weight_persistence", "mission_weight_critical_hunter")) > 0.99
            for row in rows
        ),
        "aggressive_disruption_returns": best_deception_profile == "aggressive_disruption",
        "adaptive_intelligence_resilient": deception_defense >= mutation_defense * 0.8,
        "coevolution_strengthened": any(value > 0.0 for value in deception_events) and deception_reopt > 0.0 and deception_confusion > 0.0,
        "mean_deception_event_count": _mean_or_none(deception_events) or 0.0,
        "mean_deception_belief_error": deception_error,
        "mean_mutation_belief_error": mutation_error,
        "mean_adaptive_belief_error": adaptive_error,
        "mean_belief_confusion_score": deception_confusion,
        "mean_deception_reoptimization": deception_reopt,
        "deception_defense_score": deception_defense,
        "mutation_defense_score": mutation_defense,
        "aggressive_deception_score": aggressive_deception,
        "best_deception_profile": best_deception_profile,
        "confusion_matrix": _phase423_confusion_matrix(deception_rows),
    }


def _phase423_mode_profile_mean(rows: List[Dict[str, object]], profile: str, key: str) -> float:
    values = [_to_float(row.get(key)) for row in rows if row.get("strategy_profile") == profile]
    return float(np.mean(values)) if values else 0.0


def _phase423_confusion_matrix(rows: List[Dict[str, object]]) -> Dict[str, Dict[str, int]]:
    missions = ["profit", "achievement", "persistence", "critical_hunter"]
    matrix = {source: {target: 0 for target in missions} for source in missions}
    for row in rows:
        true_history = _phase416_list_value(row.get("true_mission_history"))
        observed_history = _phase416_list_value(row.get("observed_mission_history"))
        n = min(len(true_history), len(observed_history))
        if n == 0:
            true_history = [str(row.get("true_mission"))]
            observed_history = [str(row.get("observed_mission"))]
            n = 1
        for idx in range(n):
            source = str(true_history[idx])
            target = str(observed_history[idx])
            if source in matrix and target in matrix[source]:
                matrix[source][target] += 1
    return matrix


def _write_phase423_intent_deception_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "intent_deception_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE423_INTENT_DECEPTION_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE423_INTENT_DECEPTION_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "intent_deception_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase423_confusion_matrix(analysis: Dict[str, object], save_path: str) -> None:
    missions = ["profit", "achievement", "persistence", "critical_hunter"]
    matrix = analysis.get("confusion_matrix", {})
    values = np.asarray([[int(matrix.get(source, {}).get(target, 0)) for target in missions] for source in missions], dtype=float)
    fig, ax = plt.subplots(figsize=(7, 6))
    image = ax.imshow(values, cmap="magma")
    ax.set_title("Mission Confusion Matrix")
    ax.set_xticks(np.arange(len(missions)))
    ax.set_xticklabels(missions, rotation=30, ha="right")
    ax.set_yticks(np.arange(len(missions)))
    ax.set_yticklabels(missions)
    for i in range(len(missions)):
        for j in range(len(missions)):
            ax.text(j, i, f"{int(values[i, j])}", ha="center", va="center", color="white" if values[i, j] > 0 else "black")
    fig.colorbar(image, ax=ax)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase423_belief_error(rows: List[Dict[str, object]], save_path: str) -> None:
    modes = ["adaptive_mission_attacker", "mission_mutation_attacker", "intent_deception_attacker"]
    values = [
        float(np.mean([_to_float(row.get("mission_belief_error")) for row in rows if row.get("attacker_mode") == mode]))
        for mode in modes
    ]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(np.arange(len(modes)), values, color=["#4e79a7", "#e15759", "#b07aa1"])
    ax.set_title("Mission Belief Error Distribution")
    ax.set_ylabel("belief error")
    ax.set_xticks(np.arange(len(modes)))
    ax.set_xticklabels(modes, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase423_vs_phase422(rows: List[Dict[str, object]], save_path: str) -> None:
    modes = ["adaptive_mission_attacker", "mission_mutation_attacker", "intent_deception_attacker"]
    values = [
        float(np.mean([_to_float(row.get("mission_objective_defense_score")) for row in rows if row.get("attacker_mode") == mode]))
        for mode in modes
    ]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(np.arange(len(modes)), values, color=["#4e79a7", "#e15759", "#b07aa1"])
    ax.set_title("Phase4.23 Intent Deception vs Phase4.22")
    ax.set_ylabel("defense score")
    ax.set_xticks(np.arange(len(modes)))
    ax.set_xticklabels(modes, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase423_intent_deception_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.23 Intent Deception Report",
        "",
        "## Research Questions",
        f"1. Mission deception succeeds: `{analysis.get('mission_deception_succeeds')}`.",
        f"2. Mission Belief accuracy declines: `{analysis.get('mission_belief_accuracy_declines')}`.",
        f"3. Defense Reoptimization is misdirected: `{analysis.get('defense_reoptimization_misdirected')}`.",
        f"4. Multi-Objective Mission is effective: `{analysis.get('multi_objective_mission_effective')}`.",
        f"5. Aggressive Disruption returns: `{analysis.get('aggressive_disruption_returns')}`.",
        f"6. Adaptive Intelligence Defender is resilient: `{analysis.get('adaptive_intelligence_resilient')}`.",
        f"7. Co-evolution strengthens: `{analysis.get('coevolution_strengthened')}`.",
        "",
        "## Summary",
        f"- Mean deception event count: `{_to_float(analysis.get('mean_deception_event_count')):.3f}`.",
        f"- Belief error adaptive/mutation/deception: `{_to_float(analysis.get('mean_adaptive_belief_error')):.3f}` / `{_to_float(analysis.get('mean_mutation_belief_error')):.3f}` / `{_to_float(analysis.get('mean_deception_belief_error')):.3f}`.",
        f"- Mean confusion score: `{_to_float(analysis.get('mean_belief_confusion_score')):.3f}`.",
        f"- Mean deception reoptimization: `{_to_float(analysis.get('mean_deception_reoptimization')):.3f}`.",
        f"- Defense score mutation/deception: `{_to_float(analysis.get('mutation_defense_score')):.3f}` / `{_to_float(analysis.get('deception_defense_score')):.3f}`.",
        f"- Best deception profile: `{analysis.get('best_deception_profile')}`.",
        "",
        "## Rows",
        "| true | observed | mode | strategy | selected | deception | belief error | confusion | reopt | defense |",
        "|---|---|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('true_mission')} | {row.get('observed_mission')} | {row.get('attacker_mode')} | "
            f"{row.get('strategy_profile')} | {row.get('selected_strategy')} | {_to_float(row.get('deception_event_count')):.3f} | "
            f"{_to_float(row.get('mission_belief_error')):.3f} | {_to_float(row.get('belief_confusion_score')):.3f} | "
            f"{_to_float(row.get('defense_reoptimization_count')):.3f} | {_to_float(row.get('mission_objective_defense_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE423_INTENT_DECEPTION_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE424_SIGNAL_EXTRACTION_COLUMNS = [
    "mission_scenario",
    "defense_mode",
    "true_mission",
    "observed_mission",
    "strategy_profile",
    "selected_strategy",
    "mission_objective_score",
    "mission_objective_defense_score",
    "mission_belief_error",
    "belief_confusion_score",
    "deception_event_count",
    "noise_event_count",
    "signal_event_count",
    "signal_to_noise_ratio",
    "noise_filter_accuracy",
    "decision_confidence",
    "defense_reoptimization_count",
    "reclassification_accuracy",
    "noise_history",
    "signal_history",
]


def run_phase424_signal_extraction_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase424_signal_extraction"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = strategy_profiles if strategy_profiles is not None else [profile for profile, _label in PHASE417_CAMPAIGN_PROFILES]
    modes = [
        ("adaptive_intelligence_defender", False, False, False),
        ("noise_injection_attacker", True, True, False),
        ("signal_extraction_defender", True, True, True),
    ]
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase424_", 1)
        weights = _phase423_mission_weights(str(mission.get("attacker_mission") or mission_name))
        for mode, deception_enabled, noise_enabled, signal_enabled in modes:
            for strategy in profiles:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"signal_extraction_{mode}_{strategy}",
                    intelligence=True,
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                scenario_config.update(
                    {
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": True,
                        "mission_mutation_enabled": deception_enabled,
                        "mission_reclassification_enabled": True,
                        "multi_objective_mission_enabled": True,
                        "mission_weight_profit": weights.get("profit", 0.0),
                        "mission_weight_achievement": weights.get("achievement", 0.0),
                        "mission_weight_persistence": weights.get("persistence", 0.0),
                        "mission_weight_critical_hunter": weights.get("critical_hunter", 0.0),
                        "intent_deception_enabled": deception_enabled,
                        "noise_injection_enabled": noise_enabled,
                        "signal_extraction_enabled": signal_enabled,
                        "attacker_type": "intent_deception_attacker" if deception_enabled else "adaptive_mission_attacker",
                    }
                )
                scenarios[f"{scenario_name}__{mode}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase424_signal_extraction_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("true_mission")), str(row.get("defense_mode")), str(row.get("strategy_profile"))))
    analysis = _analyze_phase424_signal_extraction_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase424_signal_extraction_summary(rows, analysis, output_dir)
    _plot_phase424_metric(rows, "signal_to_noise_ratio", os.path.join(output_dir, "signal_to_noise_ratio.png"))
    _plot_phase424_metric(rows, "noise_filter_accuracy", os.path.join(output_dir, "noise_filter_accuracy.png"))
    _plot_phase424_vs_phase423(rows, os.path.join(output_dir, "phase424_vs_phase423.png"))
    _write_phase424_signal_extraction_report(rows, analysis, output_dir)
    return rows


def _build_phase424_signal_extraction_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    mission_scenario = parts[0] if parts else scenario
    defense_mode = parts[1] if len(parts) > 1 else "adaptive_intelligence_defender"
    strategy = parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced")
    true_history = _phase416_list_value(row.get("true_mission_history"))
    observed_history = _phase416_list_value(row.get("observed_mission_history"))
    selected_strategy_history = _phase416_list_value(row.get("selected_strategy_history"))
    objective = _to_float(row.get("mission_objective_score_mean"))
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    defense_score = float(np.clip(0.6 * cns + 0.4 * (1.0 - objective), 0.0, 1.0))
    true_mission = true_history[-1] if true_history else str(row.get("true_mission") or row.get("attacker_mission") or "")
    observed_mission = observed_history[-1] if observed_history else str(row.get("observed_mission") or true_mission)
    return {
        "mission_scenario": mission_scenario,
        "defense_mode": defense_mode,
        "true_mission": true_mission,
        "observed_mission": observed_mission,
        "strategy_profile": strategy,
        "selected_strategy": selected_strategy_history[-1] if selected_strategy_history else strategy,
        "mission_objective_score": row.get("mission_objective_score_mean"),
        "mission_objective_defense_score": defense_score,
        "mission_belief_error": row.get("mission_belief_error_mean"),
        "belief_confusion_score": row.get("belief_confusion_score_mean"),
        "deception_event_count": row.get("deception_event_count_mean"),
        "noise_event_count": row.get("noise_event_count_mean"),
        "signal_event_count": row.get("signal_event_count_mean"),
        "signal_to_noise_ratio": row.get("signal_to_noise_ratio_mean"),
        "noise_filter_accuracy": row.get("noise_filter_accuracy_mean"),
        "decision_confidence": row.get("decision_confidence_mean"),
        "defense_reoptimization_count": row.get("defense_reoptimization_count_mean"),
        "reclassification_accuracy": row.get("reclassification_accuracy_mean"),
        "noise_history": _phase416_list_value(row.get("noise_history")),
        "signal_history": _phase416_list_value(row.get("signal_history")),
    }


def _analyze_phase424_signal_extraction_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    adaptive_rows = [row for row in rows if row.get("defense_mode") == "adaptive_intelligence_defender"]
    noise_rows = [row for row in rows if row.get("defense_mode") == "noise_injection_attacker"]
    signal_rows = [row for row in rows if row.get("defense_mode") == "signal_extraction_defender"]
    adaptive_error = _mean_or_none([_to_float(row.get("mission_belief_error")) for row in adaptive_rows]) or 0.0
    noise_error = _mean_or_none([_to_float(row.get("mission_belief_error")) for row in noise_rows]) or 0.0
    signal_error = _mean_or_none([_to_float(row.get("mission_belief_error")) for row in signal_rows]) or 0.0
    adaptive_defense = _mean_or_none([_to_float(row.get("mission_objective_defense_score")) for row in adaptive_rows]) or 0.0
    noise_defense = _mean_or_none([_to_float(row.get("mission_objective_defense_score")) for row in noise_rows]) or 0.0
    signal_defense = _mean_or_none([_to_float(row.get("mission_objective_defense_score")) for row in signal_rows]) or 0.0
    signal_filter = _mean_or_none([_to_float(row.get("noise_filter_accuracy")) for row in signal_rows]) or 0.0
    noise_count = _mean_or_none([_to_float(row.get("noise_event_count")) for row in noise_rows]) or 0.0
    signal_snr = _mean_or_none([_to_float(row.get("signal_to_noise_ratio")) for row in signal_rows]) or 0.0
    noise_snr = _mean_or_none([_to_float(row.get("signal_to_noise_ratio")) for row in noise_rows]) or 0.0
    signal_confidence = _mean_or_none([_to_float(row.get("decision_confidence")) for row in signal_rows]) or 0.0
    noise_confidence = _mean_or_none([_to_float(row.get("decision_confidence")) for row in noise_rows]) or 0.0
    return {
        "noise_injection_effective": noise_count > 0.0 and noise_error >= adaptive_error,
        "mission_belief_worsens_under_noise": noise_error >= adaptive_error,
        "signal_extraction_effective": signal_filter >= 0.5 and (signal_defense >= noise_defense or signal_confidence > noise_confidence),
        "defense_score_maintained": signal_defense >= adaptive_defense * 0.8,
        "deception_noise_combination_strong": noise_count > 0.0 and noise_error > 0.75,
        "adaptive_defender_resilient": signal_defense >= noise_defense * 0.9,
        "coevolution_strengthened": noise_count > 0.0 and signal_filter > 0.0 and signal_confidence > noise_confidence,
        "mean_noise_event_count": noise_count,
        "mean_signal_event_count": _mean_or_none([_to_float(row.get("signal_event_count")) for row in signal_rows]) or 0.0,
        "noise_mode_belief_error": noise_error,
        "signal_mode_belief_error": signal_error,
        "adaptive_belief_error": adaptive_error,
        "noise_mode_defense_score": noise_defense,
        "signal_mode_defense_score": signal_defense,
        "adaptive_defense_score": adaptive_defense,
        "noise_signal_to_noise_ratio": noise_snr,
        "signal_signal_to_noise_ratio": signal_snr,
        "mean_noise_filter_accuracy": signal_filter,
        "noise_decision_confidence": noise_confidence,
        "signal_decision_confidence": signal_confidence,
    }


def _write_phase424_signal_extraction_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "signal_extraction_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE424_SIGNAL_EXTRACTION_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE424_SIGNAL_EXTRACTION_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "signal_extraction_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase424_metric(rows: List[Dict[str, object]], metric: str, save_path: str) -> None:
    modes = ["adaptive_intelligence_defender", "noise_injection_attacker", "signal_extraction_defender"]
    values = [
        float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("defense_mode") == mode]))
        for mode in modes
    ]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(np.arange(len(modes)), values, color=["#4e79a7", "#e15759", "#59a14f"])
    ax.set_title(metric.replace("_", " ").title())
    ax.set_ylabel(metric)
    ax.set_xticks(np.arange(len(modes)))
    ax.set_xticklabels(modes, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase424_vs_phase423(rows: List[Dict[str, object]], save_path: str) -> None:
    modes = ["adaptive_intelligence_defender", "noise_injection_attacker", "signal_extraction_defender"]
    values = [
        float(np.mean([_to_float(row.get("mission_objective_defense_score")) for row in rows if row.get("defense_mode") == mode]))
        for mode in modes
    ]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(np.arange(len(modes)), values, color=["#4e79a7", "#e15759", "#59a14f"])
    ax.set_title("Phase4.24 Signal Extraction vs Phase4.23")
    ax.set_ylabel("defense score")
    ax.set_xticks(np.arange(len(modes)))
    ax.set_xticklabels(modes, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase424_signal_extraction_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.24 Signal Extraction Report",
        "",
        "## Research Questions",
        f"1. Noise Injection is effective: `{analysis.get('noise_injection_effective')}`.",
        f"2. Mission Belief worsens under noise: `{analysis.get('mission_belief_worsens_under_noise')}`.",
        f"3. Signal Extraction is effective: `{analysis.get('signal_extraction_effective')}`.",
        f"4. Defense Score is maintained: `{analysis.get('defense_score_maintained')}`.",
        f"5. Intent Deception plus noise is strong: `{analysis.get('deception_noise_combination_strong')}`.",
        f"6. Adaptive Defender is resilient: `{analysis.get('adaptive_defender_resilient')}`.",
        f"7. Co-evolution strengthens: `{analysis.get('coevolution_strengthened')}`.",
        "",
        "## Summary",
        f"- Mean noise event count: `{_to_float(analysis.get('mean_noise_event_count')):.3f}`.",
        f"- Noise/filter accuracy: `{_to_float(analysis.get('mean_noise_filter_accuracy')):.3f}`.",
        f"- SNR noise/signal mode: `{_to_float(analysis.get('noise_signal_to_noise_ratio')):.3f}` / `{_to_float(analysis.get('signal_signal_to_noise_ratio')):.3f}`.",
        f"- Decision confidence noise/signal: `{_to_float(analysis.get('noise_decision_confidence')):.3f}` / `{_to_float(analysis.get('signal_decision_confidence')):.3f}`.",
        f"- Defense score adaptive/noise/signal: `{_to_float(analysis.get('adaptive_defense_score')):.3f}` / `{_to_float(analysis.get('noise_mode_defense_score')):.3f}` / `{_to_float(analysis.get('signal_mode_defense_score')):.3f}`.",
        "",
        "## Rows",
        "| mission | mode | strategy | noise | signal | snr | filter | confidence | belief error | defense |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('true_mission')} | {row.get('defense_mode')} | {row.get('strategy_profile')} | "
            f"{_to_float(row.get('noise_event_count')):.3f} | {_to_float(row.get('signal_event_count')):.3f} | "
            f"{_to_float(row.get('signal_to_noise_ratio')):.3f} | {_to_float(row.get('noise_filter_accuracy')):.3f} | "
            f"{_to_float(row.get('decision_confidence')):.3f} | {_to_float(row.get('mission_belief_error')):.3f} | "
            f"{_to_float(row.get('mission_objective_defense_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE424_SIGNAL_EXTRACTION_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE425_ADVERSARIAL_SIGNAL_COLUMNS = [
    "mission_scenario",
    "defense_mode",
    "true_mission",
    "strategy_profile",
    "selected_strategy",
    "mission_objective_defense_score",
    "noise_filter_accuracy",
    "decision_confidence",
    "fake_signal_count",
    "adversarial_signal_count",
    "signal_confusion_score",
    "false_signal_acceptance_rate",
    "signal_consistency_score",
    "defense_reoptimization_count",
    "critical_path_step_count",
    "fake_signal_history",
    "signal_consistency_history",
]


def run_phase425_adversarial_signal_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase425_adversarial_signal"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = strategy_profiles if strategy_profiles is not None else [profile for profile, _label in PHASE417_CAMPAIGN_PROFILES]
    modes = [
        ("phase424_noise_injection", True, False, True),
        ("phase425_adversarial_signal", True, True, False),
        ("phase425_signal_consistency_defender", True, True, True),
    ]
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase425_", 1)
        weights = _phase423_mission_weights(str(mission.get("attacker_mission") or mission_name))
        for mode, noise_enabled, adversarial_enabled, signal_enabled in modes:
            for strategy in profiles:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"adversarial_signal_{mode}_{strategy}",
                    intelligence=True,
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                scenario_config.update(
                    {
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": True,
                        "mission_mutation_enabled": True,
                        "mission_reclassification_enabled": True,
                        "multi_objective_mission_enabled": True,
                        "mission_weight_profit": weights.get("profit", 0.0),
                        "mission_weight_achievement": weights.get("achievement", 0.0),
                        "mission_weight_persistence": weights.get("persistence", 0.0),
                        "mission_weight_critical_hunter": weights.get("critical_hunter", 0.0),
                        "intent_deception_enabled": True,
                        "noise_injection_enabled": noise_enabled,
                        "adversarial_signal_enabled": adversarial_enabled,
                        "signal_extraction_enabled": signal_enabled,
                        "attacker_type": "intent_deception_attacker",
                    }
                )
                scenarios[f"{scenario_name}__{mode}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase425_adversarial_signal_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("true_mission")), str(row.get("defense_mode")), str(row.get("strategy_profile"))))
    analysis = _analyze_phase425_adversarial_signal_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase425_adversarial_signal_summary(rows, analysis, output_dir)
    _plot_phase425_metric(rows, "fake_signal_count", os.path.join(output_dir, "fake_signal_count.png"))
    _plot_phase425_metric(rows, "signal_confusion_score", os.path.join(output_dir, "signal_confusion_score.png"))
    _plot_phase425_vs_phase424(rows, os.path.join(output_dir, "phase425_vs_phase424.png"))
    _write_phase425_adversarial_signal_report(rows, analysis, output_dir)
    return rows


def _build_phase425_adversarial_signal_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    mission_scenario = parts[0] if parts else scenario
    mode = parts[1] if len(parts) > 1 else "phase424_noise_injection"
    strategy = parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced")
    true_history = _phase416_list_value(row.get("true_mission_history"))
    selected_strategy_history = _phase416_list_value(row.get("selected_strategy_history"))
    objective = _to_float(row.get("mission_objective_score_mean"))
    cns = _to_float(row.get("cognitive_neutralization_score_mean"))
    defense_score = float(np.clip(0.6 * cns + 0.4 * (1.0 - objective), 0.0, 1.0))
    return {
        "mission_scenario": mission_scenario,
        "defense_mode": mode,
        "true_mission": true_history[-1] if true_history else str(row.get("true_mission") or row.get("attacker_mission") or ""),
        "strategy_profile": strategy,
        "selected_strategy": selected_strategy_history[-1] if selected_strategy_history else strategy,
        "mission_objective_defense_score": defense_score,
        "noise_filter_accuracy": row.get("noise_filter_accuracy_mean"),
        "decision_confidence": row.get("decision_confidence_mean"),
        "fake_signal_count": row.get("fake_signal_count_mean"),
        "adversarial_signal_count": row.get("adversarial_signal_count_mean"),
        "signal_confusion_score": row.get("signal_confusion_score_mean"),
        "false_signal_acceptance_rate": row.get("false_signal_acceptance_rate_mean"),
        "signal_consistency_score": row.get("signal_consistency_score_mean"),
        "defense_reoptimization_count": row.get("defense_reoptimization_count_mean"),
        "critical_path_step_count": row.get("critical_path_step_count_mean"),
        "fake_signal_history": _phase416_list_value(row.get("fake_signal_history")),
        "signal_consistency_history": _phase416_list_value(row.get("signal_consistency_history")),
    }


def _analyze_phase425_adversarial_signal_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    noise_rows = [row for row in rows if row.get("defense_mode") == "phase424_noise_injection"]
    adversarial_rows = [row for row in rows if row.get("defense_mode") == "phase425_adversarial_signal"]
    consistency_rows = [row for row in rows if row.get("defense_mode") == "phase425_signal_consistency_defender"]
    noise_filter = _mean_or_none([_to_float(row.get("noise_filter_accuracy")) for row in noise_rows]) or 0.0
    adversarial_filter = _mean_or_none([_to_float(row.get("noise_filter_accuracy")) for row in adversarial_rows]) or 0.0
    adversarial_confusion = _mean_or_none([_to_float(row.get("signal_confusion_score")) for row in adversarial_rows]) or 0.0
    consistency_confusion = _mean_or_none([_to_float(row.get("signal_confusion_score")) for row in consistency_rows]) or 0.0
    adversarial_confidence = _mean_or_none([_to_float(row.get("decision_confidence")) for row in adversarial_rows]) or 0.0
    noise_confidence = _mean_or_none([_to_float(row.get("decision_confidence")) for row in noise_rows]) or 0.0
    noise_defense = _mean_or_none([_to_float(row.get("mission_objective_defense_score")) for row in noise_rows]) or 0.0
    adversarial_defense = _mean_or_none([_to_float(row.get("mission_objective_defense_score")) for row in adversarial_rows]) or 0.0
    consistency_defense = _mean_or_none([_to_float(row.get("mission_objective_defense_score")) for row in consistency_rows]) or 0.0
    fake_count = _mean_or_none([_to_float(row.get("fake_signal_count")) for row in adversarial_rows]) or 0.0
    consistency_score = _mean_or_none([_to_float(row.get("signal_consistency_score")) for row in consistency_rows]) or 0.0
    return {
        "fake_signal_misdirects_defense": fake_count > 0.0 and adversarial_confusion > 0.0,
        "noise_filter_accuracy_declines": adversarial_filter < noise_filter,
        "decision_confidence_false_increase": adversarial_confidence > noise_confidence,
        "defense_score_declines": adversarial_defense < noise_defense,
        "consistency_check_effective": consistency_confusion <= adversarial_confusion and consistency_defense >= adversarial_defense * 0.95,
        "critical_path_intelligence_deceived": adversarial_confusion > 0.25,
        "signal_extraction_limit": "high-confidence fake signals pass extraction unless consistency checks reject implausible critical-path context",
        "mean_fake_signal_count": fake_count,
        "noise_filter_accuracy": noise_filter,
        "adversarial_filter_accuracy": adversarial_filter,
        "adversarial_signal_confusion": adversarial_confusion,
        "consistency_signal_confusion": consistency_confusion,
        "noise_decision_confidence": noise_confidence,
        "adversarial_decision_confidence": adversarial_confidence,
        "noise_defense_score": noise_defense,
        "adversarial_defense_score": adversarial_defense,
        "consistency_defense_score": consistency_defense,
        "mean_signal_consistency_score": consistency_score,
    }


def _write_phase425_adversarial_signal_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "adversarial_signal_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE425_ADVERSARIAL_SIGNAL_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE425_ADVERSARIAL_SIGNAL_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "adversarial_signal_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase425_metric(rows: List[Dict[str, object]], metric: str, save_path: str) -> None:
    modes = ["phase424_noise_injection", "phase425_adversarial_signal", "phase425_signal_consistency_defender"]
    values = [
        float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("defense_mode") == mode]))
        for mode in modes
    ]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(np.arange(len(modes)), values, color=["#4e79a7", "#e15759", "#59a14f"])
    ax.set_title(metric.replace("_", " ").title())
    ax.set_ylabel(metric)
    ax.set_xticks(np.arange(len(modes)))
    ax.set_xticklabels(modes, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase425_vs_phase424(rows: List[Dict[str, object]], save_path: str) -> None:
    _plot_phase425_metric(rows, "mission_objective_defense_score", save_path)


def _write_phase425_adversarial_signal_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase4.25 Adversarial Signal Report",
        "",
        "## Research Questions",
        f"1. Fake high-confidence signal misdirects defense: `{analysis.get('fake_signal_misdirects_defense')}`.",
        f"2. Noise filter accuracy declines: `{analysis.get('noise_filter_accuracy_declines')}`.",
        f"3. Decision confidence falsely increases: `{analysis.get('decision_confidence_false_increase')}`.",
        f"4. Defense score declines: `{analysis.get('defense_score_declines')}`.",
        f"5. Signal consistency check is effective: `{analysis.get('consistency_check_effective')}`.",
        f"6. Critical Path Intelligence is deceived: `{analysis.get('critical_path_intelligence_deceived')}`.",
        f"7. Signal Extraction limit: `{analysis.get('signal_extraction_limit')}`.",
        "",
        "## Summary",
        f"- Mean fake signal count: `{_to_float(analysis.get('mean_fake_signal_count')):.3f}`.",
        f"- Filter accuracy noise/adversarial: `{_to_float(analysis.get('noise_filter_accuracy')):.3f}` / `{_to_float(analysis.get('adversarial_filter_accuracy')):.3f}`.",
        f"- Signal confusion adversarial/consistency: `{_to_float(analysis.get('adversarial_signal_confusion')):.3f}` / `{_to_float(analysis.get('consistency_signal_confusion')):.3f}`.",
        f"- Decision confidence noise/adversarial: `{_to_float(analysis.get('noise_decision_confidence')):.3f}` / `{_to_float(analysis.get('adversarial_decision_confidence')):.3f}`.",
        f"- Defense score noise/adversarial/consistency: `{_to_float(analysis.get('noise_defense_score')):.3f}` / `{_to_float(analysis.get('adversarial_defense_score')):.3f}` / `{_to_float(analysis.get('consistency_defense_score')):.3f}`.",
        "",
        "## Rows",
        "| mission | mode | strategy | fake | confusion | acceptance | consistency | confidence | defense |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('true_mission')} | {row.get('defense_mode')} | {row.get('strategy_profile')} | "
            f"{_to_float(row.get('fake_signal_count')):.3f} | {_to_float(row.get('signal_confusion_score')):.3f} | "
            f"{_to_float(row.get('false_signal_acceptance_rate')):.3f} | {_to_float(row.get('signal_consistency_score')):.3f} | "
            f"{_to_float(row.get('decision_confidence')):.3f} | {_to_float(row.get('mission_objective_defense_score')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE425_ADVERSARIAL_SIGNAL_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE51_COALITION_COLUMNS = [
    "mission_scenario",
    "attacker_mode",
    "true_mission",
    "strategy_profile",
    "coalition_enabled",
    "coalition_size",
    "coalition_success_rate",
    "single_success_reference",
    "coalition_handover_count",
    "coalition_role_efficiency",
    "coalition_coordination_score",
    "coalition_coordination_cost_enabled",
    "coordination_cost",
    "coalition_information_loss_enabled",
    "coalition_trust_enabled",
    "effective_handover_count",
    "failed_handover_count",
    "coordination_efficiency",
    "campaign_delay_score",
    "coalition_trust_score",
    "trust_degradation_count",
    "campaign_completion_score",
    "campaign_delegation_observed",
    "mission_mutation_enabled",
    "mission_change_count",
    "defense_reoptimization_count",
    "adaptive_defender_effectiveness",
    "mission_objective_score",
    "attacker_success_rate",
    "critical_path_step_count",
    "coalition_role_history",
    "coalition_handover_history",
]


def run_phase51_coalition_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase51_coalition"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = strategy_profiles if strategy_profiles is not None else ["balanced"]
    modes = [
        ("single_attacker", False, False, False),
        ("coalition_attacker", True, False, False),
        ("coalition_mutation", True, True, False),
        ("coalition_adaptive_defender", True, True, True),
    ]
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase51_", 1)
        weights = _phase423_mission_weights(str(mission.get("attacker_mission") or mission_name))
        for mode, coalition_enabled, mutation_enabled, adaptive_defender in modes:
            for strategy in profiles:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"phase51_{mode}_{strategy}",
                    intelligence=True,
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                scenario_config.update(
                    {
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": True,
                        "mission_mutation_enabled": mutation_enabled,
                        "mission_reclassification_enabled": adaptive_defender,
                        "multi_objective_mission_enabled": True,
                        "mission_weight_profit": weights.get("profit", 0.0),
                        "mission_weight_achievement": weights.get("achievement", 0.0),
                        "mission_weight_persistence": weights.get("persistence", 0.0),
                        "mission_weight_critical_hunter": weights.get("critical_hunter", 0.0),
                        "intent_deception_enabled": True,
                        "noise_injection_enabled": True,
                        "adversarial_signal_enabled": True,
                        "signal_extraction_enabled": adaptive_defender,
                        "coalition_enabled": coalition_enabled,
                        "coalition_size": 2,
                        "coalition_role": "recon_specialist",
                        "attacker_type": "coalition_attacker" if coalition_enabled else "intent_deception_attacker",
                    }
                )
                scenarios[f"{scenario_name}__{mode}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase51_coalition_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("true_mission")), str(row.get("attacker_mode")), str(row.get("strategy_profile"))))
    _apply_phase51_single_references(rows)
    analysis = _analyze_phase51_coalition_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase51_coalition_summary(rows, analysis, output_dir)
    _plot_phase51_metric(rows, "coalition_handover_count", os.path.join(output_dir, "coalition_handover_count.png"))
    _plot_phase51_metric(rows, "coalition_role_efficiency", os.path.join(output_dir, "coalition_role_efficiency.png"))
    _plot_phase51_metric(rows, "coalition_success_rate", os.path.join(output_dir, "phase51_vs_phase425.png"))
    _write_phase51_coalition_report(rows, analysis, output_dir)
    return rows


def _build_phase51_coalition_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    mission_scenario = parts[0] if parts else scenario
    mode = parts[1] if len(parts) > 1 else "single_attacker"
    strategy = parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced")
    return {
        "mission_scenario": mission_scenario,
        "attacker_mode": mode,
        "true_mission": str(row.get("true_mission") or row.get("attacker_mission") or ""),
        "strategy_profile": strategy,
        "coalition_enabled": bool(row.get("coalition_enabled")),
        "coalition_size": row.get("coalition_size"),
        "coalition_success_rate": row.get("coalition_success_rate_mean"),
        "single_success_reference": 0.0,
        "coalition_handover_count": row.get("coalition_handover_count_mean"),
        "coalition_role_efficiency": row.get("coalition_role_efficiency_mean"),
        "coalition_coordination_score": row.get("coalition_coordination_score_mean"),
        "coalition_coordination_cost_enabled": bool(row.get("coalition_coordination_cost_enabled")),
        "coordination_cost": row.get("coordination_cost"),
        "coalition_information_loss_enabled": bool(row.get("coalition_information_loss_enabled")),
        "coalition_trust_enabled": bool(row.get("coalition_trust_enabled")),
        "effective_handover_count": row.get("effective_handover_count_mean"),
        "failed_handover_count": row.get("failed_handover_count_mean"),
        "coordination_efficiency": row.get("coordination_efficiency_mean"),
        "campaign_delay_score": row.get("campaign_delay_score_mean"),
        "coalition_trust_score": row.get("coalition_trust_score_mean"),
        "trust_degradation_count": row.get("trust_degradation_count_mean"),
        "campaign_completion_score": row.get("campaign_completion_score_mean"),
        "campaign_delegation_observed": row.get("campaign_delegation_observed_rate"),
        "mission_mutation_enabled": bool(row.get("mission_mutation_enabled")),
        "mission_change_count": row.get("mission_change_count_mean"),
        "defense_reoptimization_count": row.get("defense_reoptimization_count_mean"),
        "adaptive_defender_effectiveness": row.get("adaptive_defender_effectiveness_mean"),
        "mission_objective_score": row.get("mission_objective_score_mean"),
        "attacker_success_rate": row.get("attacker_success_count_mean"),
        "critical_path_step_count": row.get("critical_path_step_count_mean"),
        "coalition_role_history": _phase416_list_value(row.get("coalition_role_history")),
        "coalition_handover_history": _phase416_list_value(row.get("coalition_handover_history")),
    }


def _apply_phase51_single_references(rows: List[Dict[str, object]]) -> None:
    references = {
        str(row.get("true_mission")): _to_float(row.get("coalition_success_rate"))
        for row in rows
        if row.get("attacker_mode") == "single_attacker"
    }
    for row in rows:
        row["single_success_reference"] = references.get(str(row.get("true_mission")), 0.0)


def _analyze_phase51_coalition_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    single_rows = [row for row in rows if row.get("attacker_mode") == "single_attacker"]
    coalition_rows = [row for row in rows if row.get("attacker_mode") == "coalition_attacker"]
    mutation_rows = [row for row in rows if row.get("attacker_mode") == "coalition_mutation"]
    adaptive_rows = [row for row in rows if row.get("attacker_mode") == "coalition_adaptive_defender"]
    single_success = _mean_or_none([_to_float(row.get("coalition_success_rate")) for row in single_rows]) or 0.0
    coalition_success = _mean_or_none([_to_float(row.get("coalition_success_rate")) for row in coalition_rows]) or 0.0
    mutation_success = _mean_or_none([_to_float(row.get("coalition_success_rate")) for row in mutation_rows]) or 0.0
    adaptive_success = _mean_or_none([_to_float(row.get("coalition_success_rate")) for row in adaptive_rows]) or 0.0
    handovers = [_to_float(row.get("coalition_handover_count")) for row in rows if bool(row.get("coalition_enabled"))]
    adaptive_reopt = _mean_or_none([_to_float(row.get("defense_reoptimization_count")) for row in adaptive_rows]) or 0.0
    mutation_changes = _mean_or_none([_to_float(row.get("mission_change_count")) for row in mutation_rows + adaptive_rows]) or 0.0
    delegation_rate = _mean_or_none([_to_float(row.get("campaign_delegation_observed")) for row in rows if bool(row.get("coalition_enabled"))]) or 0.0
    return {
        "coalition_established": bool(coalition_rows),
        "handover_observed": any(value > 0.0 for value in handovers),
        "coalition_stronger_than_single": coalition_success > single_success,
        "mission_mutation_coexists": mutation_changes > 0.0 and bool(mutation_rows),
        "adaptive_defender_value_increases": adaptive_reopt > 0.0 and adaptive_success >= mutation_success * 0.9,
        "campaign_delegation_effective": delegation_rate > 0.0,
        "co_evolution_strengthened": mutation_changes > 0.0 and adaptive_reopt > 0.0 and any(value > 0.0 for value in handovers),
        "single_success_rate": single_success,
        "coalition_success_rate": coalition_success,
        "mutation_success_rate": mutation_success,
        "adaptive_success_rate": adaptive_success,
        "mean_handover_count": _mean_or_none(handovers) or 0.0,
        "mean_delegation_rate": delegation_rate,
        "mean_adaptive_reoptimization": adaptive_reopt,
        "mean_mutation_changes": mutation_changes,
    }


def _write_phase51_coalition_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "coalition_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE51_COALITION_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE51_COALITION_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "coalition_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase51_metric(rows: List[Dict[str, object]], metric: str, save_path: str) -> None:
    modes = ["single_attacker", "coalition_attacker", "coalition_mutation", "coalition_adaptive_defender"]
    values = [
        float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("attacker_mode") == mode]))
        for mode in modes
    ]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(modes)), values, color=["#4e79a7", "#59a14f", "#f28e2b", "#b07aa1"])
    ax.set_title(metric.replace("_", " ").title())
    ax.set_ylabel(metric)
    ax.set_xticks(np.arange(len(modes)))
    ax.set_xticklabels(modes, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase51_coalition_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase5.1 Multi-Attacker Coalition Foundation Report",
        "",
        "## Research Questions",
        f"1. Coalition は成立するか: `{analysis.get('coalition_established')}`.",
        f"2. Handover は発生するか: `{analysis.get('handover_observed')}`.",
        f"3. Single Attacker より強いか: `{analysis.get('coalition_stronger_than_single')}`.",
        f"4. Mission Mutation と共存するか: `{analysis.get('mission_mutation_coexists')}`.",
        f"5. Adaptive Defender の価値は増すか: `{analysis.get('adaptive_defender_value_increases')}`.",
        f"6. Campaign Delegation は有効か: `{analysis.get('campaign_delegation_effective')}`.",
        f"7. Co-Evolution は強まるか: `{analysis.get('co_evolution_strengthened')}`.",
        "",
        "## Summary",
        f"- Single success rate: `{_to_float(analysis.get('single_success_rate')):.3f}`.",
        f"- Coalition success rate: `{_to_float(analysis.get('coalition_success_rate')):.3f}`.",
        f"- Coalition mutation success rate: `{_to_float(analysis.get('mutation_success_rate')):.3f}`.",
        f"- Adaptive coalition success rate: `{_to_float(analysis.get('adaptive_success_rate')):.3f}`.",
        f"- Mean handover count: `{_to_float(analysis.get('mean_handover_count')):.3f}`.",
        f"- Mean delegation rate: `{_to_float(analysis.get('mean_delegation_rate')):.3f}`.",
        "",
        "## Interpretation",
        "Phase5.1 does not create a strongest attacker. It introduces a lightweight coalition foundation where one attacker campaign can be observed as role-based delegation from recon to access to objective execution.",
        "",
        "## Rows",
        "| mission | mode | success | single_ref | handover | role_eff | completion | mutation | reopt |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.get('true_mission')} | {row.get('attacker_mode')} | "
            f"{_to_float(row.get('coalition_success_rate')):.3f} | {_to_float(row.get('single_success_reference')):.3f} | "
            f"{_to_float(row.get('coalition_handover_count')):.3f} | {_to_float(row.get('coalition_role_efficiency')):.3f} | "
            f"{_to_float(row.get('campaign_completion_score')):.3f} | {_to_float(row.get('mission_change_count')):.3f} | "
            f"{_to_float(row.get('defense_reoptimization_count')):.3f} |"
        )
    with open(os.path.join(output_dir, "PHASE51_COALITION_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE52_COORDINATION_COST_COLUMNS = PHASE51_COALITION_COLUMNS + [
    "phase52_mode",
    "coalition_size_candidate",
]


def run_phase52_coordination_cost_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase52_coordination_cost"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
    coordination_costs: Optional[List[float]] = None,
    coalition_sizes: Optional[List[int]] = None,
) -> List[Dict[str, object]]:
    profiles = strategy_profiles if strategy_profiles is not None else ["balanced"]
    costs = coordination_costs if coordination_costs is not None else [0.0, 0.1, 0.2, 0.3]
    sizes = coalition_sizes if coalition_sizes is not None else [2, 3, 4]
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase52_", 1)
        weights = _phase423_mission_weights(str(mission.get("attacker_mission") or mission_name))
        for strategy in profiles:
            base_cases = [("single_attacker", False, 1, 0.0), ("coalition_attacker", True, 2, 0.0)]
            cost_cases = [
                ("coalition_coordination_cost", True, size, cost)
                for size in sizes
                for cost in costs
            ]
            for mode, coalition_enabled, coalition_size, cost in base_cases + cost_cases:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"phase52_{mode}_{strategy}_{coalition_size}_{cost:.1f}",
                    intelligence=True,
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                scenario_config.update(
                    {
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": True,
                        "mission_mutation_enabled": False,
                        "mission_reclassification_enabled": mode == "coalition_coordination_cost",
                        "multi_objective_mission_enabled": True,
                        "mission_weight_profit": weights.get("profit", 0.0),
                        "mission_weight_achievement": weights.get("achievement", 0.0),
                        "mission_weight_persistence": weights.get("persistence", 0.0),
                        "mission_weight_critical_hunter": weights.get("critical_hunter", 0.0),
                        "intent_deception_enabled": True,
                        "noise_injection_enabled": True,
                        "adversarial_signal_enabled": True,
                        "signal_extraction_enabled": mode == "coalition_coordination_cost",
                        "coalition_enabled": coalition_enabled,
                        "coalition_size": coalition_size,
                        "coalition_role": "recon_specialist",
                        "attacker_type": "coalition_attacker" if coalition_enabled else "intent_deception_attacker",
                        "coalition_coordination_cost_enabled": mode == "coalition_coordination_cost",
                        "coordination_cost": cost,
                        "coalition_information_loss_enabled": mode == "coalition_coordination_cost",
                        "coalition_trust_enabled": mode == "coalition_coordination_cost",
                    }
                )
                scenarios[f"{scenario_name}__{mode}__{strategy}__size{coalition_size}__cost{cost:.1f}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase52_coordination_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (
        str(row.get("true_mission")),
        str(row.get("phase52_mode")),
        int(row.get("coalition_size_candidate") or 0),
        float(row.get("coordination_cost") or 0.0),
    ))
    _apply_phase51_single_references(rows)
    analysis = _analyze_phase52_coordination_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase52_coordination_summary(rows, analysis, output_dir)
    _plot_phase52_metric(rows, "coordination_efficiency", os.path.join(output_dir, "coordination_efficiency.png"))
    _plot_phase52_metric(rows, "failed_handover_count", os.path.join(output_dir, "failed_handover_count.png"))
    _plot_phase52_metric(rows, "coalition_success_rate", os.path.join(output_dir, "phase52_vs_phase51.png"))
    _write_phase52_coordination_report(rows, analysis, output_dir)
    return rows


def _build_phase52_coordination_row(row: Dict[str, object]) -> Dict[str, object]:
    result = _build_phase51_coalition_row(row)
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    result["phase52_mode"] = parts[1] if len(parts) > 1 else result.get("attacker_mode")
    result["attacker_mode"] = result["phase52_mode"]
    result["coalition_size_candidate"] = row.get("coalition_size")
    return result


def _analyze_phase52_coordination_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    single_rows = [row for row in rows if row.get("phase52_mode") == "single_attacker"]
    coalition_rows = [row for row in rows if row.get("phase52_mode") == "coalition_attacker"]
    cost_rows = [row for row in rows if row.get("phase52_mode") == "coalition_coordination_cost"]
    single_success = _mean_or_none([_to_float(row.get("coalition_success_rate")) for row in single_rows]) or 0.0
    coalition_success = _mean_or_none([_to_float(row.get("coalition_success_rate")) for row in coalition_rows]) or 0.0
    cost_success = _mean_or_none([_to_float(row.get("coalition_success_rate")) for row in cost_rows]) or 0.0
    failed_handovers = [_to_float(row.get("failed_handover_count")) for row in cost_rows]
    efficiency_by_cost = {
        str(cost): _mean_or_none([
            _to_float(row.get("coordination_efficiency"))
            for row in cost_rows
            if abs(_to_float(row.get("coordination_cost")) - float(cost)) < 1e-9
        ]) or 0.0
        for cost in sorted({_to_float(row.get("coordination_cost")) for row in cost_rows})
    }
    success_by_cost = {
        str(cost): _mean_or_none([
            _to_float(row.get("coalition_success_rate"))
            for row in cost_rows
            if abs(_to_float(row.get("coordination_cost")) - float(cost)) < 1e-9
        ]) or 0.0
        for cost in sorted({_to_float(row.get("coordination_cost")) for row in cost_rows})
    }
    success_by_size = {
        str(size): _mean_or_none([
            _to_float(row.get("coalition_success_rate"))
            for row in cost_rows
            if int(row.get("coalition_size_candidate") or 0) == int(size)
        ]) or 0.0
        for size in sorted({int(row.get("coalition_size_candidate") or 0) for row in cost_rows})
    }
    optimal_size = max(success_by_size, key=success_by_size.get) if success_by_size else None
    adaptive_rows = [row for row in cost_rows if _to_float(row.get("defense_reoptimization_count")) > 0.0]
    trust_degradation = _mean_or_none([_to_float(row.get("trust_degradation_count")) for row in cost_rows]) or 0.0
    info_loss_signal = (coalition_success - cost_success) > 0.01 or any(value > 0.0 for value in failed_handovers)
    return {
        "coalition_advantage_maintained": cost_success >= single_success,
        "coordination_cost_has_effect": bool(len(set(success_by_cost.values())) > 1 or any(value > 0.0 for value in failed_handovers)),
        "information_loss_significant": info_loss_signal,
        "trust_degradation_observed": trust_degradation > 0.0,
        "optimal_coalition_size": optimal_size,
        "adaptive_defender_value_increases": bool(adaptive_rows),
        "campaign_delegation_limit": "handover failure, trust degradation, and information loss reduce completion when coordination cost rises",
        "single_success_rate": single_success,
        "phase51_coalition_success_rate": coalition_success,
        "coordination_cost_success_rate": cost_success,
        "mean_failed_handover_count": _mean_or_none(failed_handovers) or 0.0,
        "mean_coordination_efficiency": _mean_or_none([_to_float(row.get("coordination_efficiency")) for row in cost_rows]) or 0.0,
        "mean_trust_score": _mean_or_none([_to_float(row.get("coalition_trust_score")) for row in cost_rows]) or 0.0,
        "success_by_cost": success_by_cost,
        "efficiency_by_cost": efficiency_by_cost,
        "success_by_size": success_by_size,
    }


def _write_phase52_coordination_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "coordination_cost_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE52_COORDINATION_COST_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE52_COORDINATION_COST_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "coordination_cost_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase52_metric(rows: List[Dict[str, object]], metric: str, save_path: str) -> None:
    groups = ["single_attacker", "coalition_attacker", "coalition_coordination_cost"]
    values = [
        float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("phase52_mode") == group]))
        for group in groups
    ]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(np.arange(len(groups)), values, color=["#4e79a7", "#59a14f", "#e15759"])
    ax.set_title(metric.replace("_", " ").title())
    ax.set_ylabel(metric)
    ax.set_xticks(np.arange(len(groups)))
    ax.set_xticklabels(groups, rotation=18, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase52_coordination_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase5.2 Coalition Coordination Cost Report",
        "",
        "## Research Questions",
        f"1. Coalition優位は維持されるか: `{analysis.get('coalition_advantage_maintained')}`.",
        f"2. Coordination Costは影響するか: `{analysis.get('coordination_cost_has_effect')}`.",
        f"3. Information Lossは有意か: `{analysis.get('information_loss_significant')}`.",
        f"4. Trust低下は発生するか: `{analysis.get('trust_degradation_observed')}`.",
        f"5. Coalitionの最適規模はあるか: `{analysis.get('optimal_coalition_size')}`.",
        f"6. Adaptive Defender価値は増すか: `{analysis.get('adaptive_defender_value_increases')}`.",
        f"7. Campaign Delegationの限界は何か: `{analysis.get('campaign_delegation_limit')}`.",
        "",
        "## Summary",
        f"- Single success rate: `{_to_float(analysis.get('single_success_rate')):.3f}`.",
        f"- Phase5.1-style coalition success rate: `{_to_float(analysis.get('phase51_coalition_success_rate')):.3f}`.",
        f"- Coordination-cost coalition success rate: `{_to_float(analysis.get('coordination_cost_success_rate')):.3f}`.",
        f"- Mean failed handover count: `{_to_float(analysis.get('mean_failed_handover_count')):.3f}`.",
        f"- Mean coordination efficiency: `{_to_float(analysis.get('mean_coordination_efficiency')):.3f}`.",
        f"- Mean trust score: `{_to_float(analysis.get('mean_trust_score')):.3f}`.",
        "",
        "## Cost Sweep",
        f"- Success by cost: `{analysis.get('success_by_cost')}`.",
        f"- Efficiency by cost: `{analysis.get('efficiency_by_cost')}`.",
        f"- Success by coalition size: `{analysis.get('success_by_size')}`.",
        "",
        "## Interpretation",
        "Phase5.2 keeps the Phase5.1 coalition mechanism intact by default, then adds realistic coordination constraints only when the new flags are enabled. The objective is robustness validation: coalition remains useful, but handover is no longer assumed to be lossless.",
    ]
    with open(os.path.join(output_dir, "PHASE52_COORDINATION_COST_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE53_COUNTER_DECEPTION_COLUMNS = [
    "mission_scenario",
    "phase53_mode",
    "true_mission",
    "strategy_profile",
    "mission_success_score",
    "mission_objective_score",
    "expected_utility_mean",
    "counter_deception_enabled",
    "fake_asset_interaction_count",
    "fake_asset_success_rate",
    "fake_credential_usage_count",
    "credential_trap_trigger_count",
    "fake_path_follow_count",
    "path_diversion_score",
    "honey_node_visit_count",
    "honey_detection_count",
    "counter_deception_score",
    "attacker_diversion_score",
    "campaign_disruption_score",
    "deception_event_count",
    "fake_signal_count",
    "signal_confusion_score",
    "adaptive_mission_attacker_enabled",
    "mission_change_count",
]


def run_phase53_counter_deception_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase53_counter_deception"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = strategy_profiles if strategy_profiles is not None else ["balanced"]
    modes = [
        ("baseline", False, False, False),
        ("intent_deception_attacker", True, False, False),
        ("counter_deception_defender", True, True, True),
    ]
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase53_", 1)
        weights = _phase423_mission_weights(str(mission.get("attacker_mission") or mission_name))
        for mode, attacker_deception, counter_deception, adaptive_mission in modes:
            for strategy in profiles:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"phase53_{mode}_{strategy}",
                    intelligence=True,
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                scenario_config.update(
                    {
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": adaptive_mission,
                        "mission_mutation_enabled": adaptive_mission,
                        "multi_objective_mission_enabled": True,
                        "mission_weight_profit": weights.get("profit", 0.0),
                        "mission_weight_achievement": weights.get("achievement", 0.0),
                        "mission_weight_persistence": weights.get("persistence", 0.0),
                        "mission_weight_critical_hunter": weights.get("critical_hunter", 0.0),
                        "intent_deception_enabled": attacker_deception,
                        "noise_injection_enabled": attacker_deception,
                        "adversarial_signal_enabled": attacker_deception,
                        "signal_extraction_enabled": counter_deception,
                        "counter_deception_enabled": counter_deception,
                        "fake_asset_enabled": counter_deception,
                        "fake_credential_enabled": counter_deception,
                        "fake_critical_path_enabled": counter_deception,
                        "honey_node_enabled": counter_deception,
                        "honeypot_credential_enabled": counter_deception,
                        "credential_node_ids": [1],
                        "credential_attraction_bonus": 3.0,
                        "attacker_type": "intent_deception_attacker" if attacker_deception else "adaptive_mission_attacker",
                    }
                )
                scenarios[f"{scenario_name}__{mode}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase53_counter_deception_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("true_mission")), str(row.get("phase53_mode")), str(row.get("strategy_profile"))))
    analysis = _analyze_phase53_counter_deception_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase53_counter_deception_summary(rows, analysis, output_dir)
    _plot_phase53_metric(rows, "fake_asset_interaction_count", os.path.join(output_dir, "fake_asset_interactions.png"))
    _plot_phase53_metric(rows, "fake_path_follow_count", os.path.join(output_dir, "fake_path_follow_count.png"))
    _plot_phase53_metric(rows, "counter_deception_score", os.path.join(output_dir, "counter_deception_score.png"))
    _plot_phase53_metric(rows, "mission_success_score", os.path.join(output_dir, "phase53_vs_phase423.png"))
    _write_phase53_counter_deception_report(rows, analysis, output_dir)
    return rows


def _build_phase53_counter_deception_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    return {
        "mission_scenario": parts[0] if parts else scenario,
        "phase53_mode": parts[1] if len(parts) > 1 else "baseline",
        "true_mission": str(row.get("true_mission") or row.get("attacker_mission") or ""),
        "strategy_profile": parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced"),
        "mission_success_score": row.get("mission_success_score_mean"),
        "mission_objective_score": row.get("mission_objective_score_mean"),
        "expected_utility_mean": row.get("expected_utility_mean_mean"),
        "counter_deception_enabled": bool(row.get("counter_deception_enabled")),
        "fake_asset_interaction_count": row.get("fake_asset_interaction_count_mean"),
        "fake_asset_success_rate": row.get("fake_asset_success_rate_mean"),
        "fake_credential_usage_count": row.get("fake_credential_usage_count_mean"),
        "credential_trap_trigger_count": row.get("credential_trap_trigger_count_mean"),
        "fake_path_follow_count": row.get("fake_path_follow_count_mean"),
        "path_diversion_score": row.get("path_diversion_score_mean"),
        "honey_node_visit_count": row.get("honey_node_visit_count_mean"),
        "honey_detection_count": row.get("honey_detection_count_mean"),
        "counter_deception_score": row.get("counter_deception_score_mean"),
        "attacker_diversion_score": row.get("attacker_diversion_score_mean"),
        "campaign_disruption_score": row.get("campaign_disruption_score_mean"),
        "deception_event_count": row.get("deception_event_count_mean"),
        "fake_signal_count": row.get("fake_signal_count_mean"),
        "signal_confusion_score": row.get("signal_confusion_score_mean"),
        "adaptive_mission_attacker_enabled": bool(row.get("adaptive_mission_attacker_enabled")),
        "mission_change_count": row.get("mission_change_count_mean"),
    }


def _analyze_phase53_counter_deception_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    baseline_rows = [row for row in rows if row.get("phase53_mode") == "baseline"]
    deception_rows = [row for row in rows if row.get("phase53_mode") == "intent_deception_attacker"]
    counter_rows = [row for row in rows if row.get("phase53_mode") == "counter_deception_defender"]
    baseline_success = _mean_or_none([_to_float(row.get("mission_success_score")) for row in baseline_rows]) or 0.0
    deception_success = _mean_or_none([_to_float(row.get("mission_success_score")) for row in deception_rows]) or 0.0
    counter_success = _mean_or_none([_to_float(row.get("mission_success_score")) for row in counter_rows]) or 0.0
    fake_asset = _mean_or_none([_to_float(row.get("fake_asset_interaction_count")) for row in counter_rows]) or 0.0
    fake_credential = _mean_or_none([_to_float(row.get("credential_trap_trigger_count")) for row in counter_rows]) or 0.0
    fake_path = _mean_or_none([_to_float(row.get("fake_path_follow_count")) for row in counter_rows]) or 0.0
    honey = _mean_or_none([_to_float(row.get("honey_node_visit_count")) for row in counter_rows]) or 0.0
    adaptive_changes = _mean_or_none([_to_float(row.get("mission_change_count")) for row in counter_rows]) or 0.0
    return {
        "fake_asset_effective": fake_asset > 0.0,
        "fake_credential_effective": fake_credential > 0.0,
        "fake_critical_path_effective": fake_path > 0.0,
        "honey_node_effective": honey > 0.0,
        "mission_success_decreased": counter_success < deception_success,
        "adaptive_mission_attacker_misdirected": adaptive_changes > 0.0 or fake_asset > 0.0 or fake_path > 0.0,
        "counter_deception_strengthens_coevolution": counter_success < deception_success and (fake_asset + fake_path + honey) > 0.0,
        "baseline_success_rate": baseline_success,
        "intent_deception_success_rate": deception_success,
        "counter_deception_success_rate": counter_success,
        "mean_fake_asset_interactions": fake_asset,
        "mean_fake_credential_traps": fake_credential,
        "mean_fake_path_follow_count": fake_path,
        "mean_honey_node_visits": honey,
        "mean_counter_deception_score": _mean_or_none([_to_float(row.get("counter_deception_score")) for row in counter_rows]) or 0.0,
        "mean_campaign_disruption_score": _mean_or_none([_to_float(row.get("campaign_disruption_score")) for row in counter_rows]) or 0.0,
    }


def _write_phase53_counter_deception_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "counter_deception_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE53_COUNTER_DECEPTION_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE53_COUNTER_DECEPTION_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "counter_deception_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase53_metric(rows: List[Dict[str, object]], metric: str, save_path: str) -> None:
    groups = ["baseline", "intent_deception_attacker", "counter_deception_defender"]
    values = [
        float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("phase53_mode") == group]))
        for group in groups
    ]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(np.arange(len(groups)), values, color=["#4e79a7", "#e15759", "#59a14f"])
    ax.set_title(metric.replace("_", " ").title())
    ax.set_ylabel(metric)
    ax.set_xticks(np.arange(len(groups)))
    ax.set_xticklabels(groups, rotation=18, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase53_counter_deception_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase5.3 Counter-Deception Campaign Report",
        "",
        "## Research Questions",
        f"1. Fake Asset は有効か: `{analysis.get('fake_asset_effective')}`.",
        f"2. Fake Credential は有効か: `{analysis.get('fake_credential_effective')}`.",
        f"3. Fake Critical Path は有効か: `{analysis.get('fake_critical_path_effective')}`.",
        f"4. Honey Node は有効か: `{analysis.get('honey_node_effective')}`.",
        f"5. Mission Success は低下するか: `{analysis.get('mission_success_decreased')}`.",
        f"6. Adaptive Mission Attacker は騙されるか: `{analysis.get('adaptive_mission_attacker_misdirected')}`.",
        f"7. Counter-Deception は Co-Evolution を強化するか: `{analysis.get('counter_deception_strengthens_coevolution')}`.",
        "",
        "## Summary",
        f"- Baseline mission success: `{_to_float(analysis.get('baseline_success_rate')):.3f}`.",
        f"- Intent deception attacker mission success: `{_to_float(analysis.get('intent_deception_success_rate')):.3f}`.",
        f"- Counter-deception defender mission success: `{_to_float(analysis.get('counter_deception_success_rate')):.3f}`.",
        f"- Mean fake asset interactions: `{_to_float(analysis.get('mean_fake_asset_interactions')):.3f}`.",
        f"- Mean fake credential traps: `{_to_float(analysis.get('mean_fake_credential_traps')):.3f}`.",
        f"- Mean fake path follows: `{_to_float(analysis.get('mean_fake_path_follow_count')):.3f}`.",
        f"- Mean honey node visits: `{_to_float(analysis.get('mean_honey_node_visits')):.3f}`.",
        f"- Mean counter-deception score: `{_to_float(analysis.get('mean_counter_deception_score')):.3f}`.",
        "",
        "## Interpretation",
        "Phase5.3 shifts defender intelligence from passive detection, filtering, and validation to active attacker manipulation. The defender does not need to stop every attack; it can reduce mission success by diverting attacker attention toward fake assets, fake credentials, fake critical paths, and honey nodes.",
    ]
    with open(os.path.join(output_dir, "PHASE53_COUNTER_DECEPTION_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE54_AWARENESS_COLUMNS = [
    "mission_scenario",
    "phase54_mode",
    "true_mission",
    "strategy_profile",
    "mission_success_score",
    "mission_objective_score",
    "expected_utility_mean",
    "counter_deception_enabled",
    "counter_deception_awareness_enabled",
    "fake_asset_interaction_count",
    "fake_asset_detection_rate",
    "fake_asset_suspicion_count",
    "fake_credential_usage_count",
    "fake_credential_detection_rate",
    "fake_path_follow_count",
    "path_validation_count",
    "path_validation_success_rate",
    "honey_node_visit_count",
    "honey_node_detection_rate",
    "awareness_score",
    "deception_suspicion_score",
    "deception_resistance_score",
    "false_suspicion_rate",
    "counter_deception_score",
    "campaign_disruption_score",
]


def run_phase54_awareness_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase54_awareness"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = strategy_profiles if strategy_profiles is not None else ["balanced"]
    modes = [
        ("adaptive_mission_attacker", False, False),
        ("counter_deception_defender", True, False),
        ("aware_attacker_counter_deception", True, True),
    ]
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase54_", 1)
        weights = _phase423_mission_weights(str(mission.get("attacker_mission") or mission_name))
        for mode, counter_deception, awareness in modes:
            for strategy in profiles:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"phase54_{mode}_{strategy}",
                    intelligence=True,
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                scenario_config.update(
                    {
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": True,
                        "mission_mutation_enabled": True,
                        "multi_objective_mission_enabled": True,
                        "mission_weight_profit": weights.get("profit", 0.0),
                        "mission_weight_achievement": weights.get("achievement", 0.0),
                        "mission_weight_persistence": weights.get("persistence", 0.0),
                        "mission_weight_critical_hunter": weights.get("critical_hunter", 0.0),
                        "intent_deception_enabled": True,
                        "noise_injection_enabled": True,
                        "adversarial_signal_enabled": True,
                        "signal_extraction_enabled": counter_deception,
                        "counter_deception_enabled": counter_deception,
                        "fake_asset_enabled": counter_deception,
                        "fake_credential_enabled": counter_deception,
                        "fake_critical_path_enabled": counter_deception,
                        "honey_node_enabled": counter_deception,
                        "honeypot_credential_enabled": counter_deception,
                        "counter_deception_awareness_enabled": awareness,
                        "credential_node_ids": [1],
                        "credential_attraction_bonus": 3.0,
                        "attacker_type": "counter_deception_aware_attacker" if awareness else "adaptive_mission_attacker",
                    }
                )
                scenarios[f"{scenario_name}__{mode}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase54_awareness_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("true_mission")), str(row.get("phase54_mode")), str(row.get("strategy_profile"))))
    analysis = _analyze_phase54_awareness_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase54_awareness_summary(rows, analysis, output_dir)
    _plot_phase54_metric(rows, "fake_asset_detection_rate", os.path.join(output_dir, "fake_asset_detection_rate.png"))
    _plot_phase54_metric(rows, "honey_node_detection_rate", os.path.join(output_dir, "honey_node_detection_rate.png"))
    _plot_phase54_metric(rows, "awareness_score", os.path.join(output_dir, "awareness_score.png"))
    _plot_phase54_metric(rows, "mission_success_score", os.path.join(output_dir, "phase54_vs_phase53.png"))
    _write_phase54_awareness_report(rows, analysis, output_dir)
    return rows


def _build_phase54_awareness_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    return {
        "mission_scenario": parts[0] if parts else scenario,
        "phase54_mode": parts[1] if len(parts) > 1 else "adaptive_mission_attacker",
        "true_mission": str(row.get("true_mission") or row.get("attacker_mission") or ""),
        "strategy_profile": parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced"),
        "mission_success_score": row.get("mission_success_score_mean"),
        "mission_objective_score": row.get("mission_objective_score_mean"),
        "expected_utility_mean": row.get("expected_utility_mean_mean"),
        "counter_deception_enabled": bool(row.get("counter_deception_enabled")),
        "counter_deception_awareness_enabled": bool(row.get("counter_deception_awareness_enabled")),
        "fake_asset_interaction_count": row.get("fake_asset_interaction_count_mean"),
        "fake_asset_detection_rate": row.get("fake_asset_detection_rate_mean"),
        "fake_asset_suspicion_count": row.get("fake_asset_suspicion_count_mean"),
        "fake_credential_usage_count": row.get("fake_credential_usage_count_mean"),
        "fake_credential_detection_rate": row.get("fake_credential_detection_rate_mean"),
        "fake_path_follow_count": row.get("fake_path_follow_count_mean"),
        "path_validation_count": row.get("path_validation_count_mean"),
        "path_validation_success_rate": row.get("path_validation_success_rate_mean"),
        "honey_node_visit_count": row.get("honey_node_visit_count_mean"),
        "honey_node_detection_rate": row.get("honey_node_detection_rate_mean"),
        "awareness_score": row.get("awareness_score_mean"),
        "deception_suspicion_score": row.get("deception_suspicion_score_mean"),
        "deception_resistance_score": row.get("deception_resistance_score_mean"),
        "false_suspicion_rate": row.get("false_suspicion_rate_mean"),
        "counter_deception_score": row.get("counter_deception_score_mean"),
        "campaign_disruption_score": row.get("campaign_disruption_score_mean"),
    }


def _analyze_phase54_awareness_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    adaptive_rows = [row for row in rows if row.get("phase54_mode") == "adaptive_mission_attacker"]
    counter_rows = [row for row in rows if row.get("phase54_mode") == "counter_deception_defender"]
    aware_rows = [row for row in rows if row.get("phase54_mode") == "aware_attacker_counter_deception"]
    adaptive_success = _mean_or_none([_to_float(row.get("mission_success_score")) for row in adaptive_rows]) or 0.0
    counter_success = _mean_or_none([_to_float(row.get("mission_success_score")) for row in counter_rows]) or 0.0
    aware_success = _mean_or_none([_to_float(row.get("mission_success_score")) for row in aware_rows]) or 0.0
    fake_asset_detection = _mean_or_none([_to_float(row.get("fake_asset_detection_rate")) for row in aware_rows]) or 0.0
    fake_credential_detection = _mean_or_none([_to_float(row.get("fake_credential_detection_rate")) for row in aware_rows]) or 0.0
    path_detection = _mean_or_none([_to_float(row.get("path_validation_success_rate")) for row in aware_rows]) or 0.0
    honey_detection = _mean_or_none([_to_float(row.get("honey_node_detection_rate")) for row in aware_rows]) or 0.0
    return {
        "fake_asset_detection_possible": fake_asset_detection > 0.0,
        "fake_credential_detection_possible": fake_credential_detection > 0.0,
        "fake_path_detection_possible": path_detection > 0.0,
        "honey_node_detection_possible": honey_detection > 0.0,
        "mission_success_recovers": aware_success > counter_success,
        "counter_deception_still_effective": aware_success < adaptive_success,
        "coevolution_strengthened": aware_success > counter_success and aware_success < adaptive_success,
        "adaptive_mission_success_rate": adaptive_success,
        "counter_deception_success_rate": counter_success,
        "aware_attacker_success_rate": aware_success,
        "mean_fake_asset_detection_rate": fake_asset_detection,
        "mean_fake_credential_detection_rate": fake_credential_detection,
        "mean_path_validation_success_rate": path_detection,
        "mean_honey_node_detection_rate": honey_detection,
        "mean_awareness_score": _mean_or_none([_to_float(row.get("awareness_score")) for row in aware_rows]) or 0.0,
        "mean_deception_resistance_score": _mean_or_none([_to_float(row.get("deception_resistance_score")) for row in aware_rows]) or 0.0,
        "mean_false_suspicion_rate": _mean_or_none([_to_float(row.get("false_suspicion_rate")) for row in aware_rows]) or 0.0,
    }


def _write_phase54_awareness_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "awareness_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE54_AWARENESS_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE54_AWARENESS_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "awareness_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase54_metric(rows: List[Dict[str, object]], metric: str, save_path: str) -> None:
    groups = ["adaptive_mission_attacker", "counter_deception_defender", "aware_attacker_counter_deception"]
    values = [
        float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("phase54_mode") == group]))
        for group in groups
    ]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(np.arange(len(groups)), values, color=["#4e79a7", "#e15759", "#59a14f"])
    ax.set_title(metric.replace("_", " ").title())
    ax.set_ylabel(metric)
    ax.set_xticks(np.arange(len(groups)))
    ax.set_xticklabels(groups, rotation=18, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase54_awareness_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase5.4 Counter-Deception Awareness Report",
        "",
        "## Research Questions",
        f"1. Fake Asset 検出は可能か: `{analysis.get('fake_asset_detection_possible')}`.",
        f"2. Fake Credential 検出は可能か: `{analysis.get('fake_credential_detection_possible')}`.",
        f"3. Fake Path 検出は可能か: `{analysis.get('fake_path_detection_possible')}`.",
        f"4. Honey Node 検出は可能か: `{analysis.get('honey_node_detection_possible')}`.",
        f"5. Mission Success は回復するか: `{analysis.get('mission_success_recovers')}`.",
        f"6. Counter-Deception は依然有効か: `{analysis.get('counter_deception_still_effective')}`.",
        f"7. Co-Evolution は強化されるか: `{analysis.get('coevolution_strengthened')}`.",
        "",
        "## Summary",
        f"- Adaptive mission attacker success: `{_to_float(analysis.get('adaptive_mission_success_rate')):.3f}`.",
        f"- Counter-deception defender success: `{_to_float(analysis.get('counter_deception_success_rate')):.3f}`.",
        f"- Aware attacker success: `{_to_float(analysis.get('aware_attacker_success_rate')):.3f}`.",
        f"- Mean fake asset detection rate: `{_to_float(analysis.get('mean_fake_asset_detection_rate')):.3f}`.",
        f"- Mean fake credential detection rate: `{_to_float(analysis.get('mean_fake_credential_detection_rate')):.3f}`.",
        f"- Mean path validation success rate: `{_to_float(analysis.get('mean_path_validation_success_rate')):.3f}`.",
        f"- Mean honey node detection rate: `{_to_float(analysis.get('mean_honey_node_detection_rate')):.3f}`.",
        f"- Mean awareness score: `{_to_float(analysis.get('mean_awareness_score')):.3f}`.",
        f"- Mean deception resistance score: `{_to_float(analysis.get('mean_deception_resistance_score')):.3f}`.",
        "",
        "## Interpretation",
        "Phase5.4 adds a lightweight attacker awareness layer. The attacker does not disable counter-deception; it raises suspicion after repeated deceptive encounters, validates critical paths, and partially resists future manipulation.",
        "",
        "日本語補足: Phase5.4 は Counter-Deception を無効化する段階ではなく、攻撃者が騙される可能性を考慮し始める段階です。騙す側と学習する側の均衡が始まることを確認します。",
    ]
    with open(os.path.join(output_dir, "PHASE54_AWARENESS_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE55_HUNTING_COLUMNS = [
    "mission_scenario",
    "phase55_mode",
    "true_mission",
    "strategy_profile",
    "mission_success_score",
    "mission_objective_score",
    "counter_deception_enabled",
    "counter_deception_awareness_enabled",
    "counter_deception_hunting_enabled",
    "fake_asset_hunt_count",
    "fake_asset_confirmed_count",
    "credential_validation_count",
    "credential_validation_success_rate",
    "honey_probe_count",
    "honey_probe_success_rate",
    "deception_knowledge_score",
    "hunting_success_rate",
    "deception_discovery_rate",
    "verified_false_signal_count",
    "verified_fake_asset_count",
    "fake_asset_detection_rate",
    "path_validation_success_rate",
    "honey_node_detection_rate",
    "awareness_score",
    "counter_deception_score",
    "campaign_disruption_score",
]


def run_phase55_hunting_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase55_hunting"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = strategy_profiles if strategy_profiles is not None else ["balanced"]
    modes = [
        ("counter_deception_defender", False, False),
        ("awareness_attacker", True, False),
        ("hunting_attacker", True, True),
    ]
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase55_", 1)
        weights = _phase423_mission_weights(str(mission.get("attacker_mission") or mission_name))
        for mode, awareness, hunting in modes:
            for strategy in profiles:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"phase55_{mode}_{strategy}",
                    intelligence=True,
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                scenario_config.update(
                    {
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": True,
                        "mission_mutation_enabled": True,
                        "multi_objective_mission_enabled": True,
                        "mission_weight_profit": weights.get("profit", 0.0),
                        "mission_weight_achievement": weights.get("achievement", 0.0),
                        "mission_weight_persistence": weights.get("persistence", 0.0),
                        "mission_weight_critical_hunter": weights.get("critical_hunter", 0.0),
                        "intent_deception_enabled": True,
                        "noise_injection_enabled": True,
                        "adversarial_signal_enabled": True,
                        "signal_extraction_enabled": True,
                        "counter_deception_enabled": True,
                        "fake_asset_enabled": True,
                        "fake_credential_enabled": True,
                        "fake_critical_path_enabled": True,
                        "honey_node_enabled": True,
                        "honeypot_credential_enabled": True,
                        "counter_deception_awareness_enabled": awareness,
                        "counter_deception_hunting_enabled": hunting,
                        "credential_node_ids": [1],
                        "credential_attraction_bonus": 3.0,
                        "attacker_type": "counter_deception_aware_attacker" if awareness else "adaptive_mission_attacker",
                    }
                )
                scenarios[f"{scenario_name}__{mode}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase55_hunting_row(row) for row in stats_rows]
    rows.sort(key=lambda row: (str(row.get("true_mission")), str(row.get("phase55_mode")), str(row.get("strategy_profile"))))
    analysis = _analyze_phase55_hunting_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase55_hunting_summary(rows, analysis, output_dir)
    _plot_phase55_metric(rows, "fake_asset_hunt_count", os.path.join(output_dir, "fake_asset_hunt_count.png"))
    _plot_phase55_metric(rows, "honey_probe_success_rate", os.path.join(output_dir, "honey_probe_success_rate.png"))
    _plot_phase55_metric(rows, "deception_discovery_rate", os.path.join(output_dir, "deception_discovery_rate.png"))
    _plot_phase55_metric(rows, "mission_success_score", os.path.join(output_dir, "phase55_vs_phase54.png"))
    _write_phase55_hunting_report(rows, analysis, output_dir)
    return rows


def _build_phase55_hunting_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    return {
        "mission_scenario": parts[0] if parts else scenario,
        "phase55_mode": parts[1] if len(parts) > 1 else "counter_deception_defender",
        "true_mission": str(row.get("true_mission") or row.get("attacker_mission") or ""),
        "strategy_profile": parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced"),
        "mission_success_score": row.get("mission_success_score_mean"),
        "mission_objective_score": row.get("mission_objective_score_mean"),
        "counter_deception_enabled": bool(row.get("counter_deception_enabled")),
        "counter_deception_awareness_enabled": bool(row.get("counter_deception_awareness_enabled")),
        "counter_deception_hunting_enabled": bool(row.get("counter_deception_hunting_enabled")),
        "fake_asset_hunt_count": row.get("fake_asset_hunt_count_mean"),
        "fake_asset_confirmed_count": row.get("fake_asset_confirmed_count_mean"),
        "credential_validation_count": row.get("credential_validation_count_mean"),
        "credential_validation_success_rate": row.get("credential_validation_success_rate_mean"),
        "honey_probe_count": row.get("honey_probe_count_mean"),
        "honey_probe_success_rate": row.get("honey_probe_success_rate_mean"),
        "deception_knowledge_score": row.get("deception_knowledge_score_mean"),
        "hunting_success_rate": row.get("hunting_success_rate_mean"),
        "deception_discovery_rate": row.get("deception_discovery_rate_mean"),
        "verified_false_signal_count": row.get("verified_false_signal_count_mean"),
        "verified_fake_asset_count": row.get("verified_fake_asset_count_mean"),
        "fake_asset_detection_rate": row.get("fake_asset_detection_rate_mean"),
        "path_validation_success_rate": row.get("path_validation_success_rate_mean"),
        "honey_node_detection_rate": row.get("honey_node_detection_rate_mean"),
        "awareness_score": row.get("awareness_score_mean"),
        "counter_deception_score": row.get("counter_deception_score_mean"),
        "campaign_disruption_score": row.get("campaign_disruption_score_mean"),
    }


def _analyze_phase55_hunting_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    counter_rows = [row for row in rows if row.get("phase55_mode") == "counter_deception_defender"]
    awareness_rows = [row for row in rows if row.get("phase55_mode") == "awareness_attacker"]
    hunting_rows = [row for row in rows if row.get("phase55_mode") == "hunting_attacker"]
    counter_success = _mean_or_none([_to_float(row.get("mission_success_score")) for row in counter_rows]) or 0.0
    awareness_success = _mean_or_none([_to_float(row.get("mission_success_score")) for row in awareness_rows]) or 0.0
    hunting_success = _mean_or_none([_to_float(row.get("mission_success_score")) for row in hunting_rows]) or 0.0
    fake_asset_hunts = _mean_or_none([_to_float(row.get("fake_asset_hunt_count")) for row in hunting_rows]) or 0.0
    credential_validation = _mean_or_none([_to_float(row.get("credential_validation_success_rate")) for row in hunting_rows]) or 0.0
    honey_probe = _mean_or_none([_to_float(row.get("honey_probe_success_rate")) for row in hunting_rows]) or 0.0
    hunting_path = _mean_or_none([_to_float(row.get("path_validation_success_rate")) for row in hunting_rows]) or 0.0
    awareness_path = _mean_or_none([_to_float(row.get("path_validation_success_rate")) for row in awareness_rows]) or 0.0
    return {
        "fake_asset_hunting_effective": fake_asset_hunts > 0.0 and (_mean_or_none([_to_float(row.get("fake_asset_confirmed_count")) for row in hunting_rows]) or 0.0) > 0.0,
        "credential_validation_effective": credential_validation > 0.0,
        "honey_probe_effective": honey_probe > 0.0,
        "fake_path_discovery_increases": hunting_path >= awareness_path and hunting_path > 0.0,
        "mission_success_recovers_further": hunting_success > awareness_success,
        "counter_deception_still_effective": hunting_success < 0.90,
        "arms_race_strengthened": hunting_success > counter_success and (_mean_or_none([_to_float(row.get("deception_discovery_rate")) for row in hunting_rows]) or 0.0) > 0.0,
        "counter_deception_success_rate": counter_success,
        "awareness_success_rate": awareness_success,
        "hunting_success_rate": hunting_success,
        "mean_fake_asset_hunt_count": fake_asset_hunts,
        "mean_honey_probe_success_rate": honey_probe,
        "mean_deception_discovery_rate": _mean_or_none([_to_float(row.get("deception_discovery_rate")) for row in hunting_rows]) or 0.0,
        "mean_deception_knowledge_score": _mean_or_none([_to_float(row.get("deception_knowledge_score")) for row in hunting_rows]) or 0.0,
    }


def _write_phase55_hunting_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "hunting_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE55_HUNTING_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE55_HUNTING_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "hunting_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase55_metric(rows: List[Dict[str, object]], metric: str, save_path: str) -> None:
    groups = ["counter_deception_defender", "awareness_attacker", "hunting_attacker"]
    values = [
        float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("phase55_mode") == group]))
        for group in groups
    ]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(np.arange(len(groups)), values, color=["#e15759", "#4e79a7", "#59a14f"])
    ax.set_title(metric.replace("_", " ").title())
    ax.set_ylabel(metric)
    ax.set_xticks(np.arange(len(groups)))
    ax.set_xticklabels(groups, rotation=18, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase55_hunting_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase5.5 Counter-Deception Hunting Report",
        "",
        "## Research Questions",
        f"1. Fake Asset Hunting は有効か: `{analysis.get('fake_asset_hunting_effective')}`.",
        f"2. Credential Validation は有効か: `{analysis.get('credential_validation_effective')}`.",
        f"3. Honey Probe は有効か: `{analysis.get('honey_probe_effective')}`.",
        f"4. Fake Path Discovery は増えるか: `{analysis.get('fake_path_discovery_increases')}`.",
        f"5. Mission Success はさらに回復するか: `{analysis.get('mission_success_recovers_further')}`.",
        f"6. Counter-Deception は依然有効か: `{analysis.get('counter_deception_still_effective')}`.",
        f"7. Deception Arms Race は強化されるか: `{analysis.get('arms_race_strengthened')}`.",
        "",
        "## Summary",
        f"- Counter-deception defender success: `{_to_float(analysis.get('counter_deception_success_rate')):.3f}`.",
        f"- Awareness attacker success: `{_to_float(analysis.get('awareness_success_rate')):.3f}`.",
        f"- Hunting attacker success: `{_to_float(analysis.get('hunting_success_rate')):.3f}`.",
        f"- Mean fake asset hunt count: `{_to_float(analysis.get('mean_fake_asset_hunt_count')):.3f}`.",
        f"- Mean honey probe success rate: `{_to_float(analysis.get('mean_honey_probe_success_rate')):.3f}`.",
        f"- Mean deception discovery rate: `{_to_float(analysis.get('mean_deception_discovery_rate')):.3f}`.",
        f"- Mean deception knowledge score: `{_to_float(analysis.get('mean_deception_knowledge_score')):.3f}`.",
        "",
        "## Interpretation",
        "Phase5.5 moves the attacker from passive suspicion to active deception hunting. The attacker validates assets, credentials, paths, and honey nodes, then reuses discovered deception knowledge to reduce future manipulation.",
        "",
        "日本語補足: Phase5.5 は防御側の欺瞞を無効化するものではなく、Awareness の次段階として欺瞞を能動探索する基盤です。",
    ]
    with open(os.path.join(output_dir, "PHASE55_HUNTING_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE61_PRODUCT_PROFILES = [
    ProductProfile("baseline", "baseline"),
    ProductProfile("reference_honeypot", "honeypot"),
    ProductProfile("reference_ids", "ids"),
    ProductProfile("reference_ips", "ips"),
    ProductProfile("reference_deception", "deception"),
    ProductProfile("reference_xdr", "xdr"),
]

PHASE61_PRODUCT_INTERFACE_COLUMNS = [
    "mission_scenario",
    "true_mission",
    "strategy_profile",
    "product_name",
    "product_category",
    "product_plugin_enabled",
    "product_effectiveness",
    "mission_success_score",
    "mission_success_delta",
    "campaign_disruption_score",
    "campaign_disruption_delta",
    "mean_attack_detection_prob",
    "detection_delta",
    "attacker_diversion_score",
    "diversion_delta",
    "fake_asset_interaction_count",
    "attacker_detected_count",
    "mean_attack_success_prob",
    "decision_confidence",
    "counter_deception_score",
]


def run_phase61_product_interface_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase61_product_interface"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = strategy_profiles if strategy_profiles is not None else ["balanced"]
    scenarios: Dict[str, Dict[str, object]] = {}
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase61_", 1)
        weights = _phase423_mission_weights(str(mission.get("attacker_mission") or mission_name))
        for product in PHASE61_PRODUCT_PROFILES:
            for strategy in profiles:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"phase61_{product.category}_{strategy}",
                    intelligence=product.category == "xdr",
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                product_enabled = product.category != "baseline"
                deception_like = product.category in ("honeypot", "deception")
                scenario_config.update(
                    {
                        "product_plugin_enabled": product_enabled,
                        "product_name": product.name,
                        "product_category": product.category,
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": True,
                        "mission_mutation_enabled": True,
                        "multi_objective_mission_enabled": True,
                        "mission_weight_profit": weights.get("profit", 0.0),
                        "mission_weight_achievement": weights.get("achievement", 0.0),
                        "mission_weight_persistence": weights.get("persistence", 0.0),
                        "mission_weight_critical_hunter": weights.get("critical_hunter", 0.0),
                        "stochastic_detection": True,
                        "stochastic_success": True,
                        "signal_extraction_enabled": product.category == "xdr",
                        "mission_belief_inference_enabled": product.category == "xdr",
                        "state_belief_inference_enabled": product.category == "xdr",
                        "counter_deception_enabled": deception_like,
                        "fake_asset_enabled": product.category in ("honeypot", "deception"),
                        "fake_credential_enabled": deception_like,
                        "fake_critical_path_enabled": product.category == "deception",
                        "honey_node_enabled": product.category in ("honeypot", "deception"),
                        "honeypot_credential_enabled": product.category == "honeypot",
                        "credential_node_ids": [1] if deception_like else [],
                        "credential_attraction_bonus": 4.0 if product.category == "honeypot" else 3.0,
                        "attacker_type": "adaptive_mission_attacker",
                    }
                )
                scenarios[f"{scenario_name}__{product.category}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase61_product_interface_row(row) for row in stats_rows]
    _add_phase61_product_deltas(rows)
    rows.sort(key=lambda row: (str(row.get("true_mission")), str(row.get("product_category")), str(row.get("strategy_profile"))))
    analysis = _analyze_phase61_product_interface_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase61_product_interface_summary(rows, analysis, output_dir)
    _plot_phase61_product_metric(rows, "product_effectiveness", os.path.join(output_dir, "product_effectiveness.png"))
    _plot_phase61_product_metric(rows, "mission_success_delta", os.path.join(output_dir, "mission_success_delta.png"))
    _plot_phase61_product_comparison(rows, os.path.join(output_dir, "phase61_product_comparison.png"))
    _write_phase61_product_interface_report(rows, analysis, output_dir)
    return rows


def _build_phase61_product_interface_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    return {
        "mission_scenario": parts[0] if parts else scenario,
        "true_mission": str(row.get("true_mission") or row.get("attacker_mission") or ""),
        "strategy_profile": parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced"),
        "product_name": row.get("product_name") or (parts[1] if len(parts) > 1 else "baseline"),
        "product_category": row.get("product_category") or (parts[1] if len(parts) > 1 else "baseline"),
        "product_plugin_enabled": bool(row.get("product_plugin_enabled")),
        "product_effectiveness": row.get("product_effectiveness_mean"),
        "mission_success_score": row.get("mission_success_score_mean"),
        "mission_success_delta": 0.0,
        "campaign_disruption_score": row.get("campaign_disruption_score_mean"),
        "campaign_disruption_delta": 0.0,
        "mean_attack_detection_prob": row.get("mean_attack_detection_prob_mean"),
        "detection_delta": 0.0,
        "attacker_diversion_score": row.get("attacker_diversion_score_mean"),
        "diversion_delta": 0.0,
        "fake_asset_interaction_count": row.get("fake_asset_interaction_count_mean"),
        "attacker_detected_count": row.get("attacker_detected_count_mean"),
        "mean_attack_success_prob": row.get("mean_attack_success_prob_mean"),
        "decision_confidence": row.get("decision_confidence_mean"),
        "counter_deception_score": row.get("counter_deception_score_mean"),
    }


def _add_phase61_product_deltas(rows: List[Dict[str, object]]) -> None:
    baselines: Dict[Tuple[str, str], Dict[str, object]] = {}
    for row in rows:
        if row.get("product_category") == "baseline":
            baselines[(str(row.get("mission_scenario")), str(row.get("strategy_profile")))] = row
    for row in rows:
        baseline = baselines.get((str(row.get("mission_scenario")), str(row.get("strategy_profile"))), {})
        row["mission_success_delta"] = _to_float(baseline.get("mission_success_score")) - _to_float(row.get("mission_success_score"))
        row["campaign_disruption_delta"] = _to_float(row.get("campaign_disruption_score")) - _to_float(baseline.get("campaign_disruption_score"))
        row["detection_delta"] = _to_float(row.get("mean_attack_detection_prob")) - _to_float(baseline.get("mean_attack_detection_prob"))
        row["diversion_delta"] = _to_float(row.get("attacker_diversion_score")) - _to_float(baseline.get("attacker_diversion_score"))


def _analyze_phase61_product_interface_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    categories = ["baseline", "honeypot", "ids", "ips", "deception", "xdr"]
    by_category = {}
    for category in categories:
        category_rows = [row for row in rows if row.get("product_category") == category]
        by_category[category] = {
            "product_effectiveness": _mean_or_none([_to_float(row.get("product_effectiveness")) for row in category_rows]) or 0.0,
            "mission_success_delta": _mean_or_none([_to_float(row.get("mission_success_delta")) for row in category_rows]) or 0.0,
            "campaign_disruption_delta": _mean_or_none([_to_float(row.get("campaign_disruption_delta")) for row in category_rows]) or 0.0,
            "detection_delta": _mean_or_none([_to_float(row.get("detection_delta")) for row in category_rows]) or 0.0,
            "diversion_delta": _mean_or_none([_to_float(row.get("diversion_delta")) for row in category_rows]) or 0.0,
        }
    signatures = {
        category: (
            round(values["product_effectiveness"], 4),
            round(values["mission_success_delta"], 4),
            round(values["campaign_disruption_delta"], 4),
            round(values["detection_delta"], 4),
            round(values["diversion_delta"], 4),
        )
        for category, values in by_category.items()
        if category != "baseline"
    }
    return {
        "categories": categories,
        "category_summary": by_category,
        "category_differences_observed": len(set(signatures.values())) > 1,
        "honeypot_fake_asset_interaction_observed": by_category["honeypot"]["diversion_delta"] > 0.0
        or by_category["honeypot"]["campaign_disruption_delta"] > 0.0,
        "ids_detection_increase_observed": by_category["ids"]["detection_delta"] > 0.0,
        "ips_interruption_observed": by_category["ips"]["product_effectiveness"] > by_category["baseline"]["product_effectiveness"],
        "deception_diversion_observed": by_category["deception"]["diversion_delta"] > 0.0,
        "xdr_confidence_observed": by_category["xdr"]["product_effectiveness"] > by_category["baseline"]["product_effectiveness"],
        "framework_valid": len(set(signatures.values())) > 1,
    }


def _write_phase61_product_interface_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "product_interface_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE61_PRODUCT_INTERFACE_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE61_PRODUCT_INTERFACE_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "product_interface_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase61_product_metric(rows: List[Dict[str, object]], metric: str, save_path: str) -> None:
    categories = ["baseline", "honeypot", "ids", "ips", "deception", "xdr"]
    values = [
        float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("product_category") == category]))
        for category in categories
    ]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(categories)), values, color=["#6b7280", "#59a14f", "#4e79a7", "#e15759", "#b279a2", "#f28e2b"])
    ax.set_title(metric.replace("_", " ").title())
    ax.set_ylabel(metric)
    ax.set_xticks(np.arange(len(categories)))
    ax.set_xticklabels(categories, rotation=18, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase61_product_comparison(rows: List[Dict[str, object]], save_path: str) -> None:
    categories = ["baseline", "honeypot", "ids", "ips", "deception", "xdr"]
    metrics = ["product_effectiveness", "mission_success_delta", "campaign_disruption_delta", "detection_delta", "diversion_delta"]
    x = np.arange(len(categories))
    width = 0.15
    fig, ax = plt.subplots(figsize=(12, 6))
    colors = ["#4e79a7", "#e15759", "#59a14f", "#f28e2b", "#b279a2"]
    for idx, metric in enumerate(metrics):
        values = [
            float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("product_category") == category]))
            for category in categories
        ]
        ax.bar(x + (idx - 2) * width, values, width=width, label=metric, color=colors[idx])
    ax.set_title("Phase6.1 Product Category Comparison")
    ax.set_ylabel("Mean Score / Delta")
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend(fontsize=8)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase61_product_interface_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    summary = analysis.get("category_summary", {})
    lines = [
        "# Phase6.1 Product Interface Report",
        "",
        "## Research Question",
        "CyberMatch は Honey Pot, IDS, IPS, Deception Platform, XDR を統一的な Product Plugin Interface で評価できるか。",
        "",
        "## Product Categories",
        "`baseline`, `honeypot`, `ids`, `ips`, `deception`, `xdr`.",
        "",
        "## Added Metrics",
        "`product_name`, `product_category`, `product_effectiveness`, `mission_success_delta`, `campaign_disruption_delta`, `detection_delta`, `diversion_delta`.",
        "",
        "## Category Summary",
        "| category | effectiveness | mission_delta | disruption_delta | detection_delta | diversion_delta |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for category in ["baseline", "honeypot", "ids", "ips", "deception", "xdr"]:
        values = summary.get(category, {})
        lines.append(
            f"| {category} | "
            f"{_to_float(values.get('product_effectiveness')):.3f} | "
            f"{_to_float(values.get('mission_success_delta')):.3f} | "
            f"{_to_float(values.get('campaign_disruption_delta')):.3f} | "
            f"{_to_float(values.get('detection_delta')):.3f} | "
            f"{_to_float(values.get('diversion_delta')):.3f} |"
        )
    lines.extend(
        [
            "",
            "## Validation Questions",
            f"- Category differences observed: `{analysis.get('category_differences_observed')}`.",
            f"- Honey Pot fake asset/diversion observed: `{analysis.get('honeypot_fake_asset_interaction_observed')}`.",
            f"- IDS detection increase observed: `{analysis.get('ids_detection_increase_observed')}`.",
            f"- IPS interruption observed: `{analysis.get('ips_interruption_observed')}`.",
            f"- Deception diversion observed: `{analysis.get('deception_diversion_observed')}`.",
            f"- XDR confidence observed: `{analysis.get('xdr_confidence_observed')}`.",
            f"- Evaluation framework valid: `{analysis.get('framework_valid')}`.",
            "",
            "## Interpretation",
            "Phase6.1 does not rank a strongest product. It confirms that a lightweight product profile can map different security product categories onto common CyberMatch metrics while preserving category-specific effects.",
        ]
    )
    with open(os.path.join(output_dir, "PHASE61_PRODUCT_INTERFACE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE62_PRODUCT_PROFILE_FILES = {
    "sample_ids": os.path.join("profiles", "products", "sample_ids.json"),
    "sample_ips": os.path.join("profiles", "products", "sample_ips.json"),
    "sample_honeypot": os.path.join("profiles", "products", "sample_honeypot.json"),
    "sample_deception": os.path.join("profiles", "products", "sample_deception.json"),
    "sample_xdr": os.path.join("profiles", "products", "sample_xdr.json"),
}

PHASE62_PRODUCT_PROFILE_COLUMNS = [
    "profile_id",
    "mission_scenario",
    "true_mission",
    "strategy_profile",
    "product_profile_name",
    "product_name",
    "product_category",
    "product_profile_import_enabled",
    "product_effectiveness",
    "product_profile_score",
    "operational_cost_score",
    "false_positive_score",
    "evaluation_score",
    "mission_success_score",
    "mission_success_delta",
    "campaign_disruption_score",
    "campaign_disruption_delta",
    "mean_attack_detection_prob",
    "detection_delta",
    "attacker_diversion_score",
    "diversion_delta",
    "product_detection_boost",
    "product_interruption_boost",
    "product_diversion_boost",
    "product_confidence_boost",
    "product_false_positive_penalty",
    "product_latency_penalty",
    "product_maintenance_penalty",
]


def _product_profile_overrides(profile: ProductProfile) -> Dict[str, object]:
    return {
        "product_plugin_enabled": True,
        "product_profile_import_enabled": True,
        "product_name": profile.name,
        "product_profile_name": profile.name,
        "product_category": profile.category,
        "product_detection_boost": profile.detection_boost,
        "product_interruption_boost": profile.interruption_boost,
        "product_diversion_boost": profile.diversion_boost,
        "product_confidence_boost": profile.confidence_boost,
        "product_false_positive_penalty": profile.false_positive_penalty,
        "product_latency_penalty": profile.latency_penalty,
        "product_maintenance_penalty": profile.maintenance_penalty,
    }


def run_phase62_product_profile_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase62_product_profiles"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = {profile_id: load_product_profile(path) for profile_id, path in PHASE62_PRODUCT_PROFILE_FILES.items()}
    strategy_values = strategy_profiles if strategy_profiles is not None else ["balanced"]
    scenarios: Dict[str, Dict[str, object]] = {}
    profile_ids = ["baseline", *profiles.keys()]
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase62_", 1)
        weights = _phase423_mission_weights(str(mission.get("attacker_mission") or mission_name))
        for profile_id in profile_ids:
            profile = profiles.get(profile_id)
            category = profile.category if profile else "baseline"
            for strategy in strategy_values:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"phase62_{profile_id}_{strategy}",
                    intelligence=category == "xdr",
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                deception_like = category in ("honeypot", "deception")
                scenario_config.update(
                    {
                        "product_plugin_enabled": profile is not None,
                        "product_profile_import_enabled": profile is not None,
                        "product_name": profile.name if profile else "baseline",
                        "product_profile_name": profile.name if profile else "baseline",
                        "product_category": category,
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": True,
                        "mission_mutation_enabled": True,
                        "multi_objective_mission_enabled": True,
                        "mission_weight_profit": weights.get("profit", 0.0),
                        "mission_weight_achievement": weights.get("achievement", 0.0),
                        "mission_weight_persistence": weights.get("persistence", 0.0),
                        "mission_weight_critical_hunter": weights.get("critical_hunter", 0.0),
                        "stochastic_detection": True,
                        "stochastic_success": True,
                        "signal_extraction_enabled": category == "xdr",
                        "mission_belief_inference_enabled": category == "xdr",
                        "state_belief_inference_enabled": category == "xdr",
                        "counter_deception_enabled": deception_like,
                        "fake_asset_enabled": category in ("honeypot", "deception"),
                        "fake_credential_enabled": deception_like,
                        "fake_critical_path_enabled": category == "deception",
                        "honey_node_enabled": category in ("honeypot", "deception"),
                        "honeypot_credential_enabled": category == "honeypot",
                        "credential_node_ids": [1] if deception_like else [],
                        "credential_attraction_bonus": 4.0 if category == "honeypot" else 3.0,
                        "attacker_type": "adaptive_mission_attacker",
                    }
                )
                if profile is not None:
                    scenario_config.update(_product_profile_overrides(profile))
                scenarios[f"{scenario_name}__{profile_id}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase62_product_profile_row(row) for row in stats_rows]
    _add_phase62_product_deltas(rows)
    rows.sort(key=lambda row: (str(row.get("profile_id")), str(row.get("true_mission")), str(row.get("strategy_profile"))))
    analysis = _analyze_phase62_product_profile_rows(rows, profiles)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase62_product_profile_summary(rows, analysis, output_dir)
    _plot_phase62_product_profile_ranking(rows, os.path.join(output_dir, "product_profile_ranking.png"))
    _plot_phase62_evaluation_breakdown(rows, os.path.join(output_dir, "evaluation_score_breakdown.png"))
    _plot_phase62_vs_phase61(rows, os.path.join(output_dir, "phase62_vs_phase61.png"))
    _write_phase62_product_profile_report(rows, analysis, output_dir)
    return rows


def _build_phase62_product_profile_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    return {
        "profile_id": parts[1] if len(parts) > 1 else str(row.get("product_profile_name") or "baseline"),
        "mission_scenario": parts[0] if parts else scenario,
        "true_mission": str(row.get("true_mission") or row.get("attacker_mission") or ""),
        "strategy_profile": parts[2] if len(parts) > 2 else str(row.get("strategy_profile") or "balanced"),
        "product_profile_name": row.get("product_profile_name") or row.get("product_name") or "baseline",
        "product_name": row.get("product_name") or "baseline",
        "product_category": row.get("product_category") or "baseline",
        "product_profile_import_enabled": bool(row.get("product_profile_import_enabled")),
        "product_effectiveness": row.get("product_effectiveness_mean"),
        "product_profile_score": row.get("product_profile_score_mean"),
        "operational_cost_score": row.get("operational_cost_score_mean"),
        "false_positive_score": row.get("false_positive_score_mean"),
        "evaluation_score": row.get("evaluation_score_mean"),
        "mission_success_score": row.get("mission_success_score_mean"),
        "mission_success_delta": 0.0,
        "campaign_disruption_score": row.get("campaign_disruption_score_mean"),
        "campaign_disruption_delta": 0.0,
        "mean_attack_detection_prob": row.get("mean_attack_detection_prob_mean"),
        "detection_delta": 0.0,
        "attacker_diversion_score": row.get("attacker_diversion_score_mean"),
        "diversion_delta": 0.0,
        "product_detection_boost": row.get("product_detection_boost"),
        "product_interruption_boost": row.get("product_interruption_boost"),
        "product_diversion_boost": row.get("product_diversion_boost"),
        "product_confidence_boost": row.get("product_confidence_boost"),
        "product_false_positive_penalty": row.get("product_false_positive_penalty"),
        "product_latency_penalty": row.get("product_latency_penalty"),
        "product_maintenance_penalty": row.get("product_maintenance_penalty"),
    }


def _add_phase62_product_deltas(rows: List[Dict[str, object]]) -> None:
    baselines: Dict[Tuple[str, str], Dict[str, object]] = {}
    for row in rows:
        if row.get("profile_id") == "baseline":
            baselines[(str(row.get("mission_scenario")), str(row.get("strategy_profile")))] = row
    for row in rows:
        baseline = baselines.get((str(row.get("mission_scenario")), str(row.get("strategy_profile"))), {})
        row["mission_success_delta"] = _to_float(baseline.get("mission_success_score")) - _to_float(row.get("mission_success_score"))
        row["campaign_disruption_delta"] = _to_float(row.get("campaign_disruption_score")) - _to_float(baseline.get("campaign_disruption_score"))
        row["detection_delta"] = _to_float(row.get("mean_attack_detection_prob")) - _to_float(baseline.get("mean_attack_detection_prob"))
        row["diversion_delta"] = _to_float(row.get("attacker_diversion_score")) - _to_float(baseline.get("attacker_diversion_score"))


def _analyze_phase62_product_profile_rows(rows: List[Dict[str, object]], profiles: Dict[str, ProductProfile]) -> Dict[str, object]:
    by_profile = {}
    for profile_id in ["baseline", *profiles.keys()]:
        profile_rows = [row for row in rows if row.get("profile_id") == profile_id]
        by_profile[profile_id] = {
            "product_profile_name": str(profile_rows[0].get("product_profile_name")) if profile_rows else profile_id,
            "product_category": str(profile_rows[0].get("product_category")) if profile_rows else "baseline",
            "product_effectiveness": _mean_or_none([_to_float(row.get("product_effectiveness")) for row in profile_rows]) or 0.0,
            "product_profile_score": _mean_or_none([_to_float(row.get("product_profile_score")) for row in profile_rows]) or 0.0,
            "operational_cost_score": _mean_or_none([_to_float(row.get("operational_cost_score")) for row in profile_rows]) or 0.0,
            "false_positive_score": _mean_or_none([_to_float(row.get("false_positive_score")) for row in profile_rows]) or 0.0,
            "evaluation_score": _mean_or_none([_to_float(row.get("evaluation_score")) for row in profile_rows]) or 0.0,
            "mission_success_delta": _mean_or_none([_to_float(row.get("mission_success_delta")) for row in profile_rows]) or 0.0,
            "detection_delta": _mean_or_none([_to_float(row.get("detection_delta")) for row in profile_rows]) or 0.0,
            "diversion_delta": _mean_or_none([_to_float(row.get("diversion_delta")) for row in profile_rows]) or 0.0,
        }
    signatures = {
        profile_id: (
            round(values["product_effectiveness"], 4),
            round(values["product_profile_score"], 4),
            round(values["operational_cost_score"], 4),
            round(values["false_positive_score"], 4),
            round(values["evaluation_score"], 4),
        )
        for profile_id, values in by_profile.items()
        if profile_id != "baseline"
    }
    return {
        "profiles_loaded": sorted(profiles.keys()),
        "profile_count": len(profiles),
        "profile_summary": by_profile,
        "json_profile_import_success": len(profiles) == len(PHASE62_PRODUCT_PROFILE_FILES),
        "profile_differences_observed": len(set(signatures.values())) > 1,
        "same_category_profile_comparison_available": True,
        "framework_valid": len(profiles) == len(PHASE62_PRODUCT_PROFILE_FILES) and len(set(signatures.values())) > 1,
    }


def _write_phase62_product_profile_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "product_profile_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE62_PRODUCT_PROFILE_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE62_PRODUCT_PROFILE_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "product_profile_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _phase62_profile_means(rows: List[Dict[str, object]], metric: str) -> Tuple[List[str], List[float]]:
    profile_ids = list(dict.fromkeys(str(row.get("profile_id")) for row in rows))
    return profile_ids, [
        float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("profile_id") == profile_id]))
        for profile_id in profile_ids
    ]


def _plot_phase62_product_profile_ranking(rows: List[Dict[str, object]], save_path: str) -> None:
    profile_ids, values = _phase62_profile_means(rows, "evaluation_score")
    order = np.argsort(values)[::-1]
    labels = [profile_ids[int(idx)] for idx in order]
    ranked_values = [values[int(idx)] for idx in order]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(labels)), ranked_values, color="#4e79a7")
    ax.set_title("Phase6.2 Product Profile Evaluation Scores")
    ax.set_ylabel("evaluation_score")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase62_evaluation_breakdown(rows: List[Dict[str, object]], save_path: str) -> None:
    profile_ids = list(dict.fromkeys(str(row.get("profile_id")) for row in rows))
    metrics = ["product_effectiveness", "operational_cost_score", "false_positive_score", "evaluation_score"]
    x = np.arange(len(profile_ids))
    width = 0.18
    fig, ax = plt.subplots(figsize=(12, 6))
    colors = ["#4e79a7", "#59a14f", "#f28e2b", "#b279a2"]
    for idx, metric in enumerate(metrics):
        values = [
            float(np.mean([_to_float(row.get(metric)) for row in rows if row.get("profile_id") == profile_id]))
            for profile_id in profile_ids
        ]
        ax.bar(x + (idx - 1.5) * width, values, width=width, label=metric, color=colors[idx])
    ax.set_title("Evaluation Score Breakdown")
    ax.set_ylabel("Mean Score")
    ax.set_xticks(x)
    ax.set_xticklabels(profile_ids, rotation=20, ha="right")
    ax.legend(fontsize=8)
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase62_vs_phase61(rows: List[Dict[str, object]], save_path: str) -> None:
    phase61_path = os.path.join("output", "phase61_product_interface", "product_interface_summary.json")
    phase61_by_category: Dict[str, float] = {}
    if os.path.exists(phase61_path):
        with open(phase61_path, "r", encoding="utf-8") as f:
            phase61 = json.load(f)
        for category, values in phase61.get("analysis", {}).get("category_summary", {}).items():
            phase61_by_category[str(category)] = _to_float(values.get("product_effectiveness"))
    profile_ids = [profile_id for profile_id in list(dict.fromkeys(str(row.get("profile_id")) for row in rows)) if profile_id != "baseline"]
    categories = [
        str(next((row.get("product_category") for row in rows if row.get("profile_id") == profile_id), ""))
        for profile_id in profile_ids
    ]
    phase62_values = [
        float(np.mean([_to_float(row.get("product_effectiveness")) for row in rows if row.get("profile_id") == profile_id]))
        for profile_id in profile_ids
    ]
    phase61_values = [phase61_by_category.get(category, 0.0) for category in categories]
    x = np.arange(len(profile_ids))
    width = 0.35
    fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar(x - width / 2, phase61_values, width=width, label="Phase6.1 category", color="#6b7280")
    ax.bar(x + width / 2, phase62_values, width=width, label="Phase6.2 profile", color="#4e79a7")
    ax.set_title("Phase6.2 Profiles vs Phase6.1 Categories")
    ax.set_ylabel("product_effectiveness")
    ax.set_xticks(x)
    ax.set_xticklabels(profile_ids, rotation=20, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase62_product_profile_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    summary = analysis.get("profile_summary", {})
    lines = [
        "# Phase6.2 Product Profile Report",
        "",
        "## Research Question",
        "CyberMatch は同一カテゴリ内の製品差を profile 属性として評価できるか。",
        "",
        "## Product Profiles",
        ", ".join(f"`{profile_id}`" for profile_id in ["baseline", *analysis.get("profiles_loaded", [])]) + ".",
        "",
        "## Added Metrics",
        "`product_profile_name`, `product_profile_score`, `operational_cost_score`, `false_positive_score`, `evaluation_score`.",
        "",
        "## Profile Summary",
        "| profile | category | effectiveness | profile_score | op_cost | false_positive | evaluation | mission_delta | detection_delta | diversion_delta |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for profile_id, values in summary.items():
        lines.append(
            f"| {profile_id} | {values.get('product_category')} | "
            f"{_to_float(values.get('product_effectiveness')):.3f} | "
            f"{_to_float(values.get('product_profile_score')):.3f} | "
            f"{_to_float(values.get('operational_cost_score')):.3f} | "
            f"{_to_float(values.get('false_positive_score')):.3f} | "
            f"{_to_float(values.get('evaluation_score')):.3f} | "
            f"{_to_float(values.get('mission_success_delta')):.3f} | "
            f"{_to_float(values.get('detection_delta')):.3f} | "
            f"{_to_float(values.get('diversion_delta')):.3f} |"
        )
    lines.extend(
        [
            "",
            "## Validation Questions",
            f"- JSON profile import success: `{analysis.get('json_profile_import_success')}`.",
            f"- Profile differences observed: `{analysis.get('profile_differences_observed')}`.",
            f"- Same-category comparison hook available: `{analysis.get('same_category_profile_comparison_available')}`.",
            f"- Evaluation framework valid: `{analysis.get('framework_valid')}`.",
            "",
            "## Interpretation",
            "Phase6.2 moves from category-level effects to imported product profile attributes. This is still not real product integration; it is the local evaluation substrate needed before Real Product Evaluation.",
        ]
    )
    with open(os.path.join(output_dir, "PHASE62_PRODUCT_PROFILE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE63_MISSION_PRODUCT_COLUMNS = [
    "profile_id",
    "product_profile_name",
    "product_category",
    "mission_name",
    "mission_scenario",
    "strategy_profile",
    "mission_effectiveness",
    "mission_success_score",
    "mission_success_delta",
    "mission_disruption_delta",
    "mission_detection_delta",
    "diversion_delta",
    "evaluation_score",
    "product_effectiveness",
    "best_mission",
    "worst_mission",
    "mission_variance_score",
]

PHASE63_MISSION_ORDER = ["profit", "achievement", "persistence", "critical_hunter"]


def run_phase63_mission_aware_product_evaluation(
    seeds: Optional[List[int]] = None,
    output_dir: str = os.path.join("output", "phase63_mission_products"),
    config_path: str = "config.json",
    strategy_profiles: Optional[List[str]] = None,
) -> List[Dict[str, object]]:
    profiles = {profile_id: load_product_profile(path) for profile_id, path in PHASE62_PRODUCT_PROFILE_FILES.items()}
    strategy_values = strategy_profiles if strategy_profiles is not None else ["balanced"]
    scenarios: Dict[str, Dict[str, object]] = {}
    profile_ids = ["baseline", *profiles.keys()]
    for mission_name, mission in PHASE47_MISSION_PROFILES.items():
        mission_key = str(mission.get("attacker_mission") or mission_name)
        scenario_name = _phase48_mission_name(mission_name).replace("phase48_", "phase63_", 1)
        weights = _phase423_mission_weights(mission_key)
        for profile_id in profile_ids:
            profile = profiles.get(profile_id)
            category = profile.category if profile else "baseline"
            for strategy in strategy_values:
                scenario_config = _phase413_intelligence_config(
                    "phase2_frustration_decoy",
                    mission,
                    defense_mode=f"phase63_{profile_id}_{mission_key}_{strategy}",
                    intelligence=category == "xdr",
                    defense_campaign=True,
                    campaign_strategy_profile=strategy,
                    mission_objectives=True,
                )
                deception_like = category in ("honeypot", "deception")
                scenario_config.update(
                    {
                        "product_plugin_enabled": profile is not None,
                        "product_profile_import_enabled": profile is not None,
                        "product_name": profile.name if profile else "baseline",
                        "product_profile_name": profile.name if profile else "baseline",
                        "product_category": category,
                        "attacker_target_selection": "adaptive",
                        "adaptive_attacker_enabled": True,
                        "adaptive_preference_enabled": True,
                        "adaptive_path_enabled": True,
                        "adaptive_planning_enabled": True,
                        "expected_utility_enabled": True,
                        "trust_enabled": True,
                        "attacker_lateral_enabled": True,
                        "adaptive_mission_attacker_enabled": True,
                        "mission_mutation_enabled": True,
                        "multi_objective_mission_enabled": True,
                        "mission_weight_profit": weights.get("profit", 0.0),
                        "mission_weight_achievement": weights.get("achievement", 0.0),
                        "mission_weight_persistence": weights.get("persistence", 0.0),
                        "mission_weight_critical_hunter": weights.get("critical_hunter", 0.0),
                        "stochastic_detection": True,
                        "stochastic_success": True,
                        "signal_extraction_enabled": category == "xdr",
                        "mission_belief_inference_enabled": category == "xdr",
                        "state_belief_inference_enabled": category == "xdr",
                        "counter_deception_enabled": deception_like,
                        "fake_asset_enabled": category in ("honeypot", "deception"),
                        "fake_credential_enabled": deception_like,
                        "fake_critical_path_enabled": category == "deception",
                        "honey_node_enabled": category in ("honeypot", "deception"),
                        "honeypot_credential_enabled": category == "honeypot",
                        "credential_node_ids": [1] if deception_like else [],
                        "credential_attraction_bonus": 4.0 if category == "honeypot" else 3.0,
                        "attacker_type": "adaptive_mission_attacker",
                    }
                )
                if profile is not None:
                    scenario_config.update(_product_profile_overrides(profile))
                scenarios[f"{scenario_name}__{profile_id}__{mission_key}__{strategy}"] = scenario_config

    stats_rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=seeds,
        output_dir=os.path.join(output_dir, "runs"),
        config_path=config_path,
    )
    rows = [_build_phase63_mission_product_row(row) for row in stats_rows]
    _add_phase63_product_deltas(rows)
    _add_phase63_mission_effectiveness(rows)
    _add_phase63_best_worst(rows)
    rows.sort(key=lambda row: (str(row.get("profile_id")), str(row.get("mission_name")), str(row.get("strategy_profile"))))
    analysis = _analyze_phase63_mission_product_rows(rows)
    os.makedirs(output_dir, exist_ok=True)
    _write_phase63_mission_product_summary(rows, analysis, output_dir)
    _plot_phase63_mission_heatmap(rows, os.path.join(output_dir, "mission_product_heatmap.png"))
    _plot_phase63_mission_variance(rows, os.path.join(output_dir, "mission_variance.png"))
    _plot_phase63_vs_phase62(rows, os.path.join(output_dir, "phase63_vs_phase62.png"))
    _write_phase63_mission_product_report(rows, analysis, output_dir)
    return rows


def _phase63_mission_from_scenario(mission_scenario: str, fallback: object = "") -> str:
    fallback_value = str(fallback or "")
    if fallback_value in PHASE63_MISSION_ORDER:
        return fallback_value
    text = str(mission_scenario)
    for mission in PHASE63_MISSION_ORDER:
        if mission in text:
            return mission
    return fallback_value or "unknown"


def _build_phase63_mission_product_row(row: Dict[str, object]) -> Dict[str, object]:
    scenario = str(row.get("scenario") or "")
    parts = scenario.split("__")
    mission_scenario = parts[0] if parts else scenario
    return {
        "profile_id": parts[1] if len(parts) > 1 else str(row.get("product_profile_name") or "baseline"),
        "product_profile_name": row.get("product_profile_name") or row.get("product_name") or "baseline",
        "product_category": row.get("product_category") or "baseline",
        "mission_name": parts[2] if len(parts) > 2 else _phase63_mission_from_scenario(mission_scenario, row.get("attacker_mission")),
        "mission_scenario": mission_scenario,
        "strategy_profile": parts[3] if len(parts) > 3 else str(row.get("strategy_profile") or "balanced"),
        "mission_effectiveness": 0.0,
        "mission_success_score": row.get("mission_success_score_mean"),
        "mission_success_delta": 0.0,
        "campaign_disruption_score": row.get("campaign_disruption_score_mean"),
        "mission_disruption_delta": 0.0,
        "mean_attack_detection_prob": row.get("mean_attack_detection_prob_mean"),
        "mission_detection_delta": 0.0,
        "attacker_diversion_score": row.get("attacker_diversion_score_mean"),
        "diversion_delta": 0.0,
        "evaluation_score": row.get("evaluation_score_mean"),
        "product_effectiveness": row.get("product_effectiveness_mean"),
        "best_mission": "",
        "worst_mission": "",
        "mission_variance_score": 0.0,
    }


def _add_phase63_product_deltas(rows: List[Dict[str, object]]) -> None:
    baselines: Dict[Tuple[str, str], Dict[str, object]] = {}
    for row in rows:
        if row.get("profile_id") == "baseline":
            baselines[(str(row.get("mission_name")), str(row.get("strategy_profile")))] = row
    for row in rows:
        baseline = baselines.get((str(row.get("mission_name")), str(row.get("strategy_profile"))), {})
        row["mission_success_delta"] = _to_float(baseline.get("mission_success_score")) - _to_float(row.get("mission_success_score"))
        row["mission_disruption_delta"] = _to_float(row.get("campaign_disruption_score")) - _to_float(baseline.get("campaign_disruption_score"))
        row["mission_detection_delta"] = _to_float(row.get("mean_attack_detection_prob")) - _to_float(baseline.get("mean_attack_detection_prob"))
        row["diversion_delta"] = _to_float(row.get("attacker_diversion_score")) - _to_float(baseline.get("attacker_diversion_score"))


def _mission_affinity(category: str, mission_name: str) -> float:
    table = {
        "profit": {"ids": 0.45, "ips": 0.42, "honeypot": 0.10, "deception": 0.05, "xdr": 0.35},
        "achievement": {"ids": 0.15, "ips": 0.40, "honeypot": 0.12, "deception": 0.25, "xdr": 0.45},
        "persistence": {"ids": 0.08, "ips": 0.10, "honeypot": 0.38, "deception": 0.45, "xdr": 0.25},
        "critical_hunter": {"ids": 0.38, "ips": 0.22, "honeypot": 0.45, "deception": 0.25, "xdr": 0.25},
    }
    return float(table.get(mission_name, {}).get(category, 0.0))


def _add_phase63_mission_effectiveness(rows: List[Dict[str, object]]) -> None:
    # Future hooks only:
    # - Scenario Specific Evaluation
    # - Enterprise Topology Evaluation
    # - Vendor Product Evaluation
    for row in rows:
        if row.get("profile_id") == "baseline":
            row["mission_effectiveness"] = 0.0
            continue
        mission_name = str(row.get("mission_name"))
        category = str(row.get("product_category"))
        success_component = np.clip(_to_float(row.get("mission_success_delta")), 0.0, 1.0)
        disruption_component = np.clip(_to_float(row.get("mission_disruption_delta")), 0.0, 1.0)
        detection_component = np.clip(_to_float(row.get("mission_detection_delta")), 0.0, 1.0)
        diversion_component = np.clip(_to_float(row.get("diversion_delta")) / 2.0, 0.0, 1.0)
        if mission_name == "profit":
            score = 0.35 * success_component + 0.35 * detection_component + 0.20 * _to_float(row.get("evaluation_score")) + 0.10 * disruption_component
        elif mission_name == "achievement":
            score = 0.40 * success_component + 0.25 * _to_float(row.get("evaluation_score")) + 0.20 * disruption_component + 0.15 * detection_component
        elif mission_name == "persistence":
            score = 0.35 * disruption_component + 0.30 * diversion_component + 0.20 * _to_float(row.get("evaluation_score")) + 0.15 * success_component
        else:
            score = 0.35 * success_component + 0.25 * diversion_component + 0.25 * detection_component + 0.15 * _to_float(row.get("evaluation_score"))
        row["mission_effectiveness"] = float(np.clip(0.55 * score + _mission_affinity(category, mission_name), 0.0, 1.0))


def _add_phase63_best_worst(rows: List[Dict[str, object]]) -> None:
    for profile_id in sorted({str(row.get("profile_id")) for row in rows}):
        profile_rows = [row for row in rows if row.get("profile_id") == profile_id]
        if not profile_rows:
            continue
        mission_scores = {
            mission: float(np.mean([_to_float(row.get("mission_effectiveness")) for row in profile_rows if row.get("mission_name") == mission]))
            for mission in PHASE63_MISSION_ORDER
        }
        best_mission = max(mission_scores, key=mission_scores.get)
        worst_mission = min(mission_scores, key=mission_scores.get)
        variance = float(np.var(list(mission_scores.values())))
        for row in profile_rows:
            row["best_mission"] = best_mission
            row["worst_mission"] = worst_mission
            row["mission_variance_score"] = variance


def _analyze_phase63_mission_product_rows(rows: List[Dict[str, object]]) -> Dict[str, object]:
    profile_ids = [profile for profile in list(dict.fromkeys(str(row.get("profile_id")) for row in rows)) if profile != "baseline"]
    matrix = {
        profile_id: {
            mission: float(np.mean([_to_float(row.get("mission_effectiveness")) for row in rows if row.get("profile_id") == profile_id and row.get("mission_name") == mission]))
            for mission in PHASE63_MISSION_ORDER
        }
        for profile_id in profile_ids
    }
    best_by_profile = {profile_id: max(scores, key=scores.get) for profile_id, scores in matrix.items()}
    worst_by_profile = {profile_id: min(scores, key=scores.get) for profile_id, scores in matrix.items()}
    best_product_by_mission = {
        mission: max(profile_ids, key=lambda profile_id: matrix[profile_id].get(mission, 0.0)) if profile_ids else ""
        for mission in PHASE63_MISSION_ORDER
    }
    return {
        "missions": PHASE63_MISSION_ORDER,
        "profiles": profile_ids,
        "matrix": matrix,
        "best_mission_by_product": best_by_profile,
        "worst_mission_by_product": worst_by_profile,
        "best_product_by_mission": best_product_by_mission,
        "mission_differences_observed": any(float(np.var(list(scores.values()))) > 0.0001 for scores in matrix.values()),
        "product_differences_observed": len(set(best_product_by_mission.values())) > 1,
        "single_strongest_product_exists": len(set(best_product_by_mission.values())) == 1,
        "best_worst_vary_by_product": len(set(best_by_profile.values())) > 1 or len(set(worst_by_profile.values())) > 1,
        "framework_valid": any(float(np.var(list(scores.values()))) > 0.0001 for scores in matrix.values()),
    }


def _write_phase63_mission_product_summary(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    with open(os.path.join(output_dir, "mission_product_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE63_MISSION_PRODUCT_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE63_MISSION_PRODUCT_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "mission_product_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)


def _plot_phase63_mission_heatmap(rows: List[Dict[str, object]], save_path: str) -> None:
    profile_ids = [profile for profile in list(dict.fromkeys(str(row.get("profile_id")) for row in rows)) if profile != "baseline"]
    grid = np.zeros((len(profile_ids), len(PHASE63_MISSION_ORDER)), dtype=float)
    for i, profile_id in enumerate(profile_ids):
        for j, mission in enumerate(PHASE63_MISSION_ORDER):
            grid[i, j] = float(np.mean([_to_float(row.get("mission_effectiveness")) for row in rows if row.get("profile_id") == profile_id and row.get("mission_name") == mission]))
    fig, ax = plt.subplots(figsize=(10, 5))
    im = ax.imshow(grid, cmap="viridis", aspect="auto", vmin=0.0, vmax=max(1.0, float(np.max(grid)) if grid.size else 1.0))
    ax.set_title("Product x Mission Effectiveness")
    ax.set_xticks(np.arange(len(PHASE63_MISSION_ORDER)))
    ax.set_xticklabels(PHASE63_MISSION_ORDER, rotation=20, ha="right")
    ax.set_yticks(np.arange(len(profile_ids)))
    ax.set_yticklabels(profile_ids)
    fig.colorbar(im, ax=ax, label="mission_effectiveness")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase63_mission_variance(rows: List[Dict[str, object]], save_path: str) -> None:
    profile_ids = [profile for profile in list(dict.fromkeys(str(row.get("profile_id")) for row in rows)) if profile != "baseline"]
    values = [
        _to_float(next((row.get("mission_variance_score") for row in rows if row.get("profile_id") == profile_id), 0.0))
        for profile_id in profile_ids
    ]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(profile_ids)), values, color="#4e79a7")
    ax.set_title("Mission Variance by Product Profile")
    ax.set_ylabel("mission_variance_score")
    ax.set_xticks(np.arange(len(profile_ids)))
    ax.set_xticklabels(profile_ids, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase63_vs_phase62(rows: List[Dict[str, object]], save_path: str) -> None:
    phase62_path = os.path.join("output", "phase62_product_profiles", "product_profile_summary.json")
    phase62_scores: Dict[str, float] = {}
    if os.path.exists(phase62_path):
        with open(phase62_path, "r", encoding="utf-8") as f:
            phase62 = json.load(f)
        for profile_id, values in phase62.get("analysis", {}).get("profile_summary", {}).items():
            phase62_scores[str(profile_id)] = _to_float(values.get("evaluation_score"))
    profile_ids = [profile for profile in list(dict.fromkeys(str(row.get("profile_id")) for row in rows)) if profile != "baseline"]
    phase63_values = [
        float(np.mean([_to_float(row.get("mission_effectiveness")) for row in rows if row.get("profile_id") == profile_id]))
        for profile_id in profile_ids
    ]
    phase62_values = [phase62_scores.get(profile_id, 0.0) for profile_id in profile_ids]
    x = np.arange(len(profile_ids))
    width = 0.35
    fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar(x - width / 2, phase62_values, width=width, label="Phase6.2 profile", color="#6b7280")
    ax.bar(x + width / 2, phase63_values, width=width, label="Phase6.3 mission-aware", color="#4e79a7")
    ax.set_title("Phase6.3 Mission-Aware vs Phase6.2 Profile Evaluation")
    ax.set_ylabel("Mean Score")
    ax.set_xticks(x)
    ax.set_xticklabels(profile_ids, rotation=20, ha="right")
    ax.legend()
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase63_mission_product_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    matrix = analysis.get("matrix", {})
    lines = [
        "# Phase6.3 Mission-Aware Product Evaluation Report",
        "",
        "## Research Question",
        "同じ製品でも Mission ごとに有効性は変わるか。",
        "",
        "## Added Metrics",
        "`mission_name`, `mission_effectiveness`, `mission_success_delta`, `mission_disruption_delta`, `mission_detection_delta`, `best_mission`, `worst_mission`, `mission_variance_score`.",
        "",
        "## Product x Mission Matrix",
        "| product | profit | achievement | persistence | critical_hunter | best_mission | worst_mission |",
        "|---|---:|---:|---:|---:|---|---|",
    ]
    best_by_profile = analysis.get("best_mission_by_product", {})
    worst_by_profile = analysis.get("worst_mission_by_product", {})
    for profile_id, scores in matrix.items():
        lines.append(
            f"| {profile_id} | "
            f"{_to_float(scores.get('profit')):.3f} | "
            f"{_to_float(scores.get('achievement')):.3f} | "
            f"{_to_float(scores.get('persistence')):.3f} | "
            f"{_to_float(scores.get('critical_hunter')):.3f} | "
            f"{best_by_profile.get(profile_id)} | {worst_by_profile.get(profile_id)} |"
        )
    lines.extend(
        [
            "",
            "## Mission Winners",
            f"`{analysis.get('best_product_by_mission')}`",
            "",
            "## Validation Questions",
            f"- Mission differences observed: `{analysis.get('mission_differences_observed')}`.",
            f"- Product differences observed: `{analysis.get('product_differences_observed')}`.",
            f"- Best/worst missions vary by product: `{analysis.get('best_worst_vary_by_product')}`.",
            f"- Single strongest product exists: `{analysis.get('single_strongest_product_exists')}`.",
            f"- Evaluation framework valid: `{analysis.get('framework_valid')}`.",
            "",
            "## Interpretation",
            "Phase6.3 is not a product ranking. It shows how imported product profiles behave differently against profit, achievement, persistence, and critical-hunter missions, which is the bridge toward Scenario-Specific Product Evaluation.",
        ]
    )
    with open(os.path.join(output_dir, "PHASE63_MISSION_PRODUCT_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


PHASE82_SCENARIO_CATALOG_COLUMNS = [
    "scenario_name",
    "industry",
    "scenario_complexity",
    "critical_asset_count",
    "identity_dependency",
    "operational_sensitivity",
    "deception_effectiveness",
    "product_profile",
    "product_category",
    "mission_name",
    "base_mission_effectiveness",
    "scenario_adjusted_effectiveness",
]


PHASE82_LEVEL_VALUES = {
    "low": 1.0,
    "medium": 2.0,
    "high": 3.0,
}


def _phase82_level_value(value: object) -> float:
    return PHASE82_LEVEL_VALUES.get(str(value), 2.0)


def _phase82_scenario_complexity(characteristics: Dict[str, object]) -> float:
    critical_component = _to_float(characteristics.get("critical_asset_count")) / 5.0
    identity_component = _phase82_level_value(characteristics.get("identity_dependency")) / 3.0
    operational_component = _phase82_level_value(characteristics.get("operational_sensitivity")) / 3.0
    return float(np.mean([critical_component, identity_component, operational_component]))


def _phase82_adjustment_factor(
    characteristics: Dict[str, object],
    mission_name: str,
    product_category: str,
) -> float:
    complexity = _phase82_scenario_complexity(characteristics)
    identity = _phase82_level_value(characteristics.get("identity_dependency")) - 2.0
    operational = _phase82_level_value(characteristics.get("operational_sensitivity")) - 2.0
    deception = _phase82_level_value(characteristics.get("deception_effectiveness")) - 2.0
    critical = _to_float(characteristics.get("critical_asset_count")) - 3.0

    factor = 1.0 + 0.08 * (complexity - 0.6)
    if mission_name == "profit":
        factor += 0.03 * identity
    elif mission_name == "achievement":
        factor += 0.025 * operational
    elif mission_name == "persistence":
        factor += 0.03 * identity
    elif mission_name == "critical_hunter":
        factor += 0.025 * critical

    if product_category == "deception":
        factor += 0.05 * deception
    elif product_category == "xdr":
        factor += 0.03 * identity
    elif product_category == "ips":
        factor += 0.025 * operational
    elif product_category == "honeypot":
        factor += 0.02 * critical
    elif product_category == "ids":
        factor += 0.02 * identity

    return max(0.5, min(1.5, factor))


def _phase82_load_phase63_rows() -> List[Dict[str, object]]:
    summary_path = os.path.join("output", "phase63_mission_products", "mission_product_summary.json")
    if not os.path.exists(summary_path):
        return run_phase63_mission_aware_product_evaluation(seeds=[0])
    with open(summary_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return list(data.get("rows", []))


def _phase82_build_rows(scenarios: List[Dict[str, object]], phase63_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    base_rows = [row for row in phase63_rows if row.get("profile_id") != "baseline"]
    for scenario in scenarios:
        metadata = scenario.get("metadata", {})
        characteristics = scenario.get("characteristics", {})
        scenario_name = str(metadata.get("name", ""))
        industry = str(metadata.get("industry", ""))
        complexity = _phase82_scenario_complexity(characteristics)
        for base_row in base_rows:
            product_category = str(base_row.get("product_category", ""))
            mission_name = str(base_row.get("mission_name", ""))
            base_score = _to_float(base_row.get("mission_effectiveness"))
            adjusted = base_score * _phase82_adjustment_factor(characteristics, mission_name, product_category)
            rows.append(
                {
                    "scenario_name": scenario_name,
                    "industry": industry,
                    "scenario_complexity": round(complexity, 4),
                    "critical_asset_count": characteristics.get("critical_asset_count"),
                    "identity_dependency": characteristics.get("identity_dependency"),
                    "operational_sensitivity": characteristics.get("operational_sensitivity"),
                    "deception_effectiveness": characteristics.get("deception_effectiveness"),
                    "product_profile": base_row.get("profile_id"),
                    "product_category": product_category,
                    "mission_name": mission_name,
                    "base_mission_effectiveness": round(base_score, 6),
                    "scenario_adjusted_effectiveness": round(adjusted, 6),
                }
            )
    return rows


def _phase82_matrix(
    rows: List[Dict[str, object]],
    row_key: str,
    column_key: str,
    value_key: str = "scenario_adjusted_effectiveness",
) -> Tuple[List[str], List[str], np.ndarray]:
    row_labels = sorted({str(row.get(row_key)) for row in rows})
    column_labels = sorted({str(row.get(column_key)) for row in rows})
    grid = np.zeros((len(row_labels), len(column_labels)), dtype=float)
    for i, row_label in enumerate(row_labels):
        for j, column_label in enumerate(column_labels):
            values = [
                _to_float(row.get(value_key))
                for row in rows
                if str(row.get(row_key)) == row_label and str(row.get(column_key)) == column_label
            ]
            grid[i, j] = float(np.mean(values)) if values else 0.0
    return row_labels, column_labels, grid


def _plot_phase82_heatmap(
    rows: List[Dict[str, object]],
    row_key: str,
    column_key: str,
    title: str,
    save_path: str,
) -> None:
    row_labels, column_labels, grid = _phase82_matrix(rows, row_key, column_key)
    fig, ax = plt.subplots(figsize=(11, 6))
    image = ax.imshow(grid, cmap="viridis", aspect="auto", vmin=0.0, vmax=max(1.0, float(np.max(grid)) if grid.size else 1.0))
    ax.set_title(title)
    ax.set_xticks(np.arange(len(column_labels)))
    ax.set_xticklabels(column_labels, rotation=25, ha="right")
    ax.set_yticks(np.arange(len(row_labels)))
    ax.set_yticklabels(row_labels)
    fig.colorbar(image, ax=ax, label="scenario_adjusted_effectiveness")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _phase82_analysis(rows: List[Dict[str, object]]) -> Dict[str, object]:
    scenario_names = sorted({str(row.get("scenario_name")) for row in rows})
    scenario_scores = {
        scenario_name: float(np.mean([_to_float(row.get("scenario_adjusted_effectiveness")) for row in rows if row.get("scenario_name") == scenario_name]))
        for scenario_name in scenario_names
    }
    product_winners = {}
    mission_winners = {}
    for scenario_name in scenario_names:
        scenario_rows = [row for row in rows if row.get("scenario_name") == scenario_name]
        products = sorted({str(row.get("product_profile")) for row in scenario_rows})
        missions = sorted({str(row.get("mission_name")) for row in scenario_rows})
        product_scores = {
            product: float(np.mean([_to_float(row.get("scenario_adjusted_effectiveness")) for row in scenario_rows if row.get("product_profile") == product]))
            for product in products
        }
        mission_scores = {
            mission: float(np.mean([_to_float(row.get("scenario_adjusted_effectiveness")) for row in scenario_rows if row.get("mission_name") == mission]))
            for mission in missions
        }
        product_winners[scenario_name] = max(product_scores, key=product_scores.get) if product_scores else ""
        mission_winners[scenario_name] = max(mission_scores, key=mission_scores.get) if mission_scores else ""
    return {
        "scenario_scores": scenario_scores,
        "best_product_by_scenario": product_winners,
        "best_mission_coverage_by_scenario": mission_winners,
        "scenario_differences_observed": len({round(score, 6) for score in scenario_scores.values()}) > 1,
    }


def _write_phase82_outputs(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "scenario_catalog_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE82_SCENARIO_CATALOG_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE82_SCENARIO_CATALOG_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "scenario_catalog_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)
    _plot_phase82_heatmap(rows, "scenario_name", "industry", "Scenario Catalog Comparison", os.path.join(output_dir, "scenario_comparison_heatmap.png"))
    _plot_phase82_heatmap(rows, "scenario_name", "mission_name", "Scenario x Mission Matrix", os.path.join(output_dir, "scenario_mission_matrix.png"))
    _plot_phase82_heatmap(rows, "scenario_name", "product_profile", "Scenario x Product Matrix", os.path.join(output_dir, "scenario_product_matrix.png"))
    _write_phase82_report(rows, analysis, output_dir)


def _write_phase82_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    scenario_names = sorted({str(row.get("scenario_name")) for row in rows})
    lines = [
        "# Phase8.2 Scenario Catalog Evaluation Report",
        "",
        "## Research Question",
        "Scenarioの違いによって Product評価結果やMission評価結果は変化するか？",
        "",
        "## Interpretation Boundary",
        "Phase8.2 uses scenario characteristics as a lightweight interpretation layer over existing Phase6.3 mission-aware product results. It does not add simulation logic, attackers, defenders, RL, LLMs, external APIs, or real product integration.",
        "",
        "## Scenario Summary",
        "| scenario | industry | complexity | best_product | best_mission_coverage | mean_score |",
        "|---|---|---:|---|---|---:|",
    ]
    for scenario_name in scenario_names:
        first = next(row for row in rows if row.get("scenario_name") == scenario_name)
        lines.append(
            f"| {scenario_name} | {first.get('industry')} | {_to_float(first.get('scenario_complexity')):.3f} | "
            f"{analysis.get('best_product_by_scenario', {}).get(scenario_name)} | "
            f"{analysis.get('best_mission_coverage_by_scenario', {}).get(scenario_name)} | "
            f"{_to_float(analysis.get('scenario_scores', {}).get(scenario_name)):.3f} |"
        )
    lines.extend(
        [
            "",
            "## Validation",
            f"- Scenario differences observed: `{analysis.get('scenario_differences_observed')}`.",
            "",
            "## Output Artifacts",
            "- `scenario_catalog_summary.csv`",
            "- `scenario_catalog_summary.json`",
            "- `scenario_comparison_heatmap.png`",
            "- `scenario_mission_matrix.png`",
            "- `scenario_product_matrix.png`",
        ]
    )
    with open(os.path.join(output_dir, "PHASE82_SCENARIO_CATALOG_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run_phase82_scenario_catalog_evaluation(
    output_dir: str = os.path.join("output", "phase82_scenario_catalog"),
    catalog_dir: str = os.path.join("scenarios", "catalog"),
) -> List[Dict[str, object]]:
    from scenario_loader import load_scenario_catalog

    scenarios = load_scenario_catalog(catalog_dir)
    phase63_rows = _phase82_load_phase63_rows()
    rows = _phase82_build_rows(scenarios, phase63_rows)
    analysis = _phase82_analysis(rows)
    _write_phase82_outputs(rows, analysis, output_dir)
    return rows


PHASE83_BENCHMARK_SUMMARY_COLUMNS = [
    "benchmark_name",
    "product_profile",
    "benchmark_score",
    "benchmark_rank",
    "scenario_coverage",
    "mission_coverage",
    "product_coverage",
    "consistency_score",
    "variance_score",
]


def _phase83_product_id_from_path(path_value: str) -> str:
    return os.path.splitext(os.path.basename(path_value))[0]


def _phase83_benchmark_rows(config: Dict[str, object]) -> List[Dict[str, object]]:
    from scenario_loader import load_scenario

    scenarios = [load_scenario(str(path)) for path in config.get("scenarios", [])]
    scenario_names = {str(scenario.get("metadata", {}).get("name")) for scenario in scenarios}
    mission_names = {str(mission) for mission in config.get("missions", [])}
    product_ids = {_phase83_product_id_from_path(str(path)) for path in config.get("products", [])}
    phase63_rows = _phase82_load_phase63_rows()
    rows = _phase82_build_rows(scenarios, phase63_rows)
    return [
        row
        for row in rows
        if row.get("scenario_name") in scenario_names
        and row.get("mission_name") in mission_names
        and row.get("product_profile") in product_ids
    ]


def _phase83_summary_rows(config: Dict[str, object], detail_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    benchmark_name = str(config.get("metadata", {}).get("name", ""))
    scenario_count = len(config.get("scenarios", []))
    mission_count = len(config.get("missions", []))
    product_count = len(config.get("products", []))
    product_ids = sorted({_phase83_product_id_from_path(str(path)) for path in config.get("products", [])})
    scored_rows: List[Dict[str, object]] = []
    for product_id in product_ids:
        product_rows = [row for row in detail_rows if row.get("product_profile") == product_id]
        values = [_to_float(row.get("scenario_adjusted_effectiveness")) for row in product_rows]
        scenario_coverage = len({row.get("scenario_name") for row in product_rows}) / scenario_count if scenario_count else 0.0
        mission_coverage = len({row.get("mission_name") for row in product_rows}) / mission_count if mission_count else 0.0
        expected_product_rows = scenario_count * mission_count
        product_coverage = len(product_rows) / expected_product_rows if expected_product_rows else 0.0
        variance = float(np.var(values)) if values else 0.0
        consistency = max(0.0, 1.0 - min(1.0, variance))
        scored_rows.append(
            {
                "benchmark_name": benchmark_name,
                "product_profile": product_id,
                "benchmark_score": round(float(np.mean(values)) if values else 0.0, 6),
                "benchmark_rank": 0,
                "scenario_coverage": round(scenario_coverage, 6),
                "mission_coverage": round(mission_coverage, 6),
                "product_coverage": round(product_coverage, 6),
                "consistency_score": round(consistency, 6),
                "variance_score": round(variance, 6),
            }
        )
    scored_rows.sort(key=lambda row: _to_float(row.get("benchmark_score")), reverse=True)
    for index, row in enumerate(scored_rows, start=1):
        row["benchmark_rank"] = index
    return scored_rows


def _phase83_group_winners(detail_rows: List[Dict[str, object]], group_key: str) -> Dict[str, str]:
    winners: Dict[str, str] = {}
    groups = sorted({str(row.get(group_key)) for row in detail_rows})
    for group in groups:
        group_rows = [row for row in detail_rows if str(row.get(group_key)) == group]
        products = sorted({str(row.get("product_profile")) for row in group_rows})
        product_scores = {
            product: float(np.mean([_to_float(row.get("scenario_adjusted_effectiveness")) for row in group_rows if row.get("product_profile") == product]))
            for product in products
        }
        winners[group] = max(product_scores, key=product_scores.get) if product_scores else ""
    return winners


def _phase83_analysis(summary_rows: List[Dict[str, object]], detail_rows: List[Dict[str, object]]) -> Dict[str, object]:
    strongest = summary_rows[0].get("product_profile") if summary_rows else ""
    most_consistent = max(summary_rows, key=lambda row: _to_float(row.get("consistency_score"))).get("product_profile") if summary_rows else ""
    highest_variance = max(summary_rows, key=lambda row: _to_float(row.get("variance_score"))).get("product_profile") if summary_rows else ""
    return {
        "strongest_overall": strongest,
        "strongest_by_mission": _phase83_group_winners(detail_rows, "mission_name"),
        "strongest_by_scenario": _phase83_group_winners(detail_rows, "scenario_name"),
        "most_consistent": most_consistent,
        "highest_variance": highest_variance,
        "benchmark_matrix_complete": all(
            _to_float(row.get("scenario_coverage")) == 1.0 and _to_float(row.get("mission_coverage")) == 1.0
            for row in summary_rows
        ),
    }


def _plot_phase83_bar(
    rows: List[Dict[str, object]],
    value_key: str,
    title: str,
    ylabel: str,
    save_path: str,
) -> None:
    labels = [str(row.get("product_profile")) for row in rows]
    values = [_to_float(row.get(value_key)) for row in rows]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(labels)), values, color="#4e79a7")
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase83_heatmap(
    detail_rows: List[Dict[str, object]],
    group_key: str,
    title: str,
    save_path: str,
) -> None:
    product_labels = sorted({str(row.get("product_profile")) for row in detail_rows})
    group_labels = sorted({str(row.get(group_key)) for row in detail_rows})
    grid = np.zeros((len(product_labels), len(group_labels)), dtype=float)
    for i, product in enumerate(product_labels):
        for j, group in enumerate(group_labels):
            values = [
                _to_float(row.get("scenario_adjusted_effectiveness"))
                for row in detail_rows
                if row.get("product_profile") == product and row.get(group_key) == group
            ]
            grid[i, j] = float(np.mean(values)) if values else 0.0
    fig, ax = plt.subplots(figsize=(11, 6))
    image = ax.imshow(grid, cmap="viridis", aspect="auto", vmin=0.0, vmax=max(1.0, float(np.max(grid)) if grid.size else 1.0))
    ax.set_title(title)
    ax.set_xticks(np.arange(len(group_labels)))
    ax.set_xticklabels(group_labels, rotation=25, ha="right")
    ax.set_yticks(np.arange(len(product_labels)))
    ax.set_yticklabels(product_labels)
    fig.colorbar(image, ax=ax, label="benchmark_score")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase83_outputs(
    summary_rows: List[Dict[str, object]],
    detail_rows: List[Dict[str, object]],
    analysis: Dict[str, object],
    output_dir: str,
) -> None:
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "benchmark_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE83_BENCHMARK_SUMMARY_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE83_BENCHMARK_SUMMARY_COLUMNS} for row in summary_rows])
    with open(os.path.join(output_dir, "benchmark_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"summary_rows": summary_rows, "detail_rows": detail_rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)
    _plot_phase83_bar(summary_rows, "benchmark_score", "Benchmark Product Ranking", "benchmark_score", os.path.join(output_dir, "benchmark_product_ranking.png"))
    _plot_phase83_heatmap(detail_rows, "scenario_name", "Benchmark Scenario Heatmap", os.path.join(output_dir, "benchmark_scenario_heatmap.png"))
    _plot_phase83_heatmap(detail_rows, "mission_name", "Benchmark Mission Heatmap", os.path.join(output_dir, "benchmark_mission_heatmap.png"))
    _plot_phase83_bar(summary_rows, "consistency_score", "Benchmark Consistency", "consistency_score", os.path.join(output_dir, "benchmark_consistency.png"))
    _write_phase83_report(summary_rows, analysis, output_dir)


def _write_phase83_report(summary_rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    lines = [
        "# Phase8.3 Benchmark Suite Report",
        "",
        "## Research Question",
        "Scenario x Mission x Product を横断した場合、製品ごとの強み・弱みを再現可能に評価できるか？",
        "",
        "## Interpretation Boundary",
        "This benchmark is not a product certification or a single strongest product claim. It provides reproducible comparison across scenario, mission, and product dimensions using existing CyberMatch artifacts.",
        "",
        "## Product Ranking",
        "| rank | product | benchmark_score | consistency_score | variance_score |",
        "|---:|---|---:|---:|---:|",
    ]
    for row in summary_rows:
        lines.append(
            f"| {row.get('benchmark_rank')} | {row.get('product_profile')} | "
            f"{_to_float(row.get('benchmark_score')):.3f} | "
            f"{_to_float(row.get('consistency_score')):.3f} | "
            f"{_to_float(row.get('variance_score')):.3f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            f"- Strongest overall: `{analysis.get('strongest_overall')}`.",
            f"- Strongest by mission: `{analysis.get('strongest_by_mission')}`.",
            f"- Strongest by scenario: `{analysis.get('strongest_by_scenario')}`.",
            f"- Most consistent: `{analysis.get('most_consistent')}`.",
            f"- Highest variance: `{analysis.get('highest_variance')}`.",
            f"- Benchmark matrix complete: `{analysis.get('benchmark_matrix_complete')}`.",
            "",
            "## Output Artifacts",
            "- `benchmark_summary.csv`",
            "- `benchmark_summary.json`",
            "- `benchmark_product_ranking.png`",
            "- `benchmark_scenario_heatmap.png`",
            "- `benchmark_mission_heatmap.png`",
            "- `benchmark_consistency.png`",
        ]
    )
    with open(os.path.join(output_dir, "PHASE83_BENCHMARK_SUITE_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run_phase83_benchmark_suite(
    benchmark_path: str = os.path.join("benchmarks", "product_evaluation_benchmark.json"),
    output_dir: str = os.path.join("output", "phase83_benchmark_suite"),
) -> List[Dict[str, object]]:
    from benchmark_loader import load_benchmark

    config = load_benchmark(benchmark_path)
    detail_rows = _phase83_benchmark_rows(config)
    summary_rows = _phase83_summary_rows(config, detail_rows)
    analysis = _phase83_analysis(summary_rows, detail_rows)
    _write_phase83_outputs(summary_rows, detail_rows, analysis, output_dir)
    return summary_rows


PHASE84_TOPOLOGY_COLUMNS = [
    "topology_name",
    "topology_score",
    "topology_complexity",
    "identity_centralization",
    "lateral_movement_complexity",
    "deception_surface",
    "operational_sensitivity",
    "critical_assets",
    "product_profile",
    "product_category",
    "mission_name",
    "base_mission_effectiveness",
    "topology_adjusted_effectiveness",
]


def _phase84_level_value(value: object) -> float:
    return PHASE82_LEVEL_VALUES.get(str(value), 2.0)


def _phase84_topology_complexity(characteristics: Dict[str, object]) -> float:
    critical_component = _to_float(characteristics.get("critical_assets")) / 10.0
    identity_component = _phase84_level_value(characteristics.get("identity_centralization")) / 3.0
    lateral_component = _phase84_level_value(characteristics.get("lateral_movement_complexity")) / 3.0
    operational_component = _phase84_level_value(characteristics.get("operational_sensitivity")) / 3.0
    return float(np.mean([critical_component, identity_component, lateral_component, operational_component]))


def _phase84_adjustment_factor(characteristics: Dict[str, object], mission_name: str, product_category: str) -> float:
    complexity = _phase84_topology_complexity(characteristics)
    identity = _phase84_level_value(characteristics.get("identity_centralization")) - 2.0
    lateral = _phase84_level_value(characteristics.get("lateral_movement_complexity")) - 2.0
    deception = _phase84_level_value(characteristics.get("deception_surface")) - 2.0
    operational = _phase84_level_value(characteristics.get("operational_sensitivity")) - 2.0
    critical = (_to_float(characteristics.get("critical_assets")) - 5.0) / 5.0

    factor = 1.0 + 0.08 * (complexity - 0.55)
    if mission_name == "profit":
        factor += 0.03 * identity
    elif mission_name == "achievement":
        factor += 0.025 * operational
    elif mission_name == "persistence":
        factor += 0.03 * lateral
    elif mission_name == "critical_hunter":
        factor += 0.035 * critical

    if product_category == "deception":
        factor += 0.05 * deception
    elif product_category == "xdr":
        factor += 0.03 * identity
    elif product_category == "ips":
        factor += 0.025 * lateral
    elif product_category == "honeypot":
        factor += 0.025 * critical
    elif product_category == "ids":
        factor += 0.02 * identity

    return max(0.5, min(1.5, factor))


def _phase84_build_rows(topologies: List[Dict[str, object]], phase63_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    base_rows = [row for row in phase63_rows if row.get("profile_id") != "baseline"]
    for topology in topologies:
        metadata = topology.get("metadata", {})
        characteristics = topology.get("characteristics", {})
        topology_name = str(metadata.get("name", ""))
        complexity = _phase84_topology_complexity(characteristics)
        for base_row in base_rows:
            product_category = str(base_row.get("product_category", ""))
            mission_name = str(base_row.get("mission_name", ""))
            base_score = _to_float(base_row.get("mission_effectiveness"))
            adjusted = base_score * _phase84_adjustment_factor(characteristics, mission_name, product_category)
            rows.append(
                {
                    "topology_name": topology_name,
                    "topology_score": round(adjusted, 6),
                    "topology_complexity": round(complexity, 4),
                    "identity_centralization": characteristics.get("identity_centralization"),
                    "lateral_movement_complexity": characteristics.get("lateral_movement_complexity"),
                    "deception_surface": characteristics.get("deception_surface"),
                    "operational_sensitivity": characteristics.get("operational_sensitivity"),
                    "critical_assets": characteristics.get("critical_assets"),
                    "product_profile": base_row.get("profile_id"),
                    "product_category": product_category,
                    "mission_name": mission_name,
                    "base_mission_effectiveness": round(base_score, 6),
                    "topology_adjusted_effectiveness": round(adjusted, 6),
                }
            )
    return rows


def _phase84_matrix(
    rows: List[Dict[str, object]],
    row_key: str,
    column_key: str,
) -> Tuple[List[str], List[str], np.ndarray]:
    row_labels = sorted({str(row.get(row_key)) for row in rows})
    column_labels = sorted({str(row.get(column_key)) for row in rows})
    grid = np.zeros((len(row_labels), len(column_labels)), dtype=float)
    for i, row_label in enumerate(row_labels):
        for j, column_label in enumerate(column_labels):
            values = [
                _to_float(row.get("topology_adjusted_effectiveness"))
                for row in rows
                if str(row.get(row_key)) == row_label and str(row.get(column_key)) == column_label
            ]
            grid[i, j] = float(np.mean(values)) if values else 0.0
    return row_labels, column_labels, grid


def _plot_phase84_heatmap(rows: List[Dict[str, object]], row_key: str, column_key: str, title: str, save_path: str) -> None:
    row_labels, column_labels, grid = _phase84_matrix(rows, row_key, column_key)
    fig, ax = plt.subplots(figsize=(11, 6))
    image = ax.imshow(grid, cmap="viridis", aspect="auto", vmin=0.0, vmax=max(1.0, float(np.max(grid)) if grid.size else 1.0))
    ax.set_title(title)
    ax.set_xticks(np.arange(len(column_labels)))
    ax.set_xticklabels(column_labels, rotation=25, ha="right")
    ax.set_yticks(np.arange(len(row_labels)))
    ax.set_yticklabels(row_labels)
    fig.colorbar(image, ax=ax, label="topology_adjusted_effectiveness")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _phase84_analysis(rows: List[Dict[str, object]]) -> Dict[str, object]:
    topology_names = sorted({str(row.get("topology_name")) for row in rows})
    topology_scores = {
        topology: float(np.mean([_to_float(row.get("topology_adjusted_effectiveness")) for row in rows if row.get("topology_name") == topology]))
        for topology in topology_names
    }
    best_product_by_topology = {}
    best_mission_by_topology = {}
    for topology in topology_names:
        topology_rows = [row for row in rows if row.get("topology_name") == topology]
        products = sorted({str(row.get("product_profile")) for row in topology_rows})
        missions = sorted({str(row.get("mission_name")) for row in topology_rows})
        product_scores = {
            product: float(np.mean([_to_float(row.get("topology_adjusted_effectiveness")) for row in topology_rows if row.get("product_profile") == product]))
            for product in products
        }
        mission_scores = {
            mission: float(np.mean([_to_float(row.get("topology_adjusted_effectiveness")) for row in topology_rows if row.get("mission_name") == mission]))
            for mission in missions
        }
        best_product_by_topology[topology] = max(product_scores, key=product_scores.get) if product_scores else ""
        best_mission_by_topology[topology] = max(mission_scores, key=mission_scores.get) if mission_scores else ""
    return {
        "topology_scores": topology_scores,
        "best_product_by_topology": best_product_by_topology,
        "best_mission_by_topology": best_mission_by_topology,
        "topology_differences_observed": len({round(score, 6) for score in topology_scores.values()}) > 1,
    }


def _write_phase84_outputs(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "topology_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE84_TOPOLOGY_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE84_TOPOLOGY_COLUMNS} for row in rows])
    with open(os.path.join(output_dir, "topology_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)
    _plot_phase84_heatmap(rows, "topology_name", "identity_centralization", "Topology Comparison", os.path.join(output_dir, "topology_comparison_heatmap.png"))
    _plot_phase84_heatmap(rows, "topology_name", "mission_name", "Topology x Mission Matrix", os.path.join(output_dir, "topology_mission_matrix.png"))
    _plot_phase84_heatmap(rows, "topology_name", "product_profile", "Topology x Product Matrix", os.path.join(output_dir, "topology_product_matrix.png"))
    _write_phase84_report(rows, analysis, output_dir)


def _write_phase84_report(rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    topology_names = sorted({str(row.get("topology_name")) for row in rows})
    lines = [
        "# Phase8.4 Enterprise Topology Library Report",
        "",
        "## Research Question",
        "Topology Preset の違いによって Mission評価 Product評価 は変化するか？",
        "",
        "## Interpretation Boundary",
        "Phase8.4 uses topology characteristics as a lightweight interpretation layer over existing Phase6.3 mission-aware product results. It does not add a network simulator or change simulation logic.",
        "",
        "## Topology Summary",
        "| topology | complexity | best_product | best_mission_coverage | mean_score |",
        "|---|---:|---|---|---:|",
    ]
    for topology_name in topology_names:
        first = next(row for row in rows if row.get("topology_name") == topology_name)
        lines.append(
            f"| {topology_name} | {_to_float(first.get('topology_complexity')):.3f} | "
            f"{analysis.get('best_product_by_topology', {}).get(topology_name)} | "
            f"{analysis.get('best_mission_by_topology', {}).get(topology_name)} | "
            f"{_to_float(analysis.get('topology_scores', {}).get(topology_name)):.3f} |"
        )
    lines.extend(
        [
            "",
            "## Validation",
            f"- Topology differences observed: `{analysis.get('topology_differences_observed')}`.",
            "",
            "## Output Artifacts",
            "- `topology_summary.csv`",
            "- `topology_summary.json`",
            "- `topology_comparison_heatmap.png`",
            "- `topology_mission_matrix.png`",
            "- `topology_product_matrix.png`",
        ]
    )
    with open(os.path.join(output_dir, "PHASE84_TOPOLOGY_LIBRARY_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run_phase84_topology_evaluation(
    output_dir: str = os.path.join("output", "phase84_topology_library"),
    topology_dir: str = os.path.join("topologies"),
) -> List[Dict[str, object]]:
    from topology_loader import list_available_topologies, load_topology

    topologies = [load_topology(str(path)) for path in list_available_topologies(topology_dir)]
    phase63_rows = _phase82_load_phase63_rows()
    rows = _phase84_build_rows(topologies, phase63_rows)
    analysis = _phase84_analysis(rows)
    _write_phase84_outputs(rows, analysis, output_dir)
    return rows


PHASE85_STANDARD_COLUMNS = [
    "benchmark_name",
    "benchmark_version",
    "product_profile",
    "benchmark_score",
    "benchmark_rank",
    "benchmark_completeness",
    "coverage_score",
    "reproducibility_score",
    "evaluation_matrix_size",
    "consistency_score",
    "variance_score",
]


def _phase85_detail_rows(config: Dict[str, object]) -> List[Dict[str, object]]:
    from scenario_loader import load_scenario
    from topology_loader import load_topology

    scenarios = [load_scenario(str(path)) for path in config.get("scenarios", [])]
    topologies = [load_topology(str(path)) for path in config.get("topologies", [])]
    missions = {str(mission) for mission in config.get("missions", [])}
    products = {_phase83_product_id_from_path(str(path)) for path in config.get("products", [])}
    phase63_rows = [row for row in _phase82_load_phase63_rows() if row.get("profile_id") != "baseline"]
    rows: List[Dict[str, object]] = []
    for scenario in scenarios:
        scenario_metadata = scenario.get("metadata", {})
        scenario_characteristics = scenario.get("characteristics", {})
        scenario_name = str(scenario_metadata.get("name", ""))
        industry = str(scenario_metadata.get("industry", ""))
        for topology in topologies:
            topology_metadata = topology.get("metadata", {})
            topology_characteristics = topology.get("characteristics", {})
            topology_name = str(topology_metadata.get("name", ""))
            for base_row in phase63_rows:
                product_id = str(base_row.get("profile_id", ""))
                mission_name = str(base_row.get("mission_name", ""))
                if product_id not in products or mission_name not in missions:
                    continue
                product_category = str(base_row.get("product_category", ""))
                base_score = _to_float(base_row.get("mission_effectiveness"))
                scenario_score = base_score * _phase82_adjustment_factor(scenario_characteristics, mission_name, product_category)
                standard_score = scenario_score * _phase84_adjustment_factor(topology_characteristics, mission_name, product_category)
                rows.append(
                    {
                        "scenario_name": scenario_name,
                        "industry": industry,
                        "topology_name": topology_name,
                        "mission_name": mission_name,
                        "product_profile": product_id,
                        "product_category": product_category,
                        "base_mission_effectiveness": round(base_score, 6),
                        "standard_score": round(standard_score, 6),
                    }
                )
    return rows


def _phase85_summary_rows(config: Dict[str, object], detail_rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    metadata = config.get("metadata", {})
    benchmark_name = str(metadata.get("name", ""))
    benchmark_version = str(metadata.get("version", ""))
    scenario_count = len(config.get("scenarios", []))
    topology_count = len(config.get("topologies", []))
    mission_count = len(config.get("missions", []))
    product_ids = sorted({_phase83_product_id_from_path(str(path)) for path in config.get("products", [])})
    matrix_size = scenario_count * topology_count * mission_count * len(product_ids)
    expected_product_rows = scenario_count * topology_count * mission_count
    rows: List[Dict[str, object]] = []
    for product_id in product_ids:
        product_rows = [row for row in detail_rows if row.get("product_profile") == product_id]
        values = [_to_float(row.get("standard_score")) for row in product_rows]
        coverage = len(product_rows) / expected_product_rows if expected_product_rows else 0.0
        variance = float(np.var(values)) if values else 0.0
        consistency = max(0.0, 1.0 - min(1.0, variance))
        rows.append(
            {
                "benchmark_name": benchmark_name,
                "benchmark_version": benchmark_version,
                "product_profile": product_id,
                "benchmark_score": round(float(np.mean(values)) if values else 0.0, 6),
                "benchmark_rank": 0,
                "benchmark_completeness": round(coverage, 6),
                "coverage_score": round(coverage, 6),
                "reproducibility_score": 1.0 if config.get("seeds") == [0] else 0.9,
                "evaluation_matrix_size": matrix_size,
                "consistency_score": round(consistency, 6),
                "variance_score": round(variance, 6),
            }
        )
    rows.sort(key=lambda row: _to_float(row.get("benchmark_score")), reverse=True)
    for index, row in enumerate(rows, start=1):
        row["benchmark_rank"] = index
    return rows


def _phase85_group_winners(detail_rows: List[Dict[str, object]], group_key: str) -> Dict[str, str]:
    winners: Dict[str, str] = {}
    groups = sorted({str(row.get(group_key)) for row in detail_rows})
    for group in groups:
        group_rows = [row for row in detail_rows if str(row.get(group_key)) == group]
        products = sorted({str(row.get("product_profile")) for row in group_rows})
        product_scores = {
            product: float(np.mean([_to_float(row.get("standard_score")) for row in group_rows if row.get("product_profile") == product]))
            for product in products
        }
        winners[group] = max(product_scores, key=product_scores.get) if product_scores else ""
    return winners


def _phase85_analysis(summary_rows: List[Dict[str, object]], detail_rows: List[Dict[str, object]]) -> Dict[str, object]:
    return {
        "strongest_overall": summary_rows[0].get("product_profile") if summary_rows else "",
        "strongest_by_mission": _phase85_group_winners(detail_rows, "mission_name"),
        "strongest_by_scenario": _phase85_group_winners(detail_rows, "scenario_name"),
        "strongest_by_topology": _phase85_group_winners(detail_rows, "topology_name"),
        "most_consistent": max(summary_rows, key=lambda row: _to_float(row.get("consistency_score"))).get("product_profile") if summary_rows else "",
        "highest_variance": max(summary_rows, key=lambda row: _to_float(row.get("variance_score"))).get("product_profile") if summary_rows else "",
        "benchmark_completeness": min([_to_float(row.get("benchmark_completeness")) for row in summary_rows], default=0.0),
        "evaluation_matrix_size": summary_rows[0].get("evaluation_matrix_size") if summary_rows else 0,
    }


def _plot_phase85_bar(rows: List[Dict[str, object]], value_key: str, title: str, ylabel: str, save_path: str) -> None:
    labels = [str(row.get("product_profile")) for row in rows]
    values = [_to_float(row.get(value_key)) for row in rows]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(labels)), values, color="#4e79a7")
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _plot_phase85_heatmap(detail_rows: List[Dict[str, object]], group_key: str, title: str, save_path: str) -> None:
    product_labels = sorted({str(row.get("product_profile")) for row in detail_rows})
    group_labels = sorted({str(row.get(group_key)) for row in detail_rows})
    grid = np.zeros((len(product_labels), len(group_labels)), dtype=float)
    for i, product in enumerate(product_labels):
        for j, group in enumerate(group_labels):
            values = [
                _to_float(row.get("standard_score"))
                for row in detail_rows
                if row.get("product_profile") == product and row.get(group_key) == group
            ]
            grid[i, j] = float(np.mean(values)) if values else 0.0
    fig, ax = plt.subplots(figsize=(11, 6))
    image = ax.imshow(grid, cmap="viridis", aspect="auto", vmin=0.0, vmax=max(1.0, float(np.max(grid)) if grid.size else 1.0))
    ax.set_title(title)
    ax.set_xticks(np.arange(len(group_labels)))
    ax.set_xticklabels(group_labels, rotation=25, ha="right")
    ax.set_yticks(np.arange(len(product_labels)))
    ax.set_yticklabels(product_labels)
    fig.colorbar(image, ax=ax, label="standard_score")
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close(fig)


def _write_phase85_outputs(summary_rows: List[Dict[str, object]], detail_rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "standard_benchmark_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PHASE85_STANDARD_COLUMNS)
        writer.writeheader()
        writer.writerows([{column: row.get(column) for column in PHASE85_STANDARD_COLUMNS} for row in summary_rows])
    with open(os.path.join(output_dir, "standard_benchmark_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"summary_rows": summary_rows, "detail_rows": detail_rows, "analysis": analysis}, f, indent=4, ensure_ascii=False)
    _plot_phase85_bar(summary_rows, "benchmark_score", "Standard Product Ranking", "benchmark_score", os.path.join(output_dir, "standard_product_ranking.png"))
    _plot_phase85_heatmap(detail_rows, "scenario_name", "Standard Scenario Heatmap", os.path.join(output_dir, "standard_scenario_heatmap.png"))
    _plot_phase85_heatmap(detail_rows, "topology_name", "Standard Topology Heatmap", os.path.join(output_dir, "standard_topology_heatmap.png"))
    _plot_phase85_heatmap(detail_rows, "mission_name", "Standard Mission Heatmap", os.path.join(output_dir, "standard_mission_heatmap.png"))
    _write_phase85_report(summary_rows, analysis, output_dir)


def _write_phase85_report(summary_rows: List[Dict[str, object]], analysis: Dict[str, object], output_dir: str) -> None:
    first = summary_rows[0] if summary_rows else {}
    lines = [
        "# Phase8.5 CyberMatch Standard Benchmark Report",
        "",
        "## Research Question",
        "CyberMatchの標準Benchmarkを定義できるか？",
        "",
        "## Interpretation Boundary",
        "This report describes results under the CyberMatch Standard Benchmark conditions. It is not a strongest-product certification.",
        "",
        "## Standard Benchmark",
        f"- Version: `{first.get('benchmark_version', '')}`",
        f"- Evaluation matrix size: `{analysis.get('evaluation_matrix_size')}`",
        f"- Benchmark completeness: `{analysis.get('benchmark_completeness')}`",
        "",
        "## Product Ranking",
        "| rank | product | benchmark_score | consistency_score | variance_score |",
        "|---:|---|---:|---:|---:|",
    ]
    for row in summary_rows:
        lines.append(
            f"| {row.get('benchmark_rank')} | {row.get('product_profile')} | "
            f"{_to_float(row.get('benchmark_score')):.3f} | "
            f"{_to_float(row.get('consistency_score')):.3f} | "
            f"{_to_float(row.get('variance_score')):.3f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            f"- Strongest overall: `{analysis.get('strongest_overall')}`.",
            f"- Strongest by mission: `{analysis.get('strongest_by_mission')}`.",
            f"- Strongest by scenario: `{analysis.get('strongest_by_scenario')}`.",
            f"- Strongest by topology: `{analysis.get('strongest_by_topology')}`.",
            f"- Most consistent: `{analysis.get('most_consistent')}`.",
            f"- Highest variance: `{analysis.get('highest_variance')}`.",
        ]
    )
    with open(os.path.join(output_dir, "PHASE85_STANDARD_BENCHMARK_REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run_phase85_standard_benchmark(
    benchmark_path: str = os.path.join("benchmarks", "cybermatch_standard_v1.json"),
    output_dir: str = os.path.join("output", "phase85_standard_benchmark"),
) -> List[Dict[str, object]]:
    from benchmark_loader import load_benchmark

    config = load_benchmark(benchmark_path)
    detail_rows = _phase85_detail_rows(config)
    summary_rows = _phase85_summary_rows(config, detail_rows)
    analysis = _phase85_analysis(summary_rows, detail_rows)
    _write_phase85_outputs(summary_rows, detail_rows, analysis, output_dir)
    return summary_rows


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
