import numpy as np
import cvxpy as cp
import matplotlib.pyplot as plt
import logging
import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

# ロギング設定
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class SimulationConfig:
    """シミュレーションのパラメータを管理するデータクラス"""
    # システム規模
    n_nodes: int = 5
    m_resources: int = 3
    
    # 制御パラメータ
    T: int = 50
    H: int = 5
    
    # システムダイナミクス
    alpha: float = 0.8
    beta: float = 0.3
    d_base: np.ndarray = field(default_factory=lambda: np.array([1.0, 0.5, 0.2, 0.8, 0.3]))
    
    # コスト重み
    Q_diag: np.ndarray = field(default_factory=lambda: np.array([10.0, 5.0, 1.0, 8.0, 2.0]))
    R_diag: np.ndarray = field(default_factory=lambda: np.array([1.0, 1.0, 1.0]))
    lambda_w: float = 0.5
    rho: float = 100.0

    # 資産価値と攻撃者の主観価値
    asset_value: np.ndarray = field(default_factory=lambda: np.array([10.0, 5.0, 1.0, 8.0, 2.0]))
    attacker_belief: np.ndarray = field(default_factory=lambda: np.array([10.0, 5.0, 1.0, 8.0, 2.0]))

    # 最小Decoy設定
    node_type: List[str] = field(default_factory=lambda: ["real", "real", "real", "real", "real"])
    node_layer: List[str] = field(default_factory=lambda: ["internet", "dmz", "user", "server", "critical"])
    adjacency_matrix: np.ndarray = field(default_factory=lambda: np.array([
        [0, 1, 0, 0, 0],
        [1, 0, 1, 1, 0],
        [0, 1, 0, 1, 0],
        [0, 1, 1, 0, 1],
        [0, 0, 0, 1, 0],
    ], dtype=int))
    entry_nodes: List[int] = field(default_factory=lambda: [0])
    critical_nodes: List[int] = field(default_factory=lambda: [4])
    decoy_detection_bonus: float = 3.0
    decoy_waste_cost: float = 2.0
    decoy_success_gain_scale: float = 0.0

    # 成功・検知の確率モデル
    stochastic_detection: bool = False
    stochastic_success: bool = False
    base_detection_prob: float = 0.2
    defense_detection_scale: float = 0.15
    decoy_detection_prob: float = 0.9
    base_success_prob: float = 0.8
    defense_success_decay: float = 0.3
    decoy_success_prob: float = 0.1
    
    # 制約
    r_max: float = 5.0
    R_total: float = 10.0
    resource_capacity: List[int] = field(default_factory=lambda: [2, 1, 1])
    
    # 更新設定
    matching_update_interval: int = 10
    dynamic_matching: bool = True
    dynamic_matching_threshold: float = 5.0
    dynamic_matching_delta_threshold: float = 0.0

    # 実行・出力設定
    show_plot: bool = False
    seed: Optional[int] = 42
    output_metrics: bool = True
    save_history: bool = True

    # 攻撃者モデル設定
    attacker_enabled: bool = False
    attacker_attack_budget: float = 3.0
    attacker_target_selection: str = "greedy"
    attacker_effort_cost_rate: float = 0.3
    attacker_detection_penalty: float = 1.0
    attacker_retreat_threshold: float = -2.0
    attacker_patience: int = 10
    attacker_perceived_no_progress_threshold: float = 0.0
    stop_on_attacker_retreat: bool = False
    perceived_utility_enabled: bool = False
    perceived_success_confidence: float = 1.0
    perceived_decoy_penalty: float = 1.0
    perceived_detection_penalty: float = 1.0
    perceived_uncertainty_decay: float = 0.95
    retreat_based_on: str = "actual"
    frustration_enabled: bool = False
    frustration_decoy_hit: float = 3.0
    frustration_credential_trap: float = 2.0
    frustration_detection: float = 1.0
    frustration_path_change: float = 0.5
    frustration_no_progress: float = 0.5
    frustration_decay: float = 0.95
    frustration_retreat_threshold: float = 10.0
    ai_uncertainty_weight: float = 2.0
    ai_replanning_weight: float = 0.5
    ai_search_weight: float = 1.0
    ai_operational_risk_weight: float = 1.5
    ai_trust_degradation_weight: float = 2.5
    cognitive_score_enabled: bool = True
    cognitive_weight_critical_protection: float = 0.30
    cognitive_weight_perceived_utility: float = 0.20
    cognitive_weight_confidence: float = 0.15
    cognitive_weight_human_frustration: float = 0.15
    cognitive_weight_ai_cost: float = 0.15
    cognitive_weight_retreat: float = 0.05
    cns_objective_enabled: bool = True
    cns_weight_human: float = 0.4
    cns_weight_ai: float = 0.4
    cns_weight_protection: float = 0.2
    attacker_greedy_mode: str = "utility"
    attacker_defense_cost_rate: float = 1.0
    attacker_detection_sensitivity: float = 1.0
    attacker_success_base_rate: float = 1.0
    attacker_success_defense_decay: float = 0.5
    attacker_belief_learning_enabled: bool = False
    attacker_belief_success_boost: float = 1.0
    attacker_belief_failure_decay: float = 0.8
    attacker_belief_detection_decay: float = 0.5
    attacker_belief_decoy_decay: float = 0.1
    attacker_belief_min: float = 0.0
    attacker_belief_max: float = 20.0
    adaptive_attacker_enabled: bool = False
    adaptive_success_weight: float = 1.0
    adaptive_decoy_weight: float = 2.0
    adaptive_detection_weight: float = 1.5
    adaptive_preference_enabled: bool = False
    adaptive_preference_weight: float = 2.0
    adaptive_success_reward: float = 1.0
    adaptive_critical_reward: float = 3.0
    adaptive_decoy_penalty: float = 2.0
    adaptive_detection_penalty: float = 1.5
    adaptive_path_enabled: bool = False
    path_preference_weight: float = 3.0
    path_success_reward: float = 1.0
    path_critical_reward: float = 5.0
    path_decoy_penalty: float = 2.0
    path_detection_penalty: float = 1.5
    adaptive_planning_enabled: bool = False
    planning_depth: int = 2
    planning_success_weight: float = 1.0
    planning_critical_weight: float = 5.0
    planning_decoy_penalty: float = 2.0
    planning_detection_penalty: float = 1.5
    trust_enabled: bool = False
    trust_decoy_penalty: float = 0.20
    trust_credential_penalty: float = 0.30
    trust_detection_penalty: float = 0.15
    trust_success_reward: float = 0.05
    expected_utility_enabled: bool = False
    expected_gain_weight: float = 1.0
    expected_success_weight: float = 1.0
    expected_detection_cost: float = 1.0
    expected_search_cost: float = 1.0
    expected_trust_weight: float = 1.0
    attacker_lateral_enabled: bool = False
    attacker_lateral_success_prob: float = 0.8
    attacker_lateral_detection_prob: float = 0.2
    decoy_lateral_decay: float = 0.5
    post_decoy_defense_enabled: bool = False
    post_decoy_defense_weight: float = 1.0
    post_decoy_defense_top_k: int = 2
    post_decoy_defense_exclude_decoy: bool = True
    post_decoy_defense_injection_mode: str = "matching_fallback"
    post_decoy_defense_belief_source: str = "attacker"
    defender_belief_estimation_enabled: bool = False
    defender_belief_observation_mode: str = "target_frequency"
    defender_belief_estimation_alpha: float = 0.5
    defender_belief_observation_noise: float = 0.0
    defender_belief_min: float = 0.0
    defender_belief_max: float = 20.0
    visible_log_success_boost: float = 2.0
    visible_log_detected_decay: float = 0.5
    visible_log_decoy_decay: float = 0.2
    visible_log_success_prob_weight: float = 1.0
    visible_log_detection_prob_weight: float = 0.5
    visible_log_defense_penalty_weight: float = 0.1
    defender_bayesian_update_enabled: bool = False
    defender_bayesian_prior_strength: float = 1.0
    defender_bayesian_success_likelihood: float = 2.0
    defender_bayesian_detected_likelihood: float = 0.5
    defender_bayesian_decoy_likelihood: float = 0.2
    defender_bayesian_critical_path_likelihood: float = 1.5
    defender_bayesian_decay: float = 0.98
    defense_objective_critical_weight: float = 1000.0
    defense_objective_post_decoy_weight: float = 1.0
    defense_objective_delay_reward: float = 5.0
    mtd_enabled: bool = False
    mtd_interval: int = 10
    mtd_strategy: str = "shuffle_belief"
    mtd_intensity: float = 0.5
    mtd_cost: float = 1.0
    mtd_success_decay_bonus: float = 0.2
    mtd_detection_bonus: float = 0.1
    mtd_shuffle_topology: bool = False
    mtd_block_critical_edges: bool = False
    mtd_edge_block_count: int = 1
    mtd_edge_block_duration: int = 1
    mtd_risk_gating_enabled: bool = False
    mtd_risk_gate_threshold: float = 5.0
    mtd_risk_gate_mode: str = "critical_path_risk"
    mtd_risk_gate_cooldown: int = 3
    mtd_conditional_policy_enabled: bool = False
    mtd_conditional_policy_mode: str = "edge_pressure_split"
    mtd_conditional_high_risk_threshold: float = 10.0
    mtd_conditional_low_risk_threshold: float = 5.0
    honeypot_credential_enabled: bool = False
    credential_node_ids: List[int] = field(default_factory=list)
    credential_attraction_bonus: float = 3.0
    credential_detection_bonus: float = 5.0
    credential_reuse_decay: float = 0.5
    credential_aware_mtd_enabled: bool = False
    credential_trigger_mtd_window: int = 3
    credential_trigger_block_count: int = 2
    credential_trigger_block_duration: int = 1
    credential_trigger_force_mtd: bool = True
    credential_trigger_risk_bonus: float = 5.0
    credential_staged_mtd_enabled: bool = False
    credential_stage1_window: int = 1
    credential_stage1_block_count: int = 2
    credential_stage1_block_duration: int = 1
    credential_stage2_window: int = 5
    credential_stage2_block_count: int = 1
    credential_stage2_block_duration: int = 2

    def __post_init__(self):
        self.d_base = np.asarray(self.d_base, dtype=float)
        self.Q_diag = np.asarray(self.Q_diag, dtype=float)
        self.R_diag = np.asarray(self.R_diag, dtype=float)
        self.asset_value = np.asarray(self.asset_value, dtype=float)
        self.attacker_belief = np.asarray(self.attacker_belief, dtype=float)
        self.adjacency_matrix = np.asarray(self.adjacency_matrix, dtype=int)
        self.resource_capacity = [int(v) for v in self.resource_capacity]
        self.validate()

    def validate(self) -> None:
        """設定値の整合性を検証する。"""
        errors = []

        if self.n_nodes <= 0:
            errors.append("n_nodes must be > 0")
        if self.m_resources <= 0:
            errors.append("m_resources must be > 0")
        if self.T <= 0:
            errors.append("T must be > 0")
        if self.H <= 0:
            errors.append("H must be > 0")
        if self.alpha < 0:
            errors.append("alpha must be >= 0")
        if self.beta < 0:
            errors.append("beta must be >= 0")
        if self.r_max < 0:
            errors.append("r_max must be >= 0")
        if self.R_total < 0:
            errors.append("R_total must be >= 0")
        if self.lambda_w < 0:
            errors.append("lambda_w must be >= 0")
        if self.rho < 0:
            errors.append("rho must be >= 0")
        if self.matching_update_interval <= 0:
            errors.append("matching_update_interval must be > 0")
        if self.dynamic_matching_threshold < 0:
            errors.append("dynamic_matching_threshold must be >= 0")
        if self.dynamic_matching_delta_threshold < 0:
            errors.append("dynamic_matching_delta_threshold must be >= 0")
        if self.attacker_attack_budget < 0:
            errors.append("attacker_attack_budget must be >= 0")
        if self.attacker_target_selection not in ("greedy", "random", "adaptive"):
            errors.append("attacker_target_selection must be one of: greedy, random, adaptive")
        if self.attacker_effort_cost_rate < 0:
            errors.append("attacker_effort_cost_rate must be >= 0")
        if self.attacker_detection_penalty < 0:
            errors.append("attacker_detection_penalty must be >= 0")
        if self.attacker_patience <= 0:
            errors.append("attacker_patience must be > 0")
        if self.attacker_perceived_no_progress_threshold < 0:
            errors.append("attacker_perceived_no_progress_threshold must be >= 0")
        if not 0 <= self.perceived_success_confidence <= 1:
            errors.append("perceived_success_confidence must be between 0 and 1")
        if self.perceived_decoy_penalty < 0:
            errors.append("perceived_decoy_penalty must be >= 0")
        if self.perceived_detection_penalty < 0:
            errors.append("perceived_detection_penalty must be >= 0")
        if not 0 <= self.perceived_uncertainty_decay <= 1:
            errors.append("perceived_uncertainty_decay must be between 0 and 1")
        if self.retreat_based_on not in ("actual", "perceived", "frustration"):
            errors.append("retreat_based_on must be one of: actual, perceived, frustration")
        if self.frustration_decoy_hit < 0:
            errors.append("frustration_decoy_hit must be >= 0")
        if self.frustration_credential_trap < 0:
            errors.append("frustration_credential_trap must be >= 0")
        if self.frustration_detection < 0:
            errors.append("frustration_detection must be >= 0")
        if self.frustration_path_change < 0:
            errors.append("frustration_path_change must be >= 0")
        if self.frustration_no_progress < 0:
            errors.append("frustration_no_progress must be >= 0")
        if not 0 <= self.frustration_decay <= 1:
            errors.append("frustration_decay must be between 0 and 1")
        if self.frustration_retreat_threshold < 0:
            errors.append("frustration_retreat_threshold must be >= 0")
        if self.ai_uncertainty_weight < 0:
            errors.append("ai_uncertainty_weight must be >= 0")
        if self.ai_replanning_weight < 0:
            errors.append("ai_replanning_weight must be >= 0")
        if self.ai_search_weight < 0:
            errors.append("ai_search_weight must be >= 0")
        if self.ai_operational_risk_weight < 0:
            errors.append("ai_operational_risk_weight must be >= 0")
        if self.ai_trust_degradation_weight < 0:
            errors.append("ai_trust_degradation_weight must be >= 0")
        if self.cognitive_weight_critical_protection < 0:
            errors.append("cognitive_weight_critical_protection must be >= 0")
        if self.cognitive_weight_perceived_utility < 0:
            errors.append("cognitive_weight_perceived_utility must be >= 0")
        if self.cognitive_weight_confidence < 0:
            errors.append("cognitive_weight_confidence must be >= 0")
        if self.cognitive_weight_human_frustration < 0:
            errors.append("cognitive_weight_human_frustration must be >= 0")
        if self.cognitive_weight_ai_cost < 0:
            errors.append("cognitive_weight_ai_cost must be >= 0")
        if self.cognitive_weight_retreat < 0:
            errors.append("cognitive_weight_retreat must be >= 0")
        if self.cns_weight_human < 0:
            errors.append("cns_weight_human must be >= 0")
        if self.cns_weight_ai < 0:
            errors.append("cns_weight_ai must be >= 0")
        if self.cns_weight_protection < 0:
            errors.append("cns_weight_protection must be >= 0")
        if self.attacker_greedy_mode not in ("legacy", "weighted_risk", "utility"):
            errors.append("attacker_greedy_mode must be one of: legacy, weighted_risk, utility")
        if self.attacker_defense_cost_rate < 0:
            errors.append("attacker_defense_cost_rate must be >= 0")
        if self.attacker_detection_sensitivity < 0:
            errors.append("attacker_detection_sensitivity must be >= 0")
        if not 0 <= self.attacker_success_base_rate <= 1:
            errors.append("attacker_success_base_rate must be between 0 and 1")
        if self.attacker_success_defense_decay < 0:
            errors.append("attacker_success_defense_decay must be >= 0")
        if self.attacker_belief_success_boost < 0:
            errors.append("attacker_belief_success_boost must be >= 0")
        if not 0 <= self.attacker_belief_failure_decay <= 1:
            errors.append("attacker_belief_failure_decay must be between 0 and 1")
        if not 0 <= self.attacker_belief_detection_decay <= 1:
            errors.append("attacker_belief_detection_decay must be between 0 and 1")
        if not 0 <= self.attacker_belief_decoy_decay <= 1:
            errors.append("attacker_belief_decoy_decay must be between 0 and 1")
        if self.attacker_belief_min < 0:
            errors.append("attacker_belief_min must be >= 0")
        if self.attacker_belief_max < self.attacker_belief_min:
            errors.append("attacker_belief_max must be >= attacker_belief_min")
        if self.adaptive_success_weight < 0:
            errors.append("adaptive_success_weight must be >= 0")
        if self.adaptive_decoy_weight < 0:
            errors.append("adaptive_decoy_weight must be >= 0")
        if self.adaptive_detection_weight < 0:
            errors.append("adaptive_detection_weight must be >= 0")
        if self.adaptive_preference_weight < 0:
            errors.append("adaptive_preference_weight must be >= 0")
        if self.adaptive_success_reward < 0:
            errors.append("adaptive_success_reward must be >= 0")
        if self.adaptive_critical_reward < 0:
            errors.append("adaptive_critical_reward must be >= 0")
        if self.adaptive_decoy_penalty < 0:
            errors.append("adaptive_decoy_penalty must be >= 0")
        if self.adaptive_detection_penalty < 0:
            errors.append("adaptive_detection_penalty must be >= 0")
        if self.path_preference_weight < 0:
            errors.append("path_preference_weight must be >= 0")
        if self.path_success_reward < 0:
            errors.append("path_success_reward must be >= 0")
        if self.path_critical_reward < 0:
            errors.append("path_critical_reward must be >= 0")
        if self.path_decoy_penalty < 0:
            errors.append("path_decoy_penalty must be >= 0")
        if self.path_detection_penalty < 0:
            errors.append("path_detection_penalty must be >= 0")
        if self.planning_depth < 0:
            errors.append("planning_depth must be >= 0")
        if self.planning_success_weight < 0:
            errors.append("planning_success_weight must be >= 0")
        if self.planning_critical_weight < 0:
            errors.append("planning_critical_weight must be >= 0")
        if self.planning_decoy_penalty < 0:
            errors.append("planning_decoy_penalty must be >= 0")
        if self.planning_detection_penalty < 0:
            errors.append("planning_detection_penalty must be >= 0")
        if not 0 <= self.trust_decoy_penalty <= 1:
            errors.append("trust_decoy_penalty must be between 0 and 1")
        if not 0 <= self.trust_credential_penalty <= 1:
            errors.append("trust_credential_penalty must be between 0 and 1")
        if not 0 <= self.trust_detection_penalty <= 1:
            errors.append("trust_detection_penalty must be between 0 and 1")
        if not 0 <= self.trust_success_reward <= 1:
            errors.append("trust_success_reward must be between 0 and 1")
        if self.expected_gain_weight < 0:
            errors.append("expected_gain_weight must be >= 0")
        if self.expected_success_weight < 0:
            errors.append("expected_success_weight must be >= 0")
        if self.expected_detection_cost < 0:
            errors.append("expected_detection_cost must be >= 0")
        if self.expected_search_cost < 0:
            errors.append("expected_search_cost must be >= 0")
        if self.expected_trust_weight < 0:
            errors.append("expected_trust_weight must be >= 0")
        if not 0 <= self.attacker_lateral_success_prob <= 1:
            errors.append("attacker_lateral_success_prob must be between 0 and 1")
        if not 0 <= self.attacker_lateral_detection_prob <= 1:
            errors.append("attacker_lateral_detection_prob must be between 0 and 1")
        if not 0 <= self.decoy_lateral_decay <= 1:
            errors.append("decoy_lateral_decay must be between 0 and 1")
        if self.post_decoy_defense_weight < 0:
            errors.append("post_decoy_defense_weight must be >= 0")
        if self.post_decoy_defense_top_k < 0:
            errors.append("post_decoy_defense_top_k must be >= 0")
        if self.post_decoy_defense_injection_mode not in (
            "matching_only",
            "fallback_only",
            "matching_fallback",
            "mpc_q",
            "all",
        ):
            errors.append("post_decoy_defense_injection_mode must be one of: matching_only, fallback_only, matching_fallback, mpc_q, all")
        if self.post_decoy_defense_belief_source not in ("attacker", "estimated", "bayesian"):
            errors.append("post_decoy_defense_belief_source must be one of: attacker, estimated, bayesian")
        if self.defender_belief_observation_mode not in (
            "none",
            "target_frequency",
            "selection_score",
            "hybrid",
            "defender_visible_log",
            "hybrid_visible",
        ):
            errors.append("defender_belief_observation_mode must be one of: none, target_frequency, selection_score, hybrid, defender_visible_log, hybrid_visible")
        if not 0 <= self.defender_belief_estimation_alpha <= 1:
            errors.append("defender_belief_estimation_alpha must be between 0 and 1")
        if self.defender_belief_observation_noise < 0:
            errors.append("defender_belief_observation_noise must be >= 0")
        if self.defender_belief_min < 0:
            errors.append("defender_belief_min must be >= 0")
        if self.defender_belief_max < self.defender_belief_min:
            errors.append("defender_belief_max must be >= defender_belief_min")
        if self.visible_log_success_boost < 0:
            errors.append("visible_log_success_boost must be >= 0")
        if not 0 <= self.visible_log_detected_decay <= 1:
            errors.append("visible_log_detected_decay must be between 0 and 1")
        if not 0 <= self.visible_log_decoy_decay <= 1:
            errors.append("visible_log_decoy_decay must be between 0 and 1")
        if self.visible_log_success_prob_weight < 0:
            errors.append("visible_log_success_prob_weight must be >= 0")
        if self.visible_log_detection_prob_weight < 0:
            errors.append("visible_log_detection_prob_weight must be >= 0")
        if self.visible_log_defense_penalty_weight < 0:
            errors.append("visible_log_defense_penalty_weight must be >= 0")
        if self.defender_bayesian_prior_strength < 0:
            errors.append("defender_bayesian_prior_strength must be >= 0")
        if self.defender_bayesian_success_likelihood < 0:
            errors.append("defender_bayesian_success_likelihood must be >= 0")
        if self.defender_bayesian_detected_likelihood < 0:
            errors.append("defender_bayesian_detected_likelihood must be >= 0")
        if self.defender_bayesian_decoy_likelihood < 0:
            errors.append("defender_bayesian_decoy_likelihood must be >= 0")
        if self.defender_bayesian_critical_path_likelihood < 0:
            errors.append("defender_bayesian_critical_path_likelihood must be >= 0")
        if not 0 <= self.defender_bayesian_decay <= 1:
            errors.append("defender_bayesian_decay must be between 0 and 1")
        if self.defense_objective_critical_weight < 0:
            errors.append("defense_objective_critical_weight must be >= 0")
        if self.defense_objective_post_decoy_weight < 0:
            errors.append("defense_objective_post_decoy_weight must be >= 0")
        if self.defense_objective_delay_reward < 0:
            errors.append("defense_objective_delay_reward must be >= 0")
        if self.mtd_interval <= 0:
            errors.append("mtd_interval must be > 0")
        if self.mtd_strategy not in ("shuffle_belief", "decay_belief", "increase_uncertainty"):
            errors.append("mtd_strategy must be one of: shuffle_belief, decay_belief, increase_uncertainty")
        if not 0 <= self.mtd_intensity <= 1:
            errors.append("mtd_intensity must be between 0 and 1")
        if self.mtd_cost < 0:
            errors.append("mtd_cost must be >= 0")
        if self.mtd_success_decay_bonus < 0:
            errors.append("mtd_success_decay_bonus must be >= 0")
        if self.mtd_detection_bonus < 0:
            errors.append("mtd_detection_bonus must be >= 0")
        if self.mtd_edge_block_count < 0:
            errors.append("mtd_edge_block_count must be >= 0")
        if self.mtd_edge_block_duration <= 0:
            errors.append("mtd_edge_block_duration must be > 0")
        if self.mtd_risk_gate_threshold < 0:
            errors.append("mtd_risk_gate_threshold must be >= 0")
        if self.mtd_risk_gate_mode not in ("critical_path_risk", "chokepoint_risk", "critical_edge_pressure"):
            errors.append("mtd_risk_gate_mode must be one of: critical_path_risk, chokepoint_risk, critical_edge_pressure")
        if self.mtd_risk_gate_cooldown < 0:
            errors.append("mtd_risk_gate_cooldown must be >= 0")
        if self.mtd_conditional_policy_mode not in ("edge_pressure_split", "critical_vs_post_decoy"):
            errors.append("mtd_conditional_policy_mode must be one of: edge_pressure_split, critical_vs_post_decoy")
        if self.mtd_conditional_high_risk_threshold < 0:
            errors.append("mtd_conditional_high_risk_threshold must be >= 0")
        if self.mtd_conditional_low_risk_threshold < 0:
            errors.append("mtd_conditional_low_risk_threshold must be >= 0")
        if self.mtd_conditional_high_risk_threshold < self.mtd_conditional_low_risk_threshold:
            errors.append("mtd_conditional_high_risk_threshold must be >= mtd_conditional_low_risk_threshold")
        if self.credential_attraction_bonus < 0:
            errors.append("credential_attraction_bonus must be >= 0")
        if self.credential_detection_bonus < 0:
            errors.append("credential_detection_bonus must be >= 0")
        if not 0 <= self.credential_reuse_decay <= 1:
            errors.append("credential_reuse_decay must be between 0 and 1")
        if self.credential_trigger_mtd_window < 0:
            errors.append("credential_trigger_mtd_window must be >= 0")
        if self.credential_trigger_block_count < 0:
            errors.append("credential_trigger_block_count must be >= 0")
        if self.credential_trigger_block_duration <= 0:
            errors.append("credential_trigger_block_duration must be > 0")
        if self.credential_trigger_risk_bonus < 0:
            errors.append("credential_trigger_risk_bonus must be >= 0")
        if self.credential_stage1_window < 0:
            errors.append("credential_stage1_window must be >= 0")
        if self.credential_stage2_window < self.credential_stage1_window:
            errors.append("credential_stage2_window must be >= credential_stage1_window")
        if self.credential_stage1_block_count < 0:
            errors.append("credential_stage1_block_count must be >= 0")
        if self.credential_stage2_block_count < 0:
            errors.append("credential_stage2_block_count must be >= 0")
        if self.credential_stage1_block_duration <= 0:
            errors.append("credential_stage1_block_duration must be > 0")
        if self.credential_stage2_block_duration <= 0:
            errors.append("credential_stage2_block_duration must be > 0")

        if self.d_base.shape != (self.n_nodes,):
            errors.append(f"d_base length must equal n_nodes ({self.n_nodes})")
        if self.Q_diag.shape != (self.n_nodes,):
            errors.append(f"Q_diag length must equal n_nodes ({self.n_nodes})")
        if self.R_diag.shape != (self.m_resources,):
            errors.append(f"R_diag length must equal m_resources ({self.m_resources})")
        if self.asset_value.shape != (self.n_nodes,):
            errors.append(f"asset_value length must equal n_nodes ({self.n_nodes})")
        if self.attacker_belief.shape != (self.n_nodes,):
            errors.append(f"attacker_belief length must equal n_nodes ({self.n_nodes})")
        if np.any(self.asset_value < 0):
            errors.append("asset_value entries must be >= 0")
        if np.any(self.attacker_belief < 0):
            errors.append("attacker_belief entries must be >= 0")
        if len(self.node_type) != self.n_nodes:
            errors.append(f"node_type length must equal n_nodes ({self.n_nodes})")
        if len(self.node_layer) != self.n_nodes:
            errors.append(f"node_layer length must equal n_nodes ({self.n_nodes})")
        invalid_node_types = [value for value in self.node_type if value not in ("real", "decoy")]
        if invalid_node_types:
            errors.append("node_type entries must be 'real' or 'decoy'")
        if self.adjacency_matrix.shape != (self.n_nodes, self.n_nodes):
            errors.append(f"adjacency_matrix shape must be ({self.n_nodes}, {self.n_nodes})")
        elif not np.all((self.adjacency_matrix == 0) | (self.adjacency_matrix == 1)):
            errors.append("adjacency_matrix entries must be 0 or 1")
        if not self.entry_nodes:
            errors.append("entry_nodes must not be empty")
        if not self.critical_nodes:
            errors.append("critical_nodes must not be empty")
        for idx in list(self.entry_nodes) + list(self.critical_nodes):
            if idx < 0 or idx >= self.n_nodes:
                errors.append("entry_nodes and critical_nodes must contain valid node indices")
        for idx in list(self.credential_node_ids):
            if idx < 0 or idx >= self.n_nodes:
                errors.append("credential_node_ids must contain valid node indices")
        if self.decoy_detection_bonus < 0:
            errors.append("decoy_detection_bonus must be >= 0")
        if self.decoy_waste_cost < 0:
            errors.append("decoy_waste_cost must be >= 0")
        if self.decoy_success_gain_scale < 0:
            errors.append("decoy_success_gain_scale must be >= 0")
        if not 0 <= self.base_detection_prob <= 1:
            errors.append("base_detection_prob must be between 0 and 1")
        if self.defense_detection_scale < 0:
            errors.append("defense_detection_scale must be >= 0")
        if not 0 <= self.decoy_detection_prob <= 1:
            errors.append("decoy_detection_prob must be between 0 and 1")
        if not 0 <= self.base_success_prob <= 1:
            errors.append("base_success_prob must be between 0 and 1")
        if self.defense_success_decay < 0:
            errors.append("defense_success_decay must be >= 0")
        if not 0 <= self.decoy_success_prob <= 1:
            errors.append("decoy_success_prob must be between 0 and 1")
        if len(self.resource_capacity) != self.m_resources:
            errors.append(f"resource_capacity length must equal m_resources ({self.m_resources})")
        if any(cap < 0 for cap in self.resource_capacity):
            errors.append("resource_capacity entries must be >= 0")

        if errors:
            raise ValueError("Invalid SimulationConfig: " + "; ".join(errors))

    def to_json(self, filepath: str):
        """設定をJSONファイルに保存 (NumPy配列をリストに変換)"""
        self.validate()
        data = asdict(self)
        # NumPy配列をリストに変換してJSON化可能にする
        for key, value in data.items():
            if isinstance(value, np.ndarray):
                data[key] = value.tolist()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logger.info(f"Configuration saved to {filepath}")

    @classmethod
    def from_json(cls, filepath: str) -> 'SimulationConfig':
        """JSONファイルから設定を読み込み (不要なキーを除外しリストをNumPy配列に変換)"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 1. データクラスのフィールドにないキーを除外（コメント等を許可するため）
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}
        
        # 2. 配列であるべきフィールドをNumPyに変換
        array_fields = ['d_base', 'Q_diag', 'R_diag', 'asset_value', 'attacker_belief', 'adjacency_matrix']
        for field_name in array_fields:
            if field_name in filtered_data:
                filtered_data[field_name] = np.array(filtered_data[field_name])
        
        logger.info(f"Configuration loaded from {filepath}")
        return cls(**filtered_data)

@dataclass
class AttackerModel:
    """一般的なITシステムを想定した攻撃者の意思決定モデル"""

    enabled: bool = False

    # 攻撃先選択
    attack_budget: float = 3.0
    target_selection: str = "greedy"  # "greedy" | "random" | "adaptive"
    greedy_mode: str = "utility"  # "legacy" | "weighted_risk" | "utility"
    attacker_belief: Optional[np.ndarray] = None

    # 利得・コスト構造
    compromised_value: float = 0.0
    total_cost: float = 0.0
    actual_gain: float = 0.0
    actual_cost: float = 0.0
    perceived_gain: float = 0.0
    perceived_cost: float = 0.0
    confidence: float = 1.0
    frustration: float = 0.0
    max_frustration: float = 0.0
    frustration_sum: float = 0.0
    frustration_steps: int = 0
    frustration_retreats: int = 0
    ai_uncertainty_cost: float = 0.0
    ai_replanning_cost: float = 0.0
    ai_search_cost: float = 0.0
    ai_operational_risk_cost: float = 0.0
    ai_trust_degradation_cost: float = 0.0

    effort_cost_rate: float = 0.3
    detection_penalty: float = 1.0
    deception_waste: float = 0.0
    defense_cost_rate: float = 1.0
    detection_sensitivity: float = 1.0
    success_base_rate: float = 1.0
    success_defense_decay: float = 0.5
    belief_learning_enabled: bool = False
    belief_success_boost: float = 1.0
    belief_failure_decay: float = 0.8
    belief_detection_decay: float = 0.5
    belief_decoy_decay: float = 0.1
    belief_min: float = 0.0
    belief_max: float = 20.0
    adaptive_attacker_enabled: bool = False
    adaptive_success_weight: float = 1.0
    adaptive_decoy_weight: float = 2.0
    adaptive_detection_weight: float = 1.5
    adaptive_preference_enabled: bool = False
    adaptive_preference_weight: float = 2.0
    adaptive_success_reward: float = 1.0
    adaptive_critical_reward: float = 3.0
    adaptive_decoy_penalty: float = 2.0
    adaptive_detection_penalty: float = 1.5
    adaptive_path_enabled: bool = False
    path_preference_weight: float = 3.0
    path_success_reward: float = 1.0
    path_critical_reward: float = 5.0
    path_decoy_penalty: float = 2.0
    path_detection_penalty: float = 1.5
    adaptive_planning_enabled: bool = False
    planning_depth: int = 2
    planning_success_weight: float = 1.0
    planning_critical_weight: float = 5.0
    planning_decoy_penalty: float = 2.0
    planning_detection_penalty: float = 1.5
    trust_enabled: bool = False
    trust_decoy_penalty: float = 0.20
    trust_credential_penalty: float = 0.30
    trust_detection_penalty: float = 0.15
    trust_success_reward: float = 0.05
    expected_utility_enabled: bool = False
    expected_gain_weight: float = 1.0
    expected_success_weight: float = 1.0
    expected_detection_cost: float = 1.0
    expected_search_cost: float = 1.0
    expected_trust_weight: float = 1.0
    lateral_enabled: bool = False
    lateral_success_prob: float = 0.8
    lateral_detection_prob: float = 0.2
    adjacency_matrix: Optional[np.ndarray] = None
    entry_nodes: Optional[List[int]] = None
    node_type: Optional[List[str]] = None
    critical_nodes: Optional[List[int]] = None

    # 撤退条件
    retreat_threshold: float = -2.0
    patience: int = 10
    perceived_no_progress_threshold: float = 0.0
    perceived_utility_enabled: bool = False
    perceived_success_confidence: float = 1.0
    perceived_decoy_penalty: float = 1.0
    perceived_detection_penalty: float = 1.0
    perceived_uncertainty_decay: float = 0.95
    retreat_based_on: str = "actual"
    frustration_enabled: bool = False
    frustration_decoy_hit: float = 3.0
    frustration_credential_trap: float = 2.0
    frustration_detection: float = 1.0
    frustration_path_change: float = 0.5
    frustration_no_progress: float = 0.5
    frustration_decay: float = 0.95
    frustration_retreat_threshold: float = 10.0

    # 内部状態
    no_success_steps: int = 0
    retreated: bool = False
    last_selection_score: Optional[np.ndarray] = None
    last_selected_target: int = -1
    previous_selected_target: int = -1
    current_node: int = 0
    visited_nodes: Optional[set] = None
    compromised_nodes: Optional[set] = None
    node_success_memory: Optional[Dict[int, float]] = None
    node_decoy_memory: Optional[Dict[int, float]] = None
    node_detection_memory: Optional[Dict[int, float]] = None
    node_preference_score: Optional[Dict[int, float]] = None
    path_success_memory: Optional[Dict[str, float]] = None
    path_decoy_memory: Optional[Dict[str, float]] = None
    path_detection_memory: Optional[Dict[str, float]] = None
    path_preference_score: Optional[Dict[str, float]] = None
    current_attack_path: Optional[List[int]] = None
    last_planning_score: Optional[np.ndarray] = None
    last_planned_path: Optional[List[int]] = None
    last_planned_path_score: float = 0.0
    node_trust_score: Optional[Dict[int, float]] = None
    last_expected_utility: Optional[np.ndarray] = None
    last_expected_gain_estimate: Optional[np.ndarray] = None
    last_expected_detection_risk: Optional[np.ndarray] = None
    last_expected_search_cost: Optional[np.ndarray] = None

    def __post_init__(self):
        if self.attacker_belief is None:
            self.current_belief = None
        else:
            self.current_belief = np.clip(
                np.asarray(self.attacker_belief, dtype=float).copy(),
                self.belief_min,
                self.belief_max,
            )
        if self.entry_nodes:
            self.current_node = int(self.entry_nodes[0])
        self.visited_nodes = {int(self.current_node)}
        self.compromised_nodes = {int(self.current_node)}
        if self.adjacency_matrix is not None:
            self.adjacency_matrix = np.asarray(self.adjacency_matrix, dtype=int)
        n_nodes = int(len(self.current_belief)) if self.current_belief is not None else 0
        self.node_success_memory = {node_id: 0.0 for node_id in range(n_nodes)}
        self.node_decoy_memory = {node_id: 0.0 for node_id in range(n_nodes)}
        self.node_detection_memory = {node_id: 0.0 for node_id in range(n_nodes)}
        self.node_preference_score = {node_id: 0.0 for node_id in range(n_nodes)}
        self.path_success_memory = {}
        self.path_decoy_memory = {}
        self.path_detection_memory = {}
        self.path_preference_score = {}
        self.current_attack_path = [int(self.current_node)]
        self.last_planning_score = np.zeros(n_nodes, dtype=float)
        self.last_planned_path = []
        self.last_planned_path_score = 0.0
        self.node_trust_score = {node_id: 1.0 for node_id in range(n_nodes)}
        self.last_expected_utility = np.zeros(n_nodes, dtype=float)
        self.last_expected_gain_estimate = np.zeros(n_nodes, dtype=float)
        self.last_expected_detection_risk = np.zeros(n_nodes, dtype=float)
        self.last_expected_search_cost = np.zeros(n_nodes, dtype=float)

    @property
    def utility(self) -> float:
        return self.actual_utility

    @property
    def actual_utility(self) -> float:
        return self.actual_gain - self.actual_cost

    @property
    def perceived_utility(self) -> float:
        return self.perceived_gain - self.perceived_cost

    @property
    def mean_frustration(self) -> float:
        if self.frustration_steps <= 0:
            return float(self.frustration)
        return float(self.frustration_sum / self.frustration_steps)

    def select_attack(self, x_current: np.ndarray, M_current: np.ndarray) -> np.ndarray:
        previous_target = self.last_selected_target
        self.last_selection_score = np.zeros_like(x_current, dtype=float)
        self.last_selected_target = -1
        if not self.enabled or self.retreated:
            return np.zeros_like(x_current, dtype=float)

        attack_vector = np.zeros_like(x_current, dtype=float)
        if self.target_selection == "greedy":
            score = self._reachable_score(self.calculate_greedy_score(x_current, M_current))
            target_idx = int(np.argmax(score))
        elif self.target_selection == "random":
            score = np.zeros_like(x_current, dtype=float)
            candidates = self.reachable_nodes(len(x_current))
            target_idx = int(np.random.choice(candidates))
        elif self.target_selection == "adaptive":
            score = self._reachable_score(self.calculate_adaptive_score(x_current, M_current))
            target_idx = int(np.argmax(score))
        else:
            raise ValueError(f"Unsupported target_selection: {self.target_selection}")

        self.last_selection_score = score
        self.previous_selected_target = previous_target
        self.last_selected_target = target_idx
        attack_vector[target_idx] = self.attack_budget
        return attack_vector

    def _select_greedy_target(self, x_current: np.ndarray, M_current: np.ndarray) -> int:
        score = self._reachable_score(self.calculate_greedy_score(x_current, M_current))
        return int(np.argmax(score))

    def reachable_nodes(self, n_nodes: int) -> List[int]:
        if not self.lateral_enabled or self.adjacency_matrix is None:
            return list(range(n_nodes))
        neighbors = np.flatnonzero(self.adjacency_matrix[int(self.current_node)] > 0).astype(int).tolist()
        return neighbors or [int(self.current_node)]

    def _reachable_score(self, score: np.ndarray) -> np.ndarray:
        if not self.lateral_enabled:
            return score
        masked = np.full_like(score, -1.0e12, dtype=float)
        for node_idx in self.reachable_nodes(len(score)):
            masked[node_idx] = score[node_idx]
        return masked

    def record_lateral_result(self, target_idx: int, success: bool) -> None:
        if not self.lateral_enabled or target_idx < 0:
            return
        if success:
            self.current_node = int(target_idx)
            self.compromised_nodes.add(int(target_idx))
            if self.current_attack_path is None:
                self.current_attack_path = [int(target_idx)]
            elif not self.current_attack_path or self.current_attack_path[-1] != int(target_idx):
                self.current_attack_path.append(int(target_idx))
        self.visited_nodes.add(int(target_idx))

    def calculate_greedy_score(self, x_current: np.ndarray, M_current: np.ndarray) -> np.ndarray:
        defense_strength = M_current.sum(axis=1)
        attacker_belief = self._attacker_belief_or_default(len(x_current))

        if self.greedy_mode == "legacy":
            return x_current - defense_strength
        if self.greedy_mode == "weighted_risk":
            return attacker_belief * x_current - defense_strength
        if self.greedy_mode == "utility":
            expected_success_prob = self.success_base_rate * np.exp(
                -self.success_defense_decay * defense_strength
            )
            expected_success_prob = np.clip(expected_success_prob, 0.0, 1.0)
            expected_gain = attacker_belief * (x_current + self.attack_budget) * expected_success_prob
            expected_cost = (
                self.attack_budget * self.effort_cost_rate
                + self.defense_cost_rate * defense_strength
                + self.detection_penalty * self.detection_sensitivity * defense_strength
            )
            return expected_gain - expected_cost
        raise ValueError(f"Unsupported greedy_mode: {self.greedy_mode}")

    def calculate_adaptive_score(self, x_current: np.ndarray, M_current: np.ndarray) -> np.ndarray:
        score = self.calculate_greedy_score(x_current, M_current)
        if not self.adaptive_attacker_enabled:
            return score
        n_nodes = len(score)
        success_memory = self._memory_array(self.node_success_memory, n_nodes)
        decoy_memory = self._memory_array(self.node_decoy_memory, n_nodes)
        detection_memory = self._memory_array(self.node_detection_memory, n_nodes)
        preference_score = self._memory_array(self.node_preference_score, n_nodes)
        preference_weight = self.adaptive_preference_weight if self.adaptive_preference_enabled else 0.0
        path_score = self._path_candidate_score(n_nodes)
        path_weight = self.path_preference_weight if self.adaptive_path_enabled else 0.0
        planning_score = self._planning_candidate_score(x_current, M_current)
        expected_utility = self._expected_utility(x_current, M_current)
        return (
            score
            + self.adaptive_success_weight * success_memory
            + preference_weight * preference_score
            + path_weight * path_score
            + planning_score
            + expected_utility
            - self.adaptive_decoy_weight * decoy_memory
            - self.adaptive_detection_weight * detection_memory
        )

    def _memory_array(self, memory: Optional[Dict[int, float]], n_nodes: int) -> np.ndarray:
        if memory is None:
            return np.zeros(n_nodes, dtype=float)
        return np.array([float(memory.get(node_id, 0.0)) for node_id in range(n_nodes)], dtype=float)

    def memory_vector(self, memory_name: str, n_nodes: int) -> np.ndarray:
        memory = getattr(self, memory_name)
        return self._memory_array(memory, n_nodes)

    def trust_vector(self, n_nodes: int) -> np.ndarray:
        if self.node_trust_score is None:
            return np.ones(n_nodes, dtype=float)
        return np.array([float(self.node_trust_score.get(node_id, 1.0)) for node_id in range(n_nodes)], dtype=float)

    def _expected_utility(self, x_current: np.ndarray, M_current: np.ndarray) -> np.ndarray:
        n_nodes = len(x_current)
        if not self.expected_utility_enabled:
            self.last_expected_utility = np.zeros(n_nodes, dtype=float)
            self.last_expected_gain_estimate = np.zeros(n_nodes, dtype=float)
            self.last_expected_detection_risk = np.zeros(n_nodes, dtype=float)
            self.last_expected_search_cost = np.zeros(n_nodes, dtype=float)
            return self.last_expected_utility

        defense_strength = M_current.sum(axis=1)
        belief = self._attacker_belief_or_default(n_nodes)
        success_probability = np.clip(
            self.success_base_rate * np.exp(-self.success_defense_decay * defense_strength),
            0.0,
            1.0,
        )
        detection_risk = np.clip(
            self.detection_sensitivity * defense_strength / np.maximum(defense_strength + 1.0, 1.0),
            0.0,
            1.0,
        )
        trust = np.power(np.clip(self.trust_vector(n_nodes), 0.0, 1.0), self.expected_trust_weight)
        expected_gain = self.expected_gain_weight * belief * (x_current + self.attack_budget)
        search_cost = self._expected_search_cost(n_nodes)
        expected_utility = (
            expected_gain
            * (self.expected_success_weight * success_probability)
            * trust
            - self.expected_detection_cost * detection_risk
            - self.expected_search_cost * search_cost
        )
        self.last_expected_utility = np.asarray(expected_utility, dtype=float)
        self.last_expected_gain_estimate = np.asarray(expected_gain, dtype=float)
        self.last_expected_detection_risk = np.asarray(detection_risk, dtype=float)
        self.last_expected_search_cost = np.asarray(search_cost, dtype=float)
        return self.last_expected_utility

    def _expected_search_cost(self, n_nodes: int) -> np.ndarray:
        if not self.lateral_enabled or self.adjacency_matrix is None:
            return np.zeros(n_nodes, dtype=float)
        reachable = set(int(node) for node in self.reachable_nodes(n_nodes))
        visited = set(int(node) for node in (self.visited_nodes or set()))
        costs = np.ones(n_nodes, dtype=float)
        for node_id in range(n_nodes):
            if node_id == int(self.current_node):
                costs[node_id] = 0.0
            elif node_id in reachable:
                costs[node_id] = 0.25
            elif node_id in visited:
                costs[node_id] = 0.5
        return costs

    def _path_key(self, nodes: List[int]) -> str:
        return "->".join(str(int(node)) for node in nodes)

    def path_key_for_target(self, target_idx: int) -> str:
        path = list(self.current_attack_path or [int(self.current_node)])
        target = int(target_idx)
        if not path or path[-1] != target:
            path.append(target)
        return self._path_key(path)

    def _path_candidate_score(self, n_nodes: int) -> np.ndarray:
        if not self.adaptive_path_enabled or self.path_preference_score is None:
            return np.zeros(n_nodes, dtype=float)
        return np.array(
            [float(self.path_preference_score.get(self.path_key_for_target(node_id), 0.0)) for node_id in range(n_nodes)],
            dtype=float,
        )

    def path_preference_vector(self) -> np.ndarray:
        if not self.path_preference_score:
            return np.zeros(0, dtype=float)
        return np.asarray(list(self.path_preference_score.values()), dtype=float)

    def _planning_candidate_score(self, x_current: np.ndarray, M_current: np.ndarray) -> np.ndarray:
        n_nodes = len(x_current)
        if not self.adaptive_planning_enabled or self.planning_depth <= 0:
            self.last_planning_score = np.zeros(n_nodes, dtype=float)
            self.last_planned_path = []
            self.last_planned_path_score = 0.0
            return self.last_planning_score

        planning_score = np.full(n_nodes, -1.0e12, dtype=float)
        best_path: List[int] = []
        best_score = -1.0e12
        current_node = int(self.current_node)
        for target in self.reachable_nodes(n_nodes):
            target = int(target)
            value, path = self._plan_path_value(
                current_node=target,
                depth=int(self.planning_depth) - 1,
                x_current=x_current,
                M_current=M_current,
                path=[current_node, target] if current_node != target else [target],
                visited={current_node, target},
            )
            immediate = self._planning_node_value(target, M_current)
            score = immediate + value
            if self.trust_enabled:
                score *= float(self.trust_vector(n_nodes)[target])
            planning_score[target] = score
            if score > best_score:
                best_score = float(score)
                best_path = path if path else ([current_node, target] if current_node != target else [target])

        self.last_planning_score = planning_score
        self.last_planned_path = [int(node) for node in best_path]
        self.last_planned_path_score = float(best_score if best_score > -1.0e11 else 0.0)
        return planning_score

    def _plan_path_value(
        self,
        current_node: int,
        depth: int,
        x_current: np.ndarray,
        M_current: np.ndarray,
        path: List[int],
        visited: set,
    ) -> Tuple[float, List[int]]:
        if depth <= 0:
            return 0.0, list(path)

        best_value = 0.0
        best_path = list(path)
        for neighbor in self._planning_neighbors(int(current_node), len(x_current)):
            neighbor = int(neighbor)
            if neighbor in visited and len(visited) < len(x_current):
                continue
            immediate = self._planning_node_value(neighbor, M_current)
            future, future_path = self._plan_path_value(
                current_node=neighbor,
                depth=depth - 1,
                x_current=x_current,
                M_current=M_current,
                path=path + [neighbor],
                visited=visited | {neighbor},
            )
            total = immediate + future
            if total > best_value:
                best_value = float(total)
                best_path = future_path
        return best_value, best_path

    def _planning_neighbors(self, node_idx: int, n_nodes: int) -> List[int]:
        if self.lateral_enabled and self.adjacency_matrix is not None:
            neighbors = np.flatnonzero(self.adjacency_matrix[int(node_idx)] > 0).astype(int).tolist()
            return neighbors or [int(node_idx)]
        return list(range(n_nodes))

    def _planning_node_value(self, node_idx: int, M_current: np.ndarray) -> float:
        defense_strength = float(M_current[int(node_idx)].sum())
        success_prob = float(np.clip(
            self.success_base_rate * np.exp(-self.success_defense_decay * defense_strength),
            0.0,
            1.0,
        ))
        detection_prob = float(np.clip(
            self.detection_sensitivity * defense_strength / max(defense_strength + 1.0, 1.0),
            0.0,
            1.0,
        ))
        node_type = self.node_type[int(node_idx)] if self.node_type and int(node_idx) < len(self.node_type) else "real"
        critical_nodes = set(int(node) for node in (self.critical_nodes or []))
        success_reward = self.planning_success_weight * success_prob
        critical_reward = self.planning_critical_weight * success_prob if int(node_idx) in critical_nodes else 0.0
        decoy_penalty = self.planning_decoy_penalty if node_type == "decoy" else 0.0
        detection_penalty = self.planning_detection_penalty * detection_prob
        return float(success_reward + critical_reward - decoy_penalty - detection_penalty)

    def update_trust(
        self,
        target_idx: int,
        success: bool,
        detected: bool,
        attacked_decoy: bool,
        credential_decoy_trigger: bool = False,
    ) -> None:
        if not self.trust_enabled or target_idx < 0:
            return
        if self.node_trust_score is None:
            n_nodes = int(len(self.current_belief)) if self.current_belief is not None else int(target_idx) + 1
            self.node_trust_score = {node_id: 1.0 for node_id in range(n_nodes)}
        target = int(target_idx)
        current = float(self.node_trust_score.get(target, 1.0))
        if attacked_decoy:
            current -= self.trust_decoy_penalty
        if credential_decoy_trigger:
            current -= self.trust_credential_penalty
        if detected:
            current -= self.trust_detection_penalty
        if success:
            current += self.trust_success_reward
        self.node_trust_score[target] = float(np.clip(current, 0.0, 1.0))

    def serialized_path_preference(self) -> str:
        if not self.path_preference_score:
            return ""
        parts = [
            f"{key}:{float(value):.6g}"
            for key, value in sorted(self.path_preference_score.items())
            if abs(float(value)) > 0.0
        ]
        return "|".join(parts)

    def update_memory(
        self,
        target_idx: int,
        success: bool,
        detected: bool,
        attacked_decoy: bool,
        critical_reached: bool = False,
        path_key: Optional[str] = None,
    ) -> None:
        if target_idx < 0:
            return
        if self.node_success_memory is None:
            self.node_success_memory = {}
        if self.node_decoy_memory is None:
            self.node_decoy_memory = {}
        if self.node_detection_memory is None:
            self.node_detection_memory = {}
        if self.node_preference_score is None:
            self.node_preference_score = {}
        if self.path_success_memory is None:
            self.path_success_memory = {}
        if self.path_decoy_memory is None:
            self.path_decoy_memory = {}
        if self.path_detection_memory is None:
            self.path_detection_memory = {}
        if self.path_preference_score is None:
            self.path_preference_score = {}
        target = int(target_idx)
        self.node_success_memory.setdefault(target, 0.0)
        self.node_decoy_memory.setdefault(target, 0.0)
        self.node_detection_memory.setdefault(target, 0.0)
        self.node_preference_score.setdefault(target, 0.0)
        if success:
            self.node_success_memory[target] += 1.0
        if attacked_decoy:
            self.node_decoy_memory[target] += 1.0
        if detected:
            self.node_detection_memory[target] += 1.0
        if self.adaptive_preference_enabled:
            if success:
                self.node_preference_score[target] += self.adaptive_success_reward
            if critical_reached:
                self.node_preference_score[target] += self.adaptive_critical_reward
            if attacked_decoy:
                self.node_preference_score[target] -= self.adaptive_decoy_penalty
            if detected:
                self.node_preference_score[target] -= self.adaptive_detection_penalty
        if self.adaptive_path_enabled:
            key = path_key or self.path_key_for_target(target)
            self.path_success_memory.setdefault(key, 0.0)
            self.path_decoy_memory.setdefault(key, 0.0)
            self.path_detection_memory.setdefault(key, 0.0)
            self.path_preference_score.setdefault(key, 0.0)
            if critical_reached:
                self.path_success_memory[key] += 1.0
            if attacked_decoy:
                self.path_decoy_memory[key] += 1.0
            if detected:
                self.path_detection_memory[key] += 1.0
            if success:
                self.path_preference_score[key] += self.path_success_reward
            if critical_reached:
                self.path_preference_score[key] += self.path_critical_reward
            if attacked_decoy:
                self.path_preference_score[key] -= self.path_decoy_penalty
            if detected:
                self.path_preference_score[key] -= self.path_detection_penalty

    def _attacker_belief_or_default(self, n_nodes: int) -> np.ndarray:
        if self.current_belief is None:
            return np.ones(n_nodes)
        attacker_belief = np.asarray(self.current_belief, dtype=float)
        if attacker_belief.shape != (n_nodes,):
            raise ValueError(f"attacker_belief length must equal x_current length ({n_nodes})")
        return attacker_belief

    def update_belief(
        self,
        target_idx: int,
        success: bool,
        detected: bool,
        attacked_decoy: bool,
    ) -> None:
        if not self.belief_learning_enabled or target_idx < 0 or self.current_belief is None:
            return

        if success:
            self.current_belief[target_idx] += self.belief_success_boost
        else:
            self.current_belief[target_idx] *= self.belief_failure_decay
        if detected:
            self.current_belief[target_idx] *= self.belief_detection_decay
        if attacked_decoy:
            self.current_belief[target_idx] *= self.belief_decoy_decay
        self.current_belief = np.clip(self.current_belief, self.belief_min, self.belief_max)

    def update_state(
        self,
        gained: float,
        detected: bool,
        success: bool,
        deception_waste_step: float = 0.0,
        detection_penalty_step: float = 0.0,
        perceived_gained: Optional[float] = None,
        attacked_decoy: bool = False,
        credential_decoy_trigger: bool = False,
        path_changed: bool = False,
        no_progress: bool = False,
    ) -> None:
        if not self.enabled or self.retreated:
            return

        actual_cost_step = self.attack_budget * self.effort_cost_rate
        if detected:
            actual_cost_step += self.detection_penalty + detection_penalty_step
        actual_cost_step += self.deception_waste + deception_waste_step

        self.actual_gain += gained
        self.actual_cost += actual_cost_step
        self.compromised_value = self.actual_gain
        self.total_cost = self.actual_cost

        if self.perceived_utility_enabled:
            perceived_gain_step = (
                (perceived_gained if perceived_gained is not None else gained)
                * self.confidence
                * self.perceived_success_confidence
            )
            perceived_cost_step = self.attack_budget * self.effort_cost_rate
            if detected:
                perceived_cost_step += (self.detection_penalty + detection_penalty_step) * self.perceived_detection_penalty
            if attacked_decoy:
                perceived_cost_step += (self.deception_waste + deception_waste_step + self.perceived_decoy_penalty)
            if credential_decoy_trigger:
                perceived_cost_step += self.perceived_decoy_penalty
            self.perceived_gain += perceived_gain_step
            self.perceived_cost += perceived_cost_step
            if attacked_decoy or credential_decoy_trigger or detected:
                self.confidence *= self.perceived_uncertainty_decay
        else:
            self.perceived_gain = self.actual_gain
            self.perceived_cost = self.actual_cost
            self.confidence = 1.0

        if self.frustration_enabled:
            self.frustration *= self.frustration_decay
            self.ai_uncertainty_cost *= self.frustration_decay
            self.ai_replanning_cost *= self.frustration_decay
            self.ai_search_cost *= self.frustration_decay
            self.ai_operational_risk_cost *= self.frustration_decay
            self.ai_trust_degradation_cost *= self.frustration_decay
            if attacked_decoy:
                self.frustration += self.frustration_decoy_hit
                self.ai_uncertainty_cost += self.frustration_decoy_hit
            if credential_decoy_trigger:
                self.frustration += self.frustration_credential_trap
                self.ai_trust_degradation_cost += self.frustration_credential_trap
            if detected:
                self.frustration += self.frustration_detection
                self.ai_operational_risk_cost += self.frustration_detection
            if path_changed:
                self.frustration += self.frustration_path_change
                self.ai_replanning_cost += self.frustration_path_change
            if no_progress:
                self.frustration += self.frustration_no_progress
                self.ai_search_cost += self.frustration_no_progress
        else:
            self.frustration = 0.0
            self.ai_uncertainty_cost = 0.0
            self.ai_replanning_cost = 0.0
            self.ai_search_cost = 0.0
            self.ai_operational_risk_cost = 0.0
            self.ai_trust_degradation_cost = 0.0
        self.max_frustration = max(float(self.max_frustration), float(self.frustration))
        self.frustration_sum += float(self.frustration)
        self.frustration_steps += 1

        # Patience counter driven by perceived_gained when provided (oracle-leak fix).
        # An attacker who perceives progress (perceived_gained > threshold) does not count
        # the step as "no progress", even if true gain is 0 (e.g., decoy attack).
        # Falls back to true success when perceived_gained is not provided (legacy path).
        if perceived_gained is not None:
            if perceived_gained > self.perceived_no_progress_threshold:
                self.no_success_steps = 0
            else:
                self.no_success_steps += 1
        else:
            if success:
                self.no_success_steps = 0
            else:
                self.no_success_steps += 1

        if self.retreat_based_on == "frustration":
            should_retreat = self.frustration > self.frustration_retreat_threshold
        else:
            retreat_utility = self.perceived_utility if self.retreat_based_on == "perceived" else self.actual_utility
            should_retreat = retreat_utility < self.retreat_threshold
        if should_retreat or self.no_success_steps >= self.patience:
            if self.retreat_based_on == "frustration" and self.frustration > self.frustration_retreat_threshold:
                self.frustration_retreats += 1
            self.retreated = True

class OptimizationEngine:
    """ILPおよびMPCの計算を担うエンジンクラス"""
    def __init__(self, config: SimulationConfig):
        self.config = config
        self.Q = np.diag(config.Q_diag)
        self.R = np.diag(config.R_diag)
        self.stats = {
            'ilp_solve_count': 0,
            'ilp_fallback_count': 0,
            'mpc_solve_count': 0,
            'mpc_fallback_count': 0,
        }

    def update_matching_ilp(self, x_val: np.ndarray, defense_weight: Optional[np.ndarray] = None) -> np.ndarray:
        """整数線形計画法によるマッチングの最適化"""
        M_var = cp.Variable((self.config.n_nodes, self.config.m_resources), boolean=True)
        weight = self.config.Q_diag if defense_weight is None else np.asarray(defense_weight, dtype=float)
        weighted_risk = weight * x_val 
        
        expected_reduction = cp.sum(cp.multiply(M_var, np.outer(weighted_risk, np.ones(self.config.m_resources)))) * self.config.r_max
        objective = cp.Minimize(-expected_reduction)

        constraints = []
        for j in range(self.config.m_resources):
            constraints += [cp.sum(M_var[:, j]) <= self.config.resource_capacity[j]]
        for i in range(self.config.n_nodes):
            constraints += [cp.sum(M_var[i, :]) <= 1]

        prob = cp.Problem(objective, constraints)
        self.stats['ilp_solve_count'] += 1
        
        try:
            # ソルバーを固定せず、利用可能な最適なものを自動選択
            prob.solve()
            if M_var.value is None or prob.status not in (cp.OPTIMAL, cp.OPTIMAL_INACCURATE):
                raise ValueError(f"ILP solver status={prob.status}, value={M_var.value}")
            M = np.round(M_var.value)
            if not self._matching_is_feasible(M):
                raise ValueError("ILP solver returned infeasible rounded matching")
            return M
        except Exception as e:
            self.stats['ilp_fallback_count'] += 1
            logger.warning(f"ILP solver failed ({e}). Falling back to greedy allocation.")
            return self._greedy_allocation(weighted_risk)

    def _matching_is_feasible(self, M: np.ndarray) -> bool:
        return (
            M.shape == (self.config.n_nodes, self.config.m_resources)
            and np.all(M >= -1e-8)
            and np.all(M <= 1 + 1e-8)
            and np.all(np.sum(M, axis=0) <= np.asarray(self.config.resource_capacity) + 1e-8)
            and np.all(np.sum(M, axis=1) <= 1 + 1e-8)
        )

    def _greedy_allocation(self, weighted_risk: np.ndarray) -> np.ndarray:
        M_fallback = np.zeros((self.config.n_nodes, self.config.m_resources))
        risk_order = np.argsort(weighted_risk)[::-1]
        caps = list(self.config.resource_capacity)
        
        for node_idx in risk_order:
            for res_idx in range(self.config.m_resources):
                if caps[res_idx] > 0:
                    M_fallback[node_idx, res_idx] = 1.0
                    caps[res_idx] -= 1
                    break
        return M_fallback

    def solve_mpc(
        self,
        x0: np.ndarray,
        r_prev: np.ndarray,
        M_current: np.ndarray,
        defense_weight: Optional[np.ndarray] = None,
        mpc_weight: Optional[np.ndarray] = None,
    ) -> np.ndarray:
        Q_mpc = self._mpc_q_matrix(mpc_weight)
        x_var = cp.Variable((self.config.n_nodes, self.config.H + 1))
        r_var = cp.Variable((self.config.m_resources, self.config.H))
        s_var = cp.Variable((self.config.n_nodes, self.config.H))

        cost = 0
        constraints = [x_var[:, 0] == x0]
        d_k = self.config.d_base + self.config.beta * np.tanh(x0) 
        r_step_prev = r_prev

        for k in range(self.config.H):
            constraints += [
                x_var[:, k+1] == self.config.alpha * x_var[:, k] + d_k - M_current @ r_var[:, k] + s_var[:, k],
                s_var[:, k] >= 0,
                x_var[:, k+1] >= 0
            ]
            constraints += [
                r_var[:, k] >= 0,
                r_var[:, k] <= self.config.r_max,
                cp.sum(r_var[:, k]) <= self.config.R_total
            ]
            cost += cp.quad_form(x_var[:, k], Q_mpc)
            cost += cp.quad_form(r_var[:, k], self.R)
            cost += self.config.lambda_w * cp.sum_squares(r_var[:, k] - r_step_prev)
            cost += self.config.rho * cp.sum_squares(s_var[:, k])
            r_step_prev = r_var[:, k] 

        cost += cp.quad_form(x_var[:, self.config.H], Q_mpc)
        prob = cp.Problem(cp.Minimize(cost), constraints)
        self.stats['mpc_solve_count'] += 1
        
        try:
            prob.solve(solver=cp.OSQP, warm_start=True)
            if r_var[:, 0].value is None or prob.status not in (cp.OPTIMAL, cp.OPTIMAL_INACCURATE):
                raise ValueError(f"MPC solver status={prob.status}")
            return self._clip_resource_vector(r_var[:, 0].value)
        except Exception as e:
            logger.error(f"MPC solver error: {e}")
            self.stats['mpc_fallback_count'] += 1
            return self._greedy_resource_fallback(x0, M_current, defense_weight=defense_weight)

    def _mpc_q_matrix(self, mpc_weight: Optional[np.ndarray]) -> np.ndarray:
        if mpc_weight is None:
            return self.Q
        weight = np.asarray(mpc_weight, dtype=float)
        if weight.shape != (self.config.n_nodes,):
            raise ValueError(f"mpc_weight shape must be ({self.config.n_nodes},)")
        if np.any(weight < 0):
            raise ValueError("mpc_weight entries must be >= 0")
        return np.diag(weight)

    def _clip_resource_vector(self, r_value: np.ndarray) -> np.ndarray:
        r = np.clip(np.asarray(r_value, dtype=float), 0.0, self.config.r_max)
        total = float(np.sum(r))
        if total > self.config.R_total and total > 0:
            r *= self.config.R_total / total
        return r

    def _greedy_resource_fallback(
        self,
        x0: np.ndarray,
        M_current: np.ndarray,
        defense_weight: Optional[np.ndarray] = None,
    ) -> np.ndarray:
        weight = self.config.Q_diag if defense_weight is None else np.asarray(defense_weight, dtype=float)
        scores = M_current.T @ (weight * x0)
        r = np.zeros(self.config.m_resources)
        remaining = self.config.R_total
        for res_idx in np.argsort(scores)[::-1]:
            if remaining <= 1e-12 or scores[res_idx] <= 0:
                break
            amount = min(self.config.r_max, remaining)
            r[res_idx] = amount
            remaining -= amount
        return r

class CyberDefenseSimulator:
    """シミュレーション実行を管理するメインクラス"""
    def __init__(self, config: SimulationConfig):
        config.validate()
        self.config = config
        self.engine = OptimizationEngine(config)
        self.reset()

    def reset(self):
        self.rng = np.random.default_rng(self.config.seed)
        if self.config.seed is not None:
            np.random.seed(self.config.seed)
        self.x_current = self.rng.uniform(0, 1, self.config.n_nodes)
        self.r_prev = np.zeros(self.config.m_resources)
        self.M = self.engine.update_matching_ilp(self.x_current)
        self.current_adjacency_matrix = self.config.adjacency_matrix.copy()
        self.active_adjacency_matrix = self.config.adjacency_matrix.copy()
        self.attacker = self._create_attacker()
        self.attacker_retreat_step = None
        self.first_decoy_step = None
        self.critical_compromise = False
        self.critical_compromise_step = None
        self.defender_observed_belief = np.zeros(self.config.n_nodes)
        self.defender_estimated_belief = self.config.Q_diag.copy()
        self.defender_target_counts = np.zeros(self.config.n_nodes)
        self.defender_visible_log_observation = np.zeros(self.config.n_nodes)
        self.defender_bayesian_alpha = (
            np.ones(self.config.n_nodes, dtype=float) * self.config.defender_bayesian_prior_strength
        )
        self.current_step = -1
        self.mtd_active = False
        self.mtd_event_count = 0
        self.mtd_total_cost = 0.0
        self.mtd_last_step = None
        self.mtd_current_event = False
        self.mtd_affected_belief = self.attacker.current_belief.copy()
        self.mtd_blocked_edges = {}
        self.mtd_blocked_edges_step = []
        self.mtd_edge_block_events = 0
        self.mtd_edge_block_active_steps = 0
        self.mtd_risk_gate_score_current = 0.0
        self.mtd_risk_gate_fired_current = False
        self.mtd_risk_gate_suppressed_current = False
        self.mtd_active_block_count_current = int(self.config.mtd_edge_block_count)
        self.mtd_active_block_duration_current = int(self.config.mtd_edge_block_duration)
        self.mtd_conditional_policy_action_current = "none"
        self.credential_reuse_factor = np.ones(self.config.n_nodes, dtype=float)
        self.last_credential_trigger_step = None
        self.credential_trigger_mtd_event_count = 0
        self.credential_trigger_recently_active_current = False
        self.credential_aware_mtd_fire_current = False
        self.credential_aware_block_count_current = int(self.config.mtd_edge_block_count)
        self.credential_aware_block_duration_current = int(self.config.mtd_edge_block_duration)
        self.credential_mtd_stage_current = "none"
        self.credential_stage1_action_current = False
        self.credential_stage2_action_current = False
        self.history = {
            'x': [],
            'raw_x': [],
            'r': [],
            'M': [],
            'clip_low': [],
            'clip_high': [],
            'matching_update_reason': [],
            'attack_vector': [],
            'attacker_utility': [],
            'attacker_cost': [],
            'attacker_gain': [],
            'actual_utility': [],
            'perceived_utility': [],
            'confidence': [],
            'frustration': [],
            'ai_uncertainty_cost': [],
            'ai_replanning_cost': [],
            'ai_search_cost': [],
            'ai_operational_risk_cost': [],
            'ai_trust_degradation_cost': [],
            'ai_total_decision_cost': [],
            'attacker_retreated': [],
            'attacker_detected': [],
            'attacker_success': [],
            'attacker_selection_score': [],
            'attacker_selected_target': [],
            'attacker_attacked_decoy': [],
            'credential_obtained': [],
            'credential_used': [],
            'credential_decoy_trigger': [],
            'credential_trigger_recently_active': [],
            'credential_aware_mtd_fire': [],
            'credential_aware_block_count': [],
            'credential_aware_block_duration': [],
            'credential_mtd_stage': [],
            'credential_stage1_action': [],
            'credential_stage2_action': [],
            'decoy_waste_step': [],
            'attack_success_prob': [],
            'attack_detection_prob': [],
            'target_defense_strength': [],
            'attacker_current_belief': [],
            'success_memory': [],
            'decoy_memory': [],
            'detection_memory': [],
            'preference_score': [],
            'path_preference_score': [],
            'planning_score': [],
            'trust_score': [],
            'expected_utility': [],
            'defender_observed_belief': [],
            'defender_estimated_belief': [],
            'defender_target_counts': [],
            'defender_visible_log_observation': [],
            'defender_bayesian_alpha': [],
            'defender_bayesian_belief': [],
            'effective_defense_weight': [],
            'post_decoy_defense_active': [],
            'post_decoy_defense_injection_mode': [],
            'post_decoy_defense_matching_active': [],
            'post_decoy_defense_fallback_active': [],
            'post_decoy_defense_mpc_q_active': [],
            'mtd_active': [],
            'mtd_event': [],
            'mtd_total_cost': [],
            'mtd_affected_belief': [],
            'mtd_blocked_edges_step': [],
            'mtd_risk_gate_score': [],
            'mtd_risk_gate_fired': [],
            'mtd_risk_gate_suppressed': [],
            'mtd_active_block_count': [],
            'mtd_active_block_duration': [],
            'mtd_conditional_policy_action': [],
            'attacker_current_node': [],
            'attacker_visited_nodes': [],
            'attacker_compromised_nodes': [],
            'critical_compromise': [],
            'adjacency_matrix': [],
            'active_adjacency_matrix': [],
            'attacker_perceived_gain': [],
            'attacker_critical_true_gain': [],
            'belief_entropy': [],
        }

    def _create_attacker(self) -> AttackerModel:
        return AttackerModel(
            enabled=self.config.attacker_enabled,
            attack_budget=self.config.attacker_attack_budget,
            target_selection=self.config.attacker_target_selection,
            greedy_mode=self.config.attacker_greedy_mode,
            attacker_belief=self.config.attacker_belief.copy(),
            effort_cost_rate=self.config.attacker_effort_cost_rate,
            detection_penalty=self.config.attacker_detection_penalty,
            retreat_threshold=self.config.attacker_retreat_threshold,
            patience=self.config.attacker_patience,
            defense_cost_rate=self.config.attacker_defense_cost_rate,
            detection_sensitivity=self.config.attacker_detection_sensitivity,
            success_base_rate=self.config.attacker_success_base_rate,
            success_defense_decay=self.config.attacker_success_defense_decay,
            belief_learning_enabled=self.config.attacker_belief_learning_enabled,
            belief_success_boost=self.config.attacker_belief_success_boost,
            belief_failure_decay=self.config.attacker_belief_failure_decay,
            belief_detection_decay=self.config.attacker_belief_detection_decay,
            belief_decoy_decay=self.config.attacker_belief_decoy_decay,
            belief_min=self.config.attacker_belief_min,
            belief_max=self.config.attacker_belief_max,
            adaptive_attacker_enabled=self.config.adaptive_attacker_enabled,
            adaptive_success_weight=self.config.adaptive_success_weight,
            adaptive_decoy_weight=self.config.adaptive_decoy_weight,
            adaptive_detection_weight=self.config.adaptive_detection_weight,
            adaptive_preference_enabled=self.config.adaptive_preference_enabled,
            adaptive_preference_weight=self.config.adaptive_preference_weight,
            adaptive_success_reward=self.config.adaptive_success_reward,
            adaptive_critical_reward=self.config.adaptive_critical_reward,
            adaptive_decoy_penalty=self.config.adaptive_decoy_penalty,
            adaptive_detection_penalty=self.config.adaptive_detection_penalty,
            adaptive_path_enabled=self.config.adaptive_path_enabled,
            path_preference_weight=self.config.path_preference_weight,
            path_success_reward=self.config.path_success_reward,
            path_critical_reward=self.config.path_critical_reward,
            path_decoy_penalty=self.config.path_decoy_penalty,
            path_detection_penalty=self.config.path_detection_penalty,
            adaptive_planning_enabled=self.config.adaptive_planning_enabled,
            planning_depth=self.config.planning_depth,
            planning_success_weight=self.config.planning_success_weight,
            planning_critical_weight=self.config.planning_critical_weight,
            planning_decoy_penalty=self.config.planning_decoy_penalty,
            planning_detection_penalty=self.config.planning_detection_penalty,
            trust_enabled=self.config.trust_enabled,
            trust_decoy_penalty=self.config.trust_decoy_penalty,
            trust_credential_penalty=self.config.trust_credential_penalty,
            trust_detection_penalty=self.config.trust_detection_penalty,
            trust_success_reward=self.config.trust_success_reward,
            expected_utility_enabled=self.config.expected_utility_enabled,
            expected_gain_weight=self.config.expected_gain_weight,
            expected_success_weight=self.config.expected_success_weight,
            expected_detection_cost=self.config.expected_detection_cost,
            expected_search_cost=self.config.expected_search_cost,
            expected_trust_weight=self.config.expected_trust_weight,
            lateral_enabled=self.config.attacker_lateral_enabled,
            lateral_success_prob=self.config.attacker_lateral_success_prob,
            lateral_detection_prob=self.config.attacker_lateral_detection_prob,
            adjacency_matrix=self.active_adjacency_matrix.copy(),
            entry_nodes=list(self.config.entry_nodes),
            node_type=list(self.config.node_type),
            critical_nodes=list(self.config.critical_nodes),
            perceived_no_progress_threshold=self.config.attacker_perceived_no_progress_threshold,
            perceived_utility_enabled=self.config.perceived_utility_enabled,
            perceived_success_confidence=self.config.perceived_success_confidence,
            perceived_decoy_penalty=self.config.perceived_decoy_penalty,
            perceived_detection_penalty=self.config.perceived_detection_penalty,
            perceived_uncertainty_decay=self.config.perceived_uncertainty_decay,
            retreat_based_on=self.config.retreat_based_on,
            frustration_enabled=self.config.frustration_enabled,
            frustration_decoy_hit=self.config.frustration_decoy_hit,
            frustration_credential_trap=self.config.frustration_credential_trap,
            frustration_detection=self.config.frustration_detection,
            frustration_path_change=self.config.frustration_path_change,
            frustration_no_progress=self.config.frustration_no_progress,
            frustration_decay=self.config.frustration_decay,
            frustration_retreat_threshold=self.config.frustration_retreat_threshold,
        )

    def _attacker_risk_view(self) -> np.ndarray:
        risk_view = self.x_current.copy()
        if not self.config.honeypot_credential_enabled:
            return risk_view
        for node_id in self.config.credential_node_ids:
            risk_view[int(node_id)] += (
                self.config.credential_attraction_bonus
                * self.credential_reuse_factor[int(node_id)]
            )
        return risk_view

    def _resolve_credential_observation(
        self,
        selected_target: int,
        success: bool,
        attack_active: bool,
    ) -> tuple[bool, bool, bool]:
        if (
            not self.config.honeypot_credential_enabled
            or not attack_active
            or not success
            or selected_target < 0
            or selected_target not in self.config.credential_node_ids
        ):
            return False, False, False

        obtain_probability = (
            1.0
            if self.config.credential_attraction_bonus >= 1.0
            else self.config.credential_attraction_bonus
        )
        credential_obtained = bool(self.rng.random() < obtain_probability)
        credential_used = credential_obtained
        credential_decoy_trigger = credential_used
        if credential_decoy_trigger:
            self.credential_reuse_factor[int(selected_target)] *= self.config.credential_reuse_decay
        return credential_obtained, credential_used, credential_decoy_trigger

    def _credential_trigger_recently_active(self, t: int) -> bool:
        if self.last_credential_trigger_step is None:
            return False
        return t - int(self.last_credential_trigger_step) <= self.config.credential_trigger_mtd_window

    def _credential_mtd_stage(self, t: int) -> str:
        if self.last_credential_trigger_step is None:
            return "none"
        age = t - int(self.last_credential_trigger_step)
        if age <= self.config.credential_stage1_window:
            return "stage1"
        if age <= self.config.credential_stage2_window:
            return "stage2"
        return "none"

    def run(self):
        logger.info(f"Starting simulation for T={self.config.T} steps...")
        for t in range(self.config.T):
            self.current_step = t
            self._restore_expired_mtd_edge_blocks(t)
            self._sync_attacker_adjacency()
            x_previous = self.x_current.copy()
            defense_weight = self._effective_defense_weight()
            post_decoy_defense_active = bool(not np.allclose(defense_weight, self.config.Q_diag))
            fallback_weight = self._fallback_weight_for_mode(defense_weight)
            mpc_weight = self._mpc_weight_for_mode(defense_weight)
            r_opt = self.engine.solve_mpc(
                self.x_current,
                self.r_prev,
                self.M,
                defense_weight=fallback_weight,
                mpc_weight=mpc_weight,
            )
            mtd_affected_belief = self._apply_mtd(t)
            attack_vector = self.attacker.select_attack(self._attacker_risk_view(), self.M)
            selected_target = int(self.attacker.last_selected_target)
            attacked_decoy = self._is_decoy_target(selected_target)
            target_defense_strength = self._target_defense_strength(selected_target, r_opt)
            d_current = self.config.d_base + self.config.beta * np.tanh(self.x_current) + attack_vector
            raw_x = self.config.alpha * self.x_current + d_current - self.M @ r_opt
            self.x_current = np.clip(raw_x, 0, 100)
            clip_low = np.maximum(0.0, -raw_x)
            clip_high = np.maximum(0.0, raw_x - 100.0)
            attack_active = bool(self.attacker.enabled and np.sum(attack_vector) > 0.0)
            decoy_waste_step = self.config.decoy_waste_cost if attack_active and attacked_decoy else 0.0
            detection_penalty_step = self.config.decoy_detection_bonus if attack_active and attacked_decoy else 0.0
            gained = self._calculate_attacker_gain(
                x_previous,
                self.x_current,
                selected_target,
            ) if attack_active else 0.0
            if attack_active:
                if self.config.attacker_lateral_enabled:
                    success_prob = self._lateral_success_probability(attacked_decoy)
                    success = bool(self.rng.random() < success_prob)
                else:
                    success_prob = self._attack_success_probability(
                        gained,
                        attacked_decoy,
                        target_defense_strength,
                    )
                    success = self._attack_succeeds(gained, attacked_decoy, target_defense_strength)
                if not success:
                    gained = 0.0
                # Perceived gain: what the attacker believes they gained (belief-based, no decoy penalty).
                # For real-node attacks: zeroed on failure (attacker knows the attack was repelled).
                # For decoy attacks: NOT zeroed on the success flag, because in deterministic mode
                # success=False is an artifact of decoy_success_gain_scale=0 zeroing the true gain;
                # the attacker still observes a state change and perceives positive value.
                perceived_gain = self._calculate_perceived_gain(x_previous, self.x_current, selected_target)
                if not success and not attacked_decoy:
                    perceived_gain = 0.0
                # Critical true gain: attack-ONLY contribution to critical-node risk.
                # Counterfactual definition:
                #   natural_raw = raw_x - attack_vector  (state without the attack vector)
                #   attack_contribution[i] = clip(raw_x[i],0,100) - clip(natural_raw[i],0,100)
                #                          = x_current[i] - clip(raw_x[i] - attack_vector[i], 0, 100)
                # When attack_vector[critical]=0 (critical not attacked): contribution=0 → no drift.
                # When attack_vector[critical]>0 (critical directly attacked): contribution>0.
                # This excludes d_base / alpha*x / beta*tanh(x) natural-drift terms from the metric,
                # so a perfect defender that prevents all critical attacks will see critical_true_gain=0.
                _natural_raw = raw_x - attack_vector
                _attack_contribution = np.maximum(
                    np.clip(raw_x, 0.0, 100.0) - np.clip(_natural_raw, 0.0, 100.0),
                    0.0,
                )
                _critical_idx = np.asarray(list(self.config.critical_nodes), dtype=int)
                critical_true_gain = float(
                    np.sum(_attack_contribution[_critical_idx] * self.config.asset_value[_critical_idx])
                )
                credential_obtained, credential_used, credential_decoy_trigger = self._resolve_credential_observation(
                    selected_target=selected_target,
                    success=success,
                    attack_active=attack_active,
                )
                if credential_decoy_trigger:
                    self.last_credential_trigger_step = t
                    # Credential access perceived value: attacker believes they gained privileged
                    # access worth belief[target] × credential_attraction_bonus.
                    # True gain: zero (credential node is a honeypot; only perceived is affected).
                    if selected_target >= 0 and self.attacker.current_belief is not None:
                        perceived_gain += (
                            float(self.attacker.current_belief[selected_target])
                            * self.config.credential_attraction_bonus
                        )
                if self.config.attacker_lateral_enabled:
                    detection_prob = self._lateral_detection_probability(credential_decoy_trigger)
                    detected = bool(self.rng.random() < detection_prob)
                else:
                    detection_prob = self._attack_detection_probability(
                        r_opt,
                        success,
                        attacked_decoy,
                        target_defense_strength,
                        credential_decoy_trigger,
                    )
                    detected = self._detect_attacker(
                        r_opt,
                        success,
                        attacked_decoy=attacked_decoy,
                        target_defense_strength=target_defense_strength,
                        credential_decoy_trigger=credential_decoy_trigger,
                    )
            else:
                success = False
                detected = False
                success_prob = 0.0
                detection_prob = 0.0
                credential_obtained = False
                credential_used = False
                credential_decoy_trigger = False
                perceived_gain = 0.0
                critical_true_gain = 0.0
            path_changed = (
                self.config.attacker_lateral_enabled
                and self.attacker.previous_selected_target >= 0
                and selected_target >= 0
                and self.attacker.previous_selected_target != selected_target
            )
            no_progress = (
                self.config.attacker_lateral_enabled
                and selected_target >= 0
                and not self._target_moves_closer_to_critical(int(self.attacker.current_node), int(selected_target))
            )
            self.attacker.update_state(
                gained=gained,
                detected=detected,
                success=success,
                deception_waste_step=decoy_waste_step,
                detection_penalty_step=detection_penalty_step,
                perceived_gained=perceived_gain,
                attacked_decoy=attacked_decoy,
                credential_decoy_trigger=credential_decoy_trigger,
                path_changed=path_changed,
                no_progress=no_progress,
            )
            self.attacker.update_belief(
                target_idx=selected_target,
                success=success,
                detected=detected,
                attacked_decoy=attacked_decoy,
            )
            critical_reached = bool(
                attack_active
                and success
                and selected_target in self.config.critical_nodes
            )
            path_key = self.attacker.path_key_for_target(selected_target) if selected_target >= 0 else None
            self.attacker.update_memory(
                target_idx=selected_target,
                success=success,
                detected=detected,
                attacked_decoy=attacked_decoy,
                critical_reached=critical_reached,
                path_key=path_key,
            )
            self.attacker.update_trust(
                target_idx=selected_target,
                success=success,
                detected=detected,
                attacked_decoy=attacked_decoy,
                credential_decoy_trigger=credential_decoy_trigger,
            )
            belief_entropy_step = self._belief_entropy()
            self.attacker.record_lateral_result(selected_target, success)
            if (
                critical_reached
                and not self.critical_compromise
            ):
                self.critical_compromise = True
                self.critical_compromise_step = t
            if attack_active and attacked_decoy and self.first_decoy_step is None:
                self.first_decoy_step = t
            if self.attacker.retreated and self.attacker_retreat_step is None:
                self.attacker_retreat_step = t

            self._update_defender_belief_estimate(
                selected_target=selected_target,
                selection_score=self.attacker.last_selection_score,
                attack_active=attack_active,
                success=success,
                detected=detected,
                attacked_decoy=attacked_decoy,
                target_defense_strength=target_defense_strength,
                attack_success_prob=success_prob,
                attack_detection_prob=detection_prob,
            )
            self._update_defender_bayesian_belief(
                selected_target=selected_target,
                success=success,
                detected=detected,
                attacked_decoy=attacked_decoy,
            )
            
            self.history['x'].append(self.x_current.copy())
            self.history['raw_x'].append(raw_x.copy())
            self.history['r'].append(r_opt.copy())
            self.history['M'].append(self.M.copy())
            self.history['clip_low'].append(clip_low)
            self.history['clip_high'].append(clip_high)
            self.history['attack_vector'].append(attack_vector.copy())
            self.history['attacker_utility'].append(float(self.attacker.utility))
            self.history['attacker_cost'].append(float(self.attacker.total_cost))
            self.history['attacker_gain'].append(float(gained))
            self.history['actual_utility'].append(float(self.attacker.actual_utility))
            self.history['perceived_utility'].append(float(self.attacker.perceived_utility))
            self.history['confidence'].append(float(self.attacker.confidence))
            self.history['frustration'].append(float(self.attacker.frustration))
            ai_total_decision_cost = (
                self.attacker.ai_uncertainty_cost * self.config.ai_uncertainty_weight
                + self.attacker.ai_replanning_cost * self.config.ai_replanning_weight
                + self.attacker.ai_search_cost * self.config.ai_search_weight
                + self.attacker.ai_operational_risk_cost * self.config.ai_operational_risk_weight
                + self.attacker.ai_trust_degradation_cost * self.config.ai_trust_degradation_weight
            )
            self.history['ai_uncertainty_cost'].append(float(self.attacker.ai_uncertainty_cost))
            self.history['ai_replanning_cost'].append(float(self.attacker.ai_replanning_cost))
            self.history['ai_search_cost'].append(float(self.attacker.ai_search_cost))
            self.history['ai_operational_risk_cost'].append(float(self.attacker.ai_operational_risk_cost))
            self.history['ai_trust_degradation_cost'].append(float(self.attacker.ai_trust_degradation_cost))
            self.history['ai_total_decision_cost'].append(float(ai_total_decision_cost))
            self.history['attacker_retreated'].append(bool(self.attacker.retreated))
            self.history['attacker_detected'].append(bool(detected))
            self.history['attacker_success'].append(bool(success))
            self.history['attacker_selection_score'].append(self.attacker.last_selection_score.copy())
            self.history['attacker_selected_target'].append(int(self.attacker.last_selected_target))
            self.history['attacker_attacked_decoy'].append(bool(attack_active and attacked_decoy))
            self.history['credential_obtained'].append(bool(credential_obtained))
            self.history['credential_used'].append(bool(credential_used))
            self.history['credential_decoy_trigger'].append(bool(credential_decoy_trigger))
            self.history['credential_trigger_recently_active'].append(bool(self.credential_trigger_recently_active_current))
            self.history['credential_aware_mtd_fire'].append(bool(self.credential_aware_mtd_fire_current))
            self.history['credential_aware_block_count'].append(int(self.credential_aware_block_count_current))
            self.history['credential_aware_block_duration'].append(int(self.credential_aware_block_duration_current))
            self.history['credential_mtd_stage'].append(str(self.credential_mtd_stage_current))
            self.history['credential_stage1_action'].append(bool(self.credential_stage1_action_current))
            self.history['credential_stage2_action'].append(bool(self.credential_stage2_action_current))
            self.history['decoy_waste_step'].append(float(decoy_waste_step))
            self.history['attack_success_prob'].append(float(success_prob))
            self.history['attack_detection_prob'].append(float(detection_prob))
            self.history['target_defense_strength'].append(float(target_defense_strength))
            self.history['attacker_current_belief'].append(self.attacker.current_belief.copy())
            self.history['success_memory'].append(
                self.attacker.memory_vector('node_success_memory', self.config.n_nodes)
            )
            self.history['decoy_memory'].append(
                self.attacker.memory_vector('node_decoy_memory', self.config.n_nodes)
            )
            self.history['detection_memory'].append(
                self.attacker.memory_vector('node_detection_memory', self.config.n_nodes)
            )
            self.history['preference_score'].append(
                self.attacker.memory_vector('node_preference_score', self.config.n_nodes)
            )
            self.history['path_preference_score'].append(self.attacker.serialized_path_preference())
            self.history['planning_score'].append(
                np.asarray(self.attacker.last_planning_score, dtype=float).copy()
                if self.attacker.last_planning_score is not None
                else np.zeros(self.config.n_nodes, dtype=float)
            )
            self.history['trust_score'].append(self.attacker.trust_vector(self.config.n_nodes))
            self.history['expected_utility'].append(
                np.asarray(self.attacker.last_expected_utility, dtype=float).copy()
                if self.attacker.last_expected_utility is not None
                else np.zeros(self.config.n_nodes, dtype=float)
            )
            self.history['defender_observed_belief'].append(self.defender_observed_belief.copy())
            self.history['defender_estimated_belief'].append(self.defender_estimated_belief.copy())
            self.history['defender_target_counts'].append(self.defender_target_counts.copy())
            self.history['defender_visible_log_observation'].append(self.defender_visible_log_observation.copy())
            self.history['defender_bayesian_alpha'].append(self.defender_bayesian_alpha.copy())
            self.history['defender_bayesian_belief'].append(self._defender_bayesian_belief().copy())
            self.history['effective_defense_weight'].append(defense_weight.copy())
            self.history['post_decoy_defense_active'].append(post_decoy_defense_active)
            self.history['post_decoy_defense_injection_mode'].append(self.config.post_decoy_defense_injection_mode)
            self.history['post_decoy_defense_matching_active'].append(
                bool(post_decoy_defense_active and self.config.post_decoy_defense_injection_mode in ("matching_only", "matching_fallback", "all"))
            )
            self.history['post_decoy_defense_fallback_active'].append(
                bool(post_decoy_defense_active and self.config.post_decoy_defense_injection_mode in ("fallback_only", "matching_fallback", "all"))
            )
            self.history['post_decoy_defense_mpc_q_active'].append(
                bool(post_decoy_defense_active and self.config.post_decoy_defense_injection_mode in ("mpc_q", "all"))
            )
            self.history['mtd_active'].append(bool(self.mtd_active))
            self.history['mtd_event'].append(bool(self.mtd_current_event))
            self.history['mtd_total_cost'].append(float(self.mtd_total_cost))
            self.history['mtd_affected_belief'].append(mtd_affected_belief.copy())
            blocked_edges = sorted(self.mtd_blocked_edges.keys())
            self.history['mtd_blocked_edges_step'].append('|'.join(blocked_edges))
            self.history['mtd_risk_gate_score'].append(float(self.mtd_risk_gate_score_current))
            self.history['mtd_risk_gate_fired'].append(bool(self.mtd_risk_gate_fired_current))
            self.history['mtd_risk_gate_suppressed'].append(bool(self.mtd_risk_gate_suppressed_current))
            self.history['mtd_active_block_count'].append(int(self.mtd_active_block_count_current))
            self.history['mtd_active_block_duration'].append(int(self.mtd_active_block_duration_current))
            self.history['mtd_conditional_policy_action'].append(str(self.mtd_conditional_policy_action_current))
            if blocked_edges:
                self.mtd_edge_block_active_steps += 1
            self.history['attacker_current_node'].append(int(self.attacker.current_node))
            self.history['attacker_visited_nodes'].append(self._set_to_indicator(self.attacker.visited_nodes))
            self.history['attacker_compromised_nodes'].append(self._set_to_indicator(self.attacker.compromised_nodes))
            self.history['critical_compromise'].append(bool(self.critical_compromise))
            self.history['adjacency_matrix'].append(self.current_adjacency_matrix.copy())
            self.history['active_adjacency_matrix'].append(self.active_adjacency_matrix.copy())
            self.history['attacker_perceived_gain'].append(float(perceived_gain))
            self.history['attacker_critical_true_gain'].append(float(critical_true_gain))
            self.history['belief_entropy'].append(float(belief_entropy_step))
            self.r_prev = r_opt.copy()

            reason = self._check_and_update_matching(t, x_previous)
            self.history['matching_update_reason'].append(reason)
            if self.config.stop_on_attacker_retreat and self.attacker.retreated:
                logger.info(f"Attacker retreated at step {t}. Stopping simulation early.")
                break
        return self.history

    def _effective_defense_weight(self) -> np.ndarray:
        weights = self.config.Q_diag.copy()
        if (
            not self.config.post_decoy_defense_enabled
            or self.first_decoy_step is None
            or self.config.post_decoy_defense_top_k == 0
        ):
            return weights

        if self.config.post_decoy_defense_belief_source == "attacker":
            belief = np.asarray(self.attacker.current_belief, dtype=float).copy()
        elif self.config.post_decoy_defense_belief_source == "bayesian":
            belief = self._defender_bayesian_belief()
        else:
            belief = np.asarray(self.defender_estimated_belief, dtype=float).copy()
        if self.config.post_decoy_defense_exclude_decoy:
            decoy_mask = np.asarray([value == "decoy" for value in self.config.node_type], dtype=bool)
            belief[decoy_mask] = 0.0

        top_k = min(self.config.post_decoy_defense_top_k, self.config.n_nodes)
        if top_k <= 0 or np.all(belief <= 0):
            return weights
        top_indices = np.argsort(belief)[::-1][:top_k]
        boost = np.zeros_like(weights)
        boost[top_indices] = belief[top_indices]
        return np.clip(weights + (self.config.post_decoy_defense_weight * boost), 0.0, None)

    def _apply_mtd(self, t: int) -> np.ndarray:
        self.mtd_active = False
        self.mtd_current_event = False
        self.mtd_affected_belief = self.attacker.current_belief.copy()
        self.mtd_active_block_count_current = int(self.config.mtd_edge_block_count)
        self.mtd_active_block_duration_current = int(self.config.mtd_edge_block_duration)
        self.mtd_conditional_policy_action_current = "none"
        self.credential_trigger_recently_active_current = (
            self.config.credential_aware_mtd_enabled
            and self._credential_trigger_recently_active(t)
        )
        self.credential_aware_mtd_fire_current = False
        self.credential_aware_block_count_current = int(self.config.mtd_edge_block_count)
        self.credential_aware_block_duration_current = int(self.config.mtd_edge_block_duration)
        self.credential_mtd_stage_current = (
            self._credential_mtd_stage(t)
            if self.config.credential_staged_mtd_enabled
            else "none"
        )
        self.credential_stage1_action_current = False
        self.credential_stage2_action_current = False
        self.mtd_risk_gate_score_current = (
            self._mtd_risk_gate_score()
            if self.config.mtd_enabled
            and (
                self.config.mtd_risk_gating_enabled
                or self.config.mtd_conditional_policy_enabled
                or self.config.credential_aware_mtd_enabled
                or self.config.credential_staged_mtd_enabled
            )
            else 0.0
        )
        self.mtd_risk_gate_fired_current = False
        self.mtd_risk_gate_suppressed_current = False
        if not self.config.mtd_enabled:
            return self.mtd_affected_belief.copy()
        interval_due = (t + 1) % self.config.mtd_interval == 0
        cooldown_ok = (
            self.mtd_last_step is None
            or t - self.mtd_last_step >= self.config.mtd_risk_gate_cooldown
        )
        credential_force = (
            self.config.credential_aware_mtd_enabled
            and self.config.credential_trigger_force_mtd
            and self.credential_trigger_recently_active_current
        )
        staged_force = (
            self.config.credential_staged_mtd_enabled
            and self.credential_mtd_stage_current != "none"
        )
        credential_force = bool(credential_force and not self.config.credential_staged_mtd_enabled)
        if not interval_due and not credential_force and not staged_force:
            return self.mtd_affected_belief.copy()
        if (credential_force or staged_force) and not cooldown_ok:
            self.mtd_risk_gate_suppressed_current = True
            return self.mtd_affected_belief.copy()
        if self.config.mtd_conditional_policy_enabled and not credential_force and not staged_force:
            action, block_count, block_duration = self._select_mtd_conditional_policy(
                self.mtd_risk_gate_score_current
            )
            self.mtd_conditional_policy_action_current = action
            self.mtd_active_block_count_current = int(block_count)
            self.mtd_active_block_duration_current = int(block_duration)
            if action == "suppress" or not cooldown_ok:
                self.mtd_risk_gate_suppressed_current = True
                return self.mtd_affected_belief.copy()
        elif self.config.mtd_risk_gating_enabled and not credential_force and not staged_force:
            if self.mtd_risk_gate_score_current < self.config.mtd_risk_gate_threshold or not cooldown_ok:
                self.mtd_risk_gate_suppressed_current = True
                return self.mtd_affected_belief.copy()
        if staged_force:
            if self.credential_mtd_stage_current == "stage1":
                self.mtd_active_block_count_current = int(self.config.credential_stage1_block_count)
                self.mtd_active_block_duration_current = int(self.config.credential_stage1_block_duration)
            elif self.credential_mtd_stage_current == "stage2":
                self.mtd_active_block_count_current = int(self.config.credential_stage2_block_count)
                self.mtd_active_block_duration_current = int(self.config.credential_stage2_block_duration)
            self.credential_aware_block_count_current = int(self.mtd_active_block_count_current)
            self.credential_aware_block_duration_current = int(self.mtd_active_block_duration_current)
        elif self.credential_trigger_recently_active_current:
            self.mtd_active_block_count_current = int(self.config.credential_trigger_block_count)
            self.mtd_active_block_duration_current = int(self.config.credential_trigger_block_duration)
            self.credential_aware_block_count_current = int(self.mtd_active_block_count_current)
            self.credential_aware_block_duration_current = int(self.mtd_active_block_duration_current)

        current = np.asarray(self.attacker.current_belief, dtype=float).copy()
        intensity = self.config.mtd_intensity
        if self.config.mtd_strategy == "shuffle_belief":
            adjusted = (1.0 - intensity) * current + intensity * self.rng.permutation(current)
        elif self.config.mtd_strategy == "decay_belief":
            adjusted = current * (1.0 - intensity)
        elif self.config.mtd_strategy == "increase_uncertainty":
            adjusted = (1.0 - intensity) * current + intensity * float(np.mean(current))
        else:
            adjusted = current

        adjusted = np.clip(
            adjusted,
            self.config.attacker_belief_min,
            self.config.attacker_belief_max,
        )
        self.attacker.current_belief = adjusted
        self.mtd_active = True
        self.mtd_current_event = True
        self.credential_aware_mtd_fire_current = bool(
            self.credential_trigger_recently_active_current or staged_force
        )
        self.credential_stage1_action_current = bool(staged_force and self.credential_mtd_stage_current == "stage1")
        self.credential_stage2_action_current = bool(staged_force and self.credential_mtd_stage_current == "stage2")
        if self.credential_aware_mtd_fire_current:
            self.credential_trigger_mtd_event_count += 1
        self.mtd_risk_gate_fired_current = bool(self.config.mtd_risk_gating_enabled)
        self.mtd_event_count += 1
        self.mtd_total_cost += self.config.mtd_cost
        self.mtd_last_step = t
        self.mtd_affected_belief = adjusted.copy()
        if self.config.mtd_shuffle_topology:
            self._shuffle_topology()
        if self.config.mtd_block_critical_edges:
            self._block_critical_edges(t)
        self._sync_attacker_adjacency()
        return adjusted.copy()

    def _mtd_risk_gate_score(self) -> float:
        mode = self.config.mtd_risk_gate_mode
        risk = np.asarray(self.x_current, dtype=float)
        score = 0.0
        if mode == "critical_path_risk":
            nodes = self._critical_path_nodes()
            score = float(sum(risk[int(node)] for node in nodes))
        elif mode == "chokepoint_risk":
            paths = self._paths_to_critical()
            node_frequency = self._node_path_frequency(paths)
            nodes = self._chokepoint_nodes(node_frequency)
            score = float(sum(risk[int(node)] for node in nodes))
        elif mode == "critical_edge_pressure":
            total = 0.0
            for edge in self._critical_edges():
                src, dst = self._parse_edge_key(edge)
                total += float(risk[src] + risk[dst])
            score = total
        if (
            self.config.credential_aware_mtd_enabled
            and self._credential_trigger_recently_active(self.current_step)
        ):
            score += self.config.credential_trigger_risk_bonus
        return float(score)

    def _select_mtd_conditional_policy(self, score: float) -> tuple:
        mode = self.config.mtd_conditional_policy_mode
        if mode == "edge_pressure_split":
            if score >= self.config.mtd_conditional_high_risk_threshold:
                return "count2", 2, 1
            if score >= self.config.mtd_conditional_low_risk_threshold:
                return "duration2", 1, 2
            return "suppress", 0, 0
        if mode == "critical_vs_post_decoy":
            if score >= self.config.mtd_conditional_high_risk_threshold:
                return "count2", 2, 1
            if self.first_decoy_step is not None:
                return "duration2", 1, 2
            return "suppress", 0, 0
        return "suppress", 0, 0

    def _mtd_recently_active(self, t: Optional[int] = None) -> bool:
        step = self.current_step if t is None else t
        return self.mtd_last_step is not None and step == self.mtd_last_step

    def _sync_attacker_adjacency(self) -> None:
        self.attacker.adjacency_matrix = self.active_adjacency_matrix.copy()

    def _restore_expired_mtd_edge_blocks(self, t: int) -> None:
        expired = [edge for edge, expires_at in self.mtd_blocked_edges.items() if t >= expires_at]
        for edge in expired:
            del self.mtd_blocked_edges[edge]
        self.active_adjacency_matrix = self.current_adjacency_matrix.copy()
        for edge in self.mtd_blocked_edges:
            i, j = self._parse_edge_key(edge)
            self.active_adjacency_matrix[i, j] = 0
            self.active_adjacency_matrix[j, i] = 0

    def _block_critical_edges(self, t: int) -> None:
        block_count = int(self.mtd_active_block_count_current)
        block_duration = int(self.mtd_active_block_duration_current)
        if block_count <= 0 or block_duration <= 0:
            return
        critical_edges = self._critical_edges()
        selected = []
        for edge in critical_edges:
            if edge in self.mtd_blocked_edges:
                continue
            i, j = self._parse_edge_key(edge)
            if self.active_adjacency_matrix[i, j] <= 0 and self.active_adjacency_matrix[j, i] <= 0:
                continue
            selected.append(edge)
            if len(selected) >= block_count:
                break
        if not selected:
            return
        expires_at = t + block_duration
        for edge in selected:
            i, j = self._parse_edge_key(edge)
            self.mtd_blocked_edges[edge] = expires_at
            self.active_adjacency_matrix[i, j] = 0
            self.active_adjacency_matrix[j, i] = 0
        self.mtd_blocked_edges_step = selected
        self.mtd_edge_block_events += 1

    def _parse_edge_key(self, edge: str) -> tuple:
        left, right = edge.split("->", 1)
        return int(left), int(right)

    def _shuffle_topology(self) -> None:
        protected = set(self.config.entry_nodes) | set(self.config.critical_nodes)
        candidates = [idx for idx in range(self.config.n_nodes) if idx not in protected]
        if len(candidates) < 2:
            return
        adjacency = self.current_adjacency_matrix.copy()
        for _ in range(10):
            a, b = self.rng.choice(candidates, size=2, replace=False)
            a = int(a)
            b = int(b)
            previous = int(adjacency[a, b])
            adjacency[a, b] = adjacency[b, a] = 1 - previous
            if self._entry_can_reach_critical(adjacency):
                self.current_adjacency_matrix = adjacency
                self._restore_expired_mtd_edge_blocks(self.current_step)
                self._sync_attacker_adjacency()
                return
            adjacency[a, b] = adjacency[b, a] = previous

    def _reachable_from_entries(self) -> set:
        # Use active_adjacency_matrix so MTD edge blocks are reflected in reachability.
        # Falls back to config.adjacency_matrix if active_adjacency_matrix is not yet
        # initialized (should not happen after reset(), but guarded for safety).
        adjacency = (
            self.active_adjacency_matrix
            if hasattr(self, 'active_adjacency_matrix')
            else self.config.adjacency_matrix
        )
        reachable = set()
        stack = [int(node) for node in self.config.entry_nodes]
        while stack:
            node = stack.pop()
            if node in reachable:
                continue
            reachable.add(node)
            for neighbor in np.flatnonzero(adjacency[node] > 0).astype(int).tolist():
                if neighbor not in reachable:
                    stack.append(int(neighbor))
        return reachable

    def _paths_to_critical_on(self, adjacency: np.ndarray, max_depth: int = 6) -> list:
        """Compute paths from entry nodes to critical nodes on the given adjacency matrix.
        Used by _paths_to_critical() (active topology) and calculate_metrics() (static topology).
        """
        critical = set(int(node) for node in self.config.critical_nodes)
        paths: list = []

        def dfs(node: int, path: list) -> None:
            if len(path) - 1 > max_depth:
                return
            if node in critical:
                paths.append(list(path))
                return
            for neighbor in np.flatnonzero(adjacency[node] > 0).astype(int).tolist():
                neighbor = int(neighbor)
                if neighbor in path:
                    continue
                dfs(neighbor, path + [neighbor])

        for entry in self.config.entry_nodes:
            dfs(int(entry), [int(entry)])
        return paths

    def _paths_to_critical(self, max_depth: int = 6) -> list:
        # Use active_adjacency_matrix so MTD edge blocks shrink the reachable path set.
        # This ensures _mtd_risk_gate_score() and _block_critical_edges() operate on the
        # actual live topology rather than the static initial topology.
        # Falls back to config.adjacency_matrix if active_adjacency_matrix is not yet
        # initialized (should not happen after reset(), but guarded for safety).
        adjacency = (
            self.active_adjacency_matrix
            if hasattr(self, 'active_adjacency_matrix')
            else self.config.adjacency_matrix
        )
        return self._paths_to_critical_on(adjacency, max_depth)

    def _distance_to_nearest_critical(self, source: int) -> Optional[int]:
        if int(source) in {int(node) for node in self.config.critical_nodes}:
            return 0
        adjacency = (
            self.active_adjacency_matrix
            if hasattr(self, 'active_adjacency_matrix')
            else self.config.adjacency_matrix
        )
        critical = {int(node) for node in self.config.critical_nodes}
        visited = {int(source)}
        queue = [(int(source), 0)]
        while queue:
            node, distance = queue.pop(0)
            for neighbor in np.flatnonzero(adjacency[node] > 0).astype(int).tolist():
                neighbor = int(neighbor)
                if neighbor in visited:
                    continue
                if neighbor in critical:
                    return distance + 1
                visited.add(neighbor)
                queue.append((neighbor, distance + 1))
        return None

    def _target_moves_closer_to_critical(self, current_node: int, target_node: int) -> bool:
        current_distance = self._distance_to_nearest_critical(current_node)
        target_distance = self._distance_to_nearest_critical(target_node)
        if current_distance is None or target_distance is None:
            return False
        return target_distance < current_distance

    def _node_path_frequency(self, paths: list) -> np.ndarray:
        frequency = np.zeros(self.config.n_nodes, dtype=int)
        for path in paths:
            for node in path:
                frequency[int(node)] += 1
        return frequency

    def _edge_path_frequency(self, paths: list) -> dict:
        frequency = {}
        for path in paths:
            for left, right in zip(path[:-1], path[1:]):
                key = f"{int(left)}->{int(right)}"
                frequency[key] = frequency.get(key, 0) + 1
        return frequency

    def _chokepoint_nodes(self, node_frequency: np.ndarray) -> list:
        excluded = set(int(node) for node in list(self.config.entry_nodes) + list(self.config.critical_nodes))
        candidates = [
            (idx, int(count))
            for idx, count in enumerate(node_frequency.tolist())
            if idx not in excluded and int(count) > 0
        ]
        if not candidates:
            return []
        max_count = max(count for _, count in candidates)
        return [int(idx) for idx, count in candidates if count == max_count]

    def _critical_edges(self, edge_frequency: Optional[dict] = None) -> list:
        frequency = edge_frequency if edge_frequency is not None else self._edge_path_frequency(self._paths_to_critical())
        if not frequency:
            return []
        ranked = sorted(
            ((edge, int(count)) for edge, count in frequency.items() if int(count) > 0),
            key=lambda item: (-item[1], item[0]),
        )
        if not ranked:
            return []
        max_count = ranked[0][1]
        return [edge for edge, count in ranked if count == max_count]

    def _entry_can_reach_critical(self, adjacency: np.ndarray) -> bool:
        critical = set(self.config.critical_nodes)
        frontier = list(self.config.entry_nodes)
        visited = set()
        while frontier:
            node = int(frontier.pop())
            if node in critical:
                return True
            if node in visited:
                continue
            visited.add(node)
            frontier.extend(int(idx) for idx in np.flatnonzero(adjacency[node] > 0) if int(idx) not in visited)
        return False

    def _lateral_success_probability(self, attacked_decoy: bool) -> float:
        probability = self.config.attacker_lateral_success_prob
        if attacked_decoy:
            probability *= self.config.decoy_lateral_decay
        if self._mtd_recently_active():
            probability *= np.exp(-self.config.mtd_success_decay_bonus)
        return float(np.clip(probability, 0.0, 1.0))

    def _lateral_detection_probability(self, credential_decoy_trigger: bool = False) -> float:
        probability = self.config.attacker_lateral_detection_prob
        if self._mtd_recently_active():
            probability += self.config.mtd_detection_bonus
        if credential_decoy_trigger:
            probability += self.config.credential_detection_bonus
        return float(np.clip(probability, 0.0, 1.0))

    def _set_to_indicator(self, values: set) -> np.ndarray:
        indicator = np.zeros(self.config.n_nodes, dtype=int)
        for idx in values or set():
            if 0 <= int(idx) < self.config.n_nodes:
                indicator[int(idx)] = 1
        return indicator

    def _update_defender_belief_estimate(
        self,
        selected_target: int,
        selection_score: np.ndarray,
        attack_active: bool,
        success: bool = False,
        detected: bool = False,
        attacked_decoy: bool = False,
        target_defense_strength: float = 0.0,
        attack_success_prob: float = 0.0,
        attack_detection_prob: float = 0.0,
    ) -> None:
        if not self.config.defender_belief_estimation_enabled:
            return
        if selected_target < 0 or not attack_active:
            return

        self.defender_target_counts[selected_target] += 1
        belief_sum = float(np.sum(self.config.attacker_belief))
        target_total = max(float(np.sum(self.defender_target_counts)), 1.0)
        target_frequency_observed = self.defender_target_counts / target_total * belief_sum

        # TODO: Replace direct selection-score observation with estimates from defender-visible logs.
        score = np.maximum(np.asarray(selection_score, dtype=float), 0.0)
        score_sum = float(np.sum(score))
        if score_sum > 0:
            selection_score_observed = score / score_sum * belief_sum
        else:
            selection_score_observed = np.zeros(self.config.n_nodes)
        visible_log_observed = self._defender_visible_log_observation(
            selected_target=selected_target,
            success=success,
            detected=detected,
            attacked_decoy=attacked_decoy,
            target_defense_strength=target_defense_strength,
            attack_success_prob=attack_success_prob,
            attack_detection_prob=attack_detection_prob,
        )
        self.defender_visible_log_observation = visible_log_observed.copy()

        mode = self.config.defender_belief_observation_mode
        if mode == "none":
            return
        if mode == "target_frequency":
            observed = target_frequency_observed
        elif mode == "selection_score":
            observed = selection_score_observed
        elif mode == "hybrid":
            observed = 0.5 * target_frequency_observed + 0.5 * selection_score_observed
        elif mode == "defender_visible_log":
            observed = visible_log_observed
        elif mode == "hybrid_visible":
            observed = 0.5 * target_frequency_observed + 0.5 * visible_log_observed
        else:
            observed = np.zeros(self.config.n_nodes)

        if self.config.defender_belief_observation_noise > 0:
            observed = observed + self.rng.normal(
                0.0,
                self.config.defender_belief_observation_noise,
                size=self.config.n_nodes,
            )
        observed = np.clip(
            observed,
            self.config.defender_belief_min,
            self.config.defender_belief_max,
        )
        alpha = self.config.defender_belief_estimation_alpha
        estimated = alpha * self.defender_estimated_belief + (1.0 - alpha) * observed
        self.defender_observed_belief = observed
        self.defender_estimated_belief = np.clip(
            estimated,
            self.config.defender_belief_min,
            self.config.defender_belief_max,
        )

    def _defender_visible_log_observation(
        self,
        selected_target: int,
        success: bool,
        detected: bool,
        attacked_decoy: bool,
        target_defense_strength: float,
        attack_success_prob: float,
        attack_detection_prob: float,
    ) -> np.ndarray:
        observed = np.zeros(self.config.n_nodes)
        if selected_target < 0:
            return observed

        score = 1.0
        if success:
            score += self.config.visible_log_success_boost
        if detected:
            score *= self.config.visible_log_detected_decay
        if attacked_decoy:
            score *= self.config.visible_log_decoy_decay
        score += self.config.visible_log_success_prob_weight * attack_success_prob
        score -= self.config.visible_log_detection_prob_weight * attack_detection_prob
        score -= self.config.visible_log_defense_penalty_weight * target_defense_strength
        score = max(float(score), 0.0)
        observed[selected_target] = score

        total = float(np.sum(observed))
        if total > 0:
            observed = observed / total * float(np.sum(self.config.attacker_belief))
        return observed

    def _update_defender_bayesian_belief(
        self,
        selected_target: int,
        success: bool,
        detected: bool,
        attacked_decoy: bool,
    ) -> None:
        if not self.config.defender_bayesian_update_enabled:
            return
        if selected_target < 0:
            return

        self.defender_bayesian_alpha *= self.config.defender_bayesian_decay
        increment = 1.0
        if success:
            increment *= self.config.defender_bayesian_success_likelihood
        if detected:
            increment *= self.config.defender_bayesian_detected_likelihood
        if attacked_decoy:
            increment *= self.config.defender_bayesian_decoy_likelihood
        if selected_target in self._critical_path_nodes():
            increment *= self.config.defender_bayesian_critical_path_likelihood
        self.defender_bayesian_alpha[int(selected_target)] += increment

    def _defender_bayesian_belief(self) -> np.ndarray:
        total = float(np.sum(self.defender_bayesian_alpha))
        if total <= 0:
            return np.ones(self.config.n_nodes, dtype=float) / self.config.n_nodes
        return self.defender_bayesian_alpha / total * float(np.sum(self.config.attacker_belief))

    def _critical_path_nodes(self) -> set:
        return {int(node) for path in self._paths_to_critical() for node in path}

    def _matching_weight_for_mode(self, effective_weight: np.ndarray) -> Optional[np.ndarray]:
        if self.config.post_decoy_defense_injection_mode in ("matching_only", "matching_fallback", "all"):
            return effective_weight
        return None

    def _fallback_weight_for_mode(self, effective_weight: np.ndarray) -> Optional[np.ndarray]:
        if self.config.post_decoy_defense_injection_mode in ("fallback_only", "matching_fallback", "all"):
            return effective_weight
        return None

    def _mpc_weight_for_mode(self, effective_weight: np.ndarray) -> Optional[np.ndarray]:
        if self.config.post_decoy_defense_injection_mode in ("mpc_q", "all"):
            return effective_weight
        return None

    def _is_decoy_target(self, target_idx: int) -> bool:
        if target_idx < 0:
            return False
        return self.config.node_type[target_idx] == "decoy"

    def _target_defense_strength(self, target_idx: int, r_opt: np.ndarray) -> float:
        if target_idx < 0:
            return 0.0
        return float(self.M[target_idx, :] @ r_opt)

    def _calculate_attacker_gain(self, old_x: np.ndarray, new_x: np.ndarray, target_idx: int = -1) -> float:
        # True gain: aggregate defender asset loss this step.
        # For decoy targets gain_multiplier = decoy_success_gain_scale (default 0.0),
        # so attacking a decoy yields zero true gain.
        # Lateral movement and honeypot credential change which node is targeted; their effect
        # flows through the standard risk_increase path automatically.
        # TODO(design): explicit per-node lateral compromise gain (access-event value separate from
        # state-change value) and credential-access gain require a design decision on gain accounting
        # that goes beyond metric instrumentation — deferred to design review.
        risk_increase = np.maximum(new_x - old_x, 0.0)
        gain_multiplier = self.config.decoy_success_gain_scale if self._is_decoy_target(target_idx) else 1.0
        return float(np.sum(risk_increase * self.config.asset_value) * gain_multiplier)

    def _calculate_perceived_gain(self, old_x: np.ndarray, new_x: np.ndarray, target_idx: int = -1) -> float:
        """Gain the attacker *perceives* based on their current belief about node values.

        Unlike _calculate_attacker_gain this does NOT apply decoy_success_gain_scale.
        An attacker targeting a decoy node is unaware it is a decoy, so they perceive
        full value proportional to their belief.

        When target_idx >= 0 only the targeted node contributes (attacker's rational focus).
        When target_idx < 0 the gain is summed over all nodes.
        """
        risk_increase = np.maximum(
            np.asarray(new_x, dtype=float) - np.asarray(old_x, dtype=float), 0.0
        )
        if self.attacker.current_belief is None:
            belief = np.ones(len(old_x), dtype=float)
        else:
            belief = np.asarray(self.attacker.current_belief, dtype=float)
        if target_idx >= 0:
            return float(risk_increase[target_idx] * belief[target_idx])
        return float(np.sum(risk_increase * belief))

    def _belief_entropy(self) -> float:
        """Normalized Shannon entropy of the attacker's current belief distribution.

        Range: 0.0 (all belief on one node) to 1.0 (uniform across all nodes).
        High value => attacker cannot identify the high-value asset => deception is effective.

        Definition: H_norm = H / log2(n)
          H = -sum(p_i * log2(p_i)),  p_i = belief_i / sum(belief)
        If sum(belief) == 0 or n <= 1, returns 1.0 (maximum uncertainty by convention).
        Zero-probability entries contribute 0 to H (0 * log(0) = 0 limit).
        """
        belief = np.asarray(self.attacker.current_belief, dtype=float)
        total = float(np.sum(belief))
        n = int(len(belief))
        if total <= 0.0 or n <= 1:
            return 1.0
        p = belief / total
        p_pos = np.where(p > 0.0, p, 1e-15)
        H = -float(np.sum(p * np.log2(p_pos)))
        H_max = float(np.log2(n))
        if H_max <= 0.0:
            return 1.0
        return float(np.clip(H / H_max, 0.0, 1.0))

    def _attack_succeeds(
        self,
        gained: float,
        attacked_decoy: bool,
        target_defense_strength: float,
    ) -> bool:
        if not self.config.stochastic_success:
            return bool(gained > 0.01)
        return bool(self.rng.random() < self._attack_success_probability(
            gained,
            attacked_decoy,
            target_defense_strength,
        ))

    def _attack_success_probability(
        self,
        gained: float,
        attacked_decoy: bool,
        target_defense_strength: float,
    ) -> float:
        if not self.config.stochastic_success:
            return 1.0 if gained > 0.01 else 0.0
        if attacked_decoy:
            probability = self.config.decoy_success_prob
        else:
            probability = self.config.base_success_prob * np.exp(
                -self.config.defense_success_decay * target_defense_strength
            )
        if self._mtd_recently_active():
            probability *= np.exp(-self.config.mtd_success_decay_bonus)
        return float(np.clip(probability, 0.0, 1.0))

    def _detect_attacker(
        self,
        r_opt: np.ndarray,
        success: bool,
        attacked_decoy: bool = False,
        target_defense_strength: float = 0.0,
        credential_decoy_trigger: bool = False,
    ) -> bool:
        # TODO: 将来はノード種別、デコイ誘引度、honeypot credential、MTD、横展開検知を反映する。
        if not self.config.stochastic_detection:
            detected = bool(np.sum(r_opt) > 0.0 and success)
            if attacked_decoy or credential_decoy_trigger:
                detected = True
            return detected
        return bool(self.rng.random() < self._attack_detection_probability(
            r_opt,
            success,
            attacked_decoy,
            target_defense_strength,
            credential_decoy_trigger,
        ))

    def _attack_detection_probability(
        self,
        r_opt: np.ndarray,
        success: bool,
        attacked_decoy: bool = False,
        target_defense_strength: float = 0.0,
        credential_decoy_trigger: bool = False,
    ) -> float:
        if not self.config.stochastic_detection:
            detected = bool(np.sum(r_opt) > 0.0 and success)
            if attacked_decoy or credential_decoy_trigger:
                detected = True
            return 1.0 if detected else 0.0
        if attacked_decoy:
            probability = self.config.decoy_detection_prob
        else:
            probability = self.config.base_detection_prob + (
                self.config.defense_detection_scale * target_defense_strength
            )
        if self._mtd_recently_active():
            probability += self.config.mtd_detection_bonus
        if credential_decoy_trigger:
            probability += self.config.credential_detection_bonus
        return float(np.clip(probability, 0.0, 1.0))

    def _check_and_update_matching(self, t: int, x_previous: np.ndarray) -> str:
        reasons = []
        if (t + 1) % self.config.matching_update_interval == 0:
            reasons.append('interval')
        if self.config.dynamic_matching and np.max(self.x_current) > self.config.dynamic_matching_threshold:
            reasons.append('risk_threshold')
        if (
            self.config.dynamic_matching
            and self.config.dynamic_matching_delta_threshold > 0
            and np.max(self.x_current - x_previous) > self.config.dynamic_matching_delta_threshold
        ):
            reasons.append('risk_delta')
        if reasons:
            self.M = self.engine.update_matching_ilp(
                self.x_current,
                defense_weight=self._matching_weight_for_mode(self._effective_defense_weight()),
            )
            return '+'.join(reasons)
        return ''

    @staticmethod
    def _score01(value: float) -> float:
        return float(np.clip(float(value), 0.0, 1.0))

    def _calculate_neutralization_scores(
        self,
        attacker_utility: np.ndarray,
        attacker_success_count: int,
        valid_attack_count: int,
        attacker_decoy_attack_rate: float,
        credential_trigger_rate: float,
        post_decoy_metrics: Dict[str, object],
        static_critical_paths: List[List[int]],
        critical_paths: List[List[int]],
    ) -> Dict[str, float]:
        steps = max(int(len(attacker_utility)), 1)
        horizon = max(int(self.config.T), steps, 1)

        if self.critical_compromise_step is None:
            compromise_delay_score = 1.0
        else:
            compromise_delay_score = self._score01(float(self.critical_compromise_step) / max(float(horizon - 1), 1.0))
        critical_protection_score = (
            1.0
            if not self.critical_compromise
            else self._score01(0.3 * compromise_delay_score)
        )

        final_utility = float(attacker_utility[-1]) if len(attacker_utility) > 0 else float(self.attacker.utility)
        utility_scale = max(
            float(np.sum(self.config.asset_value)) + float(self.config.attacker_attack_budget * horizon),
            1.0,
        )
        final_utility_score = 1.0 if final_utility <= 0.0 else self._score01(1.0 - final_utility / utility_scale)
        negative_utility_rate = (
            float(np.mean(attacker_utility <= 0.0))
            if len(attacker_utility) > 0
            else float(final_utility <= 0.0)
        )
        utility_suppression_score = self._score01(
            0.6 * final_utility_score + 0.4 * negative_utility_rate
        )

        post_decoy_attack_count = int(post_decoy_metrics.get('post_decoy_attack_count', 0) or 0)
        post_decoy_real_attack_count = int(post_decoy_metrics.get('post_decoy_real_attack_count', 0) or 0)
        post_decoy_real_suppression = self._score01(
            1.0 - post_decoy_real_attack_count / max(post_decoy_attack_count, valid_attack_count, 1)
        )
        mtd_event_rate = self._score01(float(self.mtd_event_count) / float(horizon))
        deception_waste_score = self._score01(
            0.35 * attacker_decoy_attack_rate
            + 0.25 * credential_trigger_rate
            + 0.20 * mtd_event_rate
            + 0.20 * post_decoy_real_suppression
        )

        active_path_reduction = self._score01(
            1.0 - float(len(critical_paths)) / max(float(len(static_critical_paths)), 1.0)
        )
        lateral_failure_score = (
            self._score01(1.0 - attacker_success_count / max(valid_attack_count, 1))
            if self.config.attacker_lateral_enabled
            else 0.0
        )
        edge_block_activity_score = self._score01(float(self.mtd_edge_block_active_steps) / float(horizon))
        edge_block_event_score = self._score01(float(self.mtd_edge_block_events) / max(float(len(static_critical_paths)), 1.0))
        friction_score = self._score01(
            0.35 * compromise_delay_score
            + 0.25 * lateral_failure_score
            + 0.20 * edge_block_activity_score
            + 0.20 * max(active_path_reduction, edge_block_event_score)
        )

        if self.attacker.retreated:
            retreat_step = self.attacker_retreat_step if self.attacker_retreat_step is not None else horizon - 1
            retreat_score = self._score01(1.0 - float(retreat_step) / max(float(horizon - 1), 1.0))
        else:
            retreat_score = 0.0

        neutralization_score = self._score01(
            0.35 * critical_protection_score
            + 0.25 * utility_suppression_score
            + 0.15 * deception_waste_score
            + 0.15 * friction_score
            + 0.10 * retreat_score
        )

        return {
            'critical_protection_score': critical_protection_score,
            'utility_suppression_score': utility_suppression_score,
            'deception_waste_score': deception_waste_score,
            'friction_score': friction_score,
            'retreat_score': retreat_score,
            'neutralization_score': neutralization_score,
        }

    def _calculate_cognitive_scores(
        self,
        neutralization_scores: Dict[str, float],
        perceived_utility_final: float,
        confidence_final: float,
        frustration_final: float,
        ai_weighted_cost: float,
    ) -> Dict[str, float]:
        if not self.config.cognitive_score_enabled:
            return {
                'cognitive_neutralization_score': 0.0,
                'cognitive_human_score': 0.0,
                'cognitive_ai_score': 0.0,
            }

        utility_scale = max(
            float(np.sum(self.config.asset_value)) + float(self.config.attacker_attack_budget * max(self.config.T, 1)),
            1.0,
        )
        utility_component = (
            1.0
            if perceived_utility_final <= 0.0
            else self._score01(1.0 - perceived_utility_final / utility_scale)
        )
        confidence_component = self._score01(1.0 - confidence_final)
        frustration_scale = max(float(self.config.frustration_retreat_threshold), 1.0)
        frustration_component = self._score01(frustration_final / (frustration_final + frustration_scale))
        ai_cost_component = self._score01(ai_weighted_cost / (ai_weighted_cost + frustration_scale))
        retreat_component = 1.0 if self.attacker.retreated else 0.0

        human_weight_sum = max(
            self.config.cognitive_weight_perceived_utility
            + self.config.cognitive_weight_confidence
            + self.config.cognitive_weight_human_frustration
            + self.config.cognitive_weight_retreat,
            1e-9,
        )
        cognitive_human_score = self._score01(
            (
                self.config.cognitive_weight_perceived_utility * utility_component
                + self.config.cognitive_weight_confidence * confidence_component
                + self.config.cognitive_weight_human_frustration * frustration_component
                + self.config.cognitive_weight_retreat * retreat_component
            )
            / human_weight_sum
        )

        ai_weight_sum = max(
            self.config.cognitive_weight_ai_cost
            + self.config.cognitive_weight_confidence
            + self.config.cognitive_weight_perceived_utility
            + self.config.cognitive_weight_retreat,
            1e-9,
        )
        cognitive_ai_score = self._score01(
            (
                self.config.cognitive_weight_ai_cost * ai_cost_component
                + self.config.cognitive_weight_confidence * confidence_component
                + self.config.cognitive_weight_perceived_utility * utility_component
                + self.config.cognitive_weight_retreat * retreat_component
            )
            / ai_weight_sum
        )

        combined_human_weight = (
            self.config.cognitive_weight_perceived_utility
            + self.config.cognitive_weight_confidence
            + self.config.cognitive_weight_human_frustration
            + self.config.cognitive_weight_retreat
        )
        combined_ai_weight = (
            self.config.cognitive_weight_ai_cost
            + self.config.cognitive_weight_confidence
            + self.config.cognitive_weight_perceived_utility
            + self.config.cognitive_weight_retreat
        )
        combined_weight_sum = max(
            self.config.cognitive_weight_critical_protection
            + combined_human_weight
            + combined_ai_weight,
            1e-9,
        )
        cognitive_neutralization_score = self._score01(
            (
                self.config.cognitive_weight_critical_protection
                * float(neutralization_scores.get('critical_protection_score', 0.0))
                + combined_human_weight * cognitive_human_score
                + combined_ai_weight * cognitive_ai_score
            )
            / combined_weight_sum
        )

        return {
            'cognitive_neutralization_score': cognitive_neutralization_score,
            'cognitive_human_score': cognitive_human_score,
            'cognitive_ai_score': cognitive_ai_score,
        }

    def _calculate_cns_objective_scores(
        self,
        neutralization_scores: Dict[str, float],
        cognitive_scores: Dict[str, float],
    ) -> Dict[str, float]:
        if not self.config.cns_objective_enabled:
            return {
                'cns_objective_score': 0.0,
                'cns_human_contribution': 0.0,
                'cns_ai_contribution': 0.0,
                'cns_protection_contribution': 0.0,
            }

        human = self.config.cns_weight_human * float(cognitive_scores.get('cognitive_human_score', 0.0))
        ai = self.config.cns_weight_ai * float(cognitive_scores.get('cognitive_ai_score', 0.0))
        protection = self.config.cns_weight_protection * float(
            neutralization_scores.get('critical_protection_score', 0.0)
        )
        return {
            'cns_objective_score': self._score01(human + ai + protection),
            'cns_human_contribution': float(human),
            'cns_ai_contribution': float(ai),
            'cns_protection_contribution': float(protection),
        }

    def calculate_metrics(self) -> Dict[str, object]:
        hx = np.asarray(self.history['x'], dtype=float)
        hr = np.asarray(self.history['r'], dtype=float)
        clip_low = np.asarray(self.history['clip_low'], dtype=float)
        clip_high = np.asarray(self.history['clip_high'], dtype=float)
        attacker_success = np.asarray(self.history['attacker_success'], dtype=bool)
        attacker_detected = np.asarray(self.history['attacker_detected'], dtype=bool)
        attacker_attacked_decoy = np.asarray(self.history['attacker_attacked_decoy'], dtype=bool)
        credential_obtained = np.asarray(self.history['credential_obtained'], dtype=bool)
        credential_used = np.asarray(self.history['credential_used'], dtype=bool)
        credential_decoy_trigger = np.asarray(self.history['credential_decoy_trigger'], dtype=bool)
        credential_trigger_recently_active = np.asarray(self.history['credential_trigger_recently_active'], dtype=bool)
        credential_aware_mtd_fire = np.asarray(self.history['credential_aware_mtd_fire'], dtype=bool)
        credential_mtd_stage = np.asarray(self.history['credential_mtd_stage'], dtype='<U32')
        credential_stage1_action = np.asarray(self.history['credential_stage1_action'], dtype=bool)
        credential_stage2_action = np.asarray(self.history['credential_stage2_action'], dtype=bool)
        decoy_waste_step = np.asarray(self.history['decoy_waste_step'], dtype=float)
        attack_success_prob = np.asarray(self.history['attack_success_prob'], dtype=float)
        attack_detection_prob = np.asarray(self.history['attack_detection_prob'], dtype=float)
        target_defense_strength = np.asarray(self.history['target_defense_strength'], dtype=float)
        post_decoy_defense_active = np.asarray(self.history['post_decoy_defense_active'], dtype=bool)
        post_decoy_defense_matching_active = np.asarray(self.history['post_decoy_defense_matching_active'], dtype=bool)
        post_decoy_defense_fallback_active = np.asarray(self.history['post_decoy_defense_fallback_active'], dtype=bool)
        post_decoy_defense_mpc_q_active = np.asarray(self.history['post_decoy_defense_mpc_q_active'], dtype=bool)
        effective_defense_weight = np.asarray(self.history['effective_defense_weight'], dtype=float)
        mtd_total_cost_history = np.asarray(self.history['mtd_total_cost'], dtype=float)
        mtd_risk_gate_score = np.asarray(self.history['mtd_risk_gate_score'], dtype=float)
        mtd_risk_gate_fired = np.asarray(self.history['mtd_risk_gate_fired'], dtype=bool)
        mtd_risk_gate_suppressed = np.asarray(self.history['mtd_risk_gate_suppressed'], dtype=bool)
        mtd_conditional_actions = np.asarray(self.history['mtd_conditional_policy_action'], dtype='<U32')
        attacker_perceived_gain_series = np.asarray(self.history.get('attacker_perceived_gain', []), dtype=float)
        attacker_critical_true_gain_series = np.asarray(self.history.get('attacker_critical_true_gain', []), dtype=float)
        belief_entropy_series = np.asarray(self.history.get('belief_entropy', []), dtype=float)
        actual_utility_series = np.asarray(self.history.get('actual_utility', []), dtype=float)
        perceived_utility_series = np.asarray(self.history.get('perceived_utility', []), dtype=float)
        confidence_series = np.asarray(self.history.get('confidence', []), dtype=float)
        frustration_series = np.asarray(self.history.get('frustration', []), dtype=float)
        ai_uncertainty_cost_series = np.asarray(self.history.get('ai_uncertainty_cost', []), dtype=float)
        ai_replanning_cost_series = np.asarray(self.history.get('ai_replanning_cost', []), dtype=float)
        ai_search_cost_series = np.asarray(self.history.get('ai_search_cost', []), dtype=float)
        ai_operational_risk_cost_series = np.asarray(self.history.get('ai_operational_risk_cost', []), dtype=float)
        ai_trust_degradation_cost_series = np.asarray(self.history.get('ai_trust_degradation_cost', []), dtype=float)
        ai_total_decision_cost_series = np.asarray(self.history.get('ai_total_decision_cost', []), dtype=float)
        success_memory_history = np.asarray(self.history.get('success_memory', []), dtype=float)
        decoy_memory_history = np.asarray(self.history.get('decoy_memory', []), dtype=float)
        detection_memory_history = np.asarray(self.history.get('detection_memory', []), dtype=float)
        preference_history = np.asarray(self.history.get('preference_score', []), dtype=float)
        planning_history = np.asarray(self.history.get('planning_score', []), dtype=float)
        trust_history = np.asarray(self.history.get('trust_score', []), dtype=float)
        expected_utility_history = np.asarray(self.history.get('expected_utility', []), dtype=float)
        ai_weighted_cost = (
            float(np.mean(ai_total_decision_cost_series))
            if len(ai_total_decision_cost_series) > 0
            else float(
                self.attacker.ai_uncertainty_cost * self.config.ai_uncertainty_weight
                + self.attacker.ai_replanning_cost * self.config.ai_replanning_weight
                + self.attacker.ai_search_cost * self.config.ai_search_weight
                + self.attacker.ai_operational_risk_cost * self.config.ai_operational_risk_weight
                + self.attacker.ai_trust_degradation_cost * self.config.ai_trust_degradation_weight
            )
        )
        human_frustration_mean = (
            float(np.mean(frustration_series))
            if len(frustration_series) > 0
            else float(self.attacker.mean_frustration)
        )
        human_vs_ai_cost_ratio = (
            float(human_frustration_mean / ai_weighted_cost)
            if ai_weighted_cost > 0.0
            else None
        )
        initial_belief = self.config.attacker_belief.astype(float)
        final_belief = np.asarray(self.attacker.current_belief, dtype=float)
        defender_belief_error = self.defender_estimated_belief - final_belief
        defender_bayesian_belief = self._defender_bayesian_belief()
        defender_bayesian_error = defender_bayesian_belief - final_belief
        reasons = self.history['matching_update_reason']
        reason_counts: Dict[str, int] = {}
        for reason in reasons:
            if not reason:
                continue
            for part in reason.split('+'):
                reason_counts[part] = reason_counts.get(part, 0) + 1

        if len(hx) == 0:
            initial_risk_sum = final_risk_sum = max_risk = mean_risk = 0.0
            weighted_cumulative_risk = 0.0
        else:
            initial_risk_sum = float(np.sum(hx[0]))
            final_risk_sum = float(np.sum(hx[-1]))
            max_risk = float(np.max(hx))
            mean_risk = float(np.mean(hx))
            weighted_cumulative_risk = float(np.sum((hx ** 2) * self.config.Q_diag))

        if len(hr) == 0:
            cumulative_resource = max_resource = max_resource_sum_per_step = resource_variation = 0.0
        else:
            cumulative_resource = float(np.sum(hr))
            max_resource = float(np.max(hr))
            max_resource_sum_per_step = float(np.max(np.sum(hr, axis=1)))
            resource_variation = float(np.sum(np.abs(np.diff(hr, axis=0)))) if len(hr) > 1 else 0.0

        steps_for_rate = max(int(len(hx)), 1)
        attacker_success_count = int(np.count_nonzero(attacker_success))
        attacker_detected_count = int(np.count_nonzero(attacker_detected))
        successes_for_ratio = max(attacker_success_count, 1)
        attacker_avg_gain_per_success = float(self.attacker.compromised_value / successes_for_ratio)
        attacker_cost_per_success = float(self.attacker.total_cost / successes_for_ratio)
        attacker_detection_rate = float(attacker_detected_count / successes_for_ratio)
        attacker_success_rate = float(attacker_success_count / steps_for_rate)
        selected_targets = np.asarray(self.history['attacker_selected_target'], dtype=int)
        valid_targets = selected_targets[selected_targets >= 0]
        valid_attack_mask = selected_targets >= 0
        target_switch_count = int(np.count_nonzero(np.diff(valid_targets) != 0)) if len(valid_targets) > 1 else 0
        target_counts = np.bincount(valid_targets, minlength=self.config.n_nodes).astype(int).tolist()
        attacker_most_targeted_node = int(np.argmax(target_counts)) if len(valid_targets) > 0 else None
        belief_error = self.config.attacker_belief - self.config.asset_value
        belief_change = final_belief - initial_belief
        decoy_mask = np.asarray([value == "decoy" for value in self.config.node_type], dtype=bool)
        if np.any(decoy_mask):
            attacker_belief_decoy_reduction = float(np.sum(np.maximum(0.0, initial_belief[decoy_mask] - final_belief[decoy_mask])))
        else:
            attacker_belief_decoy_reduction = 0.0
        attacker_decoy_attack_count = int(np.count_nonzero(attacker_attacked_decoy))
        valid_attack_count = int(len(valid_targets))
        attacker_real_attack_count = valid_attack_count - attacker_decoy_attack_count
        attacker_decoy_attack_rate = float(attacker_decoy_attack_count / max(valid_attack_count, 1))
        credential_obtained_count = int(np.count_nonzero(credential_obtained))
        credential_used_count = int(np.count_nonzero(credential_used))
        credential_decoy_trigger_count = int(np.count_nonzero(credential_decoy_trigger))
        credential_trigger_rate = float(credential_decoy_trigger_count / max(credential_used_count, 1))
        if np.any(valid_attack_mask):
            mean_attack_success_prob = float(np.mean(attack_success_prob[valid_attack_mask]))
            mean_attack_detection_prob = float(np.mean(attack_detection_prob[valid_attack_mask]))
            mean_target_defense_strength = float(np.mean(target_defense_strength[valid_attack_mask]))
        else:
            mean_attack_success_prob = 0.0
            mean_attack_detection_prob = 0.0
            mean_target_defense_strength = 0.0
        post_decoy_metrics = self._calculate_post_decoy_metrics(
            selected_targets=selected_targets,
            attacker_attacked_decoy=attacker_attacked_decoy,
        )
        attack_transition_matrix = self._calculate_attack_transition_matrix(selected_targets)
        mtd_cost_per_reduction = (
            float(self.mtd_total_cost / max(float(post_decoy_metrics.get('post_decoy_compromised_value', 0.0)), 1.0))
            if self.mtd_total_cost > 0
            else None
        )
        critical_paths = self._paths_to_critical()
        node_path_frequency = self._node_path_frequency(critical_paths)
        edge_path_frequency = self._edge_path_frequency(critical_paths)
        chokepoint_nodes = self._chokepoint_nodes(node_path_frequency)
        critical_edges = self._critical_edges(edge_path_frequency)
        static_critical_paths = self._paths_to_critical_on(self.config.adjacency_matrix)
        static_node_path_frequency = self._node_path_frequency(static_critical_paths)
        static_edge_path_frequency = self._edge_path_frequency(static_critical_paths)
        static_chokepoint_nodes = self._chokepoint_nodes(static_node_path_frequency)
        static_critical_edges = self._critical_edges(static_edge_path_frequency)
        decoy_nodes = {idx for idx, node_type in enumerate(self.config.node_type) if node_type == "decoy"}
        static_critical_path_nodes = {
            int(node)
            for path in static_critical_paths
            for node in path
        }
        final_preference = (
            preference_history[-1]
            if len(preference_history) > 0
            else np.zeros(self.config.n_nodes, dtype=float)
        )
        preferred_node_id = int(np.argmax(final_preference)) if len(final_preference) > 0 else None
        preferred_node_score = (
            float(final_preference[int(preferred_node_id)])
            if preferred_node_id is not None
            else 0.0
        )
        preferred_node_on_critical_path = (
            bool(preferred_node_score > 0.0 and preferred_node_id in static_critical_path_nodes)
            if preferred_node_id is not None
            else False
        )
        path_preference_values = self.attacker.path_preference_vector()
        positive_path_preferences = {
            key: float(value)
            for key, value in (self.attacker.path_preference_score or {}).items()
            if float(value) > 0.0
        }
        if positive_path_preferences:
            preferred_path, preferred_path_score = max(
                positive_path_preferences.items(),
                key=lambda item: item[1],
            )
        else:
            preferred_path, preferred_path_score = None, 0.0
        static_critical_path_keys = {
            "->".join(str(int(node)) for node in path)
            for path in static_critical_paths
        }
        def _path_nodes_on_static_critical_path(nodes: List[int], path_key: Optional[str]) -> bool:
            if not nodes:
                return False
            if path_key and path_key in static_critical_path_keys:
                return True
            for static_path in static_critical_paths:
                static_nodes = [int(node) for node in static_path]
                if nodes == static_nodes[:len(nodes)]:
                    return True
                for start in range(0, len(static_nodes) - len(nodes) + 1):
                    if nodes == static_nodes[start:start + len(nodes)]:
                        return True
            return False
        preferred_path_nodes = (
            [int(part) for part in str(preferred_path).split("->")]
            if preferred_path
            else []
        )
        preferred_path_is_critical = _path_nodes_on_static_critical_path(preferred_path_nodes, preferred_path)
        if planning_history.size > 0:
            planning_score_values = planning_history[
                np.isfinite(planning_history) & (planning_history > -1.0e11)
            ]
        else:
            planning_score_values = np.asarray([], dtype=float)
        planned_path_nodes = [int(node) for node in (self.attacker.last_planned_path or [])]
        planned_path = "->".join(str(node) for node in planned_path_nodes) if planned_path_nodes else None
        planned_path_is_critical = _path_nodes_on_static_critical_path(planned_path_nodes, planned_path)
        final_trust = (
            trust_history[-1]
            if len(trust_history) > 0
            else self.attacker.trust_vector(self.config.n_nodes)
        )
        trust_mean = float(np.mean(final_trust)) if len(final_trust) > 0 else 1.0
        trust_min = float(np.min(final_trust)) if len(final_trust) > 0 else 1.0
        trust_max = float(np.max(final_trust)) if len(final_trust) > 0 else 1.0
        trust_collapse_rate = float(np.mean(final_trust < 0.5)) if len(final_trust) > 0 else 0.0
        least_trusted_node = int(np.argmin(final_trust)) if len(final_trust) > 0 else None
        most_trusted_node = int(np.argmax(final_trust)) if len(final_trust) > 0 else None
        expected_utility_values = (
            expected_utility_history[np.isfinite(expected_utility_history)]
            if expected_utility_history.size > 0
            else np.asarray([], dtype=float)
        )
        expected_utility_final_values = (
            expected_utility_history[-1]
            if len(expected_utility_history) > 0
            else np.asarray([], dtype=float)
        )
        expected_gain_vector = (
            self.attacker.last_expected_gain_estimate
            if self.attacker.last_expected_gain_estimate is not None
            else np.zeros(self.config.n_nodes, dtype=float)
        )
        expected_detection_vector = (
            self.attacker.last_expected_detection_risk
            if self.attacker.last_expected_detection_risk is not None
            else np.zeros(self.config.n_nodes, dtype=float)
        )
        expected_search_vector = (
            self.attacker.last_expected_search_cost
            if self.attacker.last_expected_search_cost is not None
            else np.zeros(self.config.n_nodes, dtype=float)
        )
        decoy_on_critical_path = any(
            int(node) in decoy_nodes
            for path in critical_paths
            for node in path
        )
        critical_compromise_step_bonus = (
            float(self.critical_compromise_step)
            if self.critical_compromise_step is not None
            else float(self.config.T)
        )
        defense_objective_score = (
            self.config.defense_objective_critical_weight * float(bool(self.critical_compromise))
            + self.config.defense_objective_post_decoy_weight * float(post_decoy_metrics.get('post_decoy_compromised_value', 0.0))
            - self.config.defense_objective_delay_reward * critical_compromise_step_bonus
        )
        neutralization_scores = self._calculate_neutralization_scores(
            attacker_utility=np.asarray(self.history['attacker_utility'], dtype=float),
            attacker_success_count=attacker_success_count,
            valid_attack_count=valid_attack_count,
            attacker_decoy_attack_rate=attacker_decoy_attack_rate,
            credential_trigger_rate=credential_trigger_rate,
            post_decoy_metrics=post_decoy_metrics,
            static_critical_paths=static_critical_paths,
            critical_paths=critical_paths,
        )
        cognitive_scores = self._calculate_cognitive_scores(
            neutralization_scores=neutralization_scores,
            perceived_utility_final=float(self.attacker.perceived_utility),
            confidence_final=float(self.attacker.confidence),
            frustration_final=float(self.attacker.frustration),
            ai_weighted_cost=ai_weighted_cost,
        )
        cns_objective_scores = self._calculate_cns_objective_scores(
            neutralization_scores=neutralization_scores,
            cognitive_scores=cognitive_scores,
        )

        return {
            'steps': int(len(hx)),
            'n_nodes': int(self.config.n_nodes),
            'm_resources': int(self.config.m_resources),
            'initial_risk_sum': initial_risk_sum,
            'final_risk_sum': final_risk_sum,
            'max_risk': max_risk,
            'mean_risk': mean_risk,
            'weighted_cumulative_risk': weighted_cumulative_risk,
            'cumulative_resource': cumulative_resource,
            'max_resource': max_resource,
            'max_resource_sum_per_step': max_resource_sum_per_step,
            'resource_variation': resource_variation,
            'matching_update_count': int(sum(1 for reason in reasons if reason)),
            'matching_update_reason_counts': reason_counts,
            'ilp_fallback_count': int(self.engine.stats['ilp_fallback_count']),
            'mpc_fallback_count': int(self.engine.stats['mpc_fallback_count']),
            'clip_low_count': int(np.count_nonzero(clip_low > 0)),
            'clip_high_count': int(np.count_nonzero(clip_high > 0)),
            'attacker_enabled': bool(self.attacker.enabled),
            'attacker_retreated': bool(self.attacker.retreated),
            'attacker_retreat_step': self.attacker_retreat_step,
            'attacker_utility_final': float(self.attacker.utility),
            'actual_utility_final': float(self.attacker.actual_utility),
            'perceived_utility_final': float(self.attacker.perceived_utility),
            'actual_gain': float(self.attacker.actual_gain),
            'actual_cost': float(self.attacker.actual_cost),
            'perceived_gain': float(self.attacker.perceived_gain),
            'perceived_cost': float(self.attacker.perceived_cost),
            'mean_confidence': float(np.mean(confidence_series)) if len(confidence_series) > 0 else float(self.attacker.confidence),
            'retreat_based_on': self.config.retreat_based_on,
            'perceived_utility_enabled': bool(self.config.perceived_utility_enabled),
            'perceived_success_confidence': float(self.config.perceived_success_confidence),
            'perceived_decoy_penalty': float(self.config.perceived_decoy_penalty),
            'perceived_detection_penalty': float(self.config.perceived_detection_penalty),
            'perceived_uncertainty_decay': float(self.config.perceived_uncertainty_decay),
            'frustration_enabled': bool(self.config.frustration_enabled),
            'frustration_final': float(self.attacker.frustration),
            'frustration_mean': human_frustration_mean,
            'frustration_max': float(np.max(frustration_series)) if len(frustration_series) > 0 else float(self.attacker.max_frustration),
            'frustration_retreats': int(self.attacker.frustration_retreats),
            'frustration_decoy_hit': float(self.config.frustration_decoy_hit),
            'frustration_credential_trap': float(self.config.frustration_credential_trap),
            'frustration_detection': float(self.config.frustration_detection),
            'frustration_path_change': float(self.config.frustration_path_change),
            'frustration_no_progress': float(self.config.frustration_no_progress),
            'frustration_decay': float(self.config.frustration_decay),
            'frustration_retreat_threshold': float(self.config.frustration_retreat_threshold),
            'human_frustration_final': float(self.attacker.frustration),
            'human_frustration_mean': human_frustration_mean,
            'human_frustration_max': float(np.max(frustration_series)) if len(frustration_series) > 0 else float(self.attacker.max_frustration),
            'ai_uncertainty_cost': float(np.mean(ai_uncertainty_cost_series)) if len(ai_uncertainty_cost_series) > 0 else float(self.attacker.ai_uncertainty_cost),
            'ai_replanning_cost': float(np.mean(ai_replanning_cost_series)) if len(ai_replanning_cost_series) > 0 else float(self.attacker.ai_replanning_cost),
            'ai_search_cost': float(np.mean(ai_search_cost_series)) if len(ai_search_cost_series) > 0 else float(self.attacker.ai_search_cost),
            'ai_operational_risk_cost': float(np.mean(ai_operational_risk_cost_series)) if len(ai_operational_risk_cost_series) > 0 else float(self.attacker.ai_operational_risk_cost),
            'ai_trust_degradation_cost': float(np.mean(ai_trust_degradation_cost_series)) if len(ai_trust_degradation_cost_series) > 0 else float(self.attacker.ai_trust_degradation_cost),
            'ai_total_decision_cost': ai_weighted_cost,
            'ai_weighted_cost': ai_weighted_cost,
            'human_vs_ai_cost_ratio': human_vs_ai_cost_ratio,
            'ai_uncertainty_weight': float(self.config.ai_uncertainty_weight),
            'ai_replanning_weight': float(self.config.ai_replanning_weight),
            'ai_search_weight': float(self.config.ai_search_weight),
            'ai_operational_risk_weight': float(self.config.ai_operational_risk_weight),
            'ai_trust_degradation_weight': float(self.config.ai_trust_degradation_weight),
            'cognitive_score_enabled': bool(self.config.cognitive_score_enabled),
            'cognitive_weight_critical_protection': float(self.config.cognitive_weight_critical_protection),
            'cognitive_weight_perceived_utility': float(self.config.cognitive_weight_perceived_utility),
            'cognitive_weight_confidence': float(self.config.cognitive_weight_confidence),
            'cognitive_weight_human_frustration': float(self.config.cognitive_weight_human_frustration),
            'cognitive_weight_ai_cost': float(self.config.cognitive_weight_ai_cost),
            'cognitive_weight_retreat': float(self.config.cognitive_weight_retreat),
            **cognitive_scores,
            'cns_objective_enabled': bool(self.config.cns_objective_enabled),
            'cns_weight_human': float(self.config.cns_weight_human),
            'cns_weight_ai': float(self.config.cns_weight_ai),
            'cns_weight_protection': float(self.config.cns_weight_protection),
            **cns_objective_scores,
            'attacker_total_cost': float(self.attacker.total_cost),
            'attacker_compromised_value': float(self.attacker.compromised_value),
            'attacker_no_success_steps': int(self.attacker.no_success_steps),
            'attacker_success_count': attacker_success_count,
            'attacker_detected_count': attacker_detected_count,
            'attacker_avg_gain_per_success': attacker_avg_gain_per_success,
            'attacker_cost_per_success': attacker_cost_per_success,
            'attacker_detection_rate': attacker_detection_rate,
            'attacker_success_rate': attacker_success_rate,
            'attacker_target_counts': target_counts,
            'attacker_most_targeted_node': attacker_most_targeted_node,
            'target_switch_count': target_switch_count,
            'attacker_greedy_mode': self.attacker.greedy_mode,
            'asset_value': self.config.asset_value.tolist(),
            'attacker_belief': self.config.attacker_belief.tolist(),
            'asset_value_sum': float(np.sum(self.config.asset_value)),
            'attacker_belief_sum': float(np.sum(self.config.attacker_belief)),
            'attacker_belief_error_l1': float(np.sum(np.abs(belief_error))),
            'attacker_belief_error_l2': float(np.sqrt(np.sum(belief_error ** 2))),
            'node_type': list(self.config.node_type),
            'node_layer': list(self.config.node_layer),
            'adjacency_matrix': self.current_adjacency_matrix.astype(int).tolist(),
            'active_adjacency_matrix': self.active_adjacency_matrix.astype(int).tolist(),
            'entry_nodes': list(self.config.entry_nodes),
            'critical_nodes': list(self.config.critical_nodes),
            'reachable_from_entries': sorted(int(node) for node in self._reachable_from_entries()),
            'critical_path_count': int(len(critical_paths)),
            'critical_paths': [[int(node) for node in path] for path in critical_paths],
            'node_path_frequency': [int(value) for value in node_path_frequency.tolist()],
            'edge_path_frequency': {str(edge): int(count) for edge, count in edge_path_frequency.items()},
            'chokepoint_nodes': [int(node) for node in chokepoint_nodes],
            'critical_edges': [str(edge) for edge in critical_edges],
            'static_critical_path_count': int(len(static_critical_paths)),
            'static_critical_paths': [[int(node) for node in path] for path in static_critical_paths],
            'static_node_path_frequency': [int(v) for v in static_node_path_frequency.tolist()],
            'static_edge_path_frequency': {str(e): int(c) for e, c in static_edge_path_frequency.items()},
            'static_chokepoint_nodes': [int(node) for node in static_chokepoint_nodes],
            'static_critical_edges': [str(edge) for edge in static_critical_edges],
            'attacker_perceived_no_progress_threshold': float(self.config.attacker_perceived_no_progress_threshold),
            'decoy_on_critical_path': bool(decoy_on_critical_path),
            'attacker_lateral_enabled': bool(self.config.attacker_lateral_enabled),
            'attacker_lateral_success_prob': float(self.config.attacker_lateral_success_prob),
            'attacker_lateral_detection_prob': float(self.config.attacker_lateral_detection_prob),
            'decoy_lateral_decay': float(self.config.decoy_lateral_decay),
            'attacker_current_node_final': int(self.attacker.current_node),
            'attacker_visited_nodes_final': sorted(int(v) for v in self.attacker.visited_nodes),
            'attacker_compromised_nodes_final': sorted(int(v) for v in self.attacker.compromised_nodes),
            'critical_compromise': bool(self.critical_compromise),
            'critical_compromise_step': self.critical_compromise_step,
            'decoy_node_count': int(sum(1 for value in self.config.node_type if value == "decoy")),
            'attacker_decoy_attack_count': attacker_decoy_attack_count,
            'attacker_decoy_attack_rate': attacker_decoy_attack_rate,
            'attacker_decoy_waste_total': float(np.sum(decoy_waste_step)),
            'attacker_real_attack_count': attacker_real_attack_count,
            'honeypot_credential_enabled': bool(self.config.honeypot_credential_enabled),
            'credential_node_ids': [int(node_id) for node_id in self.config.credential_node_ids],
            'credential_attraction_bonus': float(self.config.credential_attraction_bonus),
            'credential_detection_bonus': float(self.config.credential_detection_bonus),
            'credential_reuse_decay': float(self.config.credential_reuse_decay),
            'credential_obtained_count': credential_obtained_count,
            'credential_used_count': credential_used_count,
            'credential_decoy_trigger_count': credential_decoy_trigger_count,
            'credential_trigger_rate': credential_trigger_rate,
            'credential_aware_mtd_enabled': bool(self.config.credential_aware_mtd_enabled),
            'credential_trigger_mtd_window': int(self.config.credential_trigger_mtd_window),
            'credential_trigger_block_count': int(self.config.credential_trigger_block_count),
            'credential_trigger_block_duration': int(self.config.credential_trigger_block_duration),
            'credential_trigger_force_mtd': bool(self.config.credential_trigger_force_mtd),
            'credential_trigger_risk_bonus': float(self.config.credential_trigger_risk_bonus),
            'credential_trigger_mtd_event_count': int(np.count_nonzero(credential_aware_mtd_fire)),
            'credential_trigger_recently_active_count': int(np.count_nonzero(credential_trigger_recently_active)),
            'credential_staged_mtd_enabled': bool(self.config.credential_staged_mtd_enabled),
            'credential_stage1_window': int(self.config.credential_stage1_window),
            'credential_stage2_window': int(self.config.credential_stage2_window),
            'credential_stage1_block_count': int(self.config.credential_stage1_block_count),
            'credential_stage1_block_duration': int(self.config.credential_stage1_block_duration),
            'credential_stage2_block_count': int(self.config.credential_stage2_block_count),
            'credential_stage2_block_duration': int(self.config.credential_stage2_block_duration),
            'credential_stage1_action_count': int(np.count_nonzero(credential_stage1_action)),
            'credential_stage2_action_count': int(np.count_nonzero(credential_stage2_action)),
            'credential_stage_none_count': int(np.count_nonzero(credential_mtd_stage == "none")),
            'stochastic_detection': bool(self.config.stochastic_detection),
            'stochastic_success': bool(self.config.stochastic_success),
            'base_detection_prob': float(self.config.base_detection_prob),
            'defense_detection_scale': float(self.config.defense_detection_scale),
            'decoy_detection_prob': float(self.config.decoy_detection_prob),
            'base_success_prob': float(self.config.base_success_prob),
            'defense_success_decay': float(self.config.defense_success_decay),
            'decoy_success_prob': float(self.config.decoy_success_prob),
            'mean_attack_success_prob': mean_attack_success_prob,
            'mean_attack_detection_prob': mean_attack_detection_prob,
            'mean_target_defense_strength': mean_target_defense_strength,
            'attacker_belief_learning_enabled': bool(self.attacker.belief_learning_enabled),
            'adaptive_attacker_enabled': bool(self.config.adaptive_attacker_enabled),
            'adaptive_success_weight': float(self.config.adaptive_success_weight),
            'adaptive_decoy_weight': float(self.config.adaptive_decoy_weight),
            'adaptive_detection_weight': float(self.config.adaptive_detection_weight),
            'adaptive_preference_enabled': bool(self.config.adaptive_preference_enabled),
            'adaptive_preference_weight': float(self.config.adaptive_preference_weight),
            'adaptive_success_reward': float(self.config.adaptive_success_reward),
            'adaptive_critical_reward': float(self.config.adaptive_critical_reward),
            'adaptive_decoy_penalty': float(self.config.adaptive_decoy_penalty),
            'adaptive_detection_penalty': float(self.config.adaptive_detection_penalty),
            'adaptive_path_enabled': bool(self.config.adaptive_path_enabled),
            'path_preference_weight': float(self.config.path_preference_weight),
            'path_success_reward': float(self.config.path_success_reward),
            'path_critical_reward': float(self.config.path_critical_reward),
            'path_decoy_penalty': float(self.config.path_decoy_penalty),
            'path_detection_penalty': float(self.config.path_detection_penalty),
            'adaptive_planning_enabled': bool(self.config.adaptive_planning_enabled),
            'planning_depth': int(self.config.planning_depth),
            'planning_success_weight': float(self.config.planning_success_weight),
            'planning_critical_weight': float(self.config.planning_critical_weight),
            'planning_decoy_penalty': float(self.config.planning_decoy_penalty),
            'planning_detection_penalty': float(self.config.planning_detection_penalty),
            'trust_enabled': bool(self.config.trust_enabled),
            'trust_decoy_penalty': float(self.config.trust_decoy_penalty),
            'trust_credential_penalty': float(self.config.trust_credential_penalty),
            'trust_detection_penalty': float(self.config.trust_detection_penalty),
            'trust_success_reward': float(self.config.trust_success_reward),
            'expected_utility_enabled': bool(self.config.expected_utility_enabled),
            'expected_gain_weight': float(self.config.expected_gain_weight),
            'expected_success_weight': float(self.config.expected_success_weight),
            'expected_detection_cost': float(self.config.expected_detection_cost),
            'expected_search_cost': float(self.config.expected_search_cost),
            'expected_trust_weight': float(self.config.expected_trust_weight),
            'adaptive_memory_success_mean': (
                float(np.mean(success_memory_history[-1]))
                if len(success_memory_history) > 0
                else 0.0
            ),
            'adaptive_memory_decoy_mean': (
                float(np.mean(decoy_memory_history[-1]))
                if len(decoy_memory_history) > 0
                else 0.0
            ),
            'adaptive_memory_detection_mean': (
                float(np.mean(detection_memory_history[-1]))
                if len(detection_memory_history) > 0
                else 0.0
            ),
            'preference_mean': float(np.mean(final_preference)) if len(final_preference) > 0 else 0.0,
            'preference_max': float(np.max(final_preference)) if len(final_preference) > 0 else 0.0,
            'preferred_node_id': preferred_node_id,
            'preferred_node_score': preferred_node_score,
            'preferred_node_on_critical_path': preferred_node_on_critical_path,
            'path_preference_mean': float(np.mean(path_preference_values)) if len(path_preference_values) > 0 else 0.0,
            'path_preference_max': float(np.max(path_preference_values)) if len(path_preference_values) > 0 else 0.0,
            'preferred_path': preferred_path,
            'preferred_path_score': float(preferred_path_score),
            'preferred_path_is_critical': bool(preferred_path_is_critical),
            'planning_score_mean': float(np.mean(planning_score_values)) if len(planning_score_values) > 0 else 0.0,
            'planning_score_max': float(np.max(planning_score_values)) if len(planning_score_values) > 0 else 0.0,
            'planned_path': planned_path,
            'planned_path_score': float(self.attacker.last_planned_path_score),
            'planned_path_is_critical': bool(planned_path_is_critical),
            'trust_mean': trust_mean,
            'trust_min': trust_min,
            'trust_max': trust_max,
            'trust_collapse_rate': trust_collapse_rate,
            'least_trusted_node': least_trusted_node,
            'most_trusted_node': most_trusted_node,
            'node_trust_score': [float(value) for value in final_trust.tolist()],
            'expected_utility_final': float(np.max(expected_utility_final_values)) if len(expected_utility_final_values) > 0 else 0.0,
            'expected_utility_mean': float(np.mean(expected_utility_values)) if len(expected_utility_values) > 0 else 0.0,
            'expected_gain_estimate': float(np.mean(expected_gain_vector)) if len(expected_gain_vector) > 0 else 0.0,
            'expected_detection_risk': float(np.mean(expected_detection_vector)) if len(expected_detection_vector) > 0 else 0.0,
            'expected_search_cost': float(np.mean(expected_search_vector)) if len(expected_search_vector) > 0 else 0.0,
            'attacker_initial_belief': initial_belief.tolist(),
            'attacker_final_belief': final_belief.tolist(),
            'attacker_belief_change_l1': float(np.sum(np.abs(belief_change))),
            'attacker_belief_change_l2': float(np.sqrt(np.sum(belief_change ** 2))),
            'attacker_belief_decoy_reduction': attacker_belief_decoy_reduction,
            'first_decoy_step': self.first_decoy_step,
            'attack_transition_matrix': attack_transition_matrix,
            'post_decoy_defense_enabled': bool(self.config.post_decoy_defense_enabled),
            'post_decoy_defense_weight': float(self.config.post_decoy_defense_weight),
            'post_decoy_defense_top_k': int(self.config.post_decoy_defense_top_k),
            'post_decoy_defense_injection_mode': self.config.post_decoy_defense_injection_mode,
            'post_decoy_defense_belief_source': self.config.post_decoy_defense_belief_source,
            'defender_belief_estimation_enabled': bool(self.config.defender_belief_estimation_enabled),
            'defender_belief_observation_mode': self.config.defender_belief_observation_mode,
            'visible_log_observation_enabled': self.config.defender_belief_observation_mode in ("defender_visible_log", "hybrid_visible"),
            'visible_log_success_boost': float(self.config.visible_log_success_boost),
            'visible_log_detected_decay': float(self.config.visible_log_detected_decay),
            'visible_log_decoy_decay': float(self.config.visible_log_decoy_decay),
            'visible_log_success_prob_weight': float(self.config.visible_log_success_prob_weight),
            'visible_log_detection_prob_weight': float(self.config.visible_log_detection_prob_weight),
            'visible_log_defense_penalty_weight': float(self.config.visible_log_defense_penalty_weight),
            'defender_observed_belief_final': self.defender_observed_belief.tolist(),
            'defender_estimated_belief_final': self.defender_estimated_belief.tolist(),
            'defender_target_counts_final': self.defender_target_counts.astype(int).tolist(),
            'defender_estimation_error_l1': float(np.sum(np.abs(defender_belief_error))),
            'defender_estimation_error_l2': float(np.sqrt(np.sum(defender_belief_error ** 2))),
            'defender_estimation_error_to_attacker_l1': float(np.sum(np.abs(defender_belief_error))),
            'defender_estimation_error_to_attacker_l2': float(np.sqrt(np.sum(defender_belief_error ** 2))),
            'defender_bayesian_update_enabled': bool(self.config.defender_bayesian_update_enabled),
            'defender_bayesian_prior_strength': float(self.config.defender_bayesian_prior_strength),
            'defender_bayesian_success_likelihood': float(self.config.defender_bayesian_success_likelihood),
            'defender_bayesian_detected_likelihood': float(self.config.defender_bayesian_detected_likelihood),
            'defender_bayesian_decoy_likelihood': float(self.config.defender_bayesian_decoy_likelihood),
            'defender_bayesian_critical_path_likelihood': float(self.config.defender_bayesian_critical_path_likelihood),
            'defender_bayesian_decay': float(self.config.defender_bayesian_decay),
            'defender_bayesian_alpha_final': self.defender_bayesian_alpha.tolist(),
            'defender_bayesian_belief_final': defender_bayesian_belief.tolist(),
            'defender_bayesian_error_l1': float(np.sum(np.abs(defender_bayesian_error))),
            'defender_bayesian_error_l2': float(np.sqrt(np.sum(defender_bayesian_error ** 2))),
            'defense_objective_critical_weight': float(self.config.defense_objective_critical_weight),
            'defense_objective_post_decoy_weight': float(self.config.defense_objective_post_decoy_weight),
            'defense_objective_delay_reward': float(self.config.defense_objective_delay_reward),
            'defense_objective_score': float(defense_objective_score),
            'mtd_enabled': bool(self.config.mtd_enabled),
            'mtd_strategy': self.config.mtd_strategy,
            'mtd_interval': int(self.config.mtd_interval),
            'mtd_intensity': float(self.config.mtd_intensity),
            'mtd_success_decay_bonus': float(self.config.mtd_success_decay_bonus),
            'mtd_detection_bonus': float(self.config.mtd_detection_bonus),
            'mtd_shuffle_topology': bool(self.config.mtd_shuffle_topology),
            'mtd_block_critical_edges': bool(self.config.mtd_block_critical_edges),
            'mtd_edge_block_count': int(self.config.mtd_edge_block_count),
            'mtd_edge_block_duration': int(self.config.mtd_edge_block_duration),
            'mtd_risk_gating_enabled': bool(self.config.mtd_risk_gating_enabled),
            'mtd_risk_gate_mode': self.config.mtd_risk_gate_mode,
            'mtd_risk_gate_threshold': float(self.config.mtd_risk_gate_threshold),
            'mtd_risk_gate_cooldown': int(self.config.mtd_risk_gate_cooldown),
            'mtd_risk_gate_fire_count': int(np.count_nonzero(mtd_risk_gate_fired)),
            'mtd_risk_gate_suppressed_count': int(np.count_nonzero(mtd_risk_gate_suppressed)),
            'mtd_risk_gate_score_mean': float(np.mean(mtd_risk_gate_score)) if len(mtd_risk_gate_score) > 0 else 0.0,
            'mtd_conditional_policy_enabled': bool(self.config.mtd_conditional_policy_enabled),
            'mtd_conditional_policy_mode': self.config.mtd_conditional_policy_mode,
            'mtd_conditional_high_risk_threshold': float(self.config.mtd_conditional_high_risk_threshold),
            'mtd_conditional_low_risk_threshold': float(self.config.mtd_conditional_low_risk_threshold),
            'mtd_conditional_count2_action_count': int(np.count_nonzero(mtd_conditional_actions == "count2")),
            'mtd_conditional_duration2_action_count': int(np.count_nonzero(mtd_conditional_actions == "duration2")),
            'mtd_conditional_suppress_count': int(np.count_nonzero(mtd_conditional_actions == "suppress")),
            'mtd_blocked_edges': sorted(str(edge) for edge in self.mtd_blocked_edges.keys()),
            'mtd_blocked_edge_count': int(len(self.mtd_blocked_edges)),
            'mtd_edge_block_events': int(self.mtd_edge_block_events),
            'mtd_edge_block_active_steps': int(self.mtd_edge_block_active_steps),
            'mtd_event_count': int(self.mtd_event_count),
            'mtd_total_cost': float(self.mtd_total_cost if len(mtd_total_cost_history) == 0 else mtd_total_cost_history[-1]),
            'mtd_last_step': self.mtd_last_step,
            'mtd_cost_per_reduction': mtd_cost_per_reduction,
            'post_decoy_defense_active_count': int(np.count_nonzero(post_decoy_defense_active)),
            'post_decoy_defense_mpc_q_active_count': int(np.count_nonzero(post_decoy_defense_mpc_q_active)),
            'post_decoy_defense_matching_active_count': int(np.count_nonzero(post_decoy_defense_matching_active)),
            'post_decoy_defense_fallback_active_count': int(np.count_nonzero(post_decoy_defense_fallback_active)),
            'effective_defense_weight_final': (
                effective_defense_weight[-1].tolist()
                if len(effective_defense_weight) > 0
                else self.config.Q_diag.tolist()
            ),
            'attacker_perceived_gain_total': float(np.sum(attacker_perceived_gain_series)),
            'attacker_critical_true_gain_total': float(np.sum(attacker_critical_true_gain_series)),
            'belief_entropy_mean': float(np.mean(belief_entropy_series)) if len(belief_entropy_series) > 0 else 1.0,
            'belief_entropy_final': float(belief_entropy_series[-1]) if len(belief_entropy_series) > 0 else 1.0,
            'belief_entropy_min': float(np.min(belief_entropy_series)) if len(belief_entropy_series) > 0 else 1.0,
            'actual_utility_mean': float(np.mean(actual_utility_series)) if len(actual_utility_series) > 0 else float(self.attacker.actual_utility),
            'perceived_utility_mean': float(np.mean(perceived_utility_series)) if len(perceived_utility_series) > 0 else float(self.attacker.perceived_utility),
            **neutralization_scores,
            **post_decoy_metrics,
        }

    def _calculate_post_decoy_metrics(
        self,
        selected_targets: np.ndarray,
        attacker_attacked_decoy: np.ndarray,
    ) -> Dict[str, object]:
        if self.first_decoy_step is None:
            return {
                'post_decoy_attack_count': 0,
                'post_decoy_real_attack_count': 0,
                'post_decoy_decoy_attack_count': 0,
                'post_decoy_compromised_value': 0.0,
                'post_decoy_utility': 0.0,
                'post_decoy_target_counts': [0 for _ in range(self.config.n_nodes)],
                'post_decoy_most_targeted_node': None,
            }

        post_start = self.first_decoy_step + 1
        post_targets = selected_targets[post_start:]
        valid_post_targets = post_targets[post_targets >= 0]
        post_decoy_flags = attacker_attacked_decoy[post_start:]
        post_decoy_attack_count = int(len(valid_post_targets))
        post_decoy_decoy_attack_count = int(np.count_nonzero(post_decoy_flags))
        post_decoy_real_attack_count = post_decoy_attack_count - post_decoy_decoy_attack_count
        post_counts = np.bincount(valid_post_targets, minlength=self.config.n_nodes).astype(int).tolist()
        post_most_targeted_node = int(np.argmax(post_counts)) if post_decoy_attack_count > 0 else None

        gains = np.asarray(self.history['attacker_gain'], dtype=float)
        costs = np.asarray(self.history['attacker_cost'], dtype=float)
        pre_cost = float(costs[post_start - 1]) if post_start > 0 and len(costs) >= post_start else 0.0
        final_cost = float(costs[-1]) if len(costs) > 0 else 0.0
        post_compromised = float(np.sum(gains[post_start:])) if len(gains) > post_start else 0.0

        return {
            'post_decoy_attack_count': post_decoy_attack_count,
            'post_decoy_real_attack_count': post_decoy_real_attack_count,
            'post_decoy_decoy_attack_count': post_decoy_decoy_attack_count,
            'post_decoy_compromised_value': post_compromised,
            'post_decoy_utility': float(post_compromised - (final_cost - pre_cost)),
            'post_decoy_target_counts': post_counts,
            'post_decoy_most_targeted_node': post_most_targeted_node,
        }

    def _calculate_attack_transition_matrix(self, selected_targets: np.ndarray) -> Dict[str, int]:
        valid_targets = selected_targets[selected_targets >= 0]
        transitions: Dict[str, int] = {}
        for source, target in zip(valid_targets[:-1], valid_targets[1:]):
            key = f"{int(source)}->{int(target)}"
            transitions[key] = transitions.get(key, 0) + 1
        return transitions

    def save_outputs(self, output_dir: str) -> Dict[str, object]:
        os.makedirs(output_dir, exist_ok=True)
        metrics = self.calculate_metrics()
        if self.config.output_metrics:
            metrics_path = os.path.join(output_dir, "metrics.json")
            with open(metrics_path, 'w', encoding='utf-8') as f:
                json.dump(metrics, f, indent=4, ensure_ascii=False)
            logger.info(f"Metrics saved to {metrics_path}")
        if self.config.save_history:
            history_path = os.path.join(output_dir, "history.npz")
            np.savez(
                history_path,
                x=np.asarray(self.history['x'], dtype=float),
                raw_x=np.asarray(self.history['raw_x'], dtype=float),
                r=np.asarray(self.history['r'], dtype=float),
                M=np.asarray(self.history['M'], dtype=float),
                clip_low=np.asarray(self.history['clip_low'], dtype=float),
                clip_high=np.asarray(self.history['clip_high'], dtype=float),
                matching_update_reason=np.asarray(self.history['matching_update_reason'], dtype='<U64'),
                attack_vector=np.asarray(self.history['attack_vector'], dtype=float),
                attacker_utility=np.asarray(self.history['attacker_utility'], dtype=float),
                attacker_cost=np.asarray(self.history['attacker_cost'], dtype=float),
                attacker_gain=np.asarray(self.history['attacker_gain'], dtype=float),
                actual_utility=np.asarray(self.history['actual_utility'], dtype=float),
                perceived_utility=np.asarray(self.history['perceived_utility'], dtype=float),
                confidence=np.asarray(self.history['confidence'], dtype=float),
                frustration=np.asarray(self.history['frustration'], dtype=float),
                ai_uncertainty_cost=np.asarray(self.history['ai_uncertainty_cost'], dtype=float),
                ai_replanning_cost=np.asarray(self.history['ai_replanning_cost'], dtype=float),
                ai_search_cost=np.asarray(self.history['ai_search_cost'], dtype=float),
                ai_operational_risk_cost=np.asarray(self.history['ai_operational_risk_cost'], dtype=float),
                ai_trust_degradation_cost=np.asarray(self.history['ai_trust_degradation_cost'], dtype=float),
                ai_total_decision_cost=np.asarray(self.history['ai_total_decision_cost'], dtype=float),
                attacker_retreated=np.asarray(self.history['attacker_retreated'], dtype=bool),
                attacker_detected=np.asarray(self.history['attacker_detected'], dtype=bool),
                attacker_success=np.asarray(self.history['attacker_success'], dtype=bool),
                attacker_selection_score=np.asarray(self.history['attacker_selection_score'], dtype=float),
                attacker_selected_target=np.asarray(self.history['attacker_selected_target'], dtype=int),
                attacker_attacked_decoy=np.asarray(self.history['attacker_attacked_decoy'], dtype=bool),
                credential_obtained=np.asarray(self.history['credential_obtained'], dtype=bool),
                credential_used=np.asarray(self.history['credential_used'], dtype=bool),
                credential_decoy_trigger=np.asarray(self.history['credential_decoy_trigger'], dtype=bool),
                credential_trigger_recently_active=np.asarray(self.history['credential_trigger_recently_active'], dtype=bool),
                credential_aware_mtd_fire=np.asarray(self.history['credential_aware_mtd_fire'], dtype=bool),
                credential_aware_block_count=np.asarray(self.history['credential_aware_block_count'], dtype=int),
                credential_aware_block_duration=np.asarray(self.history['credential_aware_block_duration'], dtype=int),
                credential_mtd_stage=np.asarray(self.history['credential_mtd_stage'], dtype='<U32'),
                credential_stage1_action=np.asarray(self.history['credential_stage1_action'], dtype=bool),
                credential_stage2_action=np.asarray(self.history['credential_stage2_action'], dtype=bool),
                decoy_waste_step=np.asarray(self.history['decoy_waste_step'], dtype=float),
                attack_success_prob=np.asarray(self.history['attack_success_prob'], dtype=float),
                attack_detection_prob=np.asarray(self.history['attack_detection_prob'], dtype=float),
                target_defense_strength=np.asarray(self.history['target_defense_strength'], dtype=float),
                attacker_current_belief=np.asarray(self.history['attacker_current_belief'], dtype=float),
                success_memory=np.asarray(self.history['success_memory'], dtype=float),
                decoy_memory=np.asarray(self.history['decoy_memory'], dtype=float),
                detection_memory=np.asarray(self.history['detection_memory'], dtype=float),
                preference_score=np.asarray(self.history['preference_score'], dtype=float),
                path_preference_score=np.asarray(self.history['path_preference_score'], dtype='<U4096'),
                planning_score=np.asarray(self.history['planning_score'], dtype=float),
                trust_score=np.asarray(self.history['trust_score'], dtype=float),
                expected_utility=np.asarray(self.history['expected_utility'], dtype=float),
                defender_observed_belief=np.asarray(self.history['defender_observed_belief'], dtype=float),
                defender_estimated_belief=np.asarray(self.history['defender_estimated_belief'], dtype=float),
                defender_target_counts=np.asarray(self.history['defender_target_counts'], dtype=float),
                defender_visible_log_observation=np.asarray(self.history['defender_visible_log_observation'], dtype=float),
                defender_bayesian_alpha=np.asarray(self.history['defender_bayesian_alpha'], dtype=float),
                defender_bayesian_belief=np.asarray(self.history['defender_bayesian_belief'], dtype=float),
                effective_defense_weight=np.asarray(self.history['effective_defense_weight'], dtype=float),
                post_decoy_defense_active=np.asarray(self.history['post_decoy_defense_active'], dtype=bool),
                post_decoy_defense_injection_mode=np.asarray(self.history['post_decoy_defense_injection_mode'], dtype='<U32'),
                post_decoy_defense_matching_active=np.asarray(self.history['post_decoy_defense_matching_active'], dtype=bool),
                post_decoy_defense_fallback_active=np.asarray(self.history['post_decoy_defense_fallback_active'], dtype=bool),
                post_decoy_defense_mpc_q_active=np.asarray(self.history['post_decoy_defense_mpc_q_active'], dtype=bool),
                mtd_active=np.asarray(self.history['mtd_active'], dtype=bool),
                mtd_event=np.asarray(self.history['mtd_event'], dtype=bool),
                mtd_total_cost=np.asarray(self.history['mtd_total_cost'], dtype=float),
                mtd_affected_belief=np.asarray(self.history['mtd_affected_belief'], dtype=float),
                mtd_blocked_edges_step=np.asarray(self.history['mtd_blocked_edges_step'], dtype='<U128'),
                mtd_risk_gate_score=np.asarray(self.history['mtd_risk_gate_score'], dtype=float),
                mtd_risk_gate_fired=np.asarray(self.history['mtd_risk_gate_fired'], dtype=bool),
                mtd_risk_gate_suppressed=np.asarray(self.history['mtd_risk_gate_suppressed'], dtype=bool),
                mtd_active_block_count=np.asarray(self.history['mtd_active_block_count'], dtype=int),
                mtd_active_block_duration=np.asarray(self.history['mtd_active_block_duration'], dtype=int),
                mtd_conditional_policy_action=np.asarray(self.history['mtd_conditional_policy_action'], dtype='<U32'),
                attacker_current_node=np.asarray(self.history['attacker_current_node'], dtype=int),
                attacker_visited_nodes=np.asarray(self.history['attacker_visited_nodes'], dtype=int),
                attacker_compromised_nodes=np.asarray(self.history['attacker_compromised_nodes'], dtype=int),
                critical_compromise=np.asarray(self.history['critical_compromise'], dtype=bool),
                adjacency_matrix_history=np.asarray(self.history['adjacency_matrix'], dtype=int),
                active_adjacency_matrix=np.asarray(self.history['active_adjacency_matrix'], dtype=int),
                asset_value=self.config.asset_value.copy(),
                attacker_belief=self.config.attacker_belief.copy(),
                node_type=np.asarray(self.config.node_type, dtype='<U16'),
                node_layer=np.asarray(self.config.node_layer, dtype='<U32'),
                adjacency_matrix=self.current_adjacency_matrix.copy(),
                attacker_perceived_gain=np.asarray(self.history['attacker_perceived_gain'], dtype=float),
                attacker_critical_true_gain=np.asarray(self.history['attacker_critical_true_gain'], dtype=float),
                belief_entropy=np.asarray(self.history['belief_entropy'], dtype=float),
            )
            logger.info(f"History saved to {history_path}")
        return metrics

class Visualizer:
    """結果の可視化を担うクラス"""
    @staticmethod
    def plot_results(history: dict, config: SimulationConfig, save_path: str = "simulation_result.png"):
        hx = np.array(history['x'])
        hr = np.array(history['r'])
        
        plt.figure(figsize=(12, 10))
        
        plt.subplot(2, 1, 1)
        for i in range(config.n_nodes):
            plt.plot(hx[:, i], label=f'Node {i} (Weight={config.Q_diag[i]})')
        plt.title('Asset Risk Levels Over Time')
        plt.ylabel('Risk Level')
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.7)
        
        plt.subplot(2, 1, 2)
        for j in range(config.m_resources):
            plt.plot(hr[:, j], label=f'Resource {j}')
        plt.title('Defense Resource Allocation')
        plt.xlabel('Time Step')
        plt.ylabel('Resource Amount')
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        
        # ファイル保存
        plt.savefig(save_path)
        logger.info(f"Result plot saved to {save_path}")
        
        if config.show_plot:
            plt.show()
        else:
            logger.info("show_plot=False. Plot saved without opening an interactive window.")
        plt.close()

if __name__ == "__main__":
    CONFIG_FILE = "config.json"
    OUTPUT_DIR = "output"

    # 1. 出力ディレクトリの作成
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 2. 設定の読み込みまたは作成
    if os.path.exists(CONFIG_FILE):
        config = SimulationConfig.from_json(CONFIG_FILE)
    else:
        logger.info("No config file found. Using defaults and creating config.json.")
        config = SimulationConfig()
        config.to_json(CONFIG_FILE)

    # 3. シミュレーターの初期化と実行
    sim = CyberDefenseSimulator(config)
    results = sim.run()
    sim.save_outputs(OUTPUT_DIR)

    # 4. 可視化と結果の保存
    # 使用した設定も記録として保存
    config.to_json(os.path.join(OUTPUT_DIR, "used_config.json"))
    
    # グラフの保存先を指定
    Visualizer.plot_results(
        results, 
        config, 
        save_path=os.path.join(OUTPUT_DIR, "simulation_result.png")
    )
