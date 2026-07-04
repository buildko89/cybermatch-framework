import logging
logger = logging.getLogger(__name__)
import numpy as np
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Tuple, Optional
import os
import json
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
    adaptive_defender_enabled: bool = False
    adaptive_defender_mode: str = "rule_based"
    adaptive_expected_utility_threshold: float = 0.0
    adaptive_trust_collapse_threshold: float = 0.2
    adaptive_target_switch_threshold: int = 5
    adaptive_policy_default: str = "phase2_frustration_decoy"
    adaptive_policy_high_expected_utility: str = "gated_edge_pressure_count_2"
    adaptive_policy_trust_collapse: str = "phase2_frustration_decoy"
    adaptive_policy_high_switching: str = "phase2_ai_balanced"
    adaptive_selected_policy: str = ""
    adaptive_policy_reason: str = "disabled"
    adaptive_policy_switch_count: int = 0
    adaptive_policy_score: float = 0.0
    adaptive_policy_rank: int = 0
    adaptive_selection_reason: str = "disabled"
    adaptive_estimated_cns: float = 0.0
    step_adaptive_defender_enabled: bool = False
    adaptive_recheck_interval: int = 5
    adaptive_policy_switch_cost: float = 0.02
    adaptive_min_improvement: float = 0.05
    mission_aware_defender_enabled: bool = False
    mission_aware_selected_policy: str = ""
    mission_policy_match: bool = False
    mission_policy_switch_count: int = 0
    mission_aware_selection_reason: str = "disabled"
    mission_aware_cns: float = 0.0
    mission_belief_inference_enabled: bool = False
    belief_profit: float = 0.25
    belief_achievement: float = 0.25
    belief_persistence: float = 0.25
    belief_critical_hunter: float = 0.25
    predicted_mission: str = "unknown"
    mission_prediction_confidence: float = 0.0
    mission_prediction_correct: bool = False
    state_belief_inference_enabled: bool = False
    belief_recon: float = 0.20
    belief_exploitation: float = 0.20
    belief_lateral_movement: float = 0.20
    belief_targeting: float = 0.20
    belief_action_on_objective: float = 0.20
    predicted_state: str = "unknown"
    state_prediction_confidence: float = 0.0
    state_transition_count: int = 0
    virtual_topology_enabled: bool = False
    observable_events_enabled: bool = False
    critical_path_events_enabled: bool = False
    intelligence_defender_enabled: bool = False
    selected_intelligence_policy: str = ""
    intelligence_risk_score: float = 0.0
    risk_level: str = "low"
    risk_level_transition_count: int = 0
    decision_matrix_defender_enabled: bool = False
    decision_matrix_policy: str = ""
    decision_matrix_match_count: int = 0
    decision_matrix_override_count: int = 0
    defense_campaign_enabled: bool = False
    campaign_stage: str = "none"
    campaign_transition_count: int = 0
    campaign_policy_switch_count: int = 0
    campaign_effectiveness_score: float = 0.0
    campaign_strategy_profile: str = "balanced"
    strategy_profile: str = "balanced"
    strategy_effectiveness_score: float = 0.0
    profile_rank: int = 0
    intelligence_mission_weight: float = 0.4
    intelligence_state_weight: float = 0.3
    intelligence_critical_path_weight: float = 0.3
    best_weight_configuration: str = ""
    weight_sweep_rank: int = 0
    node_roles: Dict[int, str] = field(default_factory=lambda: {
        0: "internet_entry",
        1: "dmz_web",
        2: "application_server",
        3: "identity_server",
        4: "critical_asset",
    })
    nonstationary_attacker_enabled: bool = False
    attacker_phase_change_step: int = 25
    nonstationary_attacker_pattern: str = "expected_to_trust"
    attacker_mission: str = "none"
    mission_expected_utility_weight: float = 1.0
    mission_trust_weight: float = 1.0
    mission_planning_weight: float = 1.0
    mission_critical_target_weight: float = 1.0
    mission_objectives_enabled: bool = False
    mission_satisfaction: float = 0.0
    mission_objective_score: float = 0.0
    mission_failure_reason: str = "none"
    profit_expected_utility_weight: float = 0.7
    profit_success_weight: float = 0.3
    persistence_survival_weight: float = 0.5
    persistence_trust_weight: float = 0.3
    persistence_stealth_weight: float = 0.2
    critical_progress_weight: float = 0.8
    critical_reach_weight: float = 0.2
    achievement_progress_weight: float = 0.6
    achievement_critical_weight: float = 0.4
    objective_weight_profile: str = "default"
    mission_strategy_change: bool = False
    mission_sensitivity_score: float = 0.0
    multi_objective_mission_enabled: bool = False
    mission_weight_profit: float = 0.0
    mission_weight_achievement: float = 0.0
    mission_weight_persistence: float = 0.0
    mission_weight_critical_hunter: float = 0.0
    adaptive_mission_attacker_enabled: bool = False
    observed_defense_strategy: str = "none"
    defense_effectiveness_memory: float = 0.0
    strategy_failure_memory: float = 0.0
    strategy_success_memory: float = 0.0
    adaptation_count: int = 0
    ttp_change_count: int = 0
    strategy_avoidance_score: float = 0.0
    alternative_path_usage: float = 0.0
    mission_mutation_enabled: bool = False
    mission_change_count: int = 0
    mission_mutation_reason: str = "none"
    mission_stability_score: float = 1.0
    mission_mutation_success: bool = False
    attacker_type: str = "standard"
    mission_reclassification_enabled: bool = False
    mission_reclassification_count: int = 0
    defense_reoptimization_count: int = 0
    reclassification_accuracy: float = 0.0
    belief_recovery_time: int = -1
    intent_deception_enabled: bool = False
    deception_event_count: int = 0
    mission_belief_error: float = 0.0
    belief_confusion_score: float = 0.0
    true_mission: str = "unknown"
    observed_mission: str = "unknown"
    mission_masking_success: bool = False
    noise_injection_enabled: bool = False
    signal_extraction_enabled: bool = False
    noise_event_count: int = 0
    signal_event_count: int = 0
    signal_to_noise_ratio: float = 0.0
    noise_filter_accuracy: float = 0.0
    decision_confidence: float = 0.0
    adversarial_signal_enabled: bool = False
    fake_signal_count: int = 0
    adversarial_signal_count: int = 0
    signal_confusion_score: float = 0.0
    false_signal_acceptance_rate: float = 0.0
    signal_consistency_score: float = 1.0
    coalition_enabled: bool = False
    coalition_size: int = 2
    coalition_id: str = "coalition_0"
    coalition_role: str = "recon_specialist"
    coalition_handover_count: int = 0
    coalition_coordination_score: float = 0.0
    coalition_delegation_state: str = "Active Owner"
    coalition_coordination_cost_enabled: bool = False
    coordination_cost: float = 0.0
    coalition_information_loss_enabled: bool = False
    coalition_trust_enabled: bool = False
    coalition_trust_score: float = 1.0
    trust_degradation_count: int = 0
    failed_handover_count: int = 0
    counter_deception_enabled: bool = False
    fake_asset_enabled: bool = False
    fake_credential_enabled: bool = False
    fake_critical_path_enabled: bool = False
    honey_node_enabled: bool = False
    fake_asset_interaction_count: int = 0
    fake_asset_success_rate: float = 0.0
    fake_credential_usage_count: int = 0
    credential_trap_trigger_count: int = 0
    fake_path_follow_count: int = 0
    path_diversion_score: float = 0.0
    honey_node_visit_count: int = 0
    honey_detection_count: int = 0
    counter_deception_score: float = 0.0
    attacker_diversion_score: float = 0.0
    campaign_disruption_score: float = 0.0
    counter_deception_awareness_enabled: bool = False
    deception_suspicion_score: float = 0.0
    fake_asset_detection_rate: float = 0.0
    fake_asset_suspicion_count: int = 0
    fake_credential_detection_rate: float = 0.0
    path_validation_count: int = 0
    path_validation_success_rate: float = 0.0
    honey_node_detection_rate: float = 0.0
    awareness_score: float = 0.0
    deception_resistance_score: float = 0.0
    false_suspicion_rate: float = 0.0
    counter_deception_hunting_enabled: bool = False
    fake_asset_hunt_count: int = 0
    fake_asset_confirmed_count: int = 0
    credential_validation_count: int = 0
    credential_validation_success_rate: float = 0.0
    honey_probe_count: int = 0
    honey_probe_success_rate: float = 0.0
    deception_knowledge_score: float = 0.0
    hunting_success_rate: float = 0.0
    deception_discovery_rate: float = 0.0
    verified_false_signal_count: int = 0
    verified_fake_asset_count: int = 0
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
    product_plugin_enabled: bool = False
    product_profile_import_enabled: bool = False
    product_name: str = "baseline"
    product_category: str = "baseline"
    product_profile_name: str = "baseline"
    product_detection_boost: float = 0.0
    product_interruption_boost: float = 0.0
    product_diversion_boost: float = 0.0
    product_confidence_boost: float = 0.0
    product_false_positive_penalty: float = 0.0
    product_latency_penalty: float = 0.0
    product_maintenance_penalty: float = 0.0

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
        if self.coalition_size <= 0:
            errors.append("coalition_size must be > 0")
        if self.coalition_role not in ("single_attacker", "recon_specialist", "access_specialist", "objective_specialist"):
            errors.append("coalition_role must be one of: single_attacker, recon_specialist, access_specialist, objective_specialist")
        if self.coalition_delegation_state not in ("Active Owner", "Preparing Handover", "Delegated"):
            errors.append("coalition_delegation_state must be one of: Active Owner, Preparing Handover, Delegated")
        if self.coordination_cost < 0:
            errors.append("coordination_cost must be >= 0")
        if not 0 <= self.coalition_trust_score <= 1:
            errors.append("coalition_trust_score must be between 0 and 1")
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
        if self.adaptive_defender_mode not in ("rule_based", "cns_guided", "step_adaptive", "mission_aware"):
            errors.append("adaptive_defender_mode must be one of: rule_based, cns_guided, step_adaptive, mission_aware")
        if self.adaptive_target_switch_threshold < 0:
            errors.append("adaptive_target_switch_threshold must be >= 0")
        if self.adaptive_policy_switch_count < 0:
            errors.append("adaptive_policy_switch_count must be >= 0")
        if self.adaptive_recheck_interval <= 0:
            errors.append("adaptive_recheck_interval must be > 0")
        if self.adaptive_policy_switch_cost < 0:
            errors.append("adaptive_policy_switch_cost must be >= 0")
        if self.adaptive_min_improvement < 0:
            errors.append("adaptive_min_improvement must be >= 0")
        if self.mission_policy_switch_count < 0:
            errors.append("mission_policy_switch_count must be >= 0")
        for key, value in (
            ("belief_profit", self.belief_profit),
            ("belief_achievement", self.belief_achievement),
            ("belief_persistence", self.belief_persistence),
            ("belief_critical_hunter", self.belief_critical_hunter),
            ("belief_recon", self.belief_recon),
            ("belief_exploitation", self.belief_exploitation),
            ("belief_lateral_movement", self.belief_lateral_movement),
            ("belief_targeting", self.belief_targeting),
            ("belief_action_on_objective", self.belief_action_on_objective),
        ):
            if value < 0:
                errors.append(f"{key} must be >= 0")
        if self.state_transition_count < 0:
            errors.append("state_transition_count must be >= 0")
        if self.intelligence_mission_weight < 0:
            errors.append("intelligence_mission_weight must be >= 0")
        if self.intelligence_state_weight < 0:
            errors.append("intelligence_state_weight must be >= 0")
        if self.intelligence_critical_path_weight < 0:
            errors.append("intelligence_critical_path_weight must be >= 0")
        if self.campaign_strategy_profile not in (
            "balanced",
            "aggressive_disruption",
            "trust_collapse",
            "utility_suppression",
        ):
            errors.append(
                "campaign_strategy_profile must be one of: balanced, aggressive_disruption, trust_collapse, utility_suppression"
            )
        if self.attacker_phase_change_step < 0:
            errors.append("attacker_phase_change_step must be >= 0")
        if self.nonstationary_attacker_pattern not in ("expected_to_trust", "planning_to_expected"):
            errors.append("nonstationary_attacker_pattern must be one of: expected_to_trust, planning_to_expected")
        if self.attacker_mission not in ("none", "profit", "achievement", "persistence", "critical_hunter"):
            errors.append("attacker_mission must be one of: none, profit, achievement, persistence, critical_hunter")
        if self.mission_expected_utility_weight < 0:
            errors.append("mission_expected_utility_weight must be >= 0")
        if self.mission_trust_weight < 0:
            errors.append("mission_trust_weight must be >= 0")
        if self.mission_planning_weight < 0:
            errors.append("mission_planning_weight must be >= 0")
        if self.mission_critical_target_weight < 0:
            errors.append("mission_critical_target_weight must be >= 0")
        if self.defense_effectiveness_memory < 0:
            errors.append("defense_effectiveness_memory must be >= 0")
        if self.strategy_failure_memory < 0:
            errors.append("strategy_failure_memory must be >= 0")
        if self.strategy_success_memory < 0:
            errors.append("strategy_success_memory must be >= 0")
        if self.adaptation_count < 0:
            errors.append("adaptation_count must be >= 0")
        if self.ttp_change_count < 0:
            errors.append("ttp_change_count must be >= 0")
        if self.strategy_avoidance_score < 0:
            errors.append("strategy_avoidance_score must be >= 0")
        if self.alternative_path_usage < 0:
            errors.append("alternative_path_usage must be >= 0")
        if self.mission_change_count < 0:
            errors.append("mission_change_count must be >= 0")
        if not 0 <= self.mission_stability_score <= 1:
            errors.append("mission_stability_score must be between 0 and 1")
        for key, value in (
            ("mission_weight_profit", self.mission_weight_profit),
            ("mission_weight_achievement", self.mission_weight_achievement),
            ("mission_weight_persistence", self.mission_weight_persistence),
            ("mission_weight_critical_hunter", self.mission_weight_critical_hunter),
        ):
            if value < 0:
                errors.append(f"{key} must be >= 0")
        if self.attacker_type not in ("standard", "adaptive_mission_attacker", "adaptive_mission_mutator", "intent_deception_attacker", "coalition_attacker", "counter_deception_aware_attacker"):
            errors.append("attacker_type must be one of: standard, adaptive_mission_attacker, adaptive_mission_mutator, intent_deception_attacker, coalition_attacker, counter_deception_aware_attacker")
        if self.mission_reclassification_count < 0:
            errors.append("mission_reclassification_count must be >= 0")
        if self.defense_reoptimization_count < 0:
            errors.append("defense_reoptimization_count must be >= 0")
        if not 0 <= self.reclassification_accuracy <= 1:
            errors.append("reclassification_accuracy must be between 0 and 1")
        if self.belief_recovery_time < -1:
            errors.append("belief_recovery_time must be >= -1")
        if self.deception_event_count < 0:
            errors.append("deception_event_count must be >= 0")
        if not 0 <= self.mission_belief_error <= 1:
            errors.append("mission_belief_error must be between 0 and 1")
        if not 0 <= self.belief_confusion_score <= 1:
            errors.append("belief_confusion_score must be between 0 and 1")
        if self.noise_event_count < 0:
            errors.append("noise_event_count must be >= 0")
        if self.signal_event_count < 0:
            errors.append("signal_event_count must be >= 0")
        if self.signal_to_noise_ratio < 0:
            errors.append("signal_to_noise_ratio must be >= 0")
        if not 0 <= self.noise_filter_accuracy <= 1:
            errors.append("noise_filter_accuracy must be between 0 and 1")
        if not 0 <= self.decision_confidence <= 1:
            errors.append("decision_confidence must be between 0 and 1")
        if self.fake_signal_count < 0:
            errors.append("fake_signal_count must be >= 0")
        if self.adversarial_signal_count < 0:
            errors.append("adversarial_signal_count must be >= 0")
        if not 0 <= self.signal_confusion_score <= 1:
            errors.append("signal_confusion_score must be between 0 and 1")
        if not 0 <= self.false_signal_acceptance_rate <= 1:
            errors.append("false_signal_acceptance_rate must be between 0 and 1")
        if not 0 <= self.signal_consistency_score <= 1:
            errors.append("signal_consistency_score must be between 0 and 1")
        if not 0 <= self.deception_suspicion_score <= 1:
            errors.append("deception_suspicion_score must be between 0 and 1")
        for key, value in (
            ("fake_asset_detection_rate", self.fake_asset_detection_rate),
            ("fake_credential_detection_rate", self.fake_credential_detection_rate),
            ("path_validation_success_rate", self.path_validation_success_rate),
            ("honey_node_detection_rate", self.honey_node_detection_rate),
            ("awareness_score", self.awareness_score),
            ("deception_resistance_score", self.deception_resistance_score),
            ("false_suspicion_rate", self.false_suspicion_rate),
            ("credential_validation_success_rate", self.credential_validation_success_rate),
            ("honey_probe_success_rate", self.honey_probe_success_rate),
            ("deception_knowledge_score", self.deception_knowledge_score),
            ("hunting_success_rate", self.hunting_success_rate),
            ("deception_discovery_rate", self.deception_discovery_rate),
        ):
            if not 0 <= value <= 1:
                errors.append(f"{key} must be between 0 and 1")
        if self.fake_asset_suspicion_count < 0:
            errors.append("fake_asset_suspicion_count must be >= 0")
        if self.path_validation_count < 0:
            errors.append("path_validation_count must be >= 0")
        for key, value in (
            ("fake_asset_hunt_count", self.fake_asset_hunt_count),
            ("fake_asset_confirmed_count", self.fake_asset_confirmed_count),
            ("credential_validation_count", self.credential_validation_count),
            ("honey_probe_count", self.honey_probe_count),
            ("verified_false_signal_count", self.verified_false_signal_count),
            ("verified_fake_asset_count", self.verified_fake_asset_count),
        ):
            if value < 0:
                errors.append(f"{key} must be >= 0")
        for key, value in (
            ("profit_expected_utility_weight", self.profit_expected_utility_weight),
            ("profit_success_weight", self.profit_success_weight),
            ("persistence_survival_weight", self.persistence_survival_weight),
            ("persistence_trust_weight", self.persistence_trust_weight),
            ("persistence_stealth_weight", self.persistence_stealth_weight),
            ("critical_progress_weight", self.critical_progress_weight),
            ("critical_reach_weight", self.critical_reach_weight),
            ("achievement_progress_weight", self.achievement_progress_weight),
            ("achievement_critical_weight", self.achievement_critical_weight),
        ):
            if value < 0:
                errors.append(f"{key} must be >= 0")
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
        if self.mtd_risk_gate_mode not in ("critical_path_risk", "chokepoint_risk", "critical_edge_pressure", "edge_pressure"):
            errors.append("mtd_risk_gate_mode must be one of: critical_path_risk, chokepoint_risk, critical_edge_pressure, edge_pressure")
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
        if self.product_category not in ("baseline", "ids", "ips", "honeypot", "deception", "xdr"):
            errors.append("product_category must be one of: baseline, ids, ips, honeypot, deception, xdr")
        if self.product_plugin_enabled and not str(self.product_name).strip():
            errors.append("product_name must be set when product_plugin_enabled is true")
        for field_name, value in [
            ("product_detection_boost", self.product_detection_boost),
            ("product_interruption_boost", self.product_interruption_boost),
            ("product_diversion_boost", self.product_diversion_boost),
            ("product_confidence_boost", self.product_confidence_boost),
            ("product_false_positive_penalty", self.product_false_positive_penalty),
            ("product_latency_penalty", self.product_latency_penalty),
            ("product_maintenance_penalty", self.product_maintenance_penalty),
        ]:
            if not 0 <= float(value) <= 1:
                errors.append(f"{field_name} must be between 0 and 1")
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

