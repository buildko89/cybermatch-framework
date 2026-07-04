import numpy as np
import cvxpy as cp
import matplotlib.pyplot as plt
import logging
import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

from behavior_profile import BehaviorProfileEngine
from intent_inference import MissionInferenceEngine
from mission_taxonomy import MissionTaxonomyAnalyzer
from strategy_layer import StrategyInferenceEngine

# ロギング設定
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ProductProfile:
    name: str
    category: str
    detection_boost: float = 0.0
    interruption_boost: float = 0.0
    diversion_boost: float = 0.0
    confidence_boost: float = 0.0
    false_positive_penalty: float = 0.0
    latency_penalty: float = 0.0
    maintenance_penalty: float = 0.0


def load_product_profile(path: str) -> ProductProfile:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError("product profile must be a JSON object")
    missing = [field_name for field_name in ("name", "category") if field_name not in payload]
    if missing:
        raise ValueError(f"product profile missing required fields: {', '.join(missing)}")
    category = str(payload["category"]).lower()
    if category not in ("ids", "ips", "honeypot", "deception", "xdr"):
        raise ValueError("product profile category must be one of: ids, ips, honeypot, deception, xdr")

    def _score(name: str) -> float:
        return float(np.clip(float(payload.get(name, 0.0) or 0.0), 0.0, 1.0))

    # Future hooks only:
    # - Enterprise Product Profile
    # - Vendor Product Profile
    # - Scenario Specific Product Profile
    return ProductProfile(
        name=str(payload["name"]),
        category=category,
        detection_boost=_score("detection_boost"),
        interruption_boost=_score("interruption_boost"),
        diversion_boost=_score("diversion_boost"),
        confidence_boost=_score("confidence_boost"),
        false_positive_penalty=_score("false_positive_penalty"),
        latency_penalty=_score("latency_penalty"),
        maintenance_penalty=_score("maintenance_penalty"),
    )


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
    attacker_mission: str = "none"
    mission_expected_utility_weight: float = 1.0
    mission_trust_weight: float = 1.0
    mission_planning_weight: float = 1.0
    mission_critical_target_weight: float = 1.0
    adaptive_mission_attacker_enabled: bool = False
    observed_defense_strategy: str = "none"
    defense_effectiveness_memory: float = 0.0
    strategy_failure_memory: float = 0.0
    strategy_success_memory: float = 0.0
    adaptation_count: int = 0
    ttp_change_count: int = 0
    strategy_avoidance_score: float = 0.0
    alternative_path_usage: float = 0.0
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
        self.adaptation_history = []

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
        trust_score = self.trust_vector(n_nodes) if self.trust_enabled else np.ones(n_nodes, dtype=float)
        critical_bonus = np.zeros(n_nodes, dtype=float)
        if self.attacker_mission == "critical_hunter":
            for node in self.critical_nodes or []:
                if 0 <= int(node) < n_nodes:
                    critical_bonus[int(node)] = self.mission_critical_target_weight * max(float(np.max(self.current_belief)), 1.0)
        mission_adaptation_score = self._mission_adaptation_score(n_nodes, expected_utility, planning_score, trust_score)
        return (
            score
            + self.adaptive_success_weight * success_memory
            + preference_weight * preference_score
            + path_weight * path_score
            + self.mission_planning_weight * planning_score
            + self.mission_expected_utility_weight * expected_utility
            + self.mission_trust_weight * trust_score
            + critical_bonus
            + mission_adaptation_score
            - self.adaptive_decoy_weight * decoy_memory
            - self.adaptive_detection_weight * detection_memory
        )

    def _mission_adaptation_score(
        self,
        n_nodes: int,
        expected_utility: np.ndarray,
        planning_score: np.ndarray,
        trust_score: np.ndarray,
    ) -> np.ndarray:
        if not self.adaptive_mission_attacker_enabled:
            return np.zeros(n_nodes, dtype=float)
        pressure = float(np.clip(self.defense_effectiveness_memory, 0.0, 5.0))
        if pressure <= 0.0:
            return np.zeros(n_nodes, dtype=float)
        score = np.zeros(n_nodes, dtype=float)
        visited = {int(node) for node in (self.visited_nodes or set())}
        unvisited_bonus = np.array([0.0 if node in visited else 1.0 for node in range(n_nodes)], dtype=float)
        reachable = set(int(node) for node in self.reachable_nodes(n_nodes))
        lateral_bonus = np.array([1.0 if node in reachable and node != int(self.current_node) else 0.0 for node in range(n_nodes)], dtype=float)
        if self.attacker_mission == "profit":
            score += pressure * (0.60 * unvisited_bonus + 0.20 * lateral_bonus + 0.20 * np.maximum(expected_utility, 0.0))
        elif self.attacker_mission == "persistence":
            score += pressure * (0.70 * trust_score + 0.30 * lateral_bonus)
        elif self.attacker_mission == "critical_hunter":
            score += pressure * (0.65 * planning_score + 0.35 * unvisited_bonus)
        elif self.attacker_mission == "achievement":
            score += pressure * (0.50 * np.maximum(expected_utility, 0.0) + 0.30 * planning_score + 0.20 * unvisited_bonus)
        return score

    def observe_defense_strategy(
        self,
        strategy: str,
        objective_score: float,
        failure_reason: str,
    ) -> str:
        if not self.adaptive_mission_attacker_enabled:
            return "non_adaptive"
        previous_strategy = self.observed_defense_strategy
        self.observed_defense_strategy = str(strategy or "none")
        pressure = float(np.clip(1.0 - float(objective_score), 0.0, 1.0))
        mission_failure = str(failure_reason or "none") != "none"
        if mission_failure or pressure > 0.45:
            self.strategy_failure_memory = 0.80 * self.strategy_failure_memory + pressure + (0.25 if mission_failure else 0.0)
            self.strategy_success_memory *= 0.85
        else:
            self.strategy_success_memory = 0.80 * self.strategy_success_memory + float(objective_score)
            self.strategy_failure_memory *= 0.85
        self.defense_effectiveness_memory = 0.70 * self.defense_effectiveness_memory + 0.30 * max(
            self.strategy_failure_memory,
            pressure,
        )
        should_adapt = self.defense_effectiveness_memory > 0.35
        changed_strategy = previous_strategy not in ("", "none", self.observed_defense_strategy)
        if should_adapt:
            self.adaptation_count += 1
            self.ttp_change_count += 1
            if changed_strategy:
                self.strategy_avoidance_score += 0.5
            self.alternative_path_usage += self._alternative_path_increment()
            action = self._adaptation_action()
            self.adaptation_history.append(action)
            return action
        self.adaptation_history.append("observe")
        return "observe"

    def _alternative_path_increment(self) -> float:
        if self.adaptive_path_enabled or self.lateral_enabled:
            return 1.0
        return 0.5

    def _adaptation_action(self) -> str:
        if self.attacker_mission == "profit":
            return "target_switch"
        if self.attacker_mission == "persistence":
            return "stealth_lateral_shift"
        if self.attacker_mission == "critical_hunter":
            return "alternative_critical_path"
        if self.attacker_mission == "achievement":
            self.frustration_retreat_threshold += 0.25
            self.patience += 1
            return "risk_tolerance_increase"
        return "generic_ttp_change"

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
        self.attacker_phase = "stationary"
        self.attacker_strategy_name = "configured"
        self.attacker_phase_switch_count = 0
        if self.config.nonstationary_attacker_enabled:
            self._apply_attacker_strategy(self._initial_nonstationary_strategy(), count_switch=False)
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
        self.current_adaptive_policy_id = self.config.adaptive_selected_policy or self.config.adaptive_policy_default
        self.adaptive_policy_history = []
        self.adaptive_policy_switch_steps = []
        self.adaptive_cns_gain = 0.0
        self.adaptive_switch_cost_total = 0.0
        self.initial_attacker_mission = str(self.config.attacker_mission)
        self.mission_mutation_step = None
        self.first_reclassification_step = None
        self.reclassification_total_steps = 0
        self.reclassification_correct_steps = 0
        self.mission_names = ["profit", "achievement", "persistence", "critical_hunter"]
        self.current_true_mission = self._true_mission_label()
        self.current_observed_mission = self.current_true_mission
        self.mission_aware_policy_initialized = False
        self.mission_belief = np.array(
            [
                self.config.belief_profit,
                self.config.belief_achievement,
                self.config.belief_persistence,
                self.config.belief_critical_hunter,
            ],
            dtype=float,
        )
        self.mission_belief = self._normalize_mission_belief(self.mission_belief)
        self._sync_mission_prediction_metrics()
        self.state_names = ["recon", "exploitation", "lateral_movement", "targeting", "action_on_objective"]
        self.state_belief = np.array(
            [
                self.config.belief_recon,
                self.config.belief_exploitation,
                self.config.belief_lateral_movement,
                self.config.belief_targeting,
                self.config.belief_action_on_objective,
            ],
            dtype=float,
        )
        self.state_belief = self._normalize_state_belief(self.state_belief)
        self.previous_predicted_state = "unknown"
        self._sync_state_prediction_metrics()
        self.critical_path_entered = False
        self.latest_critical_path_events: List[str] = []
        self.previous_risk_level = "unknown"
        self.previous_campaign_stage = "none"
        self.previous_campaign_policy = ""
        self.coalition_role_order = ["recon_specialist", "access_specialist", "objective_specialist"]
        self.current_coalition_role = (
            self.config.coalition_role
            if self.config.coalition_role in self.coalition_role_order
            else "recon_specialist"
        )
        self.coalition_delegation_state = "Active Owner"
        self.coalition_handover_events: List[str] = []
        self.current_handover_quality = 1.0
        self.coalition_trust_score = float(np.clip(self.config.coalition_trust_score, 0.0, 1.0))
        self.trust_degradation_count = int(self.config.trust_degradation_count)
        self.failed_handover_count = int(self.config.failed_handover_count)
        self.effective_handover_count = int(self.config.coalition_handover_count)
        self.coalition_information_loss_score = 0.0
        self.fake_asset_nodes = self._counter_deception_fake_asset_nodes()
        self.fake_path_nodes = self._counter_deception_fake_path_nodes()
        self.honey_nodes = self._counter_deception_honey_nodes()
        self.fake_asset_interaction_count = 0
        self.fake_credential_usage_count = 0
        self.credential_trap_trigger_count = 0
        self.fake_path_follow_count = 0
        self.honey_node_visit_count = 0
        self.honey_detection_count = 0
        self.deception_suspicion_score = float(np.clip(self.config.deception_suspicion_score, 0.0, 1.0))
        self.fake_asset_suspicion_count = int(self.config.fake_asset_suspicion_count)
        self.fake_asset_detection_count = 0
        self.fake_credential_detection_count = 0
        self.path_validation_count = int(self.config.path_validation_count)
        self.path_validation_success_count = 0
        self.honey_node_detection_count = 0
        self.false_suspicion_count = 0
        self.fake_asset_hunt_count = int(self.config.fake_asset_hunt_count)
        self.fake_asset_confirmed_count = int(self.config.fake_asset_confirmed_count)
        self.credential_validation_count = int(self.config.credential_validation_count)
        self.credential_validation_success_count = 0
        self.honey_probe_count = int(self.config.honey_probe_count)
        self.honey_probe_success_count = 0
        self.verified_false_signal_count = int(self.config.verified_false_signal_count)
        self.verified_fake_asset_count = int(self.config.verified_fake_asset_count)
        self.deception_knowledge_score = float(np.clip(self.config.deception_knowledge_score, 0.0, 1.0))
        self.verified_fake_asset_nodes = set()
        self.verified_fake_path_nodes = set()
        self.verified_honey_nodes = set()
        self.suspicious_fake_asset_nodes = set()
        self.suspicious_fake_path_nodes = set()
        self.suspicious_honey_nodes = set()
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
            'attacker_phase': [],
            'adaptive_policy_id': [],
            'selected_policy_history': [],
            'campaign_stage_history': [],
            'campaign_policy_history': [],
            'mission_belief': [],
            'state_belief': [],
            'observable_events': [],
            'critical_path_events': [],
            'risk_score': [],
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
            'mission_satisfaction': [],
            'mission_objective_history': [],
            'mission_failure_reason_history': [],
            'observed_defense_history': [],
            'adaptation_history': [],
            'mission_history': [],
            'inferred_mission_history': [],
            'mission_confidence_history': [],
            'behavior_profile_history': [],
            'profile_confidence_history': [],
            'strategy_history': [],
            'strategy_confidence_history': [],
            'reclassified_mission_history': [],
            'selected_strategy_history': [],
            'true_mission_history': [],
            'observed_mission_history': [],
            'deception_history': [],
            'noise_history': [],
            'signal_history': [],
            'fake_signal_history': [],
            'signal_consistency_history': [],
            'coalition_role_history': [],
            'coalition_handover_history': [],
            'coalition_delegation_state_history': [],
            'coordination_history': [],
            'trust_history': [],
            'handover_failure_history': [],
            'fake_asset_interaction_history': [],
            'fake_credential_usage_history': [],
            'credential_trap_trigger_history': [],
            'fake_path_follow_history': [],
            'honey_node_visit_history': [],
            'honey_detection_history': [],
            'counter_deception_score_history': [],
            'awareness_history': [],
            'suspicion_history': [],
            'deception_knowledge_history': [],
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
            attacker_mission=self.config.attacker_mission,
            mission_expected_utility_weight=self.config.mission_expected_utility_weight,
            mission_trust_weight=self.config.mission_trust_weight,
            mission_planning_weight=self.config.mission_planning_weight,
            mission_critical_target_weight=self.config.mission_critical_target_weight,
            adaptive_mission_attacker_enabled=self.config.adaptive_mission_attacker_enabled,
            observed_defense_strategy=self.config.observed_defense_strategy,
            defense_effectiveness_memory=self.config.defense_effectiveness_memory,
            strategy_failure_memory=self.config.strategy_failure_memory,
            strategy_success_memory=self.config.strategy_success_memory,
            adaptation_count=self.config.adaptation_count,
            ttp_change_count=self.config.ttp_change_count,
            strategy_avoidance_score=self.config.strategy_avoidance_score,
            alternative_path_usage=self.config.alternative_path_usage,
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

    def _coalition_target_override(self, selected_target: int) -> int:
        if not self.config.coalition_enabled or selected_target < 0:
            return selected_target
        role = self.current_coalition_role
        critical_nodes = {int(node) for node in self.config.critical_nodes}
        if role == "recon_specialist":
            for node in self.config.entry_nodes:
                node_id = int(node)
                if node_id not in critical_nodes:
                    return node_id
        if role == "access_specialist":
            candidates = [
                int(node)
                for node in range(self.config.n_nodes)
                if int(node) not in critical_nodes
                and self._target_moves_closer_to_critical(int(self.attacker.current_node), int(node))
            ]
            if candidates:
                return max(candidates, key=lambda node: float(self.config.attacker_belief[node]))
        if role == "objective_specialist" and critical_nodes:
            return max(critical_nodes, key=lambda node: float(self.config.attacker_belief[node]))
        return selected_target

    def _coalition_success_bonus(self, selected_target: int, attack_active: bool) -> float:
        if not self.config.coalition_enabled or not attack_active or selected_target < 0:
            return 0.0
        role = self.current_coalition_role
        bonus = {
            "recon_specialist": 0.03,
            "access_specialist": 0.08,
            "objective_specialist": 0.06,
        }.get(role, 0.0)
        if role == "objective_specialist" and int(selected_target) in {int(node) for node in self.config.critical_nodes}:
            bonus += 0.04
        return float(bonus * self.current_handover_quality)

    def _counter_deception_active(self) -> bool:
        return bool(self.config.counter_deception_enabled)

    def _counter_deception_fake_asset_nodes(self) -> set:
        if not self._counter_deception_active():
            return set()
        decoys = [idx for idx, value in enumerate(self.config.node_type) if str(value) == "decoy"]
        if decoys:
            return {int(max(decoys, key=lambda node: float(self.config.attacker_belief[int(node)])))}
        critical = {int(node) for node in self.config.critical_nodes}
        candidates = [idx for idx in range(self.config.n_nodes) if idx not in critical]
        return {int(max(candidates, key=lambda node: float(self.config.attacker_belief[int(node)])))} if candidates else set()

    def _counter_deception_fake_path_nodes(self) -> set:
        if not self._counter_deception_active():
            return set()
        critical_path_nodes = self._static_critical_path_nodes()
        candidates = [
            idx
            for idx in range(self.config.n_nodes)
            if idx not in critical_path_nodes and idx not in self.config.critical_nodes
        ]
        if not candidates:
            candidates = [idx for idx in range(self.config.n_nodes) if idx not in self.config.critical_nodes]
        return {int(max(candidates, key=lambda node: float(self.config.attacker_belief[int(node)])))} if candidates else set()

    def _counter_deception_honey_nodes(self) -> set:
        if not self._counter_deception_active():
            return set()
        credential_nodes = {int(node) for node in self.config.credential_node_ids if 0 <= int(node) < self.config.n_nodes}
        if credential_nodes:
            return credential_nodes
        return set(self.fake_asset_nodes) | set(self.fake_path_nodes)

    def _counter_deception_target_override(self, selected_target: int) -> int:
        if not self._counter_deception_active() or selected_target < 0:
            return selected_target
        resistance = 0.0
        if self.config.counter_deception_awareness_enabled:
            hunting_bonus = 0.25 * self.deception_knowledge_score if self.config.counter_deception_hunting_enabled else 0.0
            resistance = float(np.clip(0.65 * self.deception_suspicion_score + hunting_bonus, 0.0, 0.90))
        if self.config.fake_critical_path_enabled and self.fake_path_nodes:
            path_candidates = list(self.fake_path_nodes - self.suspicious_fake_path_nodes - self.verified_fake_path_nodes) or list(self.fake_path_nodes)
            if self.rng.random() < max(0.10, (0.55 + self._product_diversion_boost()) * (1.0 - resistance)):
                return int(max(path_candidates, key=lambda node: float(self.config.attacker_belief[int(node)])))
        if self.config.fake_asset_enabled and self.fake_asset_nodes:
            asset_candidates = list(self.fake_asset_nodes - self.suspicious_fake_asset_nodes - self.verified_fake_asset_nodes) or list(self.fake_asset_nodes)
            if self.rng.random() < max(0.10, (0.45 + self._product_diversion_boost()) * (1.0 - resistance)):
                return int(max(asset_candidates, key=lambda node: float(self.config.attacker_belief[int(node)])))
        return selected_target

    def _counter_deception_awareness_active(self) -> bool:
        return bool(self._counter_deception_active() and self.config.counter_deception_awareness_enabled)

    def _counter_deception_hunting_active(self) -> bool:
        return bool(self._counter_deception_awareness_active() and self.config.counter_deception_hunting_enabled)

    def _counter_deception_awareness_score(self) -> float:
        detection_rates = [
            self.fake_asset_detection_count / max(self.fake_asset_interaction_count, 1),
            self.fake_credential_detection_count / max(self.fake_credential_usage_count, 1),
            self.path_validation_success_count / max(self.path_validation_count, 1),
            self.honey_node_detection_count / max(self.honey_node_visit_count, 1),
        ]
        return float(np.clip(0.50 * self.deception_suspicion_score + 0.50 * float(np.mean(detection_rates)), 0.0, 1.0))

    def _update_deception_knowledge_score(self) -> None:
        discoveries = (
            len(self.verified_fake_asset_nodes)
            + len(self.verified_fake_path_nodes)
            + len(self.verified_honey_nodes)
            + self.credential_validation_success_count
            + self.verified_false_signal_count
        )
        possible = max(
            len(self.fake_asset_nodes) + len(self.fake_path_nodes) + len(self.honey_nodes) + self.fake_credential_usage_count + 1,
            1,
        )
        self.deception_knowledge_score = float(np.clip(discoveries / possible, 0.0, 1.0))
        self.config.deception_knowledge_score = self.deception_knowledge_score

    def _run_counter_deception_hunting(
        self,
        selected_target: int,
        fake_asset_hit: bool,
        fake_credential_hit: bool,
        fake_path_hit: bool,
        honey_hit: bool,
        events: List[str],
    ) -> None:
        if not self._counter_deception_hunting_active() or selected_target < 0:
            return
        if self.deception_suspicion_score < 0.20 and not (fake_asset_hit or fake_credential_hit or fake_path_hit or honey_hit):
            return

        if fake_asset_hit or selected_target in self.suspicious_fake_asset_nodes:
            self.fake_asset_hunt_count += 1
            events.append("asset_verification")
            if fake_asset_hit:
                self.fake_asset_confirmed_count += 1
                self.verified_fake_asset_count += 1
                self.verified_fake_asset_nodes.add(int(selected_target))
                events.append("fake_asset_confirmed")

        if fake_credential_hit or self.fake_credential_usage_count > 0:
            self.credential_validation_count += 1
            events.append("credential_validation")
            if fake_credential_hit:
                self.credential_validation_success_count += 1
                self.verified_false_signal_count += 1
                events.append("credential_trap_confirmed")

        if fake_path_hit or selected_target in self.suspicious_fake_path_nodes:
            self.path_validation_count += 1
            events.append("path_verification")
            if fake_path_hit:
                self.path_validation_success_count += 1
                self.verified_fake_path_nodes.add(int(selected_target))
                events.append("fake_path_confirmed")

        if honey_hit or selected_target in self.suspicious_honey_nodes:
            self.honey_probe_count += 1
            events.append("honey_probe")
            if honey_hit:
                self.honey_probe_success_count += 1
                self.verified_honey_nodes.add(int(selected_target))
                events.append("honey_node_confirmed")

        self._update_deception_knowledge_score()

    def _update_counter_deception_awareness(
        self,
        selected_target: int,
        fake_asset_hit: bool,
        fake_credential_hit: bool,
        fake_path_hit: bool,
        honey_hit: bool,
        events: List[str],
    ) -> None:
        if not self._counter_deception_awareness_active() or selected_target < 0:
            return

        suspicion_delta = 0.0
        if fake_asset_hit:
            self.fake_asset_suspicion_count += 1
            suspicion_delta += 0.08
            if self.fake_asset_suspicion_count >= 1:
                self.fake_asset_detection_count += 1
                self.suspicious_fake_asset_nodes.add(int(selected_target))
                events.append("fake_asset_suspected")
        if fake_credential_hit:
            suspicion_delta += 0.12
            self.fake_credential_detection_count += 1
            events.append("fake_credential_suspected")

        if self.config.fake_critical_path_enabled:
            self.path_validation_count += 1
            path_nodes = self._static_critical_path_nodes()
            path_consistent = int(selected_target) in path_nodes
            proximity = self._distance_to_nearest_critical_static(int(selected_target))
            critical_proximity = proximity is not None and proximity <= 1
            event_consistent = not fake_path_hit
            validation_success = bool(fake_path_hit or not (path_consistent or critical_proximity or event_consistent))
            if validation_success:
                self.path_validation_success_count += 1
                suspicion_delta += 0.08 if fake_path_hit else 0.03
                if fake_path_hit:
                    self.suspicious_fake_path_nodes.add(int(selected_target))
                    events.append("fake_path_suspected")
            elif path_consistent and critical_proximity:
                self.false_suspicion_count += 1

        if honey_hit:
            suspicion_delta += 0.07
            self.honey_node_detection_count += 1
            self.suspicious_honey_nodes.add(int(selected_target))
            events.append("honey_node_suspected")

        if selected_target in self.config.critical_nodes and not (fake_asset_hit or fake_credential_hit or fake_path_hit or honey_hit):
            self.false_suspicion_count += 1
            suspicion_delta -= 0.02

        self.deception_suspicion_score = float(np.clip(self.deception_suspicion_score + suspicion_delta, 0.0, 1.0))
        self.config.deception_suspicion_score = self.deception_suspicion_score
        self._run_counter_deception_hunting(
            selected_target=selected_target,
            fake_asset_hit=fake_asset_hit,
            fake_credential_hit=fake_credential_hit,
            fake_path_hit=fake_path_hit,
            honey_hit=honey_hit,
            events=events,
        )

    def _counter_deception_step_effects(
        self,
        selected_target: int,
        detected: bool,
        credential_decoy_trigger: bool,
        critical_true_gain: float,
    ) -> Tuple[bool, bool, bool, bool, List[str], float]:
        if not self._counter_deception_active() or selected_target < 0:
            return False, False, False, False, [], critical_true_gain

        events: List[str] = []
        fake_asset_hit = bool(self.config.fake_asset_enabled and selected_target in self.fake_asset_nodes)
        fake_path_hit = bool(self.config.fake_critical_path_enabled and selected_target in self.fake_path_nodes)
        fake_credential_hit = bool(self.config.fake_credential_enabled and credential_decoy_trigger)
        honey_hit = bool(self.config.honey_node_enabled and selected_target in self.honey_nodes)

        if fake_asset_hit:
            self.fake_asset_interaction_count += 1
            self.attacker.confidence *= 0.92
            if self.attacker.last_expected_utility is not None and len(self.attacker.last_expected_utility) > selected_target:
                self.attacker.last_expected_utility[selected_target] *= 0.70
            events.append("fake_asset_interaction")
        if fake_credential_hit:
            self.fake_credential_usage_count += 1
            self.credential_trap_trigger_count += 1
            self.attacker.confidence *= 0.85
            events.append("fake_credential_use")
            events.append("credential_trap_trigger")
        if fake_path_hit:
            self.fake_path_follow_count += 1
            critical_true_gain = 0.0
            self.attacker.confidence *= 0.90
            events.append("fake_critical_path_follow")
        if honey_hit:
            self.honey_node_visit_count += 1
            if detected:
                self.honey_detection_count += 1
            events.append("honey_node_visit")
            if detected:
                events.append("honey_detection")
        self._update_counter_deception_awareness(
            selected_target=selected_target,
            fake_asset_hit=fake_asset_hit,
            fake_credential_hit=fake_credential_hit,
            fake_path_hit=fake_path_hit,
            honey_hit=honey_hit,
            events=events,
        )
        return fake_asset_hit, fake_credential_hit, fake_path_hit, honey_hit, events, critical_true_gain

    def _coalition_handover_success_probability(self) -> float:
        cost = float(self.config.coordination_cost) if self.config.coalition_coordination_cost_enabled else 0.0
        trust_penalty = 1.0 - self.coalition_trust_score if self.config.coalition_trust_enabled else 0.0
        information_penalty = 0.15 if self.config.coalition_information_loss_enabled else 0.0
        size_penalty = max(int(self.config.coalition_size) - 2, 0) * 0.05
        return float(np.clip(1.0 - cost - 0.5 * trust_penalty - information_penalty - size_penalty, 0.05, 1.0))

    def _apply_coalition_information_loss(self, selected_target: int, failed: bool) -> float:
        if not self.config.coalition_information_loss_enabled:
            self.coalition_information_loss_score = 0.0
            return 0.0
        base_loss = 0.12 + float(self.config.coordination_cost) * 0.25
        loss = float(np.clip(base_loss + (0.10 if failed else 0.0), 0.0, 0.6))
        if 0 <= selected_target < len(self.config.attacker_belief):
            belief = np.asarray(self.config.attacker_belief, dtype=float).copy()
            belief[int(selected_target)] = max(float(belief[int(selected_target)]) * (1.0 - loss), 0.0)
            total = float(np.sum(belief))
            if total > 0.0:
                belief = belief / total
            self.config.attacker_belief = belief
        self.coalition_information_loss_score = loss
        return loss

    def _update_coalition_delegation(
        self,
        step: int,
        observable_events: List[str],
        critical_path_events: List[str],
        selected_target: int,
        credential_used: bool,
        success: bool,
    ) -> str:
        if not self.config.coalition_enabled:
            self.config.coalition_role = "single_attacker"
            self.config.coalition_delegation_state = "Active Owner"
            self.config.coalition_coordination_score = 0.0
            return "none"

        role = self.current_coalition_role
        all_events = set(observable_events) | set(critical_path_events)
        next_role = role
        if role == "recon_specialist" and (
            "scan" in all_events or "critical_path_discovery" in all_events or step >= 1
        ):
            next_role = "access_specialist"
        elif role == "access_specialist" and (
            credential_used or "credential_use" in all_events or "lateral_move" in all_events or step >= 3
        ):
            next_role = "objective_specialist"

        handover_event = "none"
        if next_role != role:
            handover_prob = self._coalition_handover_success_probability()
            handover_success = bool(self.rng.random() < handover_prob)
            information_loss = self._apply_coalition_information_loss(selected_target, failed=not handover_success)
            if handover_success:
                self.config.coalition_handover_count += 1
                self.effective_handover_count += 1
                self.coalition_delegation_state = "Preparing Handover"
                handover_event = f"{role}->{next_role}"
                self.coalition_handover_events.append(handover_event)
                self.current_coalition_role = next_role
                if self.config.coalition_trust_enabled:
                    self.coalition_trust_score = float(np.clip(self.coalition_trust_score + 0.02, 0.0, 1.0))
            else:
                self.failed_handover_count += 1
                self.config.failed_handover_count = self.failed_handover_count
                self.coalition_delegation_state = "Active Owner"
                handover_event = f"failed:{role}->{next_role}"
                if self.config.coalition_trust_enabled:
                    self.coalition_trust_score = float(np.clip(self.coalition_trust_score - 0.15, 0.0, 1.0))
                    self.trust_degradation_count += 1
                    self.config.trust_degradation_count = self.trust_degradation_count
            cost = float(self.config.coordination_cost) if self.config.coalition_coordination_cost_enabled else 0.0
            self.current_handover_quality = float(np.clip(1.0 - cost - information_loss - (0.10 if not handover_success else 0.0), 0.1, 1.0))
        elif self.coalition_delegation_state == "Preparing Handover":
            self.coalition_delegation_state = "Delegated"
            self.current_handover_quality = float(np.clip(self.current_handover_quality + 0.03, 0.1, 1.0))
        else:
            self.coalition_delegation_state = "Active Owner"
            self.current_handover_quality = float(np.clip(self.current_handover_quality + 0.01, 0.1, 1.0))

        role_index = self.coalition_role_order.index(self.current_coalition_role)
        self.config.coalition_role = self.current_coalition_role
        self.config.coalition_delegation_state = self.coalition_delegation_state
        self.config.coalition_trust_score = self.coalition_trust_score
        self.config.coalition_coordination_score = float(
            np.clip(
                self.current_handover_quality
                * (self.effective_handover_count + int(success))
                / max(len(self.coalition_role_order), 1),
                0.0,
                1.0,
            )
        )
        self.config.coalition_id = f"coalition_{role_index % max(int(self.config.coalition_size), 1)}"
        return handover_event

    def run(self):
        logger.info(f"Starting simulation for T={self.config.T} steps...")
        for t in range(self.config.T):
            self.current_step = t
            self._mission_aware_policy_update(t)
            self._nonstationary_attacker_update(t)
            self._step_adaptive_policy_update(t)
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
            coalition_selected_target = self._coalition_target_override(selected_target)
            if coalition_selected_target != selected_target:
                selected_target = int(coalition_selected_target)
                attack_vector = np.zeros(self.config.n_nodes, dtype=float)
                attack_vector[selected_target] = float(self.attacker.attack_budget)
                self.attacker.previous_selected_target = int(self.attacker.last_selected_target)
                self.attacker.last_selected_target = selected_target
            counter_deception_selected_target = self._counter_deception_target_override(selected_target)
            if counter_deception_selected_target != selected_target:
                selected_target = int(counter_deception_selected_target)
                attack_vector = np.zeros(self.config.n_nodes, dtype=float)
                attack_vector[selected_target] = float(self.attacker.attack_budget)
                self.attacker.previous_selected_target = int(self.attacker.last_selected_target)
                self.attacker.last_selected_target = selected_target
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
                    success_prob = float(np.clip(
                        success_prob + self._coalition_success_bonus(selected_target, attack_active),
                        0.0,
                        1.0,
                    ))
                    success = bool(self.rng.random() < success_prob)
                else:
                    success_prob = self._attack_success_probability(
                        gained,
                        attacked_decoy,
                        target_defense_strength,
                    )
                    success_prob = float(np.clip(
                        success_prob + self._coalition_success_bonus(selected_target, attack_active),
                        0.0,
                        1.0,
                    ))
                    success = self._attack_succeeds(gained, attacked_decoy, target_defense_strength)
                    if self.config.coalition_enabled and not success and self.rng.random() < success_prob:
                        success = True
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
            fake_asset_hit, fake_credential_hit, fake_path_hit, honey_hit, counter_deception_events, critical_true_gain = self._counter_deception_step_effects(
                selected_target=selected_target,
                detected=detected,
                credential_decoy_trigger=credential_decoy_trigger,
                critical_true_gain=critical_true_gain,
            )
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
            # Oracle leak fix: attacker belief should be updated based on perceived success
            perceived_success = (perceived_gain > 0.0)
            perceived_decoy = attacked_decoy and detected # Attacker only knows it's a decoy if detected
            self.attacker.update_belief(
                target_idx=selected_target,
                success=perceived_success,
                detected=detected,
                attacked_decoy=perceived_decoy,
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
            critical_path_events = self._generate_critical_path_events(
                selected_target=selected_target,
                success=success,
                critical_reached=critical_reached,
            )
            observable_events = self._generate_observable_events(
                selected_target=selected_target,
                attack_active=attack_active,
                success=success,
                credential_used=credential_used,
                credential_decoy_trigger=credential_decoy_trigger,
                path_changed=path_changed,
                critical_reached=critical_reached,
            )
            observable_events = list(dict.fromkeys(observable_events + counter_deception_events))
            observable_events = list(dict.fromkeys(observable_events + critical_path_events))
            observable_events, signal_events, noise_events, fake_signal_events, consistency_score, extracted_observable_events = self._apply_noise_and_signal_extraction(
                observable_events,
                critical_path_events,
                selected_target,
            )
            coalition_handover_event = self._update_coalition_delegation(
                step=t,
                observable_events=extracted_observable_events,
                critical_path_events=critical_path_events,
                selected_target=selected_target,
                credential_used=credential_used,
                success=success,
            )
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
            self.history['attacker_phase'].append(str(self.attacker_phase))
            self.history['adaptive_policy_id'].append(str(self.current_adaptive_policy_id))
            self.history['selected_policy_history'].append(str(self.current_adaptive_policy_id))
            self.history['observable_events'].append("|".join(observable_events))
            self.history['critical_path_events'].append("|".join(critical_path_events))
            self.history['noise_history'].append("|".join(noise_events))
            self.history['signal_history'].append("|".join(signal_events))
            self.history['fake_signal_history'].append("|".join(fake_signal_events))
            self.history['signal_consistency_history'].append(float(consistency_score))
            self.history['coalition_role_history'].append(str(self.config.coalition_role))
            self.history['coalition_handover_history'].append(str(coalition_handover_event))
            self.history['coalition_delegation_state_history'].append(str(self.config.coalition_delegation_state))
            self.history['coordination_history'].append(float(self.config.coalition_coordination_score))
            self.history['trust_history'].append(float(self.coalition_trust_score))
            self.history['handover_failure_history'].append(1 if str(coalition_handover_event).startswith("failed:") else 0)
            disruption = float(
                np.clip(
                    (int(fake_asset_hit) + int(fake_credential_hit) + int(fake_path_hit) + int(honey_hit)) / 4.0,
                    0.0,
                    1.0,
                )
            )
            self.history['fake_asset_interaction_history'].append(1 if fake_asset_hit else 0)
            self.history['fake_credential_usage_history'].append(1 if fake_credential_hit else 0)
            self.history['credential_trap_trigger_history'].append(1 if fake_credential_hit else 0)
            self.history['fake_path_follow_history'].append(1 if fake_path_hit else 0)
            self.history['honey_node_visit_history'].append(1 if honey_hit else 0)
            self.history['honey_detection_history'].append(1 if honey_hit and detected else 0)
            self.history['counter_deception_score_history'].append(disruption)
            self.history['awareness_history'].append(self._counter_deception_awareness_score() if self._counter_deception_awareness_active() else 0.0)
            self.history['suspicion_history'].append(float(self.deception_suspicion_score))
            self.history['deception_knowledge_history'].append(float(self.deception_knowledge_score))
            self._mission_belief_update(
                credential_decoy_trigger=bool(credential_decoy_trigger),
                selected_target=int(selected_target) if selected_target is not None else None,
            )
            observed_mission = self._apply_intent_deception()
            self._state_belief_update(
                credential_decoy_trigger=bool(credential_decoy_trigger),
                selected_target=int(selected_target) if selected_target is not None else None,
                observable_events=extracted_observable_events,
                critical_path_events=critical_path_events,
            )
            risk_score = self._intelligence_policy_update(
                selected_target=int(selected_target) if selected_target is not None else None,
            )
            self.history['mission_belief'].append(self.mission_belief.copy())
            self.history['state_belief'].append(self.state_belief.copy())
            self.history['risk_score'].append(float(risk_score))
            self.history['campaign_stage_history'].append(str(self.config.campaign_stage))
            self.history['campaign_policy_history'].append(str(self.current_adaptive_policy_id))
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
            mission_objective_score, mission_failure_reason = self._mission_objective_step()
            if self._counter_deception_active():
                disruption_penalty = 0.08 * int(fake_asset_hit) + 0.10 * int(fake_credential_hit) + 0.12 * int(fake_path_hit)
                if self._counter_deception_awareness_active():
                    disruption_penalty *= max(0.35, 1.0 - 0.65 * self.deception_suspicion_score)
                if self._counter_deception_hunting_active():
                    disruption_penalty *= max(0.45, 1.0 - 0.50 * self.deception_knowledge_score)
                if disruption_penalty > 0.0:
                    mission_objective_score = float(np.clip(mission_objective_score - disruption_penalty, 0.0, 1.0))
                    mission_failure_reason = "counter_deception_disruption"
            self.config.mission_satisfaction = float(mission_objective_score)
            self.config.mission_objective_score = float(mission_objective_score)
            self.config.mission_failure_reason = str(mission_failure_reason)
            self._apply_mission_objective_retreat(float(mission_objective_score), str(mission_failure_reason))
            observed_strategy = str(self.config.campaign_strategy_profile if self.config.defense_campaign_enabled else self.current_adaptive_policy_id)
            adaptation_action = self.attacker.observe_defense_strategy(
                observed_strategy,
                float(mission_objective_score),
                str(mission_failure_reason),
            )
            self.config.observed_defense_strategy = self.attacker.observed_defense_strategy
            self.config.defense_effectiveness_memory = float(self.attacker.defense_effectiveness_memory)
            self.config.strategy_failure_memory = float(self.attacker.strategy_failure_memory)
            self.config.strategy_success_memory = float(self.attacker.strategy_success_memory)
            self.config.adaptation_count = int(self.attacker.adaptation_count)
            self.config.ttp_change_count = int(self.attacker.ttp_change_count)
            self.config.strategy_avoidance_score = float(self.attacker.strategy_avoidance_score)
            self.config.alternative_path_usage = float(self.attacker.alternative_path_usage)
            mutation_reason = self._maybe_mutate_mission(float(mission_objective_score), str(mission_failure_reason))
            reclassified_mission = self._maybe_reclassify_mission(
                float(mission_objective_score),
                str(mission_failure_reason),
                str(adaptation_action),
                str(mutation_reason),
            )
            self.history['mission_satisfaction'].append(float(mission_objective_score))
            self.history['mission_objective_history'].append(float(mission_objective_score))
            self.history['mission_failure_reason_history'].append(str(self.config.mission_failure_reason))
            self.history['observed_defense_history'].append(observed_strategy)
            self.history['adaptation_history'].append(str(adaptation_action))
            self.history['mission_history'].append(str(self.config.attacker_mission))
            self.history['reclassified_mission_history'].append(str(reclassified_mission))
            self.history['selected_strategy_history'].append(
                str(self.config.campaign_strategy_profile if self.config.defense_campaign_enabled else self.current_adaptive_policy_id)
            )
            self.history['true_mission_history'].append(str(self.current_true_mission))
            self.history['observed_mission_history'].append(str(observed_mission))
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

    def _initial_nonstationary_strategy(self) -> str:
        if self.config.nonstationary_attacker_pattern == "planning_to_expected":
            return "planning"
        return "expected_utility"

    def _second_nonstationary_strategy(self) -> str:
        if self.config.nonstationary_attacker_pattern == "planning_to_expected":
            return "expected_utility"
        return "trust_aware_planning"

    def _nonstationary_attacker_update(self, t: int) -> None:
        if not self.config.nonstationary_attacker_enabled:
            return
        if t == int(self.config.attacker_phase_change_step):
            self._apply_attacker_strategy(self._second_nonstationary_strategy(), count_switch=True)

    def _apply_attacker_strategy(self, strategy_name: str, count_switch: bool) -> None:
        phase = f"phase{self.attacker_phase_switch_count + 1}" if count_switch else "phase0"
        if strategy_name == "expected_utility":
            settings = {
                "adaptive_attacker_enabled": True,
                "adaptive_preference_enabled": True,
                "adaptive_path_enabled": True,
                "adaptive_planning_enabled": True,
                "trust_enabled": True,
                "expected_utility_enabled": True,
            }
        elif strategy_name == "trust_aware_planning":
            settings = {
                "adaptive_attacker_enabled": True,
                "adaptive_preference_enabled": True,
                "adaptive_path_enabled": True,
                "adaptive_planning_enabled": True,
                "trust_enabled": True,
                "expected_utility_enabled": False,
            }
        else:
            settings = {
                "adaptive_attacker_enabled": True,
                "adaptive_preference_enabled": True,
                "adaptive_path_enabled": True,
                "adaptive_planning_enabled": True,
                "trust_enabled": False,
                "expected_utility_enabled": False,
            }
            strategy_name = "planning"

        for key, value in settings.items():
            setattr(self.config, key, value)
            setattr(self.attacker, key, value)
        self.attacker.target_selection = "adaptive"
        self.config.attacker_target_selection = "adaptive"
        self.attacker_strategy_name = strategy_name
        self.attacker_phase = f"{phase}:{strategy_name}"
        if count_switch:
            self.attacker_phase_switch_count += 1

    def _step_adaptive_policy_update(self, t: int) -> None:
        if (
            not self.config.step_adaptive_defender_enabled
            or not self.config.adaptive_defender_enabled
            or t % self.config.adaptive_recheck_interval != 0
        ):
            return

        observations = self._step_adaptive_observations()
        candidates = [
            "phase2_frustration_decoy",
            "phase2_ai_balanced",
            "gated_edge_pressure_count_2",
        ]
        current_policy = self.current_adaptive_policy_id or self.config.adaptive_policy_default
        if current_policy not in candidates:
            current_policy = self.config.adaptive_policy_default
        current_score = self._estimate_step_policy_score(current_policy, observations)
        scored = [
            (policy, self._estimate_step_policy_score(policy, observations))
            for policy in candidates
        ]
        scored.sort(key=lambda item: item[1], reverse=True)
        best_policy, best_score = scored[0]
        improvement = float(best_score - current_score)
        threshold = float(self.config.adaptive_min_improvement + self.config.adaptive_policy_switch_cost)

        self.config.adaptive_policy_score = float(best_score)
        self.config.adaptive_policy_rank = 1
        self.config.adaptive_estimated_cns = float(np.clip(best_score, 0.0, 1.0))
        self.config.adaptive_selection_reason = "step_cns_recheck"
        self.config.adaptive_policy_reason = self._step_policy_reason(best_policy, observations)

        if best_policy != current_policy and improvement > threshold:
            self.current_adaptive_policy_id = best_policy
            self.config.adaptive_selected_policy = best_policy
            self.config.adaptive_policy_switch_count += 1
            self.adaptive_policy_switch_steps.append(int(t))
            self.adaptive_cns_gain += improvement
            self.adaptive_switch_cost_total += float(self.config.adaptive_policy_switch_cost)
            self._apply_step_policy(best_policy)
        else:
            self.current_adaptive_policy_id = current_policy
            self.config.adaptive_selected_policy = current_policy

        self.adaptive_policy_history.append(str(self.current_adaptive_policy_id))

    def _select_mission_aware_policy(self) -> Tuple[str, str]:
        if self.config.state_belief_inference_enabled:
            critical_event_mapping = {
                "critical_path_entry": "phase4_planning_disruptor",
                "critical_path_progress": "phase4_target_switch_inducer",
                "critical_path_near_target": "phase2_frustration_decoy",
                "critical_asset_reach": "phase2_frustration_decoy",
            }
            for event in (
                "critical_asset_reach",
                "critical_path_near_target",
                "critical_path_progress",
                "critical_path_entry",
            ):
                if event in self.latest_critical_path_events:
                    return critical_event_mapping[event], f"critical_path_{event}"
            state = self.config.predicted_state
            state_mapping = {
                "recon": "phase4_target_switch_inducer",
                "exploitation": "phase4_trust_collapse_maximizer",
                "lateral_movement": "phase4_planning_disruptor",
                "targeting": "phase2_frustration_decoy",
                "action_on_objective": "phase2_frustration_decoy",
            }
            selected = state_mapping.get(state, self.config.adaptive_policy_default)
            if state in state_mapping:
                return selected, f"state_belief_{state}"
            return selected, "state_belief_default"
        mission = self.config.predicted_mission if self.config.mission_belief_inference_enabled else self.config.attacker_mission
        mapping = {
            "profit": "phase4_expected_utility_suppressor",
            "achievement": "phase4_planning_disruptor",
            "persistence": "phase4_trust_collapse_maximizer",
            "critical_hunter": "phase4_planning_disruptor",
        }
        selected = mapping.get(mission, self.config.adaptive_policy_default)
        if mission in mapping:
            prefix = "belief_mission" if self.config.mission_belief_inference_enabled else "oracle_mission"
            return selected, f"{prefix}_{mission}"
        return selected, "oracle_mission_default"

    def _normalize_mission_belief(self, belief: np.ndarray) -> np.ndarray:
        clipped = np.clip(np.asarray(belief, dtype=float), 0.0, None)
        total = float(np.sum(clipped))
        if total <= 0.0:
            return np.full(4, 0.25, dtype=float)
        return clipped / total

    def _sync_mission_prediction_metrics(self) -> None:
        self.mission_belief = self._normalize_mission_belief(self.mission_belief)
        idx = int(np.argmax(self.mission_belief))
        predicted = self.mission_names[idx]
        self.config.belief_profit = float(self.mission_belief[0])
        self.config.belief_achievement = float(self.mission_belief[1])
        self.config.belief_persistence = float(self.mission_belief[2])
        self.config.belief_critical_hunter = float(self.mission_belief[3])
        self.config.predicted_mission = predicted
        self.config.mission_prediction_confidence = float(self.mission_belief[idx])
        self.config.mission_prediction_correct = predicted == self.config.attacker_mission

    def _mission_belief_update(self, credential_decoy_trigger: bool, selected_target: Optional[int]) -> None:
        if not self.config.mission_belief_inference_enabled:
            return

        evidence = np.zeros(4, dtype=float)
        if credential_decoy_trigger:
            evidence[0] += 0.20
            evidence[2] += 0.10

        selected_targets = np.asarray(self.history.get('attacker_selected_target', []), dtype=int)
        valid_targets = selected_targets[selected_targets >= 0]
        if len(valid_targets) >= 2 and int(valid_targets[-1]) != int(valid_targets[-2]):
            evidence[1] += 0.15

        critical_focus = (
            selected_target is not None
            and any(int(selected_target) == int(node) for node in self.config.critical_nodes)
        )
        if critical_focus:
            evidence[3] += 0.25

        trust_vector = self.attacker.trust_vector(self.config.n_nodes)
        trust_collapse_rate = float(np.mean(trust_vector < 0.5)) if len(trust_vector) > 0 else 0.0
        if trust_collapse_rate > self.config.adaptive_trust_collapse_threshold:
            evidence[2] += 0.15

        expected = self.attacker.last_expected_utility
        if expected is not None and len(expected) > 0 and float(np.max(expected)) > 0.0:
            evidence[0] += 0.05

        planning = self.attacker.last_planning_score
        if planning is not None:
            finite = np.asarray(planning, dtype=float)
            finite = finite[np.isfinite(finite) & (finite > -1.0e11)]
            if len(finite) > 0 and float(np.max(finite)) > 0.0:
                evidence[1] += 0.05

        if float(np.sum(evidence)) > 0.0:
            previous_prediction = self.config.predicted_mission
            self.mission_belief = self._normalize_mission_belief(self.mission_belief + evidence)
            self._sync_mission_prediction_metrics()
            if self.config.mission_aware_defender_enabled and self.config.adaptive_defender_enabled:
                self._mission_belief_policy_update(previous_prediction)

    def _mission_belief_policy_update(self, previous_prediction: str) -> None:
        if self.config.predicted_mission == previous_prediction and self.mission_aware_policy_initialized:
            return
        previous_policy = self.current_adaptive_policy_id or self.config.adaptive_policy_default
        selected_policy, reason = self._select_mission_aware_policy()
        self.current_adaptive_policy_id = selected_policy
        self.config.adaptive_selected_policy = selected_policy
        self.config.adaptive_policy_reason = reason
        self.config.adaptive_selection_reason = reason
        self.config.mission_aware_selected_policy = selected_policy
        self.config.mission_aware_selection_reason = reason
        self.config.mission_policy_match = selected_policy == {
            "profit": "phase4_expected_utility_suppressor",
            "achievement": "phase4_planning_disruptor",
            "persistence": "phase4_trust_collapse_maximizer",
            "critical_hunter": "phase4_planning_disruptor",
        }.get(self.config.predicted_mission, self.config.adaptive_policy_default)
        if selected_policy != previous_policy:
            self.config.mission_policy_switch_count += 1
            self.config.adaptive_policy_switch_count += 1
            self.adaptive_policy_switch_steps.append(int(self.current_step))
        self._apply_step_policy(selected_policy)
        self.mission_aware_policy_initialized = True

    def _normalize_state_belief(self, belief: np.ndarray) -> np.ndarray:
        clipped = np.clip(np.asarray(belief, dtype=float), 0.0, None)
        total = float(np.sum(clipped))
        if total <= 0.0:
            return np.full(5, 0.20, dtype=float)
        return clipped / total

    def _sync_state_prediction_metrics(self) -> None:
        self.state_belief = self._normalize_state_belief(self.state_belief)
        idx = int(np.argmax(self.state_belief))
        predicted = self.state_names[idx]
        self.config.belief_recon = float(self.state_belief[0])
        self.config.belief_exploitation = float(self.state_belief[1])
        self.config.belief_lateral_movement = float(self.state_belief[2])
        self.config.belief_targeting = float(self.state_belief[3])
        self.config.belief_action_on_objective = float(self.state_belief[4])
        if self.previous_predicted_state not in ("unknown", predicted):
            self.config.state_transition_count += 1
        self.previous_predicted_state = predicted
        self.config.predicted_state = predicted
        self.config.state_prediction_confidence = float(self.state_belief[idx])

    def _node_role(self, node_idx: Optional[int]) -> str:
        if node_idx is None:
            return "unknown"
        roles = self.config.node_roles or {}
        return str(roles.get(int(node_idx), roles.get(str(int(node_idx)), "unknown")))

    def _generate_observable_events(
        self,
        selected_target: int,
        attack_active: bool,
        success: bool,
        credential_used: bool,
        credential_decoy_trigger: bool,
        path_changed: bool,
        critical_reached: bool,
    ) -> List[str]:
        if not self.config.observable_events_enabled:
            return []

        events: List[str] = []
        role = self._node_role(selected_target)
        if attack_active and role == "internet_entry":
            events.append("scan")
        if attack_active:
            events.append("exploit_attempt")
        if credential_used or credential_decoy_trigger or role == "identity_server":
            events.append("credential_use")
        if path_changed:
            events.append("lateral_move")
        if role in ("critical_asset", "database_server") or selected_target in self.config.critical_nodes:
            events.append("critical_probe")
        if role == "database_server":
            events.append("data_access")
        if critical_reached or role == "critical_asset":
            events.append("objective_action")
        return list(dict.fromkeys(events))

    def _is_critical_path_edge(self, source: int, target: int) -> bool:
        if source < 0 or target < 0:
            return False
        for path in self._paths_to_critical_on(self.config.adjacency_matrix):
            for left, right in zip(path[:-1], path[1:]):
                if int(left) == int(source) and int(right) == int(target):
                    return True
        return False

    def _static_critical_path_nodes(self) -> set:
        return {int(node) for path in self._paths_to_critical_on(self.config.adjacency_matrix) for node in path}

    def _generate_critical_path_events(
        self,
        selected_target: int,
        success: bool,
        critical_reached: bool,
    ) -> List[str]:
        if not self.config.critical_path_events_enabled:
            self.latest_critical_path_events = []
            return []

        events: List[str] = []
        critical_path_nodes = self._static_critical_path_nodes()
        on_critical_path = selected_target in critical_path_nodes
        if on_critical_path and not self.critical_path_entered:
            events.append("critical_path_entry")
            self.critical_path_entered = True

        previous_target = int(self.attacker.previous_selected_target)
        if (
            previous_target >= 0
            and selected_target >= 0
            and self._is_critical_path_edge(previous_target, selected_target)
            and self._target_moves_closer_to_critical_static(previous_target, selected_target)
        ):
            events.append("critical_path_progress")

        distance = self._distance_to_nearest_critical_static(selected_target)
        if distance is not None and distance <= 1:
            events.append("critical_path_near_target")

        if critical_reached or selected_target in self.config.critical_nodes:
            events.append("critical_asset_reach")

        self.latest_critical_path_events = list(dict.fromkeys(events))
        return self.latest_critical_path_events

    def _signal_event_names(self) -> set:
        return {
            "objective_action",
            "critical_asset_reach",
            "critical_path_entry",
            "critical_path_progress",
            "critical_path_near_target",
            "critical_probe",
            "data_access",
        }

    def _noise_event_names(self) -> set:
        return {
            "noise_recon",
            "noise_scan",
            "credential_noise",
            "false_path",
            "fake_critical_probe",
        }

    def _apply_noise_and_signal_extraction(
        self,
        observable_events: List[str],
        critical_path_events: List[str],
        selected_target: int,
    ) -> Tuple[List[str], List[str], List[str], List[str], float, List[str]]:
        raw_events = list(observable_events)
        noise_events: List[str] = []
        if self.config.noise_injection_enabled:
            noise_events = ["noise_recon", "noise_scan", "credential_noise", "false_path", "fake_critical_probe"]
            raw_events.extend(["scan", "credential_use", "lateral_move", "critical_probe"])
            raw_events.extend(noise_events)
            self.config.noise_event_count += len(noise_events)
            if not self.config.signal_extraction_enabled and self.config.mission_belief_inference_enabled:
                noise_belief = np.array([0.36, 0.28, 0.24, 0.12], dtype=float)
                self.mission_belief = self._normalize_mission_belief(0.75 * self.mission_belief + 0.25 * noise_belief)
                self._sync_mission_prediction_metrics()

        fake_signal_events: List[str] = []
        if self.config.adversarial_signal_enabled:
            fake_signal_events = [
                "fake_critical_path_entry",
                "fake_critical_path_progress",
                "fake_critical_path_near_target",
                "fake_objective_action",
            ]
            raw_events.extend(fake_signal_events)
            raw_events.extend(["critical_path_entry", "critical_path_progress", "critical_path_near_target", "objective_action"])
            self.config.fake_signal_count += len(fake_signal_events)
            self.config.adversarial_signal_count += len(fake_signal_events)

        raw_events = list(dict.fromkeys(raw_events))
        signal_set = self._signal_event_names()
        signal_events = [event for event in raw_events if event in signal_set or event in critical_path_events]
        self.config.signal_event_count += len(signal_events)
        suspicious_fake = 0
        if fake_signal_events:
            distance = self._distance_to_nearest_critical_static(selected_target)
            proximity = 0.0 if distance is None else 1.0 / (1.0 + float(distance))
            has_real_critical_progress = bool(set(critical_path_events) & {"critical_path_progress", "critical_path_near_target", "critical_asset_reach"})
            if "fake_objective_action" in fake_signal_events and proximity < 0.5:
                suspicious_fake += 1
            if "fake_critical_path_near_target" in fake_signal_events and not has_real_critical_progress:
                suspicious_fake += 1
            if "fake_critical_path_progress" in fake_signal_events and "critical_path_progress" not in critical_path_events:
                suspicious_fake += 1
        consistency_score = float(np.clip(1.0 - suspicious_fake / max(len(fake_signal_events), 1), 0.0, 1.0)) if fake_signal_events else 1.0

        if self.config.signal_extraction_enabled:
            extracted = list(dict.fromkeys(signal_events))
            if self.config.adversarial_signal_enabled:
                if suspicious_fake > 0:
                    extracted = [
                        event
                        for event in extracted
                        if event not in ("critical_path_near_target", "objective_action")
                    ]
            filtered_noise = len([event for event in noise_events if event not in extracted])
            accepted_fake = len([event for event in fake_signal_events if event in extracted or event.replace("fake_", "") in extracted])
            self.config.false_signal_acceptance_rate = float(accepted_fake / max(len(fake_signal_events), 1)) if fake_signal_events else 0.0
            filter_denominator = max(len(noise_events) + len(fake_signal_events), 1)
            filtered_fake = max(len(fake_signal_events) - accepted_fake, 0)
            self.config.noise_filter_accuracy = float((filtered_noise + filtered_fake) / filter_denominator) if filter_denominator else 1.0
            if self.config.mission_belief_inference_enabled and signal_events:
                signal_belief = self.mission_belief.copy()
                if "critical_asset_reach" in signal_events or "critical_path_near_target" in signal_events:
                    signal_belief[self.mission_names.index("critical_hunter")] += 0.20
                    signal_belief[self.mission_names.index("achievement")] += 0.10
                if "objective_action" in signal_events:
                    signal_belief[self.mission_names.index("achievement")] += 0.20
                self.mission_belief = self._normalize_mission_belief(signal_belief)
                self._sync_mission_prediction_metrics()
        else:
            extracted = raw_events
            self.config.noise_filter_accuracy = 0.0 if noise_events else 1.0
            self.config.false_signal_acceptance_rate = 1.0 if fake_signal_events else 0.0

        self.config.signal_to_noise_ratio = float(len(signal_events) / max(len(noise_events), 1))
        self.config.signal_confusion_score = float(self.config.false_signal_acceptance_rate)
        self.config.signal_consistency_score = consistency_score
        self.config.decision_confidence = float(
            np.clip(
                0.55 * (self.config.signal_to_noise_ratio / (1.0 + self.config.signal_to_noise_ratio))
                + 0.45 * self.config.noise_filter_accuracy,
                0.0,
                1.0,
            )
        )
        confidence_boost = self._product_confidence_boost()
        if confidence_boost > 0.0:
            self.config.decision_confidence = float(np.clip(self.config.decision_confidence + confidence_boost, 0.0, 1.0))
        return raw_events, signal_events, noise_events, fake_signal_events, consistency_score, extracted

    def _state_belief_update(
        self,
        credential_decoy_trigger: bool,
        selected_target: Optional[int],
        observable_events: Optional[List[str]] = None,
        critical_path_events: Optional[List[str]] = None,
    ) -> None:
        if not self.config.state_belief_inference_enabled:
            return

        evidence = np.zeros(5, dtype=float)
        events = observable_events or []
        if self.config.observable_events_enabled and events:
            event_set = set(events)
            if "scan" in event_set:
                evidence[0] += 0.20
            if "credential_use" in event_set or "exploit_attempt" in event_set:
                evidence[1] += 0.25
            if "lateral_move" in event_set:
                evidence[2] += 0.20
            if "critical_probe" in event_set or "data_access" in event_set:
                evidence[3] += 0.30
            if "objective_action" in event_set:
                evidence[4] += 0.40
            critical_event_set = set(critical_path_events or [])
            if "critical_path_entry" in critical_event_set:
                evidence[3] += 0.15
            if "critical_path_progress" in critical_event_set:
                evidence[3] += 0.10
            if "critical_path_near_target" in critical_event_set:
                evidence[4] += 0.20
            if "critical_asset_reach" in critical_event_set:
                evidence[4] += 0.40
        else:
            if credential_decoy_trigger:
                evidence[1] += 0.20

            selected_targets = np.asarray(self.history.get('attacker_selected_target', []), dtype=int)
            valid_targets = selected_targets[selected_targets >= 0]
            if len(valid_targets) >= 2 and int(valid_targets[-1]) != int(valid_targets[-2]):
                evidence[2] += 0.20

            critical_focus = (
                selected_target is not None
                and any(int(selected_target) == int(node) for node in self.config.critical_nodes)
            )
            if critical_focus:
                evidence[3] += 0.30
            if self.critical_compromise:
                evidence[4] += 0.40

            if float(np.sum(evidence)) <= 0.0:
                evidence[0] += 0.03

        previous_state = self.config.predicted_state
        self.state_belief = self._normalize_state_belief(self.state_belief + evidence)
        self._sync_state_prediction_metrics()
        if self.config.mission_aware_defender_enabled and self.config.adaptive_defender_enabled:
            self._state_belief_policy_update(previous_state)

    def _state_belief_policy_update(self, previous_state: str) -> None:
        if self.config.predicted_state == previous_state and self.mission_aware_policy_initialized:
            return
        previous_policy = self.current_adaptive_policy_id or self.config.adaptive_policy_default
        selected_policy, reason = self._select_mission_aware_policy()
        self.current_adaptive_policy_id = selected_policy
        self.config.adaptive_selected_policy = selected_policy
        self.config.adaptive_policy_reason = reason
        self.config.adaptive_selection_reason = reason
        self.config.mission_aware_selected_policy = selected_policy
        self.config.mission_aware_selection_reason = reason
        if selected_policy != previous_policy:
            self.config.mission_policy_switch_count += 1
            self.config.adaptive_policy_switch_count += 1
            self.adaptive_policy_switch_steps.append(int(self.current_step))
        self._apply_step_policy(selected_policy)
        self.mission_aware_policy_initialized = True

    def _critical_path_proximity_for_target(self, selected_target: Optional[int]) -> float:
        if selected_target is None or int(selected_target) < 0:
            return 0.0
        distance = self._distance_to_nearest_critical_static(int(selected_target))
        return 0.0 if distance is None else float(1.0 / (1.0 + float(distance)))

    def _risk_level_for_score(self, score: float) -> str:
        if score >= 0.80:
            return "critical"
        if score >= 0.60:
            return "high"
        if score >= 0.40:
            return "medium"
        return "low"

    def _normalized_intelligence_weights(self) -> Tuple[float, float, float]:
        weights = np.array(
            [
                self.config.intelligence_mission_weight,
                self.config.intelligence_state_weight,
                self.config.intelligence_critical_path_weight,
            ],
            dtype=float,
        )
        total = float(np.sum(weights))
        if total <= 0.0:
            weights = np.array([0.4, 0.3, 0.3], dtype=float)
        else:
            weights = weights / total
        return float(weights[0]), float(weights[1]), float(weights[2])

    def _calculate_intelligence_risk_score(self, selected_target: Optional[int]) -> float:
        mission_risk = {
            "critical_hunter": 1.0,
            "persistence": 0.8,
            "achievement": 0.6,
            "profit": 0.5,
        }.get(self.config.predicted_mission, 0.4)
        state_risk = {
            "recon": 0.1,
            "exploitation": 0.3,
            "lateral_movement": 0.5,
            "targeting": 0.8,
            "action_on_objective": 1.0,
        }.get(self.config.predicted_state, 0.1)
        proximity = self._critical_path_proximity_for_target(selected_target)
        mission_weight, state_weight, critical_path_weight = self._normalized_intelligence_weights()
        score = (
            mission_weight * mission_risk
            + state_weight * state_risk
            + critical_path_weight * proximity
        )
        return float(np.clip(score, 0.0, 1.0))

    def _select_intelligence_policy(self, risk_score: float) -> Tuple[str, str]:
        level = self._risk_level_for_score(risk_score)
        if level == "critical":
            return "phase2_frustration_decoy", "intelligence_critical_risk"
        if level == "high":
            return "phase2_frustration_decoy", "intelligence_high_risk"
        if level == "medium":
            return "phase4_planning_disruptor", "intelligence_medium_risk"
        return "phase4_target_switch_inducer", "intelligence_low_risk"

    def _position_class_for_proximity(self, proximity: float) -> str:
        if proximity >= 1.0:
            return "critical"
        if proximity >= 0.5:
            return "near"
        if proximity >= 0.25:
            return "medium"
        return "far"

    def _select_decision_matrix_policy(self, selected_target: Optional[int]) -> Tuple[str, str, str]:
        mission = self.config.predicted_mission if self.config.predicted_mission in self.mission_names else self.config.attacker_mission
        if mission not in self.mission_names:
            mission = "achievement"
        state = self.config.predicted_state if self.config.predicted_state in self.state_names else "recon"
        if state == "lateral_movement":
            state_key = "lateral"
        elif state == "action_on_objective":
            state_key = "objective"
        else:
            state_key = state
        proximity = self._critical_path_proximity_for_target(selected_target)
        position = self._position_class_for_proximity(proximity)

        matrix = {
            "profit": {
                "recon": "phase4_target_switch_inducer",
                "exploitation": "phase4_expected_utility_suppressor",
                "lateral": "phase4_expected_utility_suppressor",
                "targeting": "phase2_frustration_decoy",
                "objective": "phase2_frustration_decoy",
            },
            "persistence": {
                "recon": "phase4_trust_collapse_maximizer",
                "exploitation": "phase4_trust_collapse_maximizer",
                "lateral": "phase4_trust_collapse_maximizer",
                "targeting": "phase4_planning_disruptor",
                "objective": "phase2_frustration_decoy",
            },
            "critical_hunter": {
                "recon": "phase4_planning_disruptor",
                "exploitation": "phase4_planning_disruptor",
                "lateral": "phase4_planning_disruptor",
                "targeting": "phase4_planning_disruptor",
                "objective": "phase2_frustration_decoy",
            },
            "achievement": {
                "recon": "phase4_target_switch_inducer",
                "exploitation": "phase4_planning_disruptor",
                "lateral": "phase4_planning_disruptor",
                "targeting": "phase4_planning_disruptor",
                "objective": "phase2_frustration_decoy",
            },
        }
        selected_policy = matrix.get(mission, {}).get(state_key, "phase2_frustration_decoy")
        if mission == "critical_hunter" and position in ("near", "critical"):
            selected_policy = "phase2_frustration_decoy"
        if position == "critical":
            selected_policy = "phase2_frustration_decoy"
        reason = f"decision_matrix_{mission}_{state_key}_{position}"
        return selected_policy, reason, position

    def _campaign_context(self, selected_target: Optional[int]) -> Tuple[str, str, str, str]:
        mission = self.config.predicted_mission if self.config.predicted_mission in self.mission_names else self.config.attacker_mission
        if mission not in self.mission_names:
            mission = "achievement"
        state = self.config.predicted_state if self.config.predicted_state in self.state_names else "recon"
        proximity = self._critical_path_proximity_for_target(selected_target)
        position = self._position_class_for_proximity(proximity)
        stage = state
        if position == "critical":
            stage = "action_on_objective"
        elif mission == "critical_hunter" and position == "near" and state in ("targeting", "action_on_objective"):
            stage = "targeting"
        return mission, state, position, stage

    def _campaign_stage_policy(self, profile: str) -> Dict[str, str]:
        profiles = {
            "aggressive_disruption": {
                "recon": "phase4_planning_disruptor",
                "exploitation": "phase4_planning_disruptor",
                "lateral_movement": "phase4_planning_disruptor",
                "targeting": "phase2_frustration_decoy",
                "action_on_objective": "phase2_frustration_decoy",
            },
            "trust_collapse": {
                "recon": "phase4_target_switch_inducer",
                "exploitation": "phase4_trust_collapse_maximizer",
                "lateral_movement": "phase4_trust_collapse_maximizer",
                "targeting": "phase4_planning_disruptor",
                "action_on_objective": "phase2_frustration_decoy",
            },
            "utility_suppression": {
                "recon": "phase4_target_switch_inducer",
                "exploitation": "phase4_expected_utility_suppressor",
                "lateral_movement": "phase4_expected_utility_suppressor",
                "targeting": "phase4_planning_disruptor",
                "action_on_objective": "phase2_frustration_decoy",
            },
            "balanced": {
                "recon": "phase4_target_switch_inducer",
                "exploitation": "phase4_expected_utility_suppressor",
                "lateral_movement": "phase4_trust_collapse_maximizer",
                "targeting": "phase4_planning_disruptor",
                "action_on_objective": "phase2_frustration_decoy",
            },
        }
        return profiles.get(profile, profiles["balanced"])

    def _select_campaign_policy(self, selected_target: Optional[int]) -> Tuple[str, str]:
        mission, _state, position, stage = self._campaign_context(selected_target)
        profile = self.config.campaign_strategy_profile
        stage_policy = self._campaign_stage_policy(profile)
        selected_policy = stage_policy.get(stage, "phase2_frustration_decoy")
        if mission == "critical_hunter" and stage == "targeting" and position in ("medium", "near"):
            selected_policy = "phase4_planning_disruptor"
        if mission == "critical_hunter" and position == "critical":
            selected_policy = "phase2_frustration_decoy"
        if mission == "persistence" and stage == "lateral_movement":
            selected_policy = "phase4_trust_collapse_maximizer"
        if mission == "profit" and stage == "exploitation":
            selected_policy = "phase4_expected_utility_suppressor"

        if self.previous_campaign_stage not in ("none", stage):
            self.config.campaign_transition_count += 1
        if self.previous_campaign_policy not in ("", selected_policy):
            self.config.campaign_policy_switch_count += 1
        self.previous_campaign_stage = stage
        self.previous_campaign_policy = selected_policy
        self.config.campaign_stage = stage
        self.config.strategy_profile = profile
        reason = f"campaign_{profile}_{mission}_{stage}_{position}"
        return selected_policy, reason

    def _intelligence_policy_update(self, selected_target: Optional[int]) -> float:
        risk_score = self._calculate_intelligence_risk_score(selected_target)
        risk_level = self._risk_level_for_score(risk_score)
        self.config.intelligence_risk_score = risk_score
        if self.previous_risk_level not in ("unknown", risk_level):
            self.config.risk_level_transition_count += 1
        self.previous_risk_level = risk_level
        self.config.risk_level = risk_level

        if not (
            self.config.intelligence_defender_enabled
            and self.config.adaptive_defender_enabled
        ):
            return risk_score

        previous_policy = self.current_adaptive_policy_id or self.config.adaptive_policy_default
        risk_policy, risk_reason = self._select_intelligence_policy(risk_score)
        if self.config.defense_campaign_enabled:
            selected_policy, reason = self._select_campaign_policy(selected_target)
            self.config.decision_matrix_policy = selected_policy
            self.config.decision_matrix_match_count += 1
            if selected_policy != risk_policy:
                self.config.decision_matrix_override_count += 1
        elif self.config.decision_matrix_defender_enabled:
            selected_policy, reason, _position = self._select_decision_matrix_policy(selected_target)
            self.config.decision_matrix_policy = selected_policy
            self.config.decision_matrix_match_count += 1
            if selected_policy != risk_policy:
                self.config.decision_matrix_override_count += 1
        else:
            selected_policy, reason = risk_policy, risk_reason
        self.current_adaptive_policy_id = selected_policy
        self.config.selected_intelligence_policy = selected_policy
        self.config.adaptive_selected_policy = selected_policy
        self.config.adaptive_policy_reason = reason
        self.config.adaptive_selection_reason = reason
        if selected_policy != previous_policy:
            self.config.mission_policy_switch_count += 1
            self.config.adaptive_policy_switch_count += 1
            self.adaptive_policy_switch_steps.append(int(self.current_step))
        self._apply_step_policy(selected_policy)
        return risk_score

    def _mission_aware_policy_update(self, t: int) -> None:
        if (
            self.mission_aware_policy_initialized
            or t != 0
            or not self.config.mission_aware_defender_enabled
            or not self.config.adaptive_defender_enabled
        ):
            return

        previous_policy = self.current_adaptive_policy_id or self.config.adaptive_policy_default
        selected_policy, reason = self._select_mission_aware_policy()
        self.current_adaptive_policy_id = selected_policy
        self.config.adaptive_selected_policy = selected_policy
        self.config.adaptive_policy_reason = reason
        self.config.adaptive_selection_reason = reason
        self.config.mission_aware_selected_policy = selected_policy
        self.config.mission_aware_selection_reason = reason
        self.config.mission_policy_match = selected_policy == {
            "profit": "phase4_expected_utility_suppressor",
            "achievement": "phase4_planning_disruptor",
            "persistence": "phase4_trust_collapse_maximizer",
            "critical_hunter": "phase4_planning_disruptor",
        }.get(
            self.config.predicted_mission if self.config.mission_belief_inference_enabled else self.config.attacker_mission,
            self.config.adaptive_policy_default,
        )
        if selected_policy != previous_policy:
            self.config.mission_policy_switch_count += 1
            self.config.adaptive_policy_switch_count += 1
            self.adaptive_policy_switch_steps.append(int(t))
        self._apply_step_policy(selected_policy)
        self.mission_aware_policy_initialized = True

    def _step_adaptive_observations(self) -> Dict[str, float]:
        expected = self.attacker.last_expected_utility
        expected_utility = (
            float(np.max(expected))
            if expected is not None and len(expected) > 0
            else float(self.attacker.utility)
        )
        trust = self.attacker.trust_vector(self.config.n_nodes)
        trust_collapse_rate = float(np.mean(trust < 0.5)) if len(trust) > 0 else 0.0
        selected_targets = np.asarray(self.history.get('attacker_selected_target', []), dtype=int)
        valid_targets = selected_targets[selected_targets >= 0]
        target_switch_count = float(np.count_nonzero(np.diff(valid_targets) != 0)) if len(valid_targets) > 1 else 0.0
        retreat_probability = 1.0 if self.attacker.retreated else float(
            np.clip(
                max(0.0, self.config.attacker_retreat_threshold - self.attacker.utility + 1.0)
                / max(abs(self.config.attacker_retreat_threshold) + 1.0, 1.0),
                0.0,
                1.0,
            )
        )
        critical_risk = float(np.max(self.x_current[self.config.critical_nodes])) if self.config.critical_nodes else 0.0
        critical_compromise_risk = float(np.clip(critical_risk / 100.0, 0.0, 1.0))
        return {
            "expected_utility": expected_utility,
            "trust_collapse_rate": trust_collapse_rate,
            "target_switch_count": target_switch_count,
            "retreat_probability": retreat_probability,
            "critical_compromise_risk": critical_compromise_risk,
            "attacker_strategy_name": self.attacker_strategy_name,
        }

    def _estimate_step_policy_score(self, policy_name: str, observations: Dict[str, float]) -> float:
        expected_utility = float(observations["expected_utility"])
        trust_collapse_rate = float(observations["trust_collapse_rate"])
        switch_pressure = float(np.clip(observations["target_switch_count"] / 10.0, 0.0, 1.0))
        retreat_probability = float(observations["retreat_probability"])
        critical_compromise_risk = float(observations["critical_compromise_risk"])
        expected_pressure = float(np.clip(expected_utility / 10.0, 0.0, 1.0))
        strategy_name = str(observations.get("attacker_strategy_name", ""))
        if policy_name == "phase2_frustration_decoy":
            return (
                0.35
                + 1.20 * trust_collapse_rate
                + 0.80 * retreat_probability
                - 0.20 * expected_pressure
                - 0.50 * critical_compromise_risk
                - 0.05 * switch_pressure
                + (0.10 if strategy_name == "trust_aware_planning" else 0.0)
            )
        if policy_name == "phase2_ai_balanced":
            return (
                0.25
                + 0.40 * trust_collapse_rate
                + 0.75 * retreat_probability
                + 0.20 * switch_pressure
                - 0.25 * expected_pressure
                - 0.45 * critical_compromise_risk
            )
        if policy_name == "gated_edge_pressure_count_2":
            return (
                0.10
                + 0.20 * trust_collapse_rate
                + 0.50 * retreat_probability
                + 0.85 * expected_pressure
                + 0.10 * switch_pressure
                - 0.90 * critical_compromise_risk
                + (0.35 if strategy_name == "expected_utility" else 0.0)
            )
        return trust_collapse_rate + retreat_probability - expected_pressure - critical_compromise_risk

    def _step_policy_reason(self, policy_name: str, observations: Dict[str, float]) -> str:
        if policy_name == "gated_edge_pressure_count_2" and observations["expected_utility"] > 0.0:
            return "step_expected_utility_suppression"
        if policy_name == "phase2_ai_balanced" and observations["target_switch_count"] > self.config.adaptive_target_switch_threshold:
            return "step_switch_stability"
        if policy_name == "phase2_frustration_decoy" and observations["trust_collapse_rate"] > self.config.adaptive_trust_collapse_threshold:
            return "step_trust_collapse"
        return "step_cns_score_max"

    def _apply_step_policy(self, policy_name: str) -> None:
        if policy_name == "phase2_frustration_decoy":
            self.config.frustration_retreat_threshold = 6.0
            self.config.honeypot_credential_enabled = False
            self.config.mtd_enabled = False
            self.config.mtd_risk_gating_enabled = False
            self.config.mtd_conditional_policy_enabled = False
        elif policy_name == "phase2_ai_balanced":
            self.config.honeypot_credential_enabled = True
            self.config.credential_node_ids = [1, 3]
            self.config.credential_attraction_bonus = 5.0
            self.config.credential_detection_bonus = 5.0
            self.config.frustration_decoy_hit = 3.5
            self.config.frustration_credential_trap = 3.0
            self.config.frustration_retreat_threshold = 7.0
            self.config.ai_uncertainty_weight = 1.0
            self.config.ai_replanning_weight = 1.0
            self.config.ai_search_weight = 1.0
            self.config.ai_operational_risk_weight = 1.0
            self.config.ai_trust_degradation_weight = 1.0
            self.config.mtd_enabled = False
            self.config.mtd_risk_gating_enabled = False
            self.config.mtd_conditional_policy_enabled = False
        elif policy_name == "gated_edge_pressure_count_2":
            self.config.mtd_enabled = True
            self.config.mtd_strategy = "shuffle_belief"
            self.config.mtd_interval = 1
            self.config.mtd_intensity = 0.5
            self.config.mtd_risk_gating_enabled = True
            self.config.mtd_risk_gate_mode = "edge_pressure"
            self.config.mtd_risk_gate_threshold = 10.0
            self.config.mtd_risk_gate_cooldown = 3
            self.config.mtd_edge_block_count = 2
            self.config.mtd_edge_block_duration = 1
        elif policy_name == "phase4_trust_collapse_maximizer":
            self.config.honeypot_credential_enabled = True
            self.config.credential_node_ids = [1, 3]
            self.config.credential_attraction_bonus = 7.0
            self.config.credential_detection_bonus = 8.0
            self.config.credential_reuse_decay = 0.25
            self.config.trust_enabled = True
            self.config.trust_decoy_penalty = 0.35
            self.config.trust_credential_penalty = 0.45
            self.config.trust_detection_penalty = 0.25
            self.config.frustration_decoy_hit = 4.5
            self.config.frustration_credential_trap = 5.0
            self.config.frustration_detection = 2.0
            self.config.frustration_retreat_threshold = 7.0
            self.config.stochastic_detection = True
            self.config.base_detection_prob = 0.65
            self.config.decoy_detection_prob = 1.0
        elif policy_name == "phase4_expected_utility_suppressor":
            self.config.expected_utility_enabled = True
            self.config.adaptive_planning_enabled = True
            self.config.trust_enabled = True
            self.config.ai_uncertainty_weight = 2.5
            self.config.ai_replanning_weight = 2.5
            self.config.ai_search_weight = 3.0
            self.config.ai_operational_risk_weight = 3.0
            self.config.ai_trust_degradation_weight = 1.5
            self.config.stochastic_detection = True
            self.config.base_detection_prob = 0.75
            self.config.defense_detection_scale = 0.30
            self.config.decoy_detection_prob = 1.0
            self.config.attacker_defense_cost_rate = 2.0
            self.config.expected_detection_cost = 2.0
            self.config.expected_search_cost = 2.0
        elif policy_name == "phase4_target_switch_inducer":
            self.config.attacker_lateral_enabled = True
            self.config.mtd_enabled = True
            self.config.mtd_strategy = "shuffle_belief"
            self.config.mtd_interval = 1
            self.config.mtd_intensity = 0.9
            self.config.mtd_shuffle_topology = True
            self.config.mtd_block_critical_edges = True
            self.config.mtd_edge_block_count = 2
            self.config.mtd_edge_block_duration = 2
            self.config.mtd_risk_gating_enabled = True
            self.config.mtd_risk_gate_mode = "critical_edge_pressure"
            self.config.mtd_risk_gate_threshold = 1.0
            self.config.mtd_risk_gate_cooldown = 0
            self.config.frustration_path_change = 3.0
            self.config.frustration_no_progress = 1.5
        elif policy_name == "phase4_planning_disruptor":
            self.config.adaptive_planning_enabled = True
            self.config.planning_depth = 3
            self.config.attacker_lateral_enabled = True
            self.config.post_decoy_defense_enabled = True
            self.config.post_decoy_defense_weight = 4.0
            self.config.post_decoy_defense_top_k = 2
            self.config.post_decoy_defense_exclude_decoy = True
            self.config.post_decoy_defense_injection_mode = "all"
            self.config.post_decoy_defense_belief_source = "estimated"
            self.config.defender_belief_estimation_enabled = True
            self.config.defender_belief_observation_mode = "hybrid_visible"
            self.config.mtd_enabled = True
            self.config.mtd_strategy = "increase_uncertainty"
            self.config.mtd_interval = 2
            self.config.mtd_intensity = 0.8
            self.config.mtd_block_critical_edges = True
            self.config.mtd_edge_block_count = 2
            self.config.mtd_edge_block_duration = 2
            self.config.frustration_path_change = 2.5

    def _mission_satisfaction_step(self) -> float:
        return float(self._mission_objective_step()[0])

    def _normalized_weights(self, values: List[float]) -> List[float]:
        total = float(np.sum(np.asarray(values, dtype=float)))
        if total <= 0.0:
            return [1.0 / max(len(values), 1)] * len(values)
        return [float(value) / total for value in values]

    def _mission_weight_vector(self) -> Dict[str, float]:
        weights = {
            "profit": float(self.config.mission_weight_profit),
            "achievement": float(self.config.mission_weight_achievement),
            "persistence": float(self.config.mission_weight_persistence),
            "critical_hunter": float(self.config.mission_weight_critical_hunter),
        }
        if not self.config.multi_objective_mission_enabled or sum(weights.values()) <= 0.0:
            return {mission: 1.0 if mission == self.config.attacker_mission else 0.0 for mission in self.mission_names}
        total = float(sum(weights.values()))
        return {mission: float(value) / total for mission, value in weights.items()}

    def _true_mission_label(self) -> str:
        weights = self._mission_weight_vector()
        mission = max(weights, key=lambda key: weights.get(key, 0.0))
        self.config.true_mission = mission
        return mission

    def _deception_target_for_mission(self, mission: str) -> str:
        mapping = {
            "critical_hunter": "profit",
            "profit": "persistence",
            "persistence": "achievement",
            "achievement": "profit",
        }
        return mapping.get(mission, "profit")

    def _apply_intent_deception(self) -> str:
        true_mission = self._true_mission_label()
        observed_mission = true_mission
        event = "none"
        if self.config.intent_deception_enabled:
            observed_mission = self._deception_target_for_mission(true_mission)
            event = f"mask_{true_mission}_as_{observed_mission}"
            self.config.deception_event_count += 1
            if observed_mission in self.mission_names:
                injected = np.full(len(self.mission_names), 0.08, dtype=float)
                injected[self.mission_names.index(observed_mission)] = 0.76
                self.mission_belief = self._normalize_mission_belief(0.35 * self.mission_belief + 0.65 * injected)
                self._sync_mission_prediction_metrics()
        self.current_true_mission = true_mission
        self.current_observed_mission = observed_mission
        self.config.true_mission = true_mission
        self.config.observed_mission = observed_mission
        self.history['deception_history'].append(event)
        return observed_mission

    def _mission_objective_step(self) -> Tuple[float, str]:
        mission = self.config.attacker_mission
        expected = self.attacker.last_expected_utility
        expected_component = (
            float(np.clip(np.max(expected) / 10.0, 0.0, 1.0))
            if expected is not None and len(expected) > 0
            else float(np.clip(max(self.attacker.utility, 0.0) / 10.0, 0.0, 1.0))
        )
        trust_vector = self.attacker.trust_vector(self.config.n_nodes)
        trust_component = float(np.mean(trust_vector)) if len(trust_vector) > 0 else 1.0
        success_history = np.asarray(self.history.get('attacker_success', []), dtype=bool)
        detected_history = np.asarray(self.history.get('attacker_detected', []), dtype=bool)
        success_rate = float(np.mean(success_history)) if len(success_history) > 0 else 0.0
        stealth_score = 1.0 - (float(np.mean(detected_history)) if len(detected_history) > 0 else 0.0)
        compromised_count = len(self.attacker.compromised_nodes)
        compromise_progress = float(np.clip(compromised_count / max(float(self.config.n_nodes), 1.0), 0.0, 1.0))
        selected_target = self.attacker.last_selected_target if self.attacker.last_selected_target is not None else None
        critical_path_progress = self._critical_path_proximity_for_target(selected_target)
        critical_reach = 1.0 if self.critical_compromise else 0.0
        persistence_score = 0.0 if self.attacker.retreated else 1.0
        expected_weight, success_weight = self._normalized_weights([
            self.config.profit_expected_utility_weight,
            self.config.profit_success_weight,
        ])
        progress_weight, achievement_critical_weight = self._normalized_weights([
            self.config.achievement_progress_weight,
            self.config.achievement_critical_weight,
        ])
        survival_weight, trust_weight, stealth_weight = self._normalized_weights([
            self.config.persistence_survival_weight,
            self.config.persistence_trust_weight,
            self.config.persistence_stealth_weight,
        ])
        critical_progress_weight, critical_reach_weight = self._normalized_weights([
            self.config.critical_progress_weight,
            self.config.critical_reach_weight,
        ])
        scores = {
            "profit": expected_weight * expected_component + success_weight * success_rate,
            "achievement": progress_weight * compromise_progress + achievement_critical_weight * max(critical_path_progress, critical_reach),
            "persistence": survival_weight * persistence_score + trust_weight * trust_component + stealth_weight * stealth_score,
            "critical_hunter": critical_progress_weight * critical_path_progress + critical_reach_weight * critical_reach,
        }
        reasons = {
            "profit": "expected_utility_collapse" if expected_component < 0.20 else "none",
            "achievement": "compromise_stalled" if compromise_progress < 0.20 and self.current_step > 20 else "none",
            "persistence": "trust_collapse" if trust_component < 0.55 else ("stealth_failure" if stealth_score < 0.50 else "none"),
            "critical_hunter": "critical_path_failure" if critical_path_progress < 0.25 and self.current_step > 20 else "none",
        }
        if self.config.multi_objective_mission_enabled:
            weights = self._mission_weight_vector()
            score = sum(weights.get(name, 0.0) * scores.get(name, 0.0) for name in self.mission_names)
            active_failures = [
                (name, weights.get(name, 0.0), scores.get(name, 0.0), reasons.get(name, "none"))
                for name in self.mission_names
                if weights.get(name, 0.0) > 0.0 and reasons.get(name, "none") != "none"
            ]
            if active_failures:
                failed = min(active_failures, key=lambda item: item[2])
                reason = f"multi_objective_{failed[0]}_{failed[3]}"
            else:
                reason = "none"
            return float(np.clip(score, 0.0, 1.0)), reason
        if mission in scores:
            return float(np.clip(scores[mission], 0.0, 1.0)), reasons.get(mission, "none")
        score = (expected_component + success_rate + trust_component + critical_path_progress) / 4.0
        return float(np.clip(score, 0.0, 1.0)), "none"

    def _apply_mission_objective_retreat(self, score: float, reason: str) -> None:
        if not self.config.mission_objectives_enabled or self.attacker.retreated:
            return
        mission = self.config.attacker_mission
        should_retreat = False
        if mission == "profit":
            should_retreat = reason == "expected_utility_collapse" and score < 0.20 and self.current_step >= 8
        elif mission == "persistence":
            should_retreat = reason in ("trust_collapse", "stealth_failure") and score < 0.75 and self.current_step >= 8
        elif mission == "critical_hunter":
            should_retreat = reason == "critical_path_failure" and score < 0.25 and self.current_step >= 25
        elif mission == "achievement":
            should_retreat = False
        if should_retreat:
            self.attacker.retreated = True
            self.config.mission_failure_reason = reason
            if self.attacker_retreat_step is None:
                self.attacker_retreat_step = int(self.current_step)

    def _maybe_mutate_mission(self, score: float, reason: str) -> str:
        if not self.config.mission_mutation_enabled:
            return "none"
        mission = self.config.attacker_mission
        if mission in ("none", "achievement"):
            return "none"
        pressure = float(np.clip(1.0 - score, 0.0, 1.0))
        failure_memory = float(self.config.strategy_failure_memory)
        mutation_reason = "none"
        if mission == "profit" and (
            reason == "expected_utility_collapse"
            or (self.config.campaign_strategy_profile == "utility_suppression" and score < 0.75)
            or (failure_memory > 0.65 and score < 0.80)
        ):
            mutation_reason = "profit_expected_utility_collapse_to_achievement"
        elif mission == "critical_hunter" and (
            reason == "critical_path_failure"
            or (self.config.campaign_strategy_profile == "aggressive_disruption" and score < 0.45)
            or (failure_memory > 0.65 and pressure > 0.45)
        ):
            mutation_reason = "critical_path_failure_to_achievement"
        elif mission == "persistence" and (
            reason in ("trust_collapse", "stealth_failure")
            or (self.config.campaign_strategy_profile == "trust_collapse" and score < 0.92)
            or (failure_memory > 0.80 and score < 0.92)
        ):
            mutation_reason = "trust_collapse_to_achievement"
        if mutation_reason == "none":
            return "none"
        self.config.attacker_mission = "achievement"
        self.attacker.attacker_mission = "achievement"
        self.config.mission_change_count += 1
        self.config.mission_mutation_reason = mutation_reason
        if self.mission_mutation_step is None:
            self.mission_mutation_step = int(self.current_step)
        return mutation_reason

    def _phase422_policy_for_mission(self, mission: str) -> str:
        mapping = {
            "profit": "phase4_expected_utility_suppressor",
            "achievement": "phase4_trust_collapse_maximizer",
            "persistence": "phase4_trust_collapse_maximizer",
            "critical_hunter": "phase4_planning_disruptor",
        }
        return mapping.get(mission, self.config.adaptive_policy_default)

    def _phase422_strategy_for_mission(self, mission: str) -> str:
        mapping = {
            "profit": "utility_suppression",
            "achievement": "trust_collapse",
            "persistence": "trust_collapse",
            "critical_hunter": "aggressive_disruption",
        }
        return mapping.get(mission, self.config.campaign_strategy_profile)

    def _record_reclassification_accuracy(self) -> None:
        if not self.config.mission_reclassification_enabled:
            return
        self.reclassification_total_steps += 1
        if self.config.predicted_mission == self._true_mission_label():
            self.reclassification_correct_steps += 1
        self.config.reclassification_accuracy = float(
            self.reclassification_correct_steps / max(self.reclassification_total_steps, 1)
        )

    def _maybe_reclassify_mission(
        self,
        score: float,
        reason: str,
        adaptation_action: str,
        mutation_reason: str,
    ) -> str:
        if not self.config.mission_reclassification_enabled:
            return str(self.config.predicted_mission)

        repeated_ttp_change = (
            adaptation_action not in ("observe", "non_adaptive", "none")
            and self.config.ttp_change_count > self.config.mission_reclassification_count
        )
        trigger = (
            mutation_reason != "none"
            or (reason != "none" and score < 0.55)
            or float(self.config.strategy_failure_memory) > 0.65
            or repeated_ttp_change
        )
        if trigger:
            previous_prediction = str(self.config.predicted_mission)
            previous_policy = self.current_adaptive_policy_id or self.config.adaptive_policy_default
            previous_strategy = str(self.config.campaign_strategy_profile)
            mission = str(self.config.observed_mission if self.config.intent_deception_enabled else self.config.attacker_mission)
            if mission in self.mission_names:
                self.mission_belief = np.full(len(self.mission_names), 0.05, dtype=float)
                self.mission_belief[self.mission_names.index(mission)] = 0.85
                self._sync_mission_prediction_metrics()
            selected_policy = self._phase422_policy_for_mission(self.config.predicted_mission)
            selected_strategy = self._phase422_strategy_for_mission(self.config.predicted_mission)
            reoptimized = False
            if self.config.defense_campaign_enabled and selected_strategy != previous_strategy:
                self.config.campaign_strategy_profile = selected_strategy
                self.config.strategy_profile = selected_strategy
                reoptimized = True
            if selected_policy != previous_policy:
                self.current_adaptive_policy_id = selected_policy
                self.config.selected_intelligence_policy = selected_policy
                self.config.adaptive_selected_policy = selected_policy
                self.config.adaptive_policy_reason = f"mission_reclassification_{self.config.predicted_mission}"
                self.config.adaptive_selection_reason = self.config.adaptive_policy_reason
                self.config.mission_aware_selected_policy = selected_policy
                self.config.mission_aware_selection_reason = self.config.adaptive_policy_reason
                self._apply_step_policy(selected_policy)
                reoptimized = True
            if previous_prediction != self.config.predicted_mission or trigger:
                self.config.mission_reclassification_count += 1
                if self.first_reclassification_step is None:
                    self.first_reclassification_step = int(self.current_step)
            if reoptimized:
                self.config.defense_reoptimization_count += 1
                self.config.mission_policy_switch_count += 1
                self.config.adaptive_policy_switch_count += 1
                self.adaptive_policy_switch_steps.append(int(self.current_step))
            if (
                self.config.predicted_mission == self._true_mission_label()
                and self.config.belief_recovery_time < 0
            ):
                reference_step = self.mission_mutation_step if self.mission_mutation_step is not None else self.first_reclassification_step
                self.config.belief_recovery_time = max(0, int(self.current_step) - int(reference_step or self.current_step))
        self._record_reclassification_accuracy()
        return str(self.config.predicted_mission)

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

    def _distance_to_nearest_critical_static(self, source: int) -> Optional[int]:
        if source < 0 or source >= self.config.n_nodes:
            return None
        critical = {int(node) for node in self.config.critical_nodes}
        visited = {int(source)}
        queue = [(int(source), 0)]
        while queue:
            node, distance = queue.pop(0)
            for neighbor in np.flatnonzero(self.config.adjacency_matrix[node] > 0).astype(int).tolist():
                neighbor = int(neighbor)
                if neighbor in visited:
                    continue
                if neighbor in critical:
                    return distance + 1
                visited.add(neighbor)
                queue.append((neighbor, distance + 1))
        return None

    def _target_moves_closer_to_critical_static(self, current_node: int, target_node: int) -> bool:
        current_distance = self._distance_to_nearest_critical_static(current_node)
        target_distance = self._distance_to_nearest_critical_static(target_node)
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
        interruption_boost = self._product_interruption_boost()
        if interruption_boost > 0.0:
            probability *= max(0.0, 1.0 - interruption_boost)
        return float(np.clip(probability, 0.0, 1.0))

    def _lateral_detection_probability(self, credential_decoy_trigger: bool = False) -> float:
        probability = self.config.attacker_lateral_detection_prob
        if self._mtd_recently_active():
            probability += self.config.mtd_detection_bonus
        if credential_decoy_trigger:
            probability += self.config.credential_detection_bonus
        probability += self._product_detection_boost()
        if self._product_category() == "honeypot" and credential_decoy_trigger:
            probability += 0.10
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
            probability = 1.0 if gained > 0.01 else 0.0
            interruption_boost = self._product_interruption_boost()
            if interruption_boost > 0.0 and probability > 0.0:
                probability = max(0.0, probability - interruption_boost)
            return probability
        if attacked_decoy:
            probability = self.config.decoy_success_prob
        else:
            probability = self.config.base_success_prob * np.exp(
                -self.config.defense_success_decay * target_defense_strength
            )
        if self._mtd_recently_active():
            probability *= np.exp(-self.config.mtd_success_decay_bonus)
        interruption_boost = self._product_interruption_boost()
        if interruption_boost > 0.0:
            probability *= max(0.0, 1.0 - interruption_boost)
        return float(np.clip(probability, 0.0, 1.0))

    def _product_category(self) -> str:
        if not self.config.product_plugin_enabled:
            return "baseline"
        category = str(self.config.product_category or "").lower()
        return category if category in ("ids", "ips", "honeypot", "deception", "xdr") else "baseline"

    def _product_detection_boost(self) -> float:
        if self.config.product_profile_import_enabled:
            return float(np.clip(self.config.product_detection_boost, 0.0, 1.0))
        return {"ids": 0.20, "xdr": 0.08}.get(self._product_category(), 0.0)

    def _product_interruption_boost(self) -> float:
        if self.config.product_profile_import_enabled:
            return float(np.clip(self.config.product_interruption_boost, 0.0, 1.0))
        return 0.30 if self._product_category() == "ips" else 0.0

    def _product_diversion_boost(self) -> float:
        if self.config.product_profile_import_enabled:
            return float(np.clip(self.config.product_diversion_boost, 0.0, 1.0))
        return {"honeypot": 0.10, "deception": 0.20}.get(self._product_category(), 0.0)

    def _product_confidence_boost(self) -> float:
        if self.config.product_profile_import_enabled:
            return float(np.clip(self.config.product_confidence_boost, 0.0, 1.0))
        return 0.15 if self._product_category() == "xdr" else 0.0

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
        category = self._product_category()
        probability += self._product_detection_boost()
        if category == "honeypot" and (attacked_decoy or credential_decoy_trigger):
            probability += 0.10
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
        attacker_phase_history = np.asarray(self.history.get('attacker_phase', []), dtype='<U64')
        adaptive_policy_id_history = np.asarray(self.history.get('adaptive_policy_id', []), dtype='<U64')
        mission_belief_history = np.asarray(self.history.get('mission_belief', []), dtype=float)
        state_belief_history = np.asarray(self.history.get('state_belief', []), dtype=float)
        observable_event_history = np.asarray(self.history.get('observable_events', []), dtype='<U128')
        critical_path_event_history = np.asarray(self.history.get('critical_path_events', []), dtype='<U128')
        risk_score_history = np.asarray(self.history.get('risk_score', []), dtype=float)
        mission_weight, state_weight, critical_path_weight = self._normalized_intelligence_weights()
        mission_satisfaction_series = np.asarray(self.history.get('mission_satisfaction', []), dtype=float)
        mission_objective_series = np.asarray(self.history.get('mission_objective_history', []), dtype=float)
        mission_failure_reason_history = np.asarray(self.history.get('mission_failure_reason_history', []), dtype='<U64')
        observed_defense_history = np.asarray(self.history.get('observed_defense_history', []), dtype='<U64')
        adaptation_history = np.asarray(self.history.get('adaptation_history', []), dtype='<U64')
        mission_history = np.asarray(self.history.get('mission_history', []), dtype='<U64')
        reclassified_mission_history = np.asarray(self.history.get('reclassified_mission_history', []), dtype='<U64')
        selected_strategy_history = np.asarray(self.history.get('selected_strategy_history', []), dtype='<U64')
        true_mission_history = np.asarray(self.history.get('true_mission_history', []), dtype='<U64')
        observed_mission_history = np.asarray(self.history.get('observed_mission_history', []), dtype='<U64')
        deception_history = np.asarray(self.history.get('deception_history', []), dtype='<U128')
        noise_history = np.asarray(self.history.get('noise_history', []), dtype='<U128')
        signal_history = np.asarray(self.history.get('signal_history', []), dtype='<U128')
        fake_signal_history = np.asarray(self.history.get('fake_signal_history', []), dtype='<U128')
        signal_consistency_history = np.asarray(self.history.get('signal_consistency_history', []), dtype=float)
        coalition_role_history = np.asarray(self.history.get('coalition_role_history', []), dtype='<U64')
        coalition_handover_history = np.asarray(self.history.get('coalition_handover_history', []), dtype='<U128')
        coalition_delegation_state_history = np.asarray(self.history.get('coalition_delegation_state_history', []), dtype='<U64')
        coordination_history = np.asarray(self.history.get('coordination_history', []), dtype=float)
        coalition_trust_history = np.asarray(self.history.get('trust_history', []), dtype=float)
        handover_failure_history = np.asarray(self.history.get('handover_failure_history', []), dtype=int)
        fake_asset_history = np.asarray(self.history.get('fake_asset_interaction_history', []), dtype=int)
        fake_credential_history = np.asarray(self.history.get('fake_credential_usage_history', []), dtype=int)
        credential_trap_history = np.asarray(self.history.get('credential_trap_trigger_history', []), dtype=int)
        fake_path_history = np.asarray(self.history.get('fake_path_follow_history', []), dtype=int)
        honey_node_history = np.asarray(self.history.get('honey_node_visit_history', []), dtype=int)
        honey_detection_history = np.asarray(self.history.get('honey_detection_history', []), dtype=int)
        counter_deception_history = np.asarray(self.history.get('counter_deception_score_history', []), dtype=float)
        awareness_history = np.asarray(self.history.get('awareness_history', []), dtype=float)
        suspicion_history = np.asarray(self.history.get('suspicion_history', []), dtype=float)
        deception_knowledge_history = np.asarray(self.history.get('deception_knowledge_history', []), dtype=float)
        mission_change_count = int(self.config.mission_change_count)
        mission_truth = str(true_mission_history[-1]) if len(true_mission_history) > 0 else str(self.config.attacker_mission)
        mission_inference = MissionInferenceEngine().evaluate(self.history, true_mission=mission_truth)
        behavior_engine = BehaviorProfileEngine()
        expected_profile = behavior_engine.expected_profile_for_mission(mission_truth)
        behavior_profile = behavior_engine.evaluate(self.history, expected_profile=expected_profile)
        mission_stability_score = float(
            np.clip(1.0 - mission_change_count / max(float(len(mission_history)), 1.0), 0.0, 1.0)
        )
        mission_truth_for_accuracy = true_mission_history if len(true_mission_history) > 0 else mission_history
        if len(reclassified_mission_history) > 0 and len(mission_truth_for_accuracy) > 0:
            n_reclassification = min(len(reclassified_mission_history), len(mission_truth_for_accuracy))
            self.config.reclassification_accuracy = float(
                np.mean(reclassified_mission_history[:n_reclassification] == mission_truth_for_accuracy[:n_reclassification])
            )
        mission_belief_error = float(self.config.mission_belief_error)
        belief_confusion_score = float(self.config.belief_confusion_score)
        mission_masking_success = bool(self.config.mission_masking_success)
        if len(mission_belief_history) > 0 and len(true_mission_history) > 0:
            true_probs = []
            observed_matches = []
            true_matches = []
            n_belief = min(len(mission_belief_history), len(true_mission_history))
            for idx in range(n_belief):
                true_mission = str(true_mission_history[idx])
                observed_mission = str(observed_mission_history[idx]) if idx < len(observed_mission_history) else true_mission
                predicted = self.mission_names[int(np.argmax(mission_belief_history[idx]))]
                true_prob = mission_belief_history[idx][self.mission_names.index(true_mission)] if true_mission in self.mission_names else 0.0
                true_probs.append(float(true_prob))
                observed_matches.append(predicted == observed_mission and observed_mission != true_mission)
                true_matches.append(predicted == true_mission)
            mission_belief_error = float(np.clip(1.0 - np.mean(true_probs), 0.0, 1.0)) if true_probs else 0.0
            belief_confusion_score = float(np.mean(observed_matches)) if observed_matches else 0.0
            mission_masking_success = bool(any(observed_matches) and not all(true_matches))
        self.config.mission_belief_error = mission_belief_error
        self.config.belief_confusion_score = belief_confusion_score
        self.config.mission_masking_success = mission_masking_success
        noise_tokens = [
            token
            for entry in noise_history.tolist()
            for token in str(entry).split("|")
            if token
        ]
        signal_tokens = [
            token
            for entry in signal_history.tolist()
            for token in str(entry).split("|")
            if token
        ]
        fake_signal_tokens = [
            token
            for entry in fake_signal_history.tolist()
            for token in str(entry).split("|")
            if token
        ]
        noise_event_count = len(noise_tokens)
        signal_event_count = len(signal_tokens)
        fake_signal_count = len(fake_signal_tokens)
        adversarial_signal_count = fake_signal_count
        signal_to_noise_ratio = float(signal_event_count / max(noise_event_count, 1))
        if self.config.signal_extraction_enabled:
            noise_filter_accuracy = float(np.clip(self.config.noise_filter_accuracy, 0.0, 1.0))
        else:
            noise_filter_accuracy = 0.0 if noise_event_count > 0 else 1.0
        false_signal_acceptance_rate = float(np.clip(self.config.false_signal_acceptance_rate, 0.0, 1.0))
        signal_confusion_score = false_signal_acceptance_rate
        signal_consistency_score = (
            float(np.mean(signal_consistency_history))
            if len(signal_consistency_history) > 0
            else float(self.config.signal_consistency_score)
        )
        decision_confidence = float(
            np.clip(
                0.55 * (signal_to_noise_ratio / (1.0 + signal_to_noise_ratio))
                + 0.45 * noise_filter_accuracy,
                0.0,
                1.0,
            )
        )
        if self._product_category() == "xdr":
            decision_confidence = float(np.clip(decision_confidence + 0.15, 0.0, 1.0))
        self.config.noise_event_count = noise_event_count
        self.config.signal_event_count = signal_event_count
        self.config.signal_to_noise_ratio = signal_to_noise_ratio
        self.config.noise_filter_accuracy = noise_filter_accuracy
        self.config.fake_signal_count = fake_signal_count
        self.config.adversarial_signal_count = adversarial_signal_count
        self.config.false_signal_acceptance_rate = false_signal_acceptance_rate
        self.config.signal_confusion_score = signal_confusion_score
        self.config.signal_consistency_score = signal_consistency_score
        self.config.decision_confidence = decision_confidence
        mission_mutation_success = False
        if self.mission_mutation_step is not None and len(mission_objective_series) > 1:
            pre = mission_objective_series[: max(int(self.mission_mutation_step), 1)]
            post = mission_objective_series[int(self.mission_mutation_step) + 1 :]
            mission_mutation_success = bool(len(post) > 0 and float(np.mean(post)) >= float(np.mean(pre)))
        self.config.mission_stability_score = mission_stability_score
        self.config.mission_mutation_success = mission_mutation_success
        observable_event_tokens = [
            token
            for entry in observable_event_history.tolist()
            for token in str(entry).split("|")
            if token
        ]
        critical_path_event_tokens = [
            token
            for entry in critical_path_event_history.tolist()
            for token in str(entry).split("|")
            if token
        ]
        selected_target_series = np.asarray(self.history.get('attacker_selected_target', []), dtype=int)
        critical_path_nodes_for_metrics = self._static_critical_path_nodes()
        proximity_values = []
        for target in selected_target_series.tolist():
            if int(target) < 0:
                continue
            distance = self._distance_to_nearest_critical_static(int(target))
            proximity_values.append(0.0 if distance is None else 1.0 / (1.0 + float(distance)))
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
        failed_handover_count = int(np.count_nonzero(handover_failure_history > 0))
        effective_handover_count = int(np.count_nonzero((coalition_handover_history != "none") & (np.char.startswith(coalition_handover_history, "failed:") == False)))
        coalition_handover_count = effective_handover_count
        coalition_delegated_steps = int(np.count_nonzero(coalition_delegation_state_history == "Delegated"))
        coalition_preparing_steps = int(np.count_nonzero(coalition_delegation_state_history == "Preparing Handover"))
        attempted_handover_count = effective_handover_count + failed_handover_count
        coordination_efficiency = float(effective_handover_count / max(attempted_handover_count, 1))
        campaign_delay_score = float(np.clip(failed_handover_count / max(len(hx), 1), 0.0, 1.0))
        coalition_trust_score = float(coalition_trust_history[-1]) if len(coalition_trust_history) else float(self.coalition_trust_score)
        coalition_relevant_events = 0
        coalition_role_steps = 0
        for role, event_text, critical_text in zip(coalition_role_history, observable_event_history, critical_path_event_history):
            role = str(role)
            events = set(str(event_text).split("|")) | set(str(critical_text).split("|"))
            if role == "recon_specialist":
                relevant = {"scan", "critical_path_discovery"}
            elif role == "access_specialist":
                relevant = {"credential_use", "lateral_move"}
            elif role == "objective_specialist":
                relevant = {"critical_path_near_target", "objective_action", "critical_asset_reach"}
            else:
                relevant = set()
            if relevant:
                coalition_role_steps += 1
                if events & relevant:
                    coalition_relevant_events += 1
        coalition_role_efficiency = float(coalition_relevant_events / max(coalition_role_steps, 1))
        campaign_completion_score = 0.0
        if self.config.coalition_enabled:
            stage_score = min(float(coalition_handover_count) / 2.0, 1.0)
            objective_score = 1.0 if self.critical_compromise else float(
                np.count_nonzero([("objective_action" in str(value)) or ("critical_asset_reach" in str(value)) for value in observable_event_history])
                > 0
            )
            cost = float(self.config.coordination_cost) if self.config.coalition_coordination_cost_enabled else 0.0
            campaign_completion_score = float(np.clip(
                (0.6 * stage_score + 0.4 * objective_score) * coordination_efficiency - 0.2 * cost - 0.2 * campaign_delay_score,
                0.0,
                1.0,
            ))
        coalition_success_rate = (
            float(np.clip(0.5 * attacker_success_rate + 0.5 * campaign_completion_score, 0.0, 1.0))
            if self.config.coalition_enabled
            else attacker_success_rate
        )
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
        fake_asset_interaction_count = int(np.count_nonzero(fake_asset_history > 0))
        fake_credential_usage_count = int(np.count_nonzero(fake_credential_history > 0))
        credential_trap_trigger_count = int(np.count_nonzero(credential_trap_history > 0))
        fake_path_follow_count = int(np.count_nonzero(fake_path_history > 0))
        honey_node_visit_count = int(np.count_nonzero(honey_node_history > 0))
        honey_detection_count = int(np.count_nonzero(honey_detection_history > 0))
        fake_asset_success_rate = float(fake_asset_interaction_count / max(valid_attack_count, 1))
        path_diversion_score = float(fake_path_follow_count / max(valid_attack_count, 1))
        attacker_diversion_score = float((fake_asset_interaction_count + fake_path_follow_count) / max(valid_attack_count, 1))
        counter_deception_score = float(np.mean(counter_deception_history)) if len(counter_deception_history) > 0 else 0.0
        fake_asset_detection_rate = float(self.fake_asset_detection_count / max(fake_asset_interaction_count, 1))
        fake_credential_detection_rate = float(self.fake_credential_detection_count / max(fake_credential_usage_count, 1))
        path_validation_success_rate = float(self.path_validation_success_count / max(self.path_validation_count, 1))
        honey_node_detection_rate = float(self.honey_node_detection_count / max(honey_node_visit_count, 1))
        awareness_score = (
            float(np.mean(awareness_history))
            if len(awareness_history) > 0
            else self._counter_deception_awareness_score()
        )
        deception_resistance_score = float(np.clip(
            np.mean([
                fake_asset_detection_rate,
                fake_credential_detection_rate,
                path_validation_success_rate,
                honey_node_detection_rate,
            ]),
            0.0,
            1.0,
        ))
        false_suspicion_rate = float(self.false_suspicion_count / max(valid_attack_count, 1))
        deception_suspicion_score = (
            float(suspicion_history[-1])
            if len(suspicion_history) > 0
            else float(self.deception_suspicion_score)
        )
        self.config.fake_asset_detection_rate = fake_asset_detection_rate
        self.config.fake_asset_suspicion_count = int(self.fake_asset_suspicion_count)
        self.config.fake_credential_detection_rate = fake_credential_detection_rate
        self.config.path_validation_count = int(self.path_validation_count)
        self.config.path_validation_success_rate = path_validation_success_rate
        self.config.honey_node_detection_rate = honey_node_detection_rate
        self.config.awareness_score = awareness_score
        self.config.deception_resistance_score = deception_resistance_score
        self.config.false_suspicion_rate = false_suspicion_rate
        credential_validation_success_rate = float(self.credential_validation_success_count / max(self.credential_validation_count, 1))
        honey_probe_success_rate = float(self.honey_probe_success_count / max(self.honey_probe_count, 1))
        hunting_attempt_count = self.fake_asset_hunt_count + self.credential_validation_count + self.honey_probe_count
        hunting_success_count = self.fake_asset_confirmed_count + self.credential_validation_success_count + self.honey_probe_success_count
        hunting_success_rate = float(hunting_success_count / max(hunting_attempt_count, 1))
        deception_discovery_rate = float(np.clip(
            (
                self.fake_asset_confirmed_count
                + self.credential_validation_success_count
                + self.path_validation_success_count
                + self.honey_probe_success_count
            ) / max(fake_asset_interaction_count + fake_credential_usage_count + fake_path_follow_count + honey_node_visit_count, 1),
            0.0,
            1.0,
        ))
        deception_knowledge_score = (
            float(deception_knowledge_history[-1])
            if len(deception_knowledge_history) > 0
            else float(self.deception_knowledge_score)
        )
        self.config.fake_asset_hunt_count = int(self.fake_asset_hunt_count)
        self.config.fake_asset_confirmed_count = int(self.fake_asset_confirmed_count)
        self.config.credential_validation_count = int(self.credential_validation_count)
        self.config.credential_validation_success_rate = credential_validation_success_rate
        self.config.honey_probe_count = int(self.honey_probe_count)
        self.config.honey_probe_success_rate = honey_probe_success_rate
        self.config.deception_knowledge_score = deception_knowledge_score
        self.config.hunting_success_rate = hunting_success_rate
        self.config.deception_discovery_rate = deception_discovery_rate
        self.config.verified_false_signal_count = int(self.verified_false_signal_count)
        self.config.verified_fake_asset_count = int(self.verified_fake_asset_count)
        campaign_disruption_score = float(np.clip(
            0.45 * attacker_diversion_score
            + 0.35 * path_diversion_score
            + 0.20 * (credential_trap_trigger_count + honey_detection_count) / max(valid_attack_count, 1),
            0.0,
            1.0,
        ))
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
        product_category = self._product_category()
        product_effectiveness_map = {
            "baseline": 0.0,
            "honeypot": fake_asset_success_rate,
            "ids": mean_attack_detection_prob,
            "ips": 1.0 - mean_attack_success_prob,
            "deception": attacker_diversion_score,
            "xdr": decision_confidence,
        }
        product_effectiveness = float(np.clip(product_effectiveness_map.get(product_category, 0.0), 0.0, 1.0))
        operational_cost_score = float(np.clip(
            1.0 - 0.5 * self.config.product_latency_penalty - 0.5 * self.config.product_maintenance_penalty,
            0.0,
            1.0,
        ))
        false_positive_score = float(np.clip(1.0 - self.config.product_false_positive_penalty, 0.0, 1.0))
        product_profile_score = float(np.clip(
            0.70 * product_effectiveness
            + 0.15 * operational_cost_score
            + 0.15 * false_positive_score,
            0.0,
            1.0,
        ))
        evaluation_score = float(np.clip(
            0.55 * product_effectiveness
            + 0.20 * campaign_disruption_score
            + 0.15 * operational_cost_score
            + 0.10 * false_positive_score,
            0.0,
            1.0,
        ))
        if product_category == "baseline":
            product_profile_score = 0.0
            evaluation_score = 0.0
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
            'product_plugin_enabled': bool(self.config.product_plugin_enabled),
            'product_profile_import_enabled': bool(self.config.product_profile_import_enabled),
            'product_name': str(self.config.product_name),
            'product_category': str(product_category),
            'product_profile_name': str(self.config.product_profile_name or self.config.product_name),
            'product_detection_boost': float(self.config.product_detection_boost),
            'product_interruption_boost': float(self.config.product_interruption_boost),
            'product_diversion_boost': float(self.config.product_diversion_boost),
            'product_confidence_boost': float(self.config.product_confidence_boost),
            'product_false_positive_penalty': float(self.config.product_false_positive_penalty),
            'product_latency_penalty': float(self.config.product_latency_penalty),
            'product_maintenance_penalty': float(self.config.product_maintenance_penalty),
            'product_effectiveness': product_effectiveness,
            'product_profile_score': product_profile_score,
            'operational_cost_score': operational_cost_score,
            'false_positive_score': false_positive_score,
            'evaluation_score': evaluation_score,
            'coalition_enabled': bool(self.config.coalition_enabled),
            'coalition_size': int(self.config.coalition_size),
            'coalition_id': self.config.coalition_id,
            'coalition_role': self.config.coalition_role,
            'coalition_handover_count': coalition_handover_count,
            'coalition_coordination_score': float(self.config.coalition_coordination_score),
            'coalition_delegation_state': self.config.coalition_delegation_state,
            'coalition_coordination_cost_enabled': bool(self.config.coalition_coordination_cost_enabled),
            'coordination_cost': float(self.config.coordination_cost),
            'coalition_information_loss_enabled': bool(self.config.coalition_information_loss_enabled),
            'coalition_trust_enabled': bool(self.config.coalition_trust_enabled),
            'effective_handover_count': effective_handover_count,
            'failed_handover_count': failed_handover_count,
            'coordination_efficiency': coordination_efficiency,
            'campaign_delay_score': campaign_delay_score,
            'coalition_trust_score': coalition_trust_score,
            'trust_degradation_count': int(self.trust_degradation_count),
            'coalition_success_rate': coalition_success_rate,
            'coalition_role_efficiency': coalition_role_efficiency,
            'campaign_completion_score': campaign_completion_score,
            'campaign_delegation_observed': bool(coalition_handover_count > 0 and coalition_delegated_steps > 0),
            'coalition_preparing_handover_steps': coalition_preparing_steps,
            'coalition_delegated_steps': coalition_delegated_steps,
            'coalition_role_history': coalition_role_history.astype(str).tolist(),
            'coalition_handover_history': coalition_handover_history.astype(str).tolist(),
            'coalition_delegation_state_history': coalition_delegation_state_history.astype(str).tolist(),
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
            'adaptive_defender_enabled': bool(self.config.adaptive_defender_enabled),
            'adaptive_defender_mode': self.config.adaptive_defender_mode,
            'adaptive_selected_policy': self.config.adaptive_selected_policy or self.config.adaptive_policy_default,
            'adaptive_policy_switch_count': int(self.config.adaptive_policy_switch_count),
            'adaptive_policy_reason': self.config.adaptive_policy_reason,
            'adaptive_policy_score': float(self.config.adaptive_policy_score),
            'adaptive_policy_rank': int(self.config.adaptive_policy_rank),
            'adaptive_selection_reason': self.config.adaptive_selection_reason,
            'adaptive_estimated_cns': float(self.config.adaptive_estimated_cns),
            'step_adaptive_defender_enabled': bool(self.config.step_adaptive_defender_enabled),
            'adaptive_recheck_interval': int(self.config.adaptive_recheck_interval),
            'adaptive_policy_switch_cost': float(self.config.adaptive_policy_switch_cost),
            'adaptive_min_improvement': float(self.config.adaptive_min_improvement),
            'mission_aware_defender_enabled': bool(self.config.mission_aware_defender_enabled),
            'mission_aware_selected_policy': self.config.mission_aware_selected_policy or self.config.adaptive_selected_policy or self.config.adaptive_policy_default,
            'mission_policy_match': bool(self.config.mission_policy_match),
            'mission_policy_switch_count': int(self.config.mission_policy_switch_count),
            'mission_aware_selection_reason': self.config.mission_aware_selection_reason,
            'mission_aware_cns': (
                float(cns_objective_scores.get('cns_objective_score', 0.0))
                if self.config.mission_aware_defender_enabled
                else 0.0
            ),
            'mission_belief_inference_enabled': bool(self.config.mission_belief_inference_enabled),
            'belief_profit': float(self.config.belief_profit),
            'belief_achievement': float(self.config.belief_achievement),
            'belief_persistence': float(self.config.belief_persistence),
            'belief_critical_hunter': float(self.config.belief_critical_hunter),
            'predicted_mission': self.config.predicted_mission,
            'mission_prediction_confidence': float(self.config.mission_prediction_confidence),
            'mission_prediction_correct': bool(self.config.mission_prediction_correct),
            'state_belief_inference_enabled': bool(self.config.state_belief_inference_enabled),
            'belief_recon': float(self.config.belief_recon),
            'belief_exploitation': float(self.config.belief_exploitation),
            'belief_lateral_movement': float(self.config.belief_lateral_movement),
            'belief_targeting': float(self.config.belief_targeting),
            'belief_action_on_objective': float(self.config.belief_action_on_objective),
            'predicted_state': self.config.predicted_state,
            'state_prediction_confidence': float(self.config.state_prediction_confidence),
            'state_transition_count': int(self.config.state_transition_count),
            'virtual_topology_enabled': bool(self.config.virtual_topology_enabled),
            'observable_events_enabled': bool(self.config.observable_events_enabled),
            'critical_path_events_enabled': bool(self.config.critical_path_events_enabled),
            'node_roles': {str(k): str(v) for k, v in (self.config.node_roles or {}).items()},
            'observable_event_count': int(len(observable_event_tokens)),
            'scan_count': int(observable_event_tokens.count("scan")),
            'credential_use_count': int(observable_event_tokens.count("credential_use")),
            'lateral_move_count': int(observable_event_tokens.count("lateral_move")),
            'critical_probe_count': int(observable_event_tokens.count("critical_probe")),
            'objective_action_count': int(observable_event_tokens.count("objective_action")),
            'critical_path_proximity': float(np.mean(proximity_values)) if proximity_values else 0.0,
            'critical_path_step_count': int(len(critical_path_event_tokens)),
            'critical_node_visit_count': int(
                sum(1 for target in selected_target_series.tolist() if int(target) in critical_path_nodes_for_metrics)
            ),
            'critical_edge_traversal_count': int(critical_path_event_tokens.count("critical_path_progress")),
            'critical_path_entry_count': int(critical_path_event_tokens.count("critical_path_entry")),
            'critical_path_progress_count': int(critical_path_event_tokens.count("critical_path_progress")),
            'critical_path_near_target_count': int(critical_path_event_tokens.count("critical_path_near_target")),
            'critical_asset_reach_count': int(critical_path_event_tokens.count("critical_asset_reach")),
            'intelligence_defender_enabled': bool(self.config.intelligence_defender_enabled),
            'selected_intelligence_policy': self.config.selected_intelligence_policy or self.config.adaptive_selected_policy,
            'intelligence_risk_score': (
                float(risk_score_history[-1])
                if len(risk_score_history) > 0
                else float(self.config.intelligence_risk_score)
            ),
            'intelligence_risk_score_mean': float(np.mean(risk_score_history)) if len(risk_score_history) > 0 else 0.0,
            'risk_level': self.config.risk_level,
            'risk_level_transition_count': int(self.config.risk_level_transition_count),
            'decision_matrix_defender_enabled': bool(self.config.decision_matrix_defender_enabled),
            'decision_matrix_policy': self.config.decision_matrix_policy,
            'decision_matrix_match_count': int(self.config.decision_matrix_match_count),
            'decision_matrix_override_count': int(self.config.decision_matrix_override_count),
            'defense_campaign_enabled': bool(self.config.defense_campaign_enabled),
            'campaign_effectiveness_score': (
                float(cns_objective_scores.get('cns_objective_score', 0.0))
                if self.config.defense_campaign_enabled
                else 0.0
            ),
            'campaign_stage': self.config.campaign_stage,
            'campaign_transition_count': int(self.config.campaign_transition_count),
            'campaign_policy_switch_count': int(self.config.campaign_policy_switch_count),
            'campaign_stage_history': [str(stage) for stage in self.history.get('campaign_stage_history', [])],
            'campaign_policy_history': [str(policy) for policy in self.history.get('campaign_policy_history', [])],
            'strategy_profile': self.config.campaign_strategy_profile,
            'strategy_effectiveness_score': (
                float(cns_objective_scores.get('cns_objective_score', 0.0))
                if self.config.defense_campaign_enabled
                else 0.0
            ),
            'profile_rank': int(self.config.profile_rank),
            'best_weight_configuration': self.config.best_weight_configuration,
            'mission_weight': float(mission_weight),
            'state_weight': float(state_weight),
            'critical_path_weight': float(critical_path_weight),
            'weight_sweep_rank': int(self.config.weight_sweep_rank),
            'adaptive_policy_switch_steps': [int(step) for step in self.adaptive_policy_switch_steps],
            'adaptive_policy_history': adaptive_policy_id_history.astype(str).tolist(),
            'adaptive_cns_gain': float(self.adaptive_cns_gain),
            'adaptive_switch_cost_total': float(self.adaptive_switch_cost_total),
            'adaptive_defender_effectiveness': (
                float(cns_objective_scores.get('cns_objective_score', 0.0))
                if self.config.adaptive_defender_enabled
                else 0.0
            ),
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
            'attacker_mission': self.config.attacker_mission,
            'mission_expected_utility_weight': float(self.config.mission_expected_utility_weight),
            'mission_trust_weight': float(self.config.mission_trust_weight),
            'mission_planning_weight': float(self.config.mission_planning_weight),
            'mission_critical_target_weight': float(self.config.mission_critical_target_weight),
            'mission_success_score': float(mission_satisfaction_series[-1]) if len(mission_satisfaction_series) > 0 else 0.0,
            'mission_satisfaction_score': float(np.mean(mission_satisfaction_series)) if len(mission_satisfaction_series) > 0 else 0.0,
            'mission_objectives_enabled': bool(self.config.mission_objectives_enabled),
            'mission_satisfaction': float(mission_satisfaction_series[-1]) if len(mission_satisfaction_series) > 0 else 0.0,
            'mission_objective_score': float(np.mean(mission_objective_series)) if len(mission_objective_series) > 0 else 0.0,
            'mission_failure_reason': (
                str(mission_failure_reason_history[-1])
                if len(mission_failure_reason_history) > 0
                else str(self.config.mission_failure_reason)
            ),
            'objective_weight_profile': self.config.objective_weight_profile,
            'mission_strategy_change': bool(self.config.mission_strategy_change),
            'mission_sensitivity_score': float(self.config.mission_sensitivity_score),
            'adaptive_mission_attacker_enabled': bool(self.config.adaptive_mission_attacker_enabled),
            'observed_defense_strategy': self.config.observed_defense_strategy,
            'defense_effectiveness_memory': float(self.config.defense_effectiveness_memory),
            'strategy_failure_memory': float(self.config.strategy_failure_memory),
            'strategy_success_memory': float(self.config.strategy_success_memory),
            'adaptation_count': int(self.config.adaptation_count),
            'ttp_change_count': int(self.config.ttp_change_count),
            'strategy_avoidance_score': float(self.config.strategy_avoidance_score),
            'alternative_path_usage': float(self.config.alternative_path_usage),
            'observed_defense_history': observed_defense_history.astype(str).tolist(),
            'adaptation_history': adaptation_history.astype(str).tolist(),
            'mission_mutation_enabled': bool(self.config.mission_mutation_enabled),
            'mission_change_count': mission_change_count,
            'mission_stability_score': mission_stability_score,
            'mission_mutation_reason': self.config.mission_mutation_reason,
            'mission_mutation_success': mission_mutation_success,
            'mission_history': mission_history.astype(str).tolist(),
            'inferred_mission': str(mission_inference.get('inferred_mission')),
            'mission_confidence': float(mission_inference.get('mission_confidence', 0.0)),
            'mission_entropy': float(mission_inference.get('mission_entropy', 0.0)),
            'mission_match': bool(mission_inference.get('mission_match', False)),
            'mission_confusion_score': float(mission_inference.get('mission_confusion_score', 0.0)),
            'mission_inference_scores': mission_inference.get('mission_scores', {}),
            'mission_inference_features': mission_inference.get('intent_features', {}),
            'behavior_profile': str(behavior_profile.get('behavior_profile')),
            'profile_confidence': float(behavior_profile.get('profile_confidence', 0.0)),
            'profile_entropy': float(behavior_profile.get('profile_entropy', 0.0)),
            'profile_score': float(behavior_profile.get('profile_score', 0.0)),
            'profile_match': bool(behavior_profile.get('profile_match', False)),
            'profile_distribution': behavior_profile.get('profile_distribution', {}),
            'behavior_profile_features': behavior_profile.get('behavior_features', {}),
            'attacker_type': self.config.attacker_type,
            'mission_reclassification_enabled': bool(self.config.mission_reclassification_enabled),
            'mission_reclassification_count': int(self.config.mission_reclassification_count),
            'defense_reoptimization_count': int(self.config.defense_reoptimization_count),
            'reclassification_accuracy': float(self.config.reclassification_accuracy),
            'belief_recovery_time': int(self.config.belief_recovery_time),
            'reclassified_mission_history': reclassified_mission_history.astype(str).tolist(),
            'selected_strategy_history': selected_strategy_history.astype(str).tolist(),
            'multi_objective_mission_enabled': bool(self.config.multi_objective_mission_enabled),
            'mission_weight_profit': float(self._mission_weight_vector().get("profit", 0.0)),
            'mission_weight_achievement': float(self._mission_weight_vector().get("achievement", 0.0)),
            'mission_weight_persistence': float(self._mission_weight_vector().get("persistence", 0.0)),
            'mission_weight_critical_hunter': float(self._mission_weight_vector().get("critical_hunter", 0.0)),
            'intent_deception_enabled': bool(self.config.intent_deception_enabled),
            'deception_event_count': int(self.config.deception_event_count),
            'mission_belief_error': mission_belief_error,
            'belief_confusion_score': belief_confusion_score,
            'true_mission': self.config.true_mission,
            'observed_mission': self.config.observed_mission,
            'mission_masking_success': mission_masking_success,
            'true_mission_history': true_mission_history.astype(str).tolist(),
            'observed_mission_history': observed_mission_history.astype(str).tolist(),
            'deception_history': deception_history.astype(str).tolist(),
            'noise_injection_enabled': bool(self.config.noise_injection_enabled),
            'signal_extraction_enabled': bool(self.config.signal_extraction_enabled),
            'noise_event_count': int(noise_event_count),
            'signal_event_count': int(signal_event_count),
            'signal_to_noise_ratio': signal_to_noise_ratio,
            'noise_filter_accuracy': noise_filter_accuracy,
            'decision_confidence': decision_confidence,
            'adversarial_signal_enabled': bool(self.config.adversarial_signal_enabled),
            'fake_signal_count': int(fake_signal_count),
            'adversarial_signal_count': int(adversarial_signal_count),
            'signal_confusion_score': signal_confusion_score,
            'false_signal_acceptance_rate': false_signal_acceptance_rate,
            'signal_consistency_score': signal_consistency_score,
            'noise_history': noise_history.astype(str).tolist(),
            'signal_history': signal_history.astype(str).tolist(),
            'fake_signal_history': fake_signal_history.astype(str).tolist(),
            'signal_consistency_history': signal_consistency_history.astype(float).tolist(),
            'counter_deception_enabled': bool(self.config.counter_deception_enabled),
            'fake_asset_enabled': bool(self.config.fake_asset_enabled),
            'fake_credential_enabled': bool(self.config.fake_credential_enabled),
            'fake_critical_path_enabled': bool(self.config.fake_critical_path_enabled),
            'honey_node_enabled': bool(self.config.honey_node_enabled),
            'fake_asset_interaction_count': fake_asset_interaction_count,
            'fake_asset_success_rate': fake_asset_success_rate,
            'fake_credential_usage_count': fake_credential_usage_count,
            'credential_trap_trigger_count': credential_trap_trigger_count,
            'fake_path_follow_count': fake_path_follow_count,
            'path_diversion_score': path_diversion_score,
            'honey_node_visit_count': honey_node_visit_count,
            'honey_detection_count': honey_detection_count,
            'counter_deception_score': counter_deception_score,
            'attacker_diversion_score': attacker_diversion_score,
            'campaign_disruption_score': campaign_disruption_score,
            'counter_deception_awareness_enabled': bool(self.config.counter_deception_awareness_enabled),
            'deception_suspicion_score': deception_suspicion_score,
            'fake_asset_detection_rate': fake_asset_detection_rate,
            'fake_asset_suspicion_count': int(self.fake_asset_suspicion_count),
            'fake_credential_detection_rate': fake_credential_detection_rate,
            'path_validation_count': int(self.path_validation_count),
            'path_validation_success_rate': path_validation_success_rate,
            'honey_node_detection_rate': honey_node_detection_rate,
            'awareness_score': awareness_score,
            'deception_resistance_score': deception_resistance_score,
            'false_suspicion_rate': false_suspicion_rate,
            'counter_deception_hunting_enabled': bool(self.config.counter_deception_hunting_enabled),
            'fake_asset_hunt_count': int(self.fake_asset_hunt_count),
            'fake_asset_confirmed_count': int(self.fake_asset_confirmed_count),
            'credential_validation_count': int(self.credential_validation_count),
            'credential_validation_success_rate': credential_validation_success_rate,
            'honey_probe_count': int(self.honey_probe_count),
            'honey_probe_success_rate': honey_probe_success_rate,
            'deception_knowledge_score': deception_knowledge_score,
            'hunting_success_rate': hunting_success_rate,
            'deception_discovery_rate': deception_discovery_rate,
            'verified_false_signal_count': int(self.verified_false_signal_count),
            'verified_fake_asset_count': int(self.verified_fake_asset_count),
            'profit_expected_utility_weight': float(self.config.profit_expected_utility_weight),
            'profit_success_weight': float(self.config.profit_success_weight),
            'persistence_survival_weight': float(self.config.persistence_survival_weight),
            'persistence_trust_weight': float(self.config.persistence_trust_weight),
            'persistence_stealth_weight': float(self.config.persistence_stealth_weight),
            'critical_progress_weight': float(self.config.critical_progress_weight),
            'critical_reach_weight': float(self.config.critical_reach_weight),
            'achievement_progress_weight': float(self.config.achievement_progress_weight),
            'achievement_critical_weight': float(self.config.achievement_critical_weight),
            'nonstationary_attacker_enabled': bool(self.config.nonstationary_attacker_enabled),
            'attacker_phase_change_step': int(self.config.attacker_phase_change_step),
            'nonstationary_attacker_pattern': self.config.nonstationary_attacker_pattern,
            'attacker_phase': self.attacker_phase,
            'attacker_phase_switch_count': int(self.attacker_phase_switch_count),
            'attacker_strategy_name': self.attacker_strategy_name,
            'attacker_phase_history': attacker_phase_history.astype(str).tolist(),
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
            mission_inference_history = MissionInferenceEngine().infer_history(self.history)
            behavior_profile_history = BehaviorProfileEngine().infer_history(self.history)
            strategy_inference_history = StrategyInferenceEngine().infer_history(self.history)
            target_inference_history = MissionTaxonomyAnalyzer().infer_target_history(self.history)
            target_strategy_history = []
            strategy_alignment_history = []
            strategy_engine = StrategyInferenceEngine()
            history_length = len(target_inference_history['target_history'])
            for end in range(1, history_length + 1):
                prefix = {
                    key: value[:end] if hasattr(value, "__getitem__") else value
                    for key, value in self.history.items()
                }
                target_name = target_inference_history['target_history'][end - 1]
                target_result = strategy_engine.infer(prefix, target=target_name)
                target_strategy_history.append(target_result.strategy_type)
                strategy_alignment_history.append(
                    1.0 if target_result.strategy_type in strategy_engine.strategy_candidates_for_target(target_name) else 0.0
                )
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
                attacker_phase=np.asarray(self.history['attacker_phase'], dtype='<U64'),
                adaptive_policy_id=np.asarray(self.history['adaptive_policy_id'], dtype='<U64'),
                selected_policy_history=np.asarray(self.history['selected_policy_history'], dtype='<U64'),
                campaign_stage_history=np.asarray(self.history['campaign_stage_history'], dtype='<U64'),
                campaign_policy_history=np.asarray(self.history['campaign_policy_history'], dtype='<U64'),
                mission_belief=np.asarray(self.history['mission_belief'], dtype=float),
                state_belief=np.asarray(self.history['state_belief'], dtype=float),
                observable_events=np.asarray(self.history['observable_events'], dtype='<U128'),
                critical_path_events=np.asarray(self.history['critical_path_events'], dtype='<U128'),
                risk_score=np.asarray(self.history['risk_score'], dtype=float),
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
                mission_satisfaction=np.asarray(self.history['mission_satisfaction'], dtype=float),
                mission_objective_history=np.asarray(self.history['mission_objective_history'], dtype=float),
                mission_failure_reason=np.asarray(self.history['mission_failure_reason_history'], dtype='<U64'),
                observed_defense_history=np.asarray(self.history['observed_defense_history'], dtype='<U64'),
                adaptation_history=np.asarray(self.history['adaptation_history'], dtype='<U64'),
                mission_history=np.asarray(self.history['mission_history'], dtype='<U64'),
                inferred_mission_history=np.asarray(mission_inference_history['inferred_mission_history'], dtype='<U64'),
                mission_confidence_history=np.asarray(mission_inference_history['mission_confidence_history'], dtype=float),
                mission_entropy_history=np.asarray(mission_inference_history['mission_entropy_history'], dtype=float),
                behavior_profile_history=np.asarray(behavior_profile_history['behavior_profile_history'], dtype='<U64'),
                profile_confidence_history=np.asarray(behavior_profile_history['profile_confidence_history'], dtype=float),
                profile_entropy_history=np.asarray(behavior_profile_history['profile_entropy_history'], dtype=float),
                strategy_history=np.asarray(strategy_inference_history['strategy_history'], dtype='<U64'),
                strategy_confidence_history=np.asarray(strategy_inference_history['strategy_confidence_history'], dtype=float),
                strategy_entropy_history=np.asarray(strategy_inference_history['strategy_entropy_history'], dtype=float),
                target_history=np.asarray(target_inference_history['target_history'], dtype='<U64'),
                target_strategy_history=np.asarray(target_strategy_history, dtype='<U64'),
                strategy_alignment_history=np.asarray(strategy_alignment_history, dtype=float),
                reclassified_mission_history=np.asarray(self.history['reclassified_mission_history'], dtype='<U64'),
                selected_strategy_history=np.asarray(self.history['selected_strategy_history'], dtype='<U64'),
                true_mission_history=np.asarray(self.history['true_mission_history'], dtype='<U64'),
                observed_mission_history=np.asarray(self.history['observed_mission_history'], dtype='<U64'),
                deception_history=np.asarray(self.history['deception_history'], dtype='<U128'),
                noise_history=np.asarray(self.history['noise_history'], dtype='<U128'),
                signal_history=np.asarray(self.history['signal_history'], dtype='<U128'),
                fake_signal_history=np.asarray(self.history['fake_signal_history'], dtype='<U128'),
                signal_consistency_history=np.asarray(self.history['signal_consistency_history'], dtype=float),
                coalition_role_history=np.asarray(self.history['coalition_role_history'], dtype='<U64'),
                coalition_handover_history=np.asarray(self.history['coalition_handover_history'], dtype='<U128'),
                coalition_delegation_state_history=np.asarray(self.history['coalition_delegation_state_history'], dtype='<U64'),
                coordination_history=np.asarray(self.history['coordination_history'], dtype=float),
                trust_history=np.asarray(self.history['trust_history'], dtype=float),
                handover_failure_history=np.asarray(self.history['handover_failure_history'], dtype=int),
                fake_asset_interaction_history=np.asarray(self.history['fake_asset_interaction_history'], dtype=int),
                fake_credential_usage_history=np.asarray(self.history['fake_credential_usage_history'], dtype=int),
                credential_trap_trigger_history=np.asarray(self.history['credential_trap_trigger_history'], dtype=int),
                fake_path_follow_history=np.asarray(self.history['fake_path_follow_history'], dtype=int),
                honey_node_visit_history=np.asarray(self.history['honey_node_visit_history'], dtype=int),
                honey_detection_history=np.asarray(self.history['honey_detection_history'], dtype=int),
                counter_deception_score_history=np.asarray(self.history['counter_deception_score_history'], dtype=float),
                awareness_history=np.asarray(self.history['awareness_history'], dtype=float),
                suspicion_history=np.asarray(self.history['suspicion_history'], dtype=float),
                deception_knowledge_history=np.asarray(self.history['deception_knowledge_history'], dtype=float),
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
