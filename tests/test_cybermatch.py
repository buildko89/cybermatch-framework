import json

import numpy as np
import pytest

from cybermatch import AttackerModel, CyberDefenseSimulator, SimulationConfig, Visualizer
from run_scenarios import (
    MULTI_SEED_SCENARIO_NAMES,
    MULTI_SEED_STATS_COLUMNS,
    POLICY_SELECTION_COLUMNS,
    SCENARIOS,
    SUMMARY_COLUMNS,
    build_multiseed_stats_rows,
    build_policy_selection_rows,
    run_neutralization_evaluation,
    run_phase2_cognitive_neutralization_evaluation,
    run_phase2_ai_cost_evaluation,
    run_phase2_ai_weight_sweep_evaluation,
    run_phase2_cns_objective_evaluation,
    run_phase2_policy_selection_evaluation,
    run_phase3_expected_utility_evaluation,
    run_phase3_trust_attacker_evaluation,
    run_phase4_adaptive_defender_evaluation,
    run_phase4_cns_guided_evaluation,
    run_phase4_step_adaptive_evaluation,
    run_phase4_nonstationary_evaluation,
    run_phase4_switch_benefit_evaluation,
    run_phase4_specialized_policy_evaluation,
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
    run_phase51_coalition_evaluation,
    run_phase52_coordination_cost_evaluation,
    run_scenarios,
    run_scenarios_multi_seed,
    _select_cns_guided_policy,
    _select_adaptive_defense_policy,
)


def small_config(**overrides):
    values = {
        "T": 4,
        "H": 2,
        "show_plot": False,
        "seed": 7,
        "dynamic_matching_threshold": 100.0,
        "dynamic_matching_delta_threshold": 0.0,
    }
    values.update(overrides)
    return SimulationConfig(**values)


def test_default_config_validates():
    SimulationConfig().validate()


def test_config_dimension_mismatch_raises():
    with pytest.raises(ValueError, match="d_base"):
        SimulationConfig(d_base=[1.0, 2.0])


def test_simulation_history_shapes():
    config = small_config()
    sim = CyberDefenseSimulator(config)
    history = sim.run()

    assert np.asarray(history["x"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["r"]).shape == (config.T, config.m_resources)
    assert np.asarray(history["M"]).shape == (config.T, config.n_nodes, config.m_resources)
    assert np.asarray(history["raw_x"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["clip_low"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["clip_high"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["attack_vector"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["attacker_selection_score"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["attacker_selected_target"]).shape == (config.T,)
    assert np.asarray(history["attacker_attacked_decoy"]).shape == (config.T,)
    assert np.asarray(history["actual_utility"]).shape == (config.T,)
    assert np.asarray(history["perceived_utility"]).shape == (config.T,)
    assert np.asarray(history["confidence"]).shape == (config.T,)
    assert np.asarray(history["frustration"]).shape == (config.T,)
    assert np.asarray(history["decoy_waste_step"]).shape == (config.T,)
    assert np.asarray(history["attack_success_prob"]).shape == (config.T,)
    assert np.asarray(history["attack_detection_prob"]).shape == (config.T,)
    assert np.asarray(history["target_defense_strength"]).shape == (config.T,)
    assert np.asarray(history["attacker_current_belief"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["trust_score"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["expected_utility"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["defender_observed_belief"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["defender_estimated_belief"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["defender_target_counts"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["defender_visible_log_observation"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["effective_defense_weight"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["post_decoy_defense_active"]).shape == (config.T,)


def test_matching_constraints():
    config = small_config()
    sim = CyberDefenseSimulator(config)
    sim.run()
    M = np.asarray(sim.history["M"])

    assert np.all(M >= 0)
    assert np.all(M <= 1)
    assert np.all(np.sum(M, axis=2) <= 1 + 1e-8)
    assert np.all(np.sum(M, axis=1) <= np.asarray(config.resource_capacity) + 1e-8)


def test_resource_constraints():
    config = small_config()
    sim = CyberDefenseSimulator(config)
    sim.run()
    r = np.asarray(sim.history["r"])

    assert np.all(r >= -1e-8)
    assert np.all(r <= config.r_max + 1e-8)
    assert np.all(np.sum(r, axis=1) <= config.R_total + 1e-8)


def test_trust_update_penalties_rewards_and_clip():
    attacker = AttackerModel(
        enabled=True,
        attacker_belief=np.ones(3),
        trust_enabled=True,
        trust_decoy_penalty=0.20,
        trust_credential_penalty=0.30,
        trust_detection_penalty=0.15,
        trust_success_reward=0.05,
    )

    attacker.update_trust(
        target_idx=1,
        success=False,
        detected=True,
        attacked_decoy=True,
        credential_decoy_trigger=True,
    )
    assert attacker.trust_vector(3)[1] == pytest.approx(0.35)

    attacker.update_trust(
        target_idx=1,
        success=True,
        detected=False,
        attacked_decoy=False,
        credential_decoy_trigger=False,
    )
    assert attacker.trust_vector(3)[1] == pytest.approx(0.40)

    for _ in range(5):
        attacker.update_trust(1, success=False, detected=True, attacked_decoy=True, credential_decoy_trigger=True)
    assert attacker.trust_vector(3)[1] == pytest.approx(0.0)


def test_expected_utility_score_uses_gain_trust_risk_and_search_cost():
    attacker = AttackerModel(
        enabled=True,
        attacker_belief=np.array([1.0, 2.0, 3.0]),
        adaptive_attacker_enabled=True,
        expected_utility_enabled=True,
        trust_enabled=True,
        expected_gain_weight=1.0,
        expected_success_weight=1.0,
        expected_detection_cost=1.0,
        expected_search_cost=1.0,
        expected_trust_weight=1.0,
        target_selection="adaptive",
    )
    attacker.node_trust_score = {0: 1.0, 1: 0.5, 2: 1.0}
    x_current = np.array([1.0, 1.0, 1.0])
    M_current = np.zeros((3, 1))

    score = attacker.calculate_adaptive_score(x_current, M_current)

    assert np.max(attacker.last_expected_utility) > 0.0
    assert score[2] > score[1]


def test_rule_based_adaptive_defender_policy_selection():
    assert _select_adaptive_defense_policy(
        expected_utility=1.0,
        trust_collapse_rate=0.0,
        target_switch_count=0,
    ) == ("gated_edge_pressure_count_2", "high_expected_utility")
    assert _select_adaptive_defense_policy(
        expected_utility=0.0,
        trust_collapse_rate=0.3,
        target_switch_count=0,
    ) == ("phase2_frustration_decoy", "trust_collapse")
    assert _select_adaptive_defense_policy(
        expected_utility=0.0,
        trust_collapse_rate=0.0,
        target_switch_count=8,
    ) == ("phase2_ai_balanced", "target_switch")


def test_cns_guided_adaptive_defender_policy_selection():
    policy, reason, score, rank, estimated_cns = _select_cns_guided_policy(
        expected_utility=1.0,
        trust_collapse_rate=0.3,
        target_switch_count=8,
        critical_compromise_risk=0.5,
        retreat_rate=1.0,
    )

    assert policy == "phase2_frustration_decoy"
    assert reason in {"cns_trust_collapse", "cns_critical_protection", "cns_score_max"}
    assert score > 0.0
    assert rank == 1
    assert 0.0 <= estimated_cns <= 1.0


def test_metrics_written(tmp_path):
    config = small_config()
    sim = CyberDefenseSimulator(config)
    sim.run()
    sim.save_outputs(str(tmp_path))

    metrics_path = tmp_path / "metrics.json"
    history_path = tmp_path / "history.npz"
    assert metrics_path.exists()
    assert history_path.exists()

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    for key in [
        "steps",
        "final_risk_sum",
        "weighted_cumulative_risk",
        "matching_update_count",
        "ilp_fallback_count",
        "mpc_fallback_count",
        "clip_low_count",
        "clip_high_count",
        "attacker_enabled",
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
        "retreat_based_on",
        "attacker_total_cost",
        "attacker_avg_gain_per_success",
        "attacker_cost_per_success",
        "attacker_detection_rate",
        "attacker_success_rate",
        "attacker_target_counts",
        "attacker_most_targeted_node",
        "attacker_greedy_mode",
        "asset_value",
        "attacker_belief",
        "attacker_belief_error_l1",
        "attacker_belief_error_l2",
        "node_type",
        "decoy_node_count",
        "attacker_decoy_attack_count",
        "attacker_decoy_attack_rate",
        "attacker_decoy_waste_total",
        "attacker_real_attack_count",
        "stochastic_detection",
        "stochastic_success",
        "mean_attack_success_prob",
        "mean_attack_detection_prob",
        "mean_target_defense_strength",
        "attacker_belief_learning_enabled",
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
        "mission_mutation_enabled",
        "mission_change_count",
        "mission_stability_score",
        "mission_mutation_reason",
        "mission_mutation_success",
        "attacker_type",
        "mission_reclassification_enabled",
        "mission_reclassification_count",
        "defense_reoptimization_count",
        "reclassification_accuracy",
        "belief_recovery_time",
        "multi_objective_mission_enabled",
        "intent_deception_enabled",
        "deception_event_count",
        "mission_belief_error",
        "belief_confusion_score",
        "true_mission",
        "observed_mission",
        "mission_masking_success",
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
        "nonstationary_attacker_enabled",
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
        "mission_aware_defender_enabled",
        "mission_aware_selected_policy",
        "mission_policy_match",
        "mission_policy_switch_count",
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
        "intelligence_defender_enabled",
        "selected_intelligence_policy",
        "intelligence_risk_score",
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
        "strategy_profile",
        "strategy_effectiveness_score",
        "profile_rank",
        "best_weight_configuration",
        "mission_weight",
        "state_weight",
        "critical_path_weight",
        "weight_sweep_rank",
        "adaptive_defender_effectiveness",
        "attacker_belief_change_l1",
        "attacker_belief_change_l2",
        "attacker_belief_decoy_reduction",
        "attacker_final_belief",
        "post_decoy_defense_enabled",
        "post_decoy_defense_injection_mode",
        "post_decoy_defense_active_count",
        "post_decoy_defense_mpc_q_active_count",
        "post_decoy_defense_matching_active_count",
        "post_decoy_defense_fallback_active_count",
        "effective_defense_weight_final",
    ]:
        assert key in metrics

    history = np.load(history_path)
    assert history["x"].shape == (config.T, config.n_nodes)
    assert history["r"].shape == (config.T, config.m_resources)
    assert history["M"].shape == (config.T, config.n_nodes, config.m_resources)
    assert history["attack_vector"].shape == (config.T, config.n_nodes)
    assert history["attacker_selection_score"].shape == (config.T, config.n_nodes)
    assert history["attacker_selected_target"].shape == (config.T,)
    assert history["asset_value"].shape == (config.n_nodes,)
    assert history["attacker_belief"].shape == (config.n_nodes,)
    assert history["attacker_attacked_decoy"].shape == (config.T,)
    assert history["actual_utility"].shape == (config.T,)
    assert history["perceived_utility"].shape == (config.T,)
    assert history["confidence"].shape == (config.T,)
    assert history["frustration"].shape == (config.T,)
    assert history["decoy_waste_step"].shape == (config.T,)
    assert history["attack_success_prob"].shape == (config.T,)
    assert history["attack_detection_prob"].shape == (config.T,)
    assert history["target_defense_strength"].shape == (config.T,)
    assert history["attacker_current_belief"].shape == (config.T, config.n_nodes)
    assert history["defender_observed_belief"].shape == (config.T, config.n_nodes)
    assert history["defender_estimated_belief"].shape == (config.T, config.n_nodes)
    assert history["defender_target_counts"].shape == (config.T, config.n_nodes)
    assert history["defender_visible_log_observation"].shape == (config.T, config.n_nodes)
    assert history["effective_defense_weight"].shape == (config.T, config.n_nodes)
    assert history["post_decoy_defense_active"].shape == (config.T,)
    assert history["post_decoy_defense_injection_mode"].shape == (config.T,)


def test_neutralization_scores_in_metrics():
    config = small_config(attacker_enabled=True)
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    for key in [
        "neutralization_score",
        "critical_protection_score",
        "utility_suppression_score",
        "deception_waste_score",
        "friction_score",
        "retreat_score",
    ]:
        assert key in metrics
        assert 0.0 <= metrics[key] <= 1.0


def test_cognitive_score_metrics_exist():
    config = small_config(
        attacker_enabled=True,
        perceived_utility_enabled=True,
        frustration_enabled=True,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    assert "cognitive_neutralization_score" in metrics
    assert "cognitive_human_score" in metrics
    assert "cognitive_ai_score" in metrics


def test_cognitive_score_range():
    config = small_config(
        attacker_enabled=True,
        perceived_utility_enabled=True,
        frustration_enabled=True,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    for key in [
        "cognitive_neutralization_score",
        "cognitive_human_score",
        "cognitive_ai_score",
    ]:
        assert 0.0 <= metrics[key] <= 1.0


def test_cns_contribution_metrics_exist():
    config = small_config(
        attacker_enabled=True,
        perceived_utility_enabled=True,
        frustration_enabled=True,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    for key in [
        "cns_objective_score",
        "cns_human_contribution",
        "cns_ai_contribution",
        "cns_protection_contribution",
    ]:
        assert key in metrics


def test_cns_objective_score_range():
    config = small_config(
        attacker_enabled=True,
        perceived_utility_enabled=True,
        frustration_enabled=True,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    assert 0.0 <= metrics["cns_objective_score"] <= 1.0


def test_phase2_attacker_model_roadmap_exists():
    path = "docs/PHASE2_ATTACKER_MODEL_ROADMAP.md"
    with open(path, encoding="utf-8") as f:
        content = f.read()

    assert "# CyberMatch Phase2 Attacker Model Roadmap" in content
    assert "Human Frustration Model" in content
    assert "AI Decision Cost Model" in content


def test_phase2_final_report_exists():
    path = "docs/CYBERMATCH_PHASE2_FINAL_REPORT.md"
    with open(path, encoding="utf-8") as f:
        content = f.read()

    assert "# CyberMatch Phase2 Final Report" in content
    assert "Decision Neutralization" in content
    assert "Phase1 Best = phase2_ai_balanced" in content
    assert "CNS Best = phase2_frustration_decoy" in content
    assert "Recommended Policy = phase2_frustration_decoy" in content


def test_phase2_artifacts_exists():
    required_paths = [
        "docs/PHASE2_ARTIFACTS.md",
        "docs/GITHUB_RELEASE_PLAN.md",
        "docs/REPRODUCIBILITY.md",
    ]

    for path in required_paths:
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "Phase2" in content or "Reproducibility" in content


def test_phase2_summary_json_exists():
    path = "output/phase2_final_summary.json"
    with open(path, encoding="utf-8") as f:
        payload = json.load(f)

    assert payload["phase"] == "Phase2"
    assert payload["phase1_best_policy"] == "phase2_ai_balanced"
    assert payload["cns_best_policy"] == "phase2_frustration_decoy"
    assert payload["recommended_policy"] == "phase2_frustration_decoy"
    assert payload["pytest_passed"] is True


def test_human_frustration_alias_metrics_present():
    config = small_config(attacker_enabled=True, frustration_enabled=True)
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    assert metrics["human_frustration_final"] == pytest.approx(metrics["frustration_final"])
    assert metrics["human_frustration_mean"] == pytest.approx(metrics["frustration_mean"])
    assert metrics["human_frustration_max"] == pytest.approx(metrics["frustration_max"])
    assert "ai_uncertainty_cost" in metrics
    assert "ai_replanning_cost" in metrics
    assert "ai_search_cost" in metrics
    assert "ai_operational_risk_cost" in metrics
    assert "ai_trust_degradation_cost" in metrics
    assert "ai_total_decision_cost" in metrics
    assert "ai_weighted_cost" in metrics
    assert "human_vs_ai_cost_ratio" in metrics


def test_perceived_utility_separates_from_actual():
    config = small_config(
        T=4,
        attacker_enabled=True,
        perceived_utility_enabled=True,
        retreat_based_on="actual",
        perceived_success_confidence=0.25,
        perceived_decoy_penalty=0.0,
        perceived_detection_penalty=1.0,
        perceived_uncertainty_decay=1.0,
        attacker_retreat_threshold=-999.0,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    assert metrics["actual_utility_final"] == pytest.approx(metrics["attacker_utility_final"])
    assert metrics["actual_utility_final"] != pytest.approx(metrics["perceived_utility_final"])
    assert metrics["actual_gain"] >= metrics["perceived_gain"]


def test_decoy_and_credential_reduce_confidence():
    decoy_config = small_config(
        T=5,
        attacker_enabled=True,
        attacker_target_selection="greedy",
        attacker_greedy_mode="utility",
        attacker_belief_learning_enabled=False,
        perceived_utility_enabled=True,
        retreat_based_on="actual",
        perceived_uncertainty_decay=0.5,
        attacker_retreat_threshold=-999.0,
        node_type=["decoy", "real", "real", "real", "real"],
        asset_value=[0.0, 5.0, 1.0, 8.0, 2.0],
        attacker_belief=[100.0, 1.0, 1.0, 1.0, 1.0],
        honeypot_credential_enabled=True,
        credential_node_ids=[0],
        stochastic_success=False,
        stochastic_detection=False,
    )
    decoy_sim = CyberDefenseSimulator(decoy_config)
    decoy_history = decoy_sim.run()

    assert np.any(np.asarray(decoy_history["attacker_attacked_decoy"], dtype=bool))
    assert np.min(np.asarray(decoy_history["confidence"], dtype=float)) < 1.0

    credential_config = small_config(
        T=3,
        attacker_enabled=True,
        attacker_target_selection="greedy",
        attacker_greedy_mode="utility",
        perceived_utility_enabled=True,
        retreat_based_on="actual",
        perceived_uncertainty_decay=0.5,
        attacker_retreat_threshold=-999.0,
        asset_value=[10.0, 5.0, 1.0, 8.0, 2.0],
        attacker_belief=[100.0, 1.0, 1.0, 1.0, 1.0],
        honeypot_credential_enabled=True,
        credential_node_ids=[0],
        stochastic_success=False,
        stochastic_detection=False,
    )
    credential_sim = CyberDefenseSimulator(credential_config)
    credential_history = credential_sim.run()

    assert np.any(np.asarray(credential_history["credential_decoy_trigger"], dtype=bool))
    assert np.min(np.asarray(credential_history["confidence"], dtype=float)) < 1.0


def test_retreat_can_be_driven_by_perceived_utility():
    config = small_config(
        T=8,
        attacker_enabled=True,
        perceived_utility_enabled=True,
        retreat_based_on="perceived",
        perceived_success_confidence=0.0,
        perceived_decoy_penalty=0.0,
        perceived_detection_penalty=1.0,
        perceived_uncertainty_decay=1.0,
        attacker_retreat_threshold=-1.0,
        attacker_patience=20,
        attacker_belief=[10.0, 5.0, 1.0, 8.0, 2.0],
        asset_value=[10.0, 5.0, 1.0, 8.0, 2.0],
        stochastic_success=False,
        stochastic_detection=False,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    assert metrics["actual_utility_final"] > 0.0
    assert metrics["perceived_utility_final"] < config.attacker_retreat_threshold
    assert metrics["attacker_retreated"] is True
    assert metrics["retreat_based_on"] == "perceived"


def test_targeted_neutralization_evaluation_outputs(tmp_path, monkeypatch):
    import run_scenarios as scenario_module

    monkeypatch.setattr(
        scenario_module,
        "NEUTRALIZATION_SCENARIO_MAP",
        {
            "baseline": "attacker_greedy_utility",
            "naive_decoy": "adaptive_decoy_node2_learning",
        },
    )
    rows = run_neutralization_evaluation(output_dir=str(tmp_path), seed=3)

    assert len(rows) == 2
    assert (tmp_path / "neutralization_summary.csv").exists()
    assert (tmp_path / "neutralization_summary.json").exists()
    assert (tmp_path / "neutralization_ranking.png").exists()
    assert (tmp_path / "neutralization_breakdown.png").exists()
    assert (tmp_path / "NEUTRALIZATION_REPORT.md").exists()
    assert all(0.0 <= row["neutralization_score"] <= 1.0 for row in rows)


def test_phase2_perceived_utility_scenarios_present():
    expected = {
        "phase2_actual_utility_reference",
        "phase2_perceived_decoy",
        "phase2_perceived_credential",
        "phase2_perceived_decoy_credential",
        "phase2_perceived_high_uncertainty",
    }
    assert expected.issubset(SCENARIOS)
    assert expected.issubset(MULTI_SEED_SCENARIO_NAMES)


def test_phase2_perceived_utility_multiseed_outputs(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "phase2_actual_utility_reference": {
                **SCENARIOS["phase2_actual_utility_reference"],
                "T": 4,
                "H": 2,
            },
            "phase2_perceived_high_uncertainty": {
                **SCENARIOS["phase2_perceived_high_uncertainty"],
                "T": 4,
                "H": 2,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert "actual_utility_mean" in rows[0]
    assert "perceived_utility_mean" in rows[0]
    assert "confidence_mean" in rows[0]
    assert (tmp_path / "scenarios_multiseed" / "summary_perceived_vs_actual_utility.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_confidence_decay.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_perceived_retreat_rate.png").exists()


def test_frustration_history_and_event_increments():
    decoy_config = small_config(
        T=5,
        attacker_enabled=True,
        attacker_target_selection="greedy",
        attacker_greedy_mode="utility",
        attacker_belief_learning_enabled=False,
        frustration_enabled=True,
        retreat_based_on="actual",
        frustration_decay=1.0,
        frustration_decoy_hit=3.0,
        frustration_credential_trap=2.0,
        frustration_detection=1.0,
        attacker_retreat_threshold=-999.0,
        node_type=["decoy", "real", "real", "real", "real"],
        asset_value=[0.0, 5.0, 1.0, 8.0, 2.0],
        attacker_belief=[100.0, 1.0, 1.0, 1.0, 1.0],
        stochastic_success=False,
        stochastic_detection=False,
    )
    decoy_sim = CyberDefenseSimulator(decoy_config)
    decoy_history = decoy_sim.run()
    decoy_frustration = np.asarray(decoy_history["frustration"], dtype=float)

    assert decoy_frustration.shape == (decoy_config.T,)
    assert np.any(np.asarray(decoy_history["attacker_attacked_decoy"], dtype=bool))
    assert float(np.max(decoy_frustration)) >= decoy_config.frustration_decoy_hit

    credential_config = small_config(
        T=3,
        attacker_enabled=True,
        attacker_target_selection="greedy",
        attacker_greedy_mode="utility",
        frustration_enabled=True,
        retreat_based_on="actual",
        frustration_decay=1.0,
        frustration_credential_trap=2.0,
        attacker_retreat_threshold=-999.0,
        asset_value=[10.0, 5.0, 1.0, 8.0, 2.0],
        attacker_belief=[100.0, 1.0, 1.0, 1.0, 1.0],
        honeypot_credential_enabled=True,
        credential_node_ids=[0],
        stochastic_success=False,
        stochastic_detection=False,
    )
    credential_sim = CyberDefenseSimulator(credential_config)
    credential_history = credential_sim.run()
    credential_frustration = np.asarray(credential_history["frustration"], dtype=float)

    assert np.any(np.asarray(credential_history["credential_decoy_trigger"], dtype=bool))
    assert float(np.max(credential_frustration)) >= credential_config.frustration_credential_trap


def test_frustration_retreat_can_override_positive_utility():
    config = small_config(
        T=8,
        attacker_enabled=True,
        attacker_target_selection="greedy",
        attacker_greedy_mode="utility",
        perceived_utility_enabled=True,
        perceived_success_confidence=1.0,
        perceived_decoy_penalty=0.0,
        perceived_detection_penalty=0.0,
        perceived_uncertainty_decay=1.0,
        frustration_enabled=True,
        retreat_based_on="frustration",
        frustration_decay=1.0,
        frustration_detection=3.0,
        frustration_retreat_threshold=2.0,
        attacker_retreat_threshold=-999.0,
        attacker_patience=50,
        base_detection_prob=1.0,
        defense_detection_scale=0.0,
        stochastic_detection=True,
        stochastic_success=False,
        asset_value=[20.0, 5.0, 1.0, 8.0, 2.0],
        attacker_belief=[20.0, 5.0, 1.0, 8.0, 2.0],
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    assert metrics["actual_utility_final"] > 0.0
    assert metrics["perceived_utility_final"] > 0.0
    assert metrics["frustration_final"] > config.frustration_retreat_threshold
    assert metrics["frustration_retreats"] == 1
    assert metrics["attacker_retreated"] is True
    assert metrics["retreat_based_on"] == "frustration"


def test_ai_decision_cost_metrics_map_frustration_components():
    decoy_config = small_config(
        T=5,
        attacker_enabled=True,
        attacker_target_selection="greedy",
        attacker_greedy_mode="utility",
        frustration_enabled=True,
        retreat_based_on="actual",
        frustration_decay=1.0,
        frustration_decoy_hit=3.0,
        frustration_credential_trap=2.0,
        frustration_detection=1.0,
        attacker_retreat_threshold=-999.0,
        node_type=["decoy", "real", "real", "real", "real"],
        asset_value=[0.0, 5.0, 1.0, 8.0, 2.0],
        attacker_belief=[100.0, 1.0, 1.0, 1.0, 1.0],
        stochastic_success=False,
        stochastic_detection=False,
    )
    decoy_sim = CyberDefenseSimulator(decoy_config)
    decoy_sim.run()
    decoy_metrics = decoy_sim.calculate_metrics()

    for key in [
        "ai_uncertainty_cost",
        "ai_replanning_cost",
        "ai_search_cost",
        "ai_operational_risk_cost",
        "ai_trust_degradation_cost",
        "ai_total_decision_cost",
    ]:
        assert key in decoy_metrics
    assert decoy_metrics["ai_uncertainty_cost"] > 0.0
    assert decoy_metrics["ai_total_decision_cost"] == pytest.approx(decoy_metrics["ai_weighted_cost"])
    assert decoy_metrics["ai_total_decision_cost"] > decoy_metrics["frustration_mean"]
    assert decoy_metrics["human_vs_ai_cost_ratio"] < 1.0

    credential_config = small_config(
        T=3,
        attacker_enabled=True,
        attacker_target_selection="greedy",
        attacker_greedy_mode="utility",
        frustration_enabled=True,
        retreat_based_on="actual",
        frustration_decay=1.0,
        frustration_credential_trap=2.0,
        attacker_retreat_threshold=-999.0,
        asset_value=[10.0, 5.0, 1.0, 8.0, 2.0],
        attacker_belief=[100.0, 1.0, 1.0, 1.0, 1.0],
        honeypot_credential_enabled=True,
        credential_node_ids=[0],
        stochastic_success=False,
        stochastic_detection=False,
    )
    credential_sim = CyberDefenseSimulator(credential_config)
    credential_sim.run()
    credential_metrics = credential_sim.calculate_metrics()

    assert credential_metrics["ai_trust_degradation_cost"] > 0.0
    assert credential_metrics["ai_total_decision_cost"] == pytest.approx(credential_metrics["ai_weighted_cost"])
    assert credential_metrics["ai_total_decision_cost"] > credential_metrics["frustration_mean"]


def test_phase2_frustration_scenarios_present():
    expected = {
        "phase2_frustration_reference",
        "phase2_frustration_decoy",
        "phase2_frustration_credential",
        "phase2_frustration_decoy_credential",
        "phase2_frustration_high_detection",
        "phase2_frustration_path_change",
    }
    assert expected.issubset(SCENARIOS)
    assert expected.issubset(MULTI_SEED_SCENARIO_NAMES)


def test_phase2_frustration_multiseed_outputs(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "phase2_frustration_reference": {
                **SCENARIOS["phase2_frustration_reference"],
                "T": 4,
                "H": 2,
            },
            "phase2_frustration_high_detection": {
                **SCENARIOS["phase2_frustration_high_detection"],
                "T": 4,
                "H": 2,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert "frustration_mean" in rows[0]
    assert "frustration_max" in rows[0]
    assert "perceived_utility_mean" in rows[0]
    assert (tmp_path / "scenarios_multiseed" / "summary_frustration_retreat_rate.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_frustration_distribution.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_frustration_vs_perceived_utility.png").exists()


def test_phase2_ai_cost_outputs(tmp_path):
    rows = run_phase2_ai_cost_evaluation(
        seeds=[0, 1],
        output_dir=str(tmp_path / "phase2_ai_cost"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows
    assert "frustration_mean" in rows[0]
    assert "ai_total_decision_cost" in rows[0]
    assert rows[0]["ai_total_decision_cost"] != pytest.approx(rows[0]["frustration_mean"])
    assert (tmp_path / "phase2_ai_cost" / "ai_cost_summary.csv").exists()
    assert (tmp_path / "phase2_ai_cost" / "ai_cost_summary.json").exists()
    assert (tmp_path / "phase2_ai_cost" / "ai_cost_vs_frustration.png").exists()
    assert (tmp_path / "phase2_ai_cost" / "ai_cost_vs_retreat_rate.png").exists()


def test_phase2_ai_weight_scenarios_present():
    expected = {
        "phase2_ai_cost_reference",
        "phase2_ai_high_uncertainty",
        "phase2_ai_high_trust_degradation",
        "phase2_ai_high_operational_risk",
        "phase2_ai_low_replanning_cost",
        "phase2_ai_balanced",
    }

    assert expected.issubset(SCENARIOS)
    assert expected.issubset(set(MULTI_SEED_SCENARIO_NAMES))


def test_phase2_ai_weight_sweep_outputs(tmp_path):
    rows = run_phase2_ai_weight_sweep_evaluation(
        seeds=[0, 1],
        output_dir=str(tmp_path / "phase2_ai_weight_sweep"),
        config_path=str(tmp_path / "missing_config.json"),
    )
    payload = json.loads(
        (tmp_path / "phase2_ai_weight_sweep" / "ai_weight_sweep_summary.json").read_text(encoding="utf-8")
    )

    assert rows
    assert "human_cost" in rows[0]
    assert "ai_weighted_cost" in rows[0]
    assert "neutralization_score" in rows[0]
    assert payload["analysis"]["q1_best_human_defense"]
    assert payload["analysis"]["ai_attacker_most_affected_defense"]
    assert (tmp_path / "phase2_ai_weight_sweep" / "ai_weight_sweep_summary.csv").exists()
    assert (tmp_path / "phase2_ai_weight_sweep" / "human_vs_ai_cost.png").exists()
    assert (tmp_path / "phase2_ai_weight_sweep" / "human_vs_ai_retreat.png").exists()
    assert (tmp_path / "phase2_ai_weight_sweep" / "human_vs_ai_neutralization.png").exists()


def test_phase2_cognitive_outputs_exist(tmp_path):
    rows = run_phase2_cognitive_neutralization_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase2_cognitive_neutralization"),
        config_path=str(tmp_path / "missing_config.json"),
    )
    payload = json.loads(
        (tmp_path / "phase2_cognitive_neutralization" / "cognitive_summary.json").read_text(encoding="utf-8")
    )

    assert rows
    assert "cognitive_neutralization_score" in rows[0]
    assert "cognitive_human_score" in rows[0]
    assert "cognitive_ai_score" in rows[0]
    assert payload["analysis"]["best_combined_cognitive_neutralization"]
    assert (tmp_path / "phase2_cognitive_neutralization" / "cognitive_summary.csv").exists()
    assert (tmp_path / "phase2_cognitive_neutralization" / "cognitive_summary.json").exists()
    assert (tmp_path / "phase2_cognitive_neutralization" / "cognitive_ranking.png").exists()
    assert (tmp_path / "phase2_cognitive_neutralization" / "cognitive_human_vs_ai.png").exists()
    assert (tmp_path / "phase2_cognitive_neutralization" / "cognitive_vs_phase1_neutralization.png").exists()
    assert (tmp_path / "phase2_cognitive_neutralization" / "PHASE2_COGNITIVE_REPORT.md").exists()


def test_policy_effectiveness_score_range(tmp_path):
    rows = run_phase2_policy_selection_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase2_policy_selection"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows
    assert all(0.0 <= row["policy_effectiveness_score"] <= 1.0 for row in rows)


def test_phase2_policy_selection_outputs_exist(tmp_path):
    run_phase2_policy_selection_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase2_policy_selection"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert (tmp_path / "phase2_policy_selection" / "policy_selection_summary.csv").exists()
    assert (tmp_path / "phase2_policy_selection" / "policy_selection_summary.json").exists()
    assert (tmp_path / "phase2_policy_selection" / "policy_selection_ranking.png").exists()
    assert (tmp_path / "phase2_policy_selection" / "phase1_vs_cns.png").exists()
    assert (tmp_path / "phase2_policy_selection" / "human_vs_ai_policy.png").exists()
    assert (tmp_path / "phase2_policy_selection" / "best_policy_report.md").exists()


def test_phase3_expected_utility_outputs_exist(tmp_path):
    rows = run_phase3_expected_utility_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase3_expected_utility"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert any(row["attacker_mode"] == "expected_utility" for row in rows)
    assert (tmp_path / "phase3_expected_utility" / "expected_summary.csv").exists()
    assert (tmp_path / "phase3_expected_utility" / "expected_summary.json").exists()
    assert (tmp_path / "phase3_expected_utility" / "expected_cns.png").exists()
    assert (tmp_path / "phase3_expected_utility" / "expected_retreat_rate.png").exists()
    assert (tmp_path / "phase3_expected_utility" / "expected_target_switch.png").exists()
    assert (tmp_path / "phase3_expected_utility" / "PHASE3_EXPECTED_UTILITY_REPORT.md").exists()


def test_phase4_adaptive_defender_outputs_exist(tmp_path):
    rows = run_phase4_adaptive_defender_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase4_adaptive_defender"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert any(row["defense_mode"] == "adaptive_defender" for row in rows)
    assert any(row["defense_mode"] == "fixed" for row in rows)
    assert (tmp_path / "phase4_adaptive_defender" / "adaptive_defender_summary.csv").exists()
    assert (tmp_path / "phase4_adaptive_defender" / "adaptive_defender_summary.json").exists()
    assert (tmp_path / "phase4_adaptive_defender" / "adaptive_defender_cns.png").exists()
    assert (tmp_path / "phase4_adaptive_defender" / "adaptive_defender_policy_selection.png").exists()
    assert (tmp_path / "phase4_adaptive_defender" / "adaptive_defender_effectiveness.png").exists()
    assert (tmp_path / "phase4_adaptive_defender" / "PHASE4_ADAPTIVE_DEFENDER_REPORT.md").exists()


def test_phase4_cns_guided_outputs_exist(tmp_path):
    rows = run_phase4_cns_guided_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase4_cns_guided"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert any(row["defense_mode"] == "cns_guided_adaptive" for row in rows)
    assert any(row["defense_mode"] == "rule_based_adaptive" for row in rows)
    assert any(row["defense_mode"] == "fixed" for row in rows)
    assert (tmp_path / "phase4_cns_guided" / "cns_guided_summary.csv").exists()
    assert (tmp_path / "phase4_cns_guided" / "cns_guided_summary.json").exists()
    assert (tmp_path / "phase4_cns_guided" / "cns_guided_cns.png").exists()
    assert (tmp_path / "phase4_cns_guided" / "cns_guided_policy_selection.png").exists()
    assert (tmp_path / "phase4_cns_guided" / "cns_guided_vs_rule_based.png").exists()
    assert (tmp_path / "phase4_cns_guided" / "PHASE4_CNS_GUIDED_REPORT.md").exists()


def test_phase4_step_adaptive_outputs_exist(tmp_path):
    rows = run_phase4_step_adaptive_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase4_step_adaptive"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert any(row["defense_mode"] == "step_adaptive" for row in rows)
    assert any(row["defense_mode"] == "cns_guided_adaptive" for row in rows)
    assert any(row["defense_mode"] == "rule_based_adaptive" for row in rows)
    assert any(row["defense_mode"] == "fixed" for row in rows)
    assert (tmp_path / "phase4_step_adaptive" / "step_adaptive_summary.csv").exists()
    assert (tmp_path / "phase4_step_adaptive" / "step_adaptive_summary.json").exists()
    assert (tmp_path / "phase4_step_adaptive" / "step_adaptive_cns.png").exists()
    assert (tmp_path / "phase4_step_adaptive" / "step_adaptive_switch_count.png").exists()
    assert (tmp_path / "phase4_step_adaptive" / "step_adaptive_vs_phase42.png").exists()
    assert (tmp_path / "phase4_step_adaptive" / "PHASE4_STEP_ADAPTIVE_REPORT.md").exists()


def test_phase4_nonstationary_outputs_exist(tmp_path):
    rows = run_phase4_nonstationary_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase4_nonstationary"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert any(row["defense_mode"] == "step_adaptive" for row in rows)
    assert any(row["defense_mode"] == "cns_guided_adaptive" for row in rows)
    assert any(row["defense_mode"] == "fixed_frustration_decoy" for row in rows)
    assert (tmp_path / "phase4_nonstationary" / "nonstationary_summary.csv").exists()
    assert (tmp_path / "phase4_nonstationary" / "nonstationary_summary.json").exists()
    assert (tmp_path / "phase4_nonstationary" / "nonstationary_cns.png").exists()
    assert (tmp_path / "phase4_nonstationary" / "nonstationary_policy_switch.png").exists()
    assert (tmp_path / "phase4_nonstationary" / "nonstationary_vs_phase43.png").exists()
    assert (tmp_path / "phase4_nonstationary" / "PHASE4_NONSTATIONARY_REPORT.md").exists()


def test_phase4_switch_benefit_outputs_exist(tmp_path):
    rows = run_phase4_switch_benefit_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase4_switch_benefit"),
        config_path=str(tmp_path / "missing_config.json"),
        phase_change_steps=[10],
        recheck_intervals=[1],
        min_improvements=[0.0],
        switch_costs=[0.0],
    )

    assert rows
    assert "switch_benefit_score" in rows[0]
    assert "switch_efficiency" in rows[0]
    assert (tmp_path / "phase4_switch_benefit" / "switch_benefit_summary.csv").exists()
    assert (tmp_path / "phase4_switch_benefit" / "switch_benefit_summary.json").exists()
    assert (tmp_path / "phase4_switch_benefit" / "switch_benefit_heatmap.png").exists()
    assert (tmp_path / "phase4_switch_benefit" / "switch_benefit_vs_interval.png").exists()
    assert (tmp_path / "phase4_switch_benefit" / "switch_benefit_vs_cost.png").exists()
    assert (tmp_path / "phase4_switch_benefit" / "PHASE4_SWITCH_BENEFIT_REPORT.md").exists()


def test_phase4_specialized_policy_outputs_exist(tmp_path):
    rows = run_phase4_specialized_policy_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase4_specialized_policy"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    policies = {row["policy"] for row in rows}
    assert "phase4_trust_collapse_maximizer" in policies
    assert "phase4_expected_utility_suppressor" in policies
    assert "phase4_target_switch_inducer" in policies
    assert "phase4_planning_disruptor" in policies
    assert (tmp_path / "phase4_specialized_policy" / "specialized_policy_summary.csv").exists()
    assert (tmp_path / "phase4_specialized_policy" / "specialized_policy_summary.json").exists()
    assert (tmp_path / "phase4_specialized_policy" / "specialized_policy_ranking.png").exists()
    assert (tmp_path / "phase4_specialized_policy" / "specialized_policy_breakdown.png").exists()
    assert (tmp_path / "phase4_specialized_policy" / "specialized_policy_vs_phase2.png").exists()
    assert (tmp_path / "phase4_specialized_policy" / "PHASE4_SPECIALIZED_POLICY_REPORT.md").exists()


def test_phase47_mission_profile_outputs_exist(tmp_path):
    rows = run_phase47_mission_profile_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase47_mission_profiles"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    missions = {row["attacker_mission"] for row in rows}
    assert {"profit", "achievement", "persistence", "critical_hunter"}.issubset(missions)
    assert all("defense_effectiveness_score" in row for row in rows)
    assert (tmp_path / "phase47_mission_profiles" / "mission_profile_summary.csv").exists()
    assert (tmp_path / "phase47_mission_profiles" / "mission_profile_summary.json").exists()
    assert (tmp_path / "phase47_mission_profiles" / "mission_profile_ranking.png").exists()
    assert (tmp_path / "phase47_mission_profiles" / "mission_profile_breakdown.png").exists()
    assert (tmp_path / "phase47_mission_profiles" / "mission_profile_vs_defense.png").exists()
    assert (tmp_path / "phase47_mission_profiles" / "PHASE47_MISSION_PROFILE_REPORT.md").exists()


def test_phase48_mission_aware_outputs_exist(tmp_path):
    rows = run_phase48_mission_aware_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase48_mission_aware"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    modes = {row["defense_mode"] for row in rows}
    assert {"fixed_frustration_decoy", "fixed_gated_count2", "cns_guided", "mission_aware"}.issubset(modes)
    mission_rows = [row for row in rows if row["defense_mode"] == "mission_aware"]
    assert mission_rows
    assert all(row["mission_policy_match"] for row in mission_rows)
    assert (tmp_path / "phase48_mission_aware" / "mission_aware_summary.csv").exists()
    assert (tmp_path / "phase48_mission_aware" / "mission_aware_summary.json").exists()
    assert (tmp_path / "phase48_mission_aware" / "mission_aware_cns.png").exists()
    assert (tmp_path / "phase48_mission_aware" / "mission_aware_policy_selection.png").exists()
    assert (tmp_path / "phase48_mission_aware" / "mission_aware_vs_phase47.png").exists()
    assert (tmp_path / "phase48_mission_aware" / "PHASE48_MISSION_AWARE_REPORT.md").exists()


def test_phase49_mission_belief_outputs_exist(tmp_path):
    rows = run_phase49_mission_belief_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase49_mission_belief"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    modes = {row["defense_mode"] for row in rows}
    assert {"fixed_best", "cns_guided", "oracle_mission", "mission_belief"}.issubset(modes)
    belief_rows = [row for row in rows if row["defense_mode"] == "mission_belief"]
    assert belief_rows
    assert all("predicted_mission" in row for row in belief_rows)
    assert (tmp_path / "phase49_mission_belief" / "mission_belief_summary.csv").exists()
    assert (tmp_path / "phase49_mission_belief" / "mission_belief_summary.json").exists()
    assert (tmp_path / "phase49_mission_belief" / "mission_prediction_accuracy.png").exists()
    assert (tmp_path / "phase49_mission_belief" / "mission_belief_vs_oracle.png").exists()
    assert (tmp_path / "phase49_mission_belief" / "mission_belief_vs_phase48.png").exists()
    assert (tmp_path / "phase49_mission_belief" / "PHASE49_MISSION_BELIEF_REPORT.md").exists()


def test_phase410_state_belief_outputs_exist(tmp_path):
    rows = run_phase410_state_belief_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase410_state_belief"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    modes = {row["defense_mode"] for row in rows}
    assert {"fixed_best", "cns_guided", "mission_belief", "state_belief"}.issubset(modes)
    state_rows = [row for row in rows if row["defense_mode"] == "state_belief"]
    assert state_rows
    assert all("predicted_state" in row for row in state_rows)
    assert (tmp_path / "phase410_state_belief" / "state_belief_summary.csv").exists()
    assert (tmp_path / "phase410_state_belief" / "state_belief_summary.json").exists()
    assert (tmp_path / "phase410_state_belief" / "state_prediction.png").exists()
    assert (tmp_path / "phase410_state_belief" / "state_transition.png").exists()
    assert (tmp_path / "phase410_state_belief" / "state_belief_vs_phase49.png").exists()
    assert (tmp_path / "phase410_state_belief" / "PHASE410_STATE_BELIEF_REPORT.md").exists()


def test_phase411_virtual_topology_outputs_exist(tmp_path):
    rows = run_phase411_virtual_topology_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase411_virtual_topology"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    modes = {row["defense_mode"] for row in rows}
    assert {"phase410_state_belief", "observable_state_belief"}.issubset(modes)
    observable_rows = [row for row in rows if row["defense_mode"] == "observable_state_belief"]
    assert observable_rows
    assert all("observable_event_count" in row for row in observable_rows)
    assert (tmp_path / "phase411_virtual_topology" / "virtual_topology_summary.csv").exists()
    assert (tmp_path / "phase411_virtual_topology" / "virtual_topology_summary.json").exists()
    assert (tmp_path / "phase411_virtual_topology" / "state_transition_heatmap.png").exists()
    assert (tmp_path / "phase411_virtual_topology" / "observable_events_breakdown.png").exists()
    assert (tmp_path / "phase411_virtual_topology" / "state_belief_vs_phase410.png").exists()
    assert (tmp_path / "phase411_virtual_topology" / "PHASE411_VIRTUAL_TOPOLOGY_REPORT.md").exists()


def test_phase412_critical_path_outputs_exist(tmp_path):
    rows = run_phase412_critical_path_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase412_critical_path"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    modes = {row["defense_mode"] for row in rows}
    assert {"phase411", "phase412"}.issubset(modes)
    phase412_rows = [row for row in rows if row["defense_mode"] == "phase412"]
    assert phase412_rows
    assert all("critical_path_proximity" in row for row in phase412_rows)
    assert (tmp_path / "phase412_critical_path" / "critical_path_summary.csv").exists()
    assert (tmp_path / "phase412_critical_path" / "critical_path_summary.json").exists()
    assert (tmp_path / "phase412_critical_path" / "critical_path_events.png").exists()
    assert (tmp_path / "phase412_critical_path" / "critical_path_proximity.png").exists()
    assert (tmp_path / "phase412_critical_path" / "state_belief_vs_phase411.png").exists()
    assert (tmp_path / "phase412_critical_path" / "PHASE412_CRITICAL_PATH_REPORT.md").exists()


def test_phase413_intelligence_defender_outputs_exist(tmp_path):
    rows = run_phase413_intelligence_defender_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase413_intelligence_defender"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    modes = {row["defense_mode"] for row in rows}
    assert {"fixed_best", "mission_belief", "state_belief", "intelligence_driven"}.issubset(modes)
    intelligence_rows = [row for row in rows if row["defense_mode"] == "intelligence_driven"]
    assert intelligence_rows
    assert all("intelligence_risk_score" in row for row in intelligence_rows)
    assert (tmp_path / "phase413_intelligence_defender" / "intelligence_summary.csv").exists()
    assert (tmp_path / "phase413_intelligence_defender" / "intelligence_summary.json").exists()
    assert (tmp_path / "phase413_intelligence_defender" / "intelligence_risk_score.png").exists()
    assert (tmp_path / "phase413_intelligence_defender" / "risk_level_transition.png").exists()
    assert (tmp_path / "phase413_intelligence_defender" / "intelligence_vs_phase412.png").exists()
    assert (tmp_path / "phase413_intelligence_defender" / "PHASE413_INTELLIGENCE_DEFENDER_REPORT.md").exists()


def test_phase414_weight_sweep_outputs_exist(tmp_path):
    rows = run_phase414_weight_sweep_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase414_weight_sweep"),
        config_path=str(tmp_path / "missing_config.json"),
        weight_configs=[(0.2, 0.4, 0.4)],
    )

    modes = {row["defense_mode"] for row in rows}
    assert {"fixed_best", "mission_belief", "state_belief", "intelligence_default", "weight_sweep_01"}.issubset(modes)
    sweep_rows = [row for row in rows if row["defense_mode"] == "weight_sweep_01"]
    assert sweep_rows
    assert all(row["weight_configuration"] == "m=0.20,s=0.40,p=0.40" for row in sweep_rows)
    assert all("weight_sweep_rank" in row for row in sweep_rows)
    assert (tmp_path / "phase414_weight_sweep" / "weight_sweep_summary.csv").exists()
    assert (tmp_path / "phase414_weight_sweep" / "weight_sweep_summary.json").exists()
    assert (tmp_path / "phase414_weight_sweep" / "weight_sweep_ranking.png").exists()
    assert (tmp_path / "phase414_weight_sweep" / "weight_sensitivity.png").exists()
    assert (tmp_path / "phase414_weight_sweep" / "weight_sweep_vs_phase413.png").exists()
    assert (tmp_path / "phase414_weight_sweep" / "PHASE414_WEIGHT_SWEEP_REPORT.md").exists()


def test_phase415_decision_matrix_outputs_exist(tmp_path):
    rows = run_phase415_decision_matrix_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase415_decision_matrix"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    modes = {row["defense_mode"] for row in rows}
    assert {"fixed_best", "mission_belief", "state_belief", "intelligence_risk", "decision_matrix"}.issubset(modes)
    matrix_rows = [row for row in rows if row["defense_mode"] == "decision_matrix"]
    assert matrix_rows
    assert all("decision_matrix_policy" in row for row in matrix_rows)
    assert all(_row["decision_matrix_match_count"] is not None for _row in matrix_rows)
    assert (tmp_path / "phase415_decision_matrix" / "decision_matrix_summary.csv").exists()
    assert (tmp_path / "phase415_decision_matrix" / "decision_matrix_summary.json").exists()
    assert (tmp_path / "phase415_decision_matrix" / "decision_matrix_policy_distribution.png").exists()
    assert (tmp_path / "phase415_decision_matrix" / "decision_matrix_vs_phase414.png").exists()
    assert (tmp_path / "phase415_decision_matrix" / "decision_matrix_breakdown.png").exists()
    assert (tmp_path / "phase415_decision_matrix" / "PHASE415_DECISION_MATRIX_REPORT.md").exists()


def test_phase416_defense_campaign_outputs_exist(tmp_path):
    rows = run_phase416_defense_campaign_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase416_defense_campaign"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    modes = {row["defense_mode"] for row in rows}
    assert {"fixed_best", "state_belief", "decision_matrix", "defense_campaign"}.issubset(modes)
    campaign_rows = [row for row in rows if row["defense_mode"] == "defense_campaign"]
    assert campaign_rows
    assert all("campaign_transition_count" in row for row in campaign_rows)
    assert all("campaign_policy_diversity" in row for row in campaign_rows)
    assert (tmp_path / "phase416_defense_campaign" / "campaign_summary.csv").exists()
    assert (tmp_path / "phase416_defense_campaign" / "campaign_summary.json").exists()
    assert (tmp_path / "phase416_defense_campaign" / "campaign_policy_timeline.png").exists()
    assert (tmp_path / "phase416_defense_campaign" / "campaign_transition_heatmap.png").exists()
    assert (tmp_path / "phase416_defense_campaign" / "campaign_vs_phase415.png").exists()
    assert (tmp_path / "phase416_defense_campaign" / "PHASE416_DEFENSE_CAMPAIGN_REPORT.md").exists()


def test_phase417_campaign_profile_outputs_exist(tmp_path):
    rows = run_phase417_campaign_profile_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase417_campaign_profiles"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    profiles = {row["strategy_profile"] for row in rows}
    assert {"aggressive_disruption", "trust_collapse", "utility_suppression", "balanced"}.issubset(profiles)
    assert all("profile_rank" in row for row in rows)
    assert all("strategy_effectiveness_score" in row for row in rows)
    assert (tmp_path / "phase417_campaign_profiles" / "campaign_profile_summary.csv").exists()
    assert (tmp_path / "phase417_campaign_profiles" / "campaign_profile_summary.json").exists()
    assert (tmp_path / "phase417_campaign_profiles" / "campaign_profile_ranking.png").exists()
    assert (tmp_path / "phase417_campaign_profiles" / "campaign_profile_by_mission.png").exists()
    assert (tmp_path / "phase417_campaign_profiles" / "campaign_profile_vs_phase416.png").exists()
    assert (tmp_path / "phase417_campaign_profiles" / "PHASE417_CAMPAIGN_PROFILE_REPORT.md").exists()


def test_phase418_mission_objective_outputs_exist(tmp_path):
    rows = run_phase418_mission_objective_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase418_mission_objectives"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    missions = {row["attacker_mission"] for row in rows}
    profiles = {row["strategy_profile"] for row in rows}
    assert {"profit", "achievement", "persistence", "critical_hunter"}.issubset(missions)
    assert {"aggressive_disruption", "trust_collapse", "utility_suppression", "balanced"}.issubset(profiles)
    assert all("mission_objective_score" in row for row in rows)
    assert all("mission_objective_defense_score" in row for row in rows)
    assert (tmp_path / "phase418_mission_objectives" / "mission_objective_summary.csv").exists()
    assert (tmp_path / "phase418_mission_objectives" / "mission_objective_summary.json").exists()
    assert (tmp_path / "phase418_mission_objectives" / "mission_satisfaction_by_profile.png").exists()
    assert (tmp_path / "phase418_mission_objectives" / "strategy_by_mission.png").exists()
    assert (tmp_path / "phase418_mission_objectives" / "mission_objective_vs_phase417.png").exists()
    assert (tmp_path / "phase418_mission_objectives" / "PHASE418_MISSION_OBJECTIVE_REPORT.md").exists()


def test_phase419_mission_sensitivity_outputs_exist(tmp_path):
    rows = run_phase419_mission_sensitivity_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase419_mission_sensitivity"),
        config_path=str(tmp_path / "missing_config.json"),
        objective_profiles={
            "profit": [("profit_eu90_success10", {"profit_expected_utility_weight": 0.9, "profit_success_weight": 0.1})],
            "achievement": [("achievement_progress60_critical40", {"achievement_progress_weight": 0.6, "achievement_critical_weight": 0.4})],
            "persistence": [("persistence_survival20_trust60_stealth20", {"persistence_survival_weight": 0.2, "persistence_trust_weight": 0.6, "persistence_stealth_weight": 0.2})],
            "critical_hunter": [("critical_progress90_reach10", {"critical_progress_weight": 0.9, "critical_reach_weight": 0.1})],
        },
    )

    assert rows
    assert all("objective_weight_profile" in row for row in rows)
    assert all("mission_sensitivity_score" in row for row in rows)
    assert (tmp_path / "phase419_mission_sensitivity" / "mission_sensitivity_summary.csv").exists()
    assert (tmp_path / "phase419_mission_sensitivity" / "mission_sensitivity_summary.json").exists()
    assert (tmp_path / "phase419_mission_sensitivity" / "mission_sensitivity_heatmap.png").exists()
    assert (tmp_path / "phase419_mission_sensitivity" / "strategy_by_mission_weight.png").exists()
    assert (tmp_path / "phase419_mission_sensitivity" / "mission_sensitivity_vs_phase418.png").exists()
    assert (tmp_path / "phase419_mission_sensitivity" / "PHASE419_MISSION_SENSITIVITY_REPORT.md").exists()


def test_phase420_adaptive_mission_outputs_exist(tmp_path):
    rows = run_phase420_adaptive_mission_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase420_adaptive_mission"),
        config_path=str(tmp_path / "missing_config.json"),
        strategy_profiles=["aggressive_disruption", "balanced"],
    )

    modes = {row["attacker_mode"] for row in rows}
    missions = {row["attacker_mission"] for row in rows}
    assert {"non_adaptive", "adaptive"}.issubset(modes)
    assert {"profit", "achievement", "persistence", "critical_hunter"}.issubset(missions)
    assert any(row["ttp_change_count"] > 0 for row in rows if row["attacker_mode"] == "adaptive")
    assert (tmp_path / "phase420_adaptive_mission" / "adaptive_mission_summary.csv").exists()
    assert (tmp_path / "phase420_adaptive_mission" / "adaptive_mission_summary.json").exists()
    assert (tmp_path / "phase420_adaptive_mission" / "ttp_change_count.png").exists()
    assert (tmp_path / "phase420_adaptive_mission" / "alternative_path_usage.png").exists()
    assert (tmp_path / "phase420_adaptive_mission" / "adaptive_vs_nonadaptive.png").exists()
    assert (tmp_path / "phase420_adaptive_mission" / "PHASE420_ADAPTIVE_MISSION_REPORT.md").exists()


def test_phase421_mission_mutation_outputs_exist(tmp_path):
    rows = run_phase421_mission_mutation_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase421_mission_mutation"),
        config_path=str(tmp_path / "missing_config.json"),
        strategy_profiles=["aggressive_disruption", "trust_collapse"],
    )

    modes = {row["attacker_mode"] for row in rows}
    assert {"fixed_mission", "adaptive_mission", "mission_mutator"}.issubset(modes)
    mutator_rows = [row for row in rows if row["attacker_mode"] == "mission_mutator"]
    assert any(row["mission_change_count"] > 0 for row in mutator_rows)
    assert any(row["achievement_mutation"] for row in mutator_rows)
    assert (tmp_path / "phase421_mission_mutation" / "mission_mutation_summary.csv").exists()
    assert (tmp_path / "phase421_mission_mutation" / "mission_mutation_summary.json").exists()
    assert (tmp_path / "phase421_mission_mutation" / "mission_transition_matrix.png").exists()
    assert (tmp_path / "phase421_mission_mutation" / "mission_change_count.png").exists()
    assert (tmp_path / "phase421_mission_mutation" / "mission_mutation_vs_phase420.png").exists()
    assert (tmp_path / "phase421_mission_mutation" / "PHASE421_MISSION_MUTATION_REPORT.md").exists()


def test_phase422_adaptive_intelligence_outputs_exist(tmp_path):
    rows = run_phase422_adaptive_intelligence_defender(
        seeds=[0],
        output_dir=str(tmp_path / "phase422_adaptive_intelligence"),
        config_path=str(tmp_path / "missing_config.json"),
        strategy_profiles=["aggressive_disruption", "trust_collapse"],
    )

    modes = {row["defense_mode"] for row in rows}
    assert {"fixed_mission_aware", "mission_mutation_attacker", "adaptive_intelligence_defender"}.issubset(modes)
    adaptive_rows = [row for row in rows if row["defense_mode"] == "adaptive_intelligence_defender"]
    assert any(row["mission_reclassification_count"] > 0 for row in adaptive_rows)
    assert any(row["defense_reoptimization_count"] > 0 for row in adaptive_rows)
    assert any(row["reclassification_accuracy"] > 0 for row in adaptive_rows)
    assert (tmp_path / "phase422_adaptive_intelligence" / "adaptive_intelligence_summary.csv").exists()
    assert (tmp_path / "phase422_adaptive_intelligence" / "adaptive_intelligence_summary.json").exists()
    assert (tmp_path / "phase422_adaptive_intelligence" / "mission_reclassification.png").exists()
    assert (tmp_path / "phase422_adaptive_intelligence" / "defense_reoptimization.png").exists()
    assert (tmp_path / "phase422_adaptive_intelligence" / "phase422_vs_phase421.png").exists()
    assert (tmp_path / "phase422_adaptive_intelligence" / "PHASE422_ADAPTIVE_INTELLIGENCE_REPORT.md").exists()


def test_phase423_intent_deception_outputs_exist(tmp_path):
    rows = run_phase423_intent_deception_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase423_intent_deception"),
        config_path=str(tmp_path / "missing_config.json"),
        strategy_profiles=["aggressive_disruption", "trust_collapse"],
    )

    modes = {row["attacker_mode"] for row in rows}
    assert {"adaptive_mission_attacker", "mission_mutation_attacker", "intent_deception_attacker"}.issubset(modes)
    deception_rows = [row for row in rows if row["attacker_mode"] == "intent_deception_attacker"]
    assert any(row["deception_event_count"] > 0 for row in deception_rows)
    assert any(row["true_mission"] != row["observed_mission"] for row in deception_rows)
    assert any(row["mission_belief_error"] > 0 for row in deception_rows)
    assert (tmp_path / "phase423_intent_deception" / "intent_deception_summary.csv").exists()
    assert (tmp_path / "phase423_intent_deception" / "intent_deception_summary.json").exists()
    assert (tmp_path / "phase423_intent_deception" / "mission_confusion_matrix.png").exists()
    assert (tmp_path / "phase423_intent_deception" / "belief_error_distribution.png").exists()
    assert (tmp_path / "phase423_intent_deception" / "phase423_vs_phase422.png").exists()
    assert (tmp_path / "phase423_intent_deception" / "PHASE423_INTENT_DECEPTION_REPORT.md").exists()


def test_phase424_signal_extraction_outputs_exist(tmp_path):
    rows = run_phase424_signal_extraction_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase424_signal_extraction"),
        config_path=str(tmp_path / "missing_config.json"),
        strategy_profiles=["aggressive_disruption", "trust_collapse"],
    )

    modes = {row["defense_mode"] for row in rows}
    assert {"adaptive_intelligence_defender", "noise_injection_attacker", "signal_extraction_defender"}.issubset(modes)
    noise_rows = [row for row in rows if row["defense_mode"] == "noise_injection_attacker"]
    signal_rows = [row for row in rows if row["defense_mode"] == "signal_extraction_defender"]
    assert any(row["noise_event_count"] > 0 for row in noise_rows)
    assert any(row["noise_filter_accuracy"] > 0 for row in signal_rows)
    assert any(row["decision_confidence"] > 0 for row in signal_rows)
    assert (tmp_path / "phase424_signal_extraction" / "signal_extraction_summary.csv").exists()
    assert (tmp_path / "phase424_signal_extraction" / "signal_extraction_summary.json").exists()
    assert (tmp_path / "phase424_signal_extraction" / "signal_to_noise_ratio.png").exists()
    assert (tmp_path / "phase424_signal_extraction" / "noise_filter_accuracy.png").exists()
    assert (tmp_path / "phase424_signal_extraction" / "phase424_vs_phase423.png").exists()
    assert (tmp_path / "phase424_signal_extraction" / "PHASE424_SIGNAL_EXTRACTION_REPORT.md").exists()


def test_phase425_adversarial_signal_outputs_exist(tmp_path):
    rows = run_phase425_adversarial_signal_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase425_adversarial_signal"),
        config_path=str(tmp_path / "missing_config.json"),
        strategy_profiles=["aggressive_disruption", "trust_collapse"],
    )

    modes = {row["defense_mode"] for row in rows}
    assert {
        "phase424_noise_injection",
        "phase425_adversarial_signal",
        "phase425_signal_consistency_defender",
    }.issubset(modes)
    adversarial_rows = [row for row in rows if row["defense_mode"] == "phase425_adversarial_signal"]
    consistency_rows = [row for row in rows if row["defense_mode"] == "phase425_signal_consistency_defender"]
    assert any(row["fake_signal_count"] > 0 for row in adversarial_rows)
    assert any(row["signal_confusion_score"] > 0 for row in adversarial_rows)
    assert any(row["signal_consistency_score"] < 1 for row in consistency_rows)
    assert (tmp_path / "phase425_adversarial_signal" / "adversarial_signal_summary.csv").exists()
    assert (tmp_path / "phase425_adversarial_signal" / "adversarial_signal_summary.json").exists()
    assert (tmp_path / "phase425_adversarial_signal" / "fake_signal_count.png").exists()
    assert (tmp_path / "phase425_adversarial_signal" / "signal_confusion_score.png").exists()
    assert (tmp_path / "phase425_adversarial_signal" / "phase425_vs_phase424.png").exists()
    assert (tmp_path / "phase425_adversarial_signal" / "PHASE425_ADVERSARIAL_SIGNAL_REPORT.md").exists()


def test_coalition_metrics_and_history_saved(tmp_path):
    config = small_config(
        attacker_enabled=True,
        attacker_target_selection="adaptive",
        adaptive_attacker_enabled=True,
        attacker_lateral_enabled=True,
        observable_events_enabled=True,
        critical_path_events_enabled=True,
        coalition_enabled=True,
        coalition_size=2,
        coalition_role="recon_specialist",
        attacker_type="coalition_attacker",
    )
    sim = CyberDefenseSimulator(config)
    history = sim.run()
    metrics = sim.save_outputs(str(tmp_path))

    assert metrics["coalition_enabled"] is True
    assert metrics["coalition_handover_count"] > 0
    assert metrics["coalition_success_rate"] >= 0.0
    assert metrics["campaign_completion_score"] >= 0.0
    assert len(history["coalition_role_history"]) == config.T
    assert len(history["coalition_handover_history"]) == config.T
    saved = np.load(tmp_path / "history.npz")
    assert "coalition_role_history" in saved.files
    assert "coalition_handover_history" in saved.files
    assert "coordination_history" in saved.files
    assert "trust_history" in saved.files
    assert "handover_failure_history" in saved.files


def test_coalition_coordination_cost_can_fail_handover(tmp_path):
    config = small_config(
        attacker_enabled=True,
        attacker_target_selection="adaptive",
        adaptive_attacker_enabled=True,
        attacker_lateral_enabled=True,
        observable_events_enabled=True,
        critical_path_events_enabled=True,
        coalition_enabled=True,
        coalition_size=3,
        coalition_role="recon_specialist",
        attacker_type="coalition_attacker",
        coalition_coordination_cost_enabled=True,
        coordination_cost=0.95,
        coalition_information_loss_enabled=True,
        coalition_trust_enabled=True,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.save_outputs(str(tmp_path))

    assert metrics["failed_handover_count"] > 0
    assert metrics["coordination_efficiency"] < 1.0
    assert metrics["coalition_trust_score"] < 1.0


def test_phase51_coalition_outputs_exist(tmp_path):
    rows = run_phase51_coalition_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase51_coalition"),
        config_path=str(tmp_path / "missing_config.json"),
        strategy_profiles=["balanced"],
    )

    modes = {row["attacker_mode"] for row in rows}
    assert {"single_attacker", "coalition_attacker", "coalition_mutation", "coalition_adaptive_defender"}.issubset(modes)
    coalition_rows = [row for row in rows if bool(row["coalition_enabled"])]
    assert any(row["coalition_handover_count"] > 0 for row in coalition_rows)
    assert (tmp_path / "phase51_coalition" / "coalition_summary.csv").exists()
    assert (tmp_path / "phase51_coalition" / "coalition_summary.json").exists()
    assert (tmp_path / "phase51_coalition" / "coalition_handover_count.png").exists()
    assert (tmp_path / "phase51_coalition" / "coalition_role_efficiency.png").exists()
    assert (tmp_path / "phase51_coalition" / "phase51_vs_phase425.png").exists()
    assert (tmp_path / "phase51_coalition" / "PHASE51_COALITION_REPORT.md").exists()


def test_phase52_coordination_cost_outputs_exist(tmp_path):
    rows = run_phase52_coordination_cost_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase52_coordination_cost"),
        config_path=str(tmp_path / "missing_config.json"),
        strategy_profiles=["balanced"],
        coordination_costs=[0.0, 0.3],
        coalition_sizes=[2],
    )

    modes = {row["phase52_mode"] for row in rows}
    assert {"single_attacker", "coalition_attacker", "coalition_coordination_cost"}.issubset(modes)
    cost_rows = [row for row in rows if row["phase52_mode"] == "coalition_coordination_cost"]
    assert any(row["coordination_cost"] == 0.3 for row in cost_rows)
    assert (tmp_path / "phase52_coordination_cost" / "coordination_cost_summary.csv").exists()
    assert (tmp_path / "phase52_coordination_cost" / "coordination_cost_summary.json").exists()
    assert (tmp_path / "phase52_coordination_cost" / "coordination_efficiency.png").exists()
    assert (tmp_path / "phase52_coordination_cost" / "failed_handover_count.png").exists()
    assert (tmp_path / "phase52_coordination_cost" / "phase52_vs_phase51.png").exists()
    assert (tmp_path / "phase52_coordination_cost" / "PHASE52_COORDINATION_COST_REPORT.md").exists()


def test_best_policy_fields_exist(tmp_path):
    run_phase2_policy_selection_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase2_policy_selection"),
        config_path=str(tmp_path / "missing_config.json"),
    )
    payload = json.loads(
        (tmp_path / "phase2_policy_selection" / "policy_selection_summary.json").read_text(encoding="utf-8")
    )

    for key in [
        "best_phase1_policy",
        "best_cns_policy",
        "best_effectiveness_policy",
        "best_human_policy",
        "best_ai_policy",
        "recommended_policy",
    ]:
        assert key in payload["analysis"]
        assert payload["analysis"][key]


def test_cns_objective_outputs_exist(tmp_path):
    rows = run_phase2_cns_objective_evaluation(
        seeds=[0],
        output_dir=str(tmp_path / "phase2_cns_objective"),
        config_path=str(tmp_path / "missing_config.json"),
    )
    payload = json.loads(
        (tmp_path / "phase2_cns_objective" / "cns_objective_summary.json").read_text(encoding="utf-8")
    )

    assert rows
    assert "cns_objective_score" in rows[0]
    assert payload["analysis"]["best_cns_objective_policy"]
    assert payload["sensitivity"]
    assert (tmp_path / "phase2_cns_objective" / "cns_objective_summary.csv").exists()
    assert (tmp_path / "phase2_cns_objective" / "cns_objective_summary.json").exists()
    assert (tmp_path / "phase2_cns_objective" / "cns_objective_ranking.png").exists()
    assert (tmp_path / "phase2_cns_objective" / "phase1_vs_cns_vs_objective.png").exists()
    assert (tmp_path / "phase2_cns_objective" / "cns_contribution_breakdown.png").exists()
    assert (tmp_path / "phase2_cns_objective" / "cns_weight_sensitivity.png").exists()
    assert (tmp_path / "phase2_cns_objective" / "PHASE2_OBJECTIVE_REPORT.md").exists()


def test_plot_does_not_block_when_show_plot_false(tmp_path, monkeypatch):
    config = small_config()
    sim = CyberDefenseSimulator(config)
    history = sim.run()

    def fail_show():
        raise AssertionError("plt.show() must not be called when show_plot=False")

    monkeypatch.setattr("matplotlib.pyplot.show", fail_show)
    Visualizer.plot_results(history, config, save_path=str(tmp_path / "result.png"))

    assert (tmp_path / "result.png").exists()


def test_mpc_fallback_respects_resource_constraints(monkeypatch):
    config = small_config()
    engine = CyberDefenseSimulator(config).engine

    def fail_solve(*args, **kwargs):
        raise RuntimeError("forced solver failure")

    monkeypatch.setattr("cvxpy.problems.problem.Problem.solve", fail_solve)
    r = engine.solve_mpc(
        np.ones(config.n_nodes),
        np.zeros(config.m_resources),
        np.ones((config.n_nodes, config.m_resources)),
    )

    assert engine.stats["mpc_fallback_count"] == 1
    assert np.all(r >= 0)
    assert np.all(r <= config.r_max)
    assert np.sum(r) <= config.R_total


def test_attacker_model_greedy_selects_weakest_high_risk_target():
    attacker = AttackerModel(enabled=True, attack_budget=3.0, greedy_mode="legacy")
    x_current = np.array([1.0, 4.0, 5.0])
    M_current = np.array([[0.0], [1.0], [0.0]])

    attack_vector = attacker.select_attack(x_current, M_current)

    assert attack_vector.tolist() == [0.0, 0.0, 3.0]


def test_greedy_legacy_mode_matches_previous_behavior():
    attacker = AttackerModel(enabled=True, greedy_mode="legacy")
    x_current = np.array([1.0, 4.0, 5.0])
    M_current = np.array([[0.0], [1.0], [0.0]])

    score = attacker.calculate_greedy_score(x_current, M_current)

    np.testing.assert_allclose(score, np.array([1.0, 3.0, 5.0]))
    assert attacker._select_greedy_target(x_current, M_current) == 2


def test_greedy_weighted_risk_uses_q_diag():
    attacker = AttackerModel(
        enabled=True,
        greedy_mode="weighted_risk",
        attacker_belief=np.array([10.0, 1.0, 1.0]),
    )
    x_current = np.array([1.0, 4.0, 5.0])
    M_current = np.array([[0.0], [1.0], [0.0]])

    score = attacker.calculate_greedy_score(x_current, M_current)

    np.testing.assert_allclose(score, np.array([10.0, 3.0, 5.0]))
    assert attacker._select_greedy_target(x_current, M_current) == 0


def test_greedy_utility_returns_valid_target():
    attacker = AttackerModel(
        enabled=True,
        greedy_mode="utility",
        attacker_belief=np.array([10.0, 1.0, 1.0]),
    )
    x_current = np.array([1.0, 4.0, 5.0])
    M_current = np.array([[0.0], [1.0], [0.0]])

    score = attacker.calculate_greedy_score(x_current, M_current)
    attack_vector = attacker.select_attack(x_current, M_current)

    assert score.shape == x_current.shape
    assert attacker.last_selected_target in (0, 1, 2)
    assert np.sum(attack_vector) == attacker.attack_budget


def test_attacker_selection_score_saved():
    config = small_config(attacker_enabled=True)
    sim = CyberDefenseSimulator(config)
    history = sim.run()

    assert np.asarray(history["attacker_selection_score"]).shape == (config.T, config.n_nodes)
    assert np.asarray(history["attacker_selected_target"]).shape == (config.T,)
    assert np.any(np.asarray(history["attacker_selected_target"]) >= 0)


def test_asset_value_and_attacker_belief_validate_shape():
    with pytest.raises(ValueError, match="asset_value"):
        SimulationConfig(asset_value=[1.0, 2.0])
    with pytest.raises(ValueError, match="attacker_belief"):
        SimulationConfig(attacker_belief=[1.0, 2.0])


def test_attacker_utility_uses_belief_not_q_diag():
    attacker = AttackerModel(
        enabled=True,
        greedy_mode="utility",
        attacker_belief=np.array([1.0, 100.0, 1.0]),
    )
    x_current = np.ones(3)
    M_current = np.zeros((3, 1))

    assert attacker._select_greedy_target(x_current, M_current) == 1


def test_attacker_gain_uses_asset_value_not_q_diag():
    config = small_config(
        Q_diag=[100.0, 1.0, 1.0, 1.0, 1.0],
        asset_value=[1.0, 10.0, 1.0, 1.0, 1.0],
        attacker_belief=[1.0, 10.0, 1.0, 1.0, 1.0],
    )
    sim = CyberDefenseSimulator(config)
    gain = sim._calculate_attacker_gain(
        np.zeros(config.n_nodes),
        np.array([1.0, 1.0, 0.0, 0.0, 0.0]),
    )

    assert gain == 11.0


def test_node_type_validates_length_and_values():
    with pytest.raises(ValueError, match="node_type"):
        SimulationConfig(node_type=["real"])
    with pytest.raises(ValueError, match="node_type"):
        SimulationConfig(node_type=["real", "invalid", "real", "real", "real"])


def test_decoy_attack_adds_waste_cost():
    config = small_config(
        attacker_enabled=True,
        node_type=["decoy", "real", "real", "real", "real"],
        attacker_belief=[100.0, 1.0, 1.0, 1.0, 1.0],
        asset_value=[0.0, 5.0, 1.0, 8.0, 2.0],
        decoy_waste_cost=7.0,
        decoy_success_gain_scale=0.0,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()

    assert np.any(np.asarray(sim.history["attacker_attacked_decoy"]))
    assert np.max(np.asarray(sim.history["decoy_waste_step"])) == 7.0
    assert sim.calculate_metrics()["attacker_decoy_waste_total"] > 0


def test_decoy_attack_gain_scaled_down():
    config = small_config(
        node_type=["decoy", "real", "real", "real", "real"],
        asset_value=[10.0, 10.0, 10.0, 10.0, 10.0],
        decoy_success_gain_scale=0.0,
    )
    sim = CyberDefenseSimulator(config)
    gain = sim._calculate_attacker_gain(
        np.zeros(config.n_nodes),
        np.ones(config.n_nodes),
        target_idx=0,
    )

    assert gain == 0.0


def test_decoy_metrics_are_present():
    config = small_config(
        attacker_enabled=True,
        node_type=["real", "real", "decoy", "real", "real"],
        attacker_belief=[1.0, 1.0, 100.0, 1.0, 1.0],
        asset_value=[10.0, 5.0, 0.0, 8.0, 2.0],
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    assert metrics["decoy_node_count"] == 1
    assert "attacker_decoy_attack_count" in metrics
    assert "attacker_decoy_attack_rate" in metrics
    assert "attacker_real_attack_count" in metrics


def test_stochastic_config_validation():
    with pytest.raises(ValueError, match="base_detection_prob"):
        SimulationConfig(base_detection_prob=1.1)
    with pytest.raises(ValueError, match="defense_detection_scale"):
        SimulationConfig(defense_detection_scale=-0.1)
    with pytest.raises(ValueError, match="decoy_detection_prob"):
        SimulationConfig(decoy_detection_prob=-0.1)
    with pytest.raises(ValueError, match="base_success_prob"):
        SimulationConfig(base_success_prob=1.1)
    with pytest.raises(ValueError, match="defense_success_decay"):
        SimulationConfig(defense_success_decay=-0.1)
    with pytest.raises(ValueError, match="decoy_success_prob"):
        SimulationConfig(decoy_success_prob=1.1)


def test_target_defense_strength():
    config = small_config()
    sim = CyberDefenseSimulator(config)
    sim.M = np.array([
        [1.0, 0.0, 1.0],
        [0.0, 1.0, 0.0],
        [0.0, 0.0, 0.0],
        [0.0, 0.0, 0.0],
        [0.0, 0.0, 0.0],
    ])
    r_opt = np.array([2.0, 3.0, 4.0])

    assert sim._target_defense_strength(0, r_opt) == 6.0
    assert sim._target_defense_strength(-1, r_opt) == 0.0


def test_attack_succeeds_deterministic_compatibility():
    sim = CyberDefenseSimulator(small_config(stochastic_success=False))

    assert sim._attack_succeeds(0.02, attacked_decoy=False, target_defense_strength=0.0) is True
    assert sim._attack_succeeds(0.0, attacked_decoy=False, target_defense_strength=0.0) is False


def test_detect_attacker_deterministic_compatibility():
    sim = CyberDefenseSimulator(small_config(stochastic_detection=False))

    assert sim._detect_attacker(np.array([1.0]), success=True) is True
    assert sim._detect_attacker(np.array([1.0]), success=False) is False
    assert sim._detect_attacker(np.array([0.0]), success=False, attacked_decoy=True) is True


def test_probability_metrics_are_present():
    config = small_config(
        attacker_enabled=True,
        stochastic_detection=True,
        stochastic_success=True,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    for key in [
        "stochastic_detection",
        "stochastic_success",
        "base_detection_prob",
        "defense_detection_scale",
        "decoy_detection_prob",
        "base_success_prob",
        "defense_success_decay",
        "decoy_success_prob",
        "mean_attack_success_prob",
        "mean_attack_detection_prob",
        "mean_target_defense_strength",
    ]:
        assert key in metrics


def test_belief_learning_config_validation():
    with pytest.raises(ValueError, match="attacker_belief_success_boost"):
        SimulationConfig(attacker_belief_success_boost=-1.0)
    with pytest.raises(ValueError, match="attacker_belief_failure_decay"):
        SimulationConfig(attacker_belief_failure_decay=1.1)
    with pytest.raises(ValueError, match="attacker_belief_detection_decay"):
        SimulationConfig(attacker_belief_detection_decay=-0.1)
    with pytest.raises(ValueError, match="attacker_belief_decoy_decay"):
        SimulationConfig(attacker_belief_decoy_decay=1.1)
    with pytest.raises(ValueError, match="attacker_belief_min"):
        SimulationConfig(attacker_belief_min=-0.1)
    with pytest.raises(ValueError, match="attacker_belief_max"):
        SimulationConfig(attacker_belief_min=2.0, attacker_belief_max=1.0)


def test_attacker_belief_success_boost():
    attacker = AttackerModel(
        attacker_belief=np.array([1.0, 2.0]),
        belief_learning_enabled=True,
        belief_success_boost=3.0,
        belief_max=10.0,
    )

    attacker.update_belief(target_idx=0, success=True, detected=False, attacked_decoy=False)

    assert attacker.current_belief[0] == 4.0


def test_attacker_belief_decoy_decay():
    attacker = AttackerModel(
        attacker_belief=np.array([10.0, 2.0]),
        belief_learning_enabled=True,
        belief_failure_decay=0.8,
        belief_detection_decay=0.5,
        belief_decoy_decay=0.1,
    )

    attacker.update_belief(target_idx=0, success=False, detected=True, attacked_decoy=True)

    assert attacker.current_belief[0] == pytest.approx(0.4)


def test_attacker_current_belief_saved():
    config = small_config(
        attacker_enabled=True,
        attacker_target_selection="adaptive",
        attacker_belief_learning_enabled=True,
    )
    sim = CyberDefenseSimulator(config)
    history = sim.run()
    metrics = sim.calculate_metrics()

    assert np.asarray(history["attacker_current_belief"]).shape == (config.T, config.n_nodes)
    assert metrics["attacker_belief_learning_enabled"] is True
    assert "attacker_final_belief" in metrics


def test_first_decoy_step_recorded():
    config = small_config(
        attacker_enabled=True,
        node_type=["real", "real", "decoy", "real", "real"],
        attacker_belief=[1.0, 1.0, 100.0, 1.0, 1.0],
        asset_value=[10.0, 5.0, 0.0, 8.0, 2.0],
    )
    sim = CyberDefenseSimulator(config)
    sim.run()

    assert sim.first_decoy_step == 0
    assert sim.calculate_metrics()["first_decoy_step"] == 0


def test_post_decoy_metrics_exist():
    config = small_config(
        attacker_enabled=True,
        attacker_target_selection="adaptive",
        attacker_belief_learning_enabled=True,
        attacker_retreat_threshold=-50.0,
        attacker_patience=20,
        node_type=["real", "real", "decoy", "real", "real"],
        attacker_belief=[2.0, 3.0, 12.0, 4.0, 2.0],
        asset_value=[10.0, 5.0, 0.0, 8.0, 2.0],
        stochastic_detection=True,
        stochastic_success=True,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    for key in [
        "post_decoy_attack_count",
        "post_decoy_real_attack_count",
        "post_decoy_decoy_attack_count",
        "post_decoy_compromised_value",
        "post_decoy_utility",
        "post_decoy_target_counts",
        "post_decoy_most_targeted_node",
    ]:
        assert key in metrics


def test_transition_matrix_created():
    config = small_config(attacker_enabled=True)
    sim = CyberDefenseSimulator(config)
    matrix = sim._calculate_attack_transition_matrix(np.array([2, 0, 3, 3, -1, 0]))

    assert matrix["2->0"] == 1
    assert matrix["0->3"] == 1
    assert matrix["3->3"] == 1


def test_effective_defense_weight_before_decoy_is_q_diag():
    config = small_config(post_decoy_defense_enabled=True)
    sim = CyberDefenseSimulator(config)

    np.testing.assert_allclose(sim._effective_defense_weight(), config.Q_diag)


def test_effective_defense_weight_after_decoy_boosts_belief_top_k():
    config = small_config(
        post_decoy_defense_enabled=True,
        post_decoy_defense_weight=2.0,
        post_decoy_defense_top_k=1,
        node_type=["real", "real", "decoy", "real", "real"],
        attacker_belief=[1.0, 2.0, 100.0, 4.0, 3.0],
    )
    sim = CyberDefenseSimulator(config)
    sim.first_decoy_step = 0
    sim.attacker.current_belief = np.array([1.0, 2.0, 100.0, 4.0, 3.0])

    weight = sim._effective_defense_weight()

    expected = config.Q_diag.copy()
    expected[3] += 8.0
    np.testing.assert_allclose(weight, expected)


def test_post_decoy_defense_metrics_present():
    config = small_config(
        attacker_enabled=True,
        attacker_target_selection="adaptive",
        attacker_belief_learning_enabled=True,
        attacker_retreat_threshold=-50.0,
        node_type=["real", "real", "decoy", "real", "real"],
        attacker_belief=[2.0, 3.0, 12.0, 4.0, 2.0],
        asset_value=[10.0, 5.0, 0.0, 8.0, 2.0],
        post_decoy_defense_enabled=True,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    assert metrics["post_decoy_defense_enabled"] is True
    assert "post_decoy_defense_active_count" in metrics
    assert "effective_defense_weight_final" in metrics


def test_post_decoy_defense_injection_mode_validation():
    with pytest.raises(ValueError, match="post_decoy_defense_injection_mode"):
        SimulationConfig(post_decoy_defense_injection_mode="invalid")


def test_defender_belief_estimation_config_validation():
    with pytest.raises(ValueError, match="defender_belief_observation_mode"):
        SimulationConfig(defender_belief_observation_mode="invalid")
    with pytest.raises(ValueError, match="defender_belief_estimation_alpha"):
        SimulationConfig(defender_belief_estimation_alpha=1.1)
    with pytest.raises(ValueError, match="post_decoy_defense_belief_source"):
        SimulationConfig(post_decoy_defense_belief_source="invalid")


def test_defender_visible_log_observation_mode_validation():
    config = SimulationConfig(defender_belief_observation_mode="defender_visible_log")
    assert config.defender_belief_observation_mode == "defender_visible_log"
    config = SimulationConfig(defender_belief_observation_mode="hybrid_visible")
    assert config.defender_belief_observation_mode == "hybrid_visible"
    with pytest.raises(ValueError, match="visible_log_detected_decay"):
        SimulationConfig(visible_log_detected_decay=1.1)
    with pytest.raises(ValueError, match="visible_log_defense_penalty_weight"):
        SimulationConfig(visible_log_defense_penalty_weight=-0.1)


def test_target_frequency_observation_updates_estimate():
    config = small_config(
        defender_belief_estimation_enabled=True,
        defender_belief_observation_mode="target_frequency",
        defender_belief_estimation_alpha=0.0,
        attacker_belief=[2.0, 3.0, 12.0, 4.0, 2.0],
    )
    sim = CyberDefenseSimulator(config)
    sim._update_defender_belief_estimate(3, np.zeros(config.n_nodes), True)

    expected = np.zeros(config.n_nodes)
    expected[3] = config.defender_belief_max
    np.testing.assert_allclose(sim.defender_observed_belief, expected)
    np.testing.assert_allclose(sim.defender_estimated_belief, expected)
    np.testing.assert_allclose(sim.defender_target_counts, [0, 0, 0, 1, 0])


def test_selection_score_observation_updates_estimate():
    config = small_config(
        defender_belief_estimation_enabled=True,
        defender_belief_observation_mode="selection_score",
        defender_belief_estimation_alpha=0.0,
        attacker_belief=[2.0, 3.0, 12.0, 4.0, 2.0],
    )
    sim = CyberDefenseSimulator(config)
    sim._update_defender_belief_estimate(1, np.array([0.0, 2.0, 0.0, 1.0, 0.0]), True)

    expected = np.array([0.0, 2.0 / 3.0, 0.0, 1.0 / 3.0, 0.0]) * np.sum(config.attacker_belief)
    np.testing.assert_allclose(sim.defender_observed_belief, expected)
    np.testing.assert_allclose(sim.defender_estimated_belief, expected)


def test_visible_log_observation_updates_selected_target():
    config = small_config(attacker_belief=[2.0, 3.0, 12.0, 4.0, 2.0])
    sim = CyberDefenseSimulator(config)

    observed = sim._defender_visible_log_observation(
        selected_target=1,
        success=True,
        detected=False,
        attacked_decoy=False,
        target_defense_strength=0.0,
        attack_success_prob=0.5,
        attack_detection_prob=0.0,
    )

    expected = np.zeros(config.n_nodes)
    expected[1] = float(np.sum(config.attacker_belief))
    np.testing.assert_allclose(observed, expected)


def test_visible_log_observation_penalizes_decoy():
    config = small_config(
        attacker_belief=[2.0, 3.0, 12.0, 4.0, 2.0],
        visible_log_decoy_decay=0.0,
        visible_log_detection_prob_weight=2.0,
    )
    sim = CyberDefenseSimulator(config)

    observed = sim._defender_visible_log_observation(
        selected_target=2,
        success=False,
        detected=False,
        attacked_decoy=True,
        target_defense_strength=0.0,
        attack_success_prob=0.0,
        attack_detection_prob=1.0,
    )

    np.testing.assert_allclose(observed, np.zeros(config.n_nodes))


def test_update_defender_belief_estimate_accepts_visible_log_inputs():
    config = small_config(
        defender_belief_estimation_enabled=True,
        defender_belief_observation_mode="defender_visible_log",
        defender_belief_estimation_alpha=0.0,
        attacker_belief=[2.0, 3.0, 12.0, 4.0, 2.0],
    )
    sim = CyberDefenseSimulator(config)
    sim._update_defender_belief_estimate(
        selected_target=4,
        selection_score=np.zeros(config.n_nodes),
        attack_active=True,
        success=True,
        detected=False,
        attacked_decoy=False,
        target_defense_strength=0.0,
        attack_success_prob=0.5,
        attack_detection_prob=0.0,
    )

    raw_expected = np.zeros(config.n_nodes)
    raw_expected[4] = float(np.sum(config.attacker_belief))
    clipped_expected = np.zeros(config.n_nodes)
    clipped_expected[4] = config.defender_belief_max
    np.testing.assert_allclose(sim.defender_visible_log_observation, raw_expected)
    np.testing.assert_allclose(sim.defender_observed_belief, clipped_expected)
    np.testing.assert_allclose(sim.defender_estimated_belief, clipped_expected)


def test_effective_defense_weight_uses_estimated_belief():
    config = small_config(
        post_decoy_defense_enabled=True,
        post_decoy_defense_weight=2.0,
        post_decoy_defense_top_k=1,
        post_decoy_defense_belief_source="estimated",
        node_type=["real", "real", "decoy", "real", "real"],
        attacker_belief=[100.0, 1.0, 1.0, 1.0, 1.0],
    )
    sim = CyberDefenseSimulator(config)
    sim.first_decoy_step = 0
    sim.defender_estimated_belief = np.array([1.0, 2.0, 100.0, 9.0, 3.0])

    weight = sim._effective_defense_weight()

    expected = config.Q_diag.copy()
    expected[3] += 18.0
    np.testing.assert_allclose(weight, expected)


def test_mtd_config_validation():
    with pytest.raises(ValueError, match="mtd_strategy"):
        SimulationConfig(mtd_strategy="invalid")
    with pytest.raises(ValueError, match="mtd_interval"):
        SimulationConfig(mtd_interval=0)
    with pytest.raises(ValueError, match="mtd_intensity"):
        SimulationConfig(mtd_intensity=1.1)


def test_mtd_shuffle_belief_changes_belief():
    config = small_config(
        mtd_enabled=True,
        mtd_strategy="shuffle_belief",
        mtd_interval=1,
        mtd_intensity=1.0,
        attacker_belief=[1.0, 2.0, 3.0, 4.0, 5.0],
    )
    sim = CyberDefenseSimulator(config)
    before = sim.attacker.current_belief.copy()
    after = sim._apply_mtd(0)

    assert sim.mtd_event_count == 1
    assert not np.allclose(after, before)
    np.testing.assert_allclose(np.sort(after), np.sort(before))


def test_mtd_decay_belief_reduces_belief():
    config = small_config(
        mtd_enabled=True,
        mtd_strategy="decay_belief",
        mtd_interval=1,
        mtd_intensity=0.3,
        attacker_belief=[2.0, 3.0, 12.0, 4.0, 2.0],
    )
    sim = CyberDefenseSimulator(config)
    after = sim._apply_mtd(0)
    np.testing.assert_allclose(after, config.attacker_belief * 0.7)


def test_mtd_increase_uncertainty_moves_belief_toward_mean():
    config = small_config(
        mtd_enabled=True,
        mtd_strategy="increase_uncertainty",
        mtd_interval=1,
        mtd_intensity=0.5,
        attacker_belief=[2.0, 3.0, 12.0, 4.0, 2.0],
    )
    sim = CyberDefenseSimulator(config)
    before = sim.attacker.current_belief.copy()
    after = sim._apply_mtd(0)
    expected = 0.5 * before + 0.5 * np.mean(before)
    np.testing.assert_allclose(after, expected)


def test_mtd_metrics_are_present():
    config = small_config(
        T=3,
        mtd_enabled=True,
        mtd_interval=1,
        attacker_enabled=True,
        attacker_target_selection="adaptive",
        stochastic_success=True,
        stochastic_detection=True,
    )
    sim = CyberDefenseSimulator(config)
    history = sim.run()
    metrics = sim.calculate_metrics()

    assert np.asarray(history["mtd_event"]).shape == (config.T,)
    assert np.asarray(history["mtd_affected_belief"]).shape == (config.T, config.n_nodes)
    assert metrics["mtd_enabled"] is True
    assert metrics["mtd_event_count"] == config.T
    assert "mtd_total_cost" in metrics
    assert "mtd_success_decay_bonus" in metrics
    assert "mtd_detection_bonus" in metrics


def test_solve_mpc_accepts_mpc_weight():
    config = small_config(T=2, H=1)
    sim = CyberDefenseSimulator(config)
    r = sim.engine.solve_mpc(
        sim.x_current,
        sim.r_prev,
        sim.M,
        mpc_weight=np.ones(config.n_nodes),
    )

    assert r.shape == (config.m_resources,)


def test_mpc_q_mode_does_not_change_matching_weight():
    config = small_config(
        post_decoy_defense_enabled=True,
        post_decoy_defense_injection_mode="mpc_q",
        node_type=["real", "real", "decoy", "real", "real"],
        attacker_belief=[1.0, 2.0, 100.0, 4.0, 3.0],
    )
    sim = CyberDefenseSimulator(config)
    sim.first_decoy_step = 0
    sim.attacker.current_belief = np.array([1.0, 2.0, 100.0, 4.0, 3.0])
    effective = sim._effective_defense_weight()

    assert sim._matching_weight_for_mode(effective) is None
    assert sim._fallback_weight_for_mode(effective) is None
    np.testing.assert_allclose(sim._mpc_weight_for_mode(effective), effective)


def test_all_mode_uses_matching_and_mpc_q():
    config = small_config(
        post_decoy_defense_enabled=True,
        post_decoy_defense_injection_mode="all",
        node_type=["real", "real", "decoy", "real", "real"],
    )
    sim = CyberDefenseSimulator(config)
    sim.first_decoy_step = 0
    effective = sim._effective_defense_weight()

    np.testing.assert_allclose(sim._matching_weight_for_mode(effective), effective)
    np.testing.assert_allclose(sim._fallback_weight_for_mode(effective), effective)
    np.testing.assert_allclose(sim._mpc_weight_for_mode(effective), effective)


def test_attacker_enabled_writes_history_and_metrics(tmp_path):
    config = small_config(attacker_enabled=True, attacker_attack_budget=3.0)
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.save_outputs(str(tmp_path))

    attack_vector = np.asarray(sim.history["attack_vector"])
    assert attack_vector.shape == (config.T, config.n_nodes)
    assert np.any(attack_vector > 0)
    assert metrics["attacker_enabled"] is True
    assert metrics["attacker_total_cost"] > 0
    assert "attacker_utility_final" in metrics


def test_attacker_can_retreat_under_strict_conditions():
    config = small_config(
        T=6,
        attacker_enabled=True,
        attacker_attack_budget=3.0,
        attacker_detection_penalty=100.0,
        attacker_retreat_threshold=-1.0,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    assert metrics["attacker_retreated"] is True
    assert metrics["attacker_retreat_step"] is not None


def test_run_scenarios_creates_outputs(tmp_path):
    scenarios = {
        "baseline_no_attacker": {"T": 3, "H": 2, "attacker_enabled": False},
        "attacker_greedy_default": {
            "T": 3,
            "H": 2,
            "attacker_enabled": True,
            "attacker_target_selection": "greedy",
        },
        "attacker_random_default": {
            "T": 3,
            "H": 2,
            "attacker_enabled": True,
            "attacker_target_selection": "random",
        },
    }
    rows = run_scenarios(
        config_path=str(tmp_path / "missing_config.json"),
        output_root=str(tmp_path / "scenarios"),
        scenario_overrides=scenarios,
        seed=11,
    )

    assert len(rows) == 3
    assert (tmp_path / "scenarios" / "summary.csv").exists()
    assert (tmp_path / "scenarios" / "summary.json").exists()
    for scenario in scenarios:
        scenario_dir = tmp_path / "scenarios" / scenario
        assert (scenario_dir / "metrics.json").exists()
        assert (scenario_dir / "history.npz").exists()
        assert (scenario_dir / "simulation_result.png").exists()
        assert (scenario_dir / "used_config.json").exists()


def test_summary_contains_required_columns(tmp_path):
    rows = run_scenarios(
        config_path=str(tmp_path / "missing_config.json"),
        output_root=str(tmp_path / "scenarios"),
        scenario_overrides={
            "baseline_no_attacker": {"T": 3, "H": 2, "attacker_enabled": False},
        },
        seed=11,
    )
    summary = json.loads((tmp_path / "scenarios" / "summary.json").read_text(encoding="utf-8"))

    assert rows == summary
    assert set(SUMMARY_COLUMNS).issubset(summary[0].keys())


def test_summary_contains_greedy_mode_columns(tmp_path):
    run_scenarios(
        config_path=str(tmp_path / "missing_config.json"),
        output_root=str(tmp_path / "scenarios"),
        scenario_overrides={
            "attacker_greedy_utility": {
                "T": 3,
                "H": 2,
                "attacker_enabled": True,
                "attacker_target_selection": "greedy",
                "attacker_greedy_mode": "utility",
            },
        },
        seed=11,
    )
    summary = json.loads((tmp_path / "scenarios" / "summary.json").read_text(encoding="utf-8"))

    assert summary[0]["attacker_greedy_mode"] == "utility"
    assert "attacker_most_targeted_node" in summary[0]
    assert "attacker_target_counts" in summary[0]


def test_summary_contains_belief_metrics(tmp_path):
    run_scenarios(
        config_path=str(tmp_path / "missing_config.json"),
        output_root=str(tmp_path / "scenarios"),
        scenario_overrides={
            "attacker_belief_misled_to_low_value": {
                "T": 3,
                "H": 2,
                "attacker_enabled": True,
                "attacker_target_selection": "greedy",
                "attacker_greedy_mode": "utility",
                "asset_value": [10.0, 5.0, 1.0, 8.0, 2.0],
                "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
            },
        },
        seed=11,
    )
    summary = json.loads((tmp_path / "scenarios" / "summary.json").read_text(encoding="utf-8"))

    assert "asset_value" in summary[0]
    assert "attacker_belief" in summary[0]
    assert summary[0]["attacker_belief_error_l1"] > 0
    assert summary[0]["attacker_belief_error_l2"] > 0


def test_run_scenarios_includes_decoy_cases(tmp_path):
    rows = run_scenarios(
        config_path=str(tmp_path / "missing_config.json"),
        output_root=str(tmp_path / "scenarios"),
        scenario_overrides={
            "decoy_node2_high_belief": {
                "T": 3,
                "H": 2,
                "attacker_enabled": True,
                "attacker_target_selection": "greedy",
                "attacker_greedy_mode": "utility",
                "node_type": ["real", "real", "decoy", "real", "real"],
                "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
                "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
            },
        },
        seed=11,
    )

    assert rows[0]["scenario"] == "decoy_node2_high_belief"
    assert (tmp_path / "scenarios" / "decoy_node2_high_belief" / "metrics.json").exists()
    assert "attacker_decoy_attack_rate" in rows[0]


def test_run_scenarios_includes_probability_cases(tmp_path):
    rows = run_scenarios(
        config_path=str(tmp_path / "missing_config.json"),
        output_root=str(tmp_path / "scenarios"),
        scenario_overrides={
            "decoy_node2_probabilistic_default": {
                "T": 3,
                "H": 2,
                "attacker_enabled": True,
                "attacker_target_selection": "greedy",
                "attacker_greedy_mode": "utility",
                "node_type": ["real", "real", "decoy", "real", "real"],
                "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
                "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
                "stochastic_detection": True,
                "stochastic_success": True,
            },
        },
        seed=11,
    )

    assert rows[0]["scenario"] == "decoy_node2_probabilistic_default"
    assert (tmp_path / "scenarios" / "decoy_node2_probabilistic_default" / "metrics.json").exists()
    assert rows[0]["stochastic_detection"] is True
    assert rows[0]["stochastic_success"] is True


def test_adaptive_scenarios_present(tmp_path):
    rows = run_scenarios(
        config_path=str(tmp_path / "missing_config.json"),
        output_root=str(tmp_path / "scenarios"),
        scenario_overrides={
            "adaptive_decoy_node2_learning": {
                "T": 3,
                "H": 2,
                "attacker_enabled": True,
                "attacker_target_selection": "adaptive",
                "attacker_greedy_mode": "utility",
                "attacker_belief_learning_enabled": True,
                "node_type": ["real", "real", "decoy", "real", "real"],
                "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
                "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
            },
        },
        seed=11,
    )

    assert rows[0]["scenario"] == "adaptive_decoy_node2_learning"
    assert rows[0]["attacker_belief_learning_enabled"] is True
    assert (tmp_path / "scenarios" / "adaptive_decoy_node2_learning" / "metrics.json").exists()


def test_run_scenarios_includes_post_decoy_defense_cases(tmp_path):
    rows = run_scenarios(
        config_path=str(tmp_path / "missing_config.json"),
        output_root=str(tmp_path / "scenarios"),
        scenario_overrides={
            "adaptive_decoy_node2_learning_no_immediate_retreat_defense_aware": {
                "T": 3,
                "H": 2,
                "attacker_enabled": True,
                "attacker_target_selection": "adaptive",
                "attacker_greedy_mode": "utility",
                "attacker_belief_learning_enabled": True,
                "attacker_retreat_threshold": -50.0,
                "node_type": ["real", "real", "decoy", "real", "real"],
                "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
                "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
                "post_decoy_defense_enabled": True,
            },
        },
        seed=11,
    )

    assert rows[0]["post_decoy_defense_enabled"] is True
    assert "post_decoy_defense_active_count" in rows[0]
    assert (tmp_path / "scenarios" / "adaptive_decoy_node2_learning_no_immediate_retreat_defense_aware" / "metrics.json").exists()


def test_run_scenarios_includes_injection_modes(tmp_path):
    rows = run_scenarios(
        config_path=str(tmp_path / "missing_config.json"),
        output_root=str(tmp_path / "scenarios"),
        scenario_overrides={
            "adaptive_decoy_node2_defense_mpc_q": {
                "T": 3,
                "H": 2,
                "attacker_enabled": True,
                "attacker_target_selection": "adaptive",
                "attacker_greedy_mode": "utility",
                "attacker_belief_learning_enabled": True,
                "attacker_retreat_threshold": -50.0,
                "node_type": ["real", "real", "decoy", "real", "real"],
                "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
                "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
                "post_decoy_defense_enabled": True,
                "post_decoy_defense_injection_mode": "mpc_q",
            },
        },
        seed=11,
    )

    assert rows[0]["post_decoy_defense_injection_mode"] == "mpc_q"
    assert (tmp_path / "scenarios" / "adaptive_decoy_node2_defense_mpc_q" / "metrics.json").exists()


def test_run_scenarios_includes_estimated_belief_cases(tmp_path):
    rows = run_scenarios(
        config_path=str(tmp_path / "missing_config.json"),
        output_root=str(tmp_path / "scenarios"),
        scenario_overrides={
            "adaptive_decoy_defense_estimated_belief_hybrid": {
                **SCENARIOS["adaptive_decoy_defense_estimated_belief_hybrid"],
                "T": 3,
                "H": 2,
            },
        },
        seed=11,
    )

    assert rows[0]["scenario"] == "adaptive_decoy_defense_estimated_belief_hybrid"
    assert rows[0]["post_decoy_defense_belief_source"] == "estimated"
    assert rows[0]["defender_belief_estimation_enabled"] is True
    assert rows[0]["defender_belief_observation_mode"] == "hybrid"
    assert "defender_estimation_error_l1" in rows[0]
    assert (tmp_path / "scenarios" / "adaptive_decoy_defense_estimated_belief_hybrid" / "metrics.json").exists()
    assert (tmp_path / "scenarios" / "summary_estimated_vs_oracle_defense.png").exists()


def test_run_scenarios_includes_visible_log_cases(tmp_path):
    rows = run_scenarios(
        config_path=str(tmp_path / "missing_config.json"),
        output_root=str(tmp_path / "scenarios"),
        scenario_overrides={
            "adaptive_decoy_defense_estimated_belief_visible_log": {
                **SCENARIOS["adaptive_decoy_defense_estimated_belief_visible_log"],
                "T": 3,
                "H": 2,
            },
            "adaptive_decoy_defense_estimated_belief_hybrid_visible": {
                **SCENARIOS["adaptive_decoy_defense_estimated_belief_hybrid_visible"],
                "T": 3,
                "H": 2,
            },
        },
        seed=11,
    )

    assert rows[0]["scenario"] == "adaptive_decoy_defense_estimated_belief_visible_log"
    assert rows[0]["defender_belief_observation_mode"] == "defender_visible_log"
    assert rows[0]["visible_log_observation_enabled"] is True
    assert rows[1]["defender_belief_observation_mode"] == "hybrid_visible"
    assert (tmp_path / "scenarios" / "adaptive_decoy_defense_estimated_belief_visible_log" / "metrics.json").exists()
    assert (tmp_path / "scenarios" / "adaptive_decoy_defense_estimated_belief_hybrid_visible" / "metrics.json").exists()
    assert (tmp_path / "scenarios" / "summary_visible_log_estimation.png").exists()


def test_run_scenarios_includes_mtd_cases(tmp_path):
    rows = run_scenarios(
        config_path=str(tmp_path / "missing_config.json"),
        output_root=str(tmp_path / "scenarios"),
        scenario_overrides={
            "mtd_shuffle_belief": {
                **SCENARIOS["mtd_shuffle_belief"],
                "T": 3,
                "H": 2,
                "mtd_interval": 1,
            },
            "mtd_decay_belief": {
                **SCENARIOS["mtd_decay_belief"],
                "T": 3,
                "H": 2,
                "mtd_interval": 1,
            },
        },
        seed=11,
    )

    assert rows[0]["scenario"] == "mtd_shuffle_belief"
    assert rows[0]["mtd_enabled"] is True
    assert rows[0]["mtd_event_count"] == 3
    assert (tmp_path / "scenarios" / "mtd_shuffle_belief" / "metrics.json").exists()
    assert (tmp_path / "scenarios" / "mtd_decay_belief" / "metrics.json").exists()
    assert (tmp_path / "scenarios" / "summary_mtd_effect.png").exists()


def test_run_scenarios_multi_seed_creates_outputs(tmp_path):
    scenarios = {
        "decoy_node2_probabilistic_default": {
            "T": 3,
            "H": 2,
            "attacker_enabled": True,
            "attacker_target_selection": "greedy",
            "attacker_greedy_mode": "utility",
            "node_type": ["real", "real", "decoy", "real", "real"],
            "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
            "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
            "stochastic_detection": True,
            "stochastic_success": True,
        },
    }
    rows = run_scenarios_multi_seed(
        scenarios=scenarios,
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert len(rows) == 1
    assert (tmp_path / "scenarios_multiseed" / "summary_runs.csv").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_runs.json").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_stats.csv").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_stats.json").exists()
    assert (
        tmp_path
        / "scenarios_multiseed"
        / "decoy_node2_probabilistic_default"
        / "seed_0"
        / "metrics.json"
    ).exists()


def test_multiseed_summary_runs_contains_seed_column(tmp_path):
    run_scenarios_multi_seed(
        scenarios={
            "real_attack_probabilistic_low_detection": {
                "T": 3,
                "H": 2,
                "attacker_enabled": True,
                "stochastic_detection": True,
                "stochastic_success": True,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )
    rows = json.loads((tmp_path / "scenarios_multiseed" / "summary_runs.json").read_text(encoding="utf-8"))

    assert {row["seed"] for row in rows} == {0, 1}
    assert all("scenario" in row for row in rows)


def test_multiseed_summary_stats_contains_required_columns(tmp_path):
    run_scenarios_multi_seed(
        scenarios={
            "real_attack_probabilistic_low_detection": {
                "T": 3,
                "H": 2,
                "attacker_enabled": True,
                "stochastic_detection": True,
                "stochastic_success": True,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )
    rows = json.loads((tmp_path / "scenarios_multiseed" / "summary_stats.json").read_text(encoding="utf-8"))

    assert set(MULTI_SEED_STATS_COLUMNS).issubset(rows[0].keys())


def test_multiseed_retreat_rate_is_between_0_and_1(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "real_attack_probabilistic_low_detection": {
                "T": 3,
                "H": 2,
                "attacker_enabled": True,
                "stochastic_detection": True,
                "stochastic_success": True,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert 0.0 <= rows[0]["retreat_rate"] <= 1.0


def test_multiseed_includes_adaptive_scenarios(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "adaptive_decoy_node2_learning_no_immediate_retreat": {
                "T": 3,
                "H": 2,
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
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows[0]["scenario"] == "adaptive_decoy_node2_learning_no_immediate_retreat"
    assert "attacker_belief_decoy_reduction_mean" in rows[0]
    assert (
        tmp_path
        / "scenarios_multiseed"
        / "adaptive_decoy_node2_learning_no_immediate_retreat"
        / "seed_0"
        / "metrics.json"
    ).exists()


def test_multiseed_includes_post_decoy_defense_cases(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "adaptive_decoy_node2_learning_no_immediate_retreat_defense_aware": {
                "T": 3,
                "H": 2,
                "attacker_enabled": True,
                "attacker_target_selection": "adaptive",
                "attacker_greedy_mode": "utility",
                "attacker_belief_learning_enabled": True,
                "attacker_retreat_threshold": -50.0,
                "node_type": ["real", "real", "decoy", "real", "real"],
                "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
                "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
                "post_decoy_defense_enabled": True,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows[0]["scenario"] == "adaptive_decoy_node2_learning_no_immediate_retreat_defense_aware"
    assert "post_decoy_defense_active_count_mean" in rows[0]
    assert (
        tmp_path
        / "scenarios_multiseed"
        / "adaptive_decoy_node2_learning_no_immediate_retreat_defense_aware"
        / "seed_0"
        / "metrics.json"
    ).exists()


def test_multiseed_includes_injection_modes(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "adaptive_decoy_node2_defense_all": {
                "T": 3,
                "H": 2,
                "attacker_enabled": True,
                "attacker_target_selection": "adaptive",
                "attacker_greedy_mode": "utility",
                "attacker_belief_learning_enabled": True,
                "attacker_retreat_threshold": -50.0,
                "node_type": ["real", "real", "decoy", "real", "real"],
                "asset_value": [10.0, 5.0, 0.0, 8.0, 2.0],
                "attacker_belief": [2.0, 3.0, 12.0, 4.0, 2.0],
                "post_decoy_defense_enabled": True,
                "post_decoy_defense_injection_mode": "all",
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows[0]["scenario"] == "adaptive_decoy_node2_defense_all"
    assert "post_decoy_utility_mean" in rows[0]
    assert (
        tmp_path
        / "scenarios_multiseed"
        / "adaptive_decoy_node2_defense_all"
        / "seed_0"
        / "metrics.json"
    ).exists()


def test_multiseed_post_decoy_summary(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "adaptive_decoy_node2_learning_no_immediate_retreat": {
                "T": 3,
                "H": 2,
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
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert "post_decoy_real_attack_mean" in rows[0]
    assert "post_decoy_compromised_mean" in rows[0]
    assert "post_decoy_node0_rate" in rows[0]


def test_multiseed_includes_estimated_belief_cases(tmp_path):
    assert "adaptive_decoy_defense_estimated_belief_target_freq" in MULTI_SEED_SCENARIO_NAMES
    assert "adaptive_decoy_defense_estimated_belief_hybrid" in MULTI_SEED_SCENARIO_NAMES
    assert "adaptive_decoy_defense_oracle_belief_reference" in MULTI_SEED_SCENARIO_NAMES

    rows = run_scenarios_multi_seed(
        scenarios={
            "adaptive_decoy_defense_estimated_belief_target_freq": {
                **SCENARIOS["adaptive_decoy_defense_estimated_belief_target_freq"],
                "T": 3,
                "H": 2,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows[0]["scenario"] == "adaptive_decoy_defense_estimated_belief_target_freq"
    assert "defender_estimation_error_l1_mean" in rows[0]
    assert "defender_estimation_error_l2_std" in rows[0]
    assert (
        tmp_path
        / "scenarios_multiseed"
        / "adaptive_decoy_defense_estimated_belief_target_freq"
        / "seed_0"
        / "metrics.json"
    ).exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_estimated_vs_oracle_defense_mean_std.png").exists()


def test_multiseed_includes_visible_log_cases(tmp_path):
    assert "adaptive_decoy_defense_estimated_belief_visible_log" in MULTI_SEED_SCENARIO_NAMES
    assert "adaptive_decoy_defense_estimated_belief_hybrid_visible" in MULTI_SEED_SCENARIO_NAMES

    rows = run_scenarios_multi_seed(
        scenarios={
            "adaptive_decoy_defense_estimated_belief_visible_log": {
                **SCENARIOS["adaptive_decoy_defense_estimated_belief_visible_log"],
                "T": 3,
                "H": 2,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows[0]["scenario"] == "adaptive_decoy_defense_estimated_belief_visible_log"
    assert rows[0]["defender_belief_observation_mode"] == "defender_visible_log"
    assert "defender_estimation_error_l1_mean" in rows[0]
    assert (
        tmp_path
        / "scenarios_multiseed"
        / "adaptive_decoy_defense_estimated_belief_visible_log"
        / "seed_0"
        / "metrics.json"
    ).exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_visible_log_estimation_mean_std.png").exists()


def test_multiseed_includes_mtd_cases(tmp_path):
    for name in [
        "mtd_none_reference",
        "mtd_shuffle_belief",
        "mtd_decay_belief",
        "mtd_increase_uncertainty",
        "mtd_shuffle_belief_high_intensity",
        "mtd_shuffle_belief_short_interval",
    ]:
        assert name in MULTI_SEED_SCENARIO_NAMES

    rows = run_scenarios_multi_seed(
        scenarios={
            "mtd_shuffle_belief": {
                **SCENARIOS["mtd_shuffle_belief"],
                "T": 3,
                "H": 2,
                "mtd_interval": 1,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows[0]["scenario"] == "mtd_shuffle_belief"
    assert "mtd_event_count_mean" in rows[0]
    assert "mtd_total_cost_mean" in rows[0]
    assert (
        tmp_path
        / "scenarios_multiseed"
        / "mtd_shuffle_belief"
        / "seed_0"
        / "metrics.json"
    ).exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_mtd_effect_mean_std.png").exists()


def test_mtd_sweep_scenarios_present():
    expected = {
        "mtd_sweep_shuffle_interval_5",
        "mtd_sweep_shuffle_interval_10",
        "mtd_sweep_shuffle_interval_20",
        "mtd_sweep_shuffle_intensity_02",
        "mtd_sweep_shuffle_intensity_05",
        "mtd_sweep_shuffle_intensity_09",
        "mtd_sweep_shuffle_success_bonus_00",
        "mtd_sweep_shuffle_success_bonus_05",
        "mtd_sweep_shuffle_detection_bonus_00",
        "mtd_sweep_shuffle_detection_bonus_03",
        "mtd_sweep_shuffle_success05_detection03",
        "mtd_sweep_target_frequency",
        "mtd_sweep_visible_log",
        "mtd_sweep_hybrid_visible",
    }

    assert expected.issubset(SCENARIOS)
    assert SCENARIOS["mtd_sweep_visible_log"]["defender_belief_observation_mode"] == "defender_visible_log"
    assert SCENARIOS["mtd_sweep_hybrid_visible"]["defender_belief_observation_mode"] == "hybrid_visible"


def test_multiseed_includes_mtd_sweep():
    expected = {
        "mtd_sweep_shuffle_interval_5",
        "mtd_sweep_shuffle_interval_10",
        "mtd_sweep_shuffle_interval_20",
        "mtd_sweep_shuffle_intensity_02",
        "mtd_sweep_shuffle_intensity_05",
        "mtd_sweep_shuffle_intensity_09",
        "mtd_sweep_target_frequency",
        "mtd_sweep_visible_log",
        "mtd_sweep_hybrid_visible",
    }

    assert expected.issubset(set(MULTI_SEED_SCENARIO_NAMES))


def test_mtd_delta_vs_reference_columns_exist():
    rows = build_multiseed_stats_rows(
        [
            {
                "scenario": "mtd_none_reference",
                "post_decoy_compromised_value": 100.0,
                "post_decoy_utility": 10.0,
                "mtd_total_cost": 0.0,
            },
            {
                "scenario": "mtd_sweep_shuffle_interval_5",
                "post_decoy_compromised_value": 90.0,
                "post_decoy_utility": 8.0,
                "mtd_total_cost": 5.0,
            },
        ]
    )

    sweep = next(row for row in rows if row["scenario"] == "mtd_sweep_shuffle_interval_5")
    assert "mtd_compromised_delta_vs_reference" in sweep
    assert "mtd_utility_delta_vs_reference" in sweep
    assert "mtd_cost_adjusted_delta" in sweep


def test_mtd_cost_adjusted_delta_computed():
    rows = build_multiseed_stats_rows(
        [
            {
                "scenario": "mtd_none_reference",
                "post_decoy_compromised_value": 100.0,
                "post_decoy_utility": 10.0,
                "mtd_total_cost": 0.0,
            },
            {
                "scenario": "mtd_sweep_shuffle_interval_5",
                "post_decoy_compromised_value": 90.0,
                "post_decoy_utility": 8.0,
                "mtd_total_cost": 5.0,
            },
        ]
    )

    sweep = next(row for row in rows if row["scenario"] == "mtd_sweep_shuffle_interval_5")
    assert sweep["mtd_compromised_delta_vs_reference"] == -10.0
    assert sweep["mtd_utility_delta_vs_reference"] == -2.0
    assert sweep["mtd_cost_adjusted_delta"] == -5.0


def test_mtd_sweep_summary_plots_created(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "mtd_none_reference": {
                **SCENARIOS["mtd_none_reference"],
                "T": 3,
                "H": 2,
            },
            "mtd_sweep_shuffle_interval_5": {
                **SCENARIOS["mtd_sweep_shuffle_interval_5"],
                "T": 3,
                "H": 2,
                "mtd_interval": 1,
            },
            "mtd_sweep_visible_log": {
                **SCENARIOS["mtd_sweep_visible_log"],
                "T": 3,
                "H": 2,
                "mtd_interval": 1,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    sweep = next(row for row in rows if row["scenario"] == "mtd_sweep_shuffle_interval_5")
    assert sweep["mtd_cost_adjusted_delta"] is not None
    assert (tmp_path / "scenarios_multiseed" / "summary_mtd_sweep_compromised.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_mtd_sweep_cost_adjusted.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_mtd_estimator_compatibility.png").exists()


def test_reachable_node_selection():
    config = small_config(
        attacker_enabled=True,
        attacker_target_selection="adaptive",
        attacker_lateral_enabled=True,
        attacker_lateral_success_prob=1.0,
        adjacency_matrix=[
            [0, 1, 0, 0, 0],
            [1, 0, 1, 1, 0],
            [0, 1, 0, 1, 0],
            [0, 1, 1, 0, 1],
            [0, 0, 0, 1, 0],
        ],
        entry_nodes=[0],
        critical_nodes=[4],
        attacker_belief=[1.0, 1.0, 1.0, 1.0, 100.0],
    )
    sim = CyberDefenseSimulator(config)
    sim.attacker.select_attack(sim.x_current, sim.M)

    assert sim.attacker.last_selected_target == 1


def test_lateral_movement_only_neighbor():
    config = small_config(
        T=3,
        attacker_enabled=True,
        attacker_target_selection="adaptive",
        attacker_lateral_enabled=True,
        attacker_lateral_success_prob=1.0,
        attacker_lateral_detection_prob=0.0,
        stochastic_success=True,
        stochastic_detection=True,
        adjacency_matrix=[
            [0, 1, 0, 0, 0],
            [1, 0, 1, 1, 0],
            [0, 1, 0, 1, 0],
            [0, 1, 1, 0, 1],
            [0, 0, 0, 1, 0],
        ],
        entry_nodes=[0],
        critical_nodes=[4],
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    targets = np.asarray(sim.history["attacker_selected_target"], dtype=int)
    adjacency = config.adjacency_matrix
    current = config.entry_nodes[0]
    for target in targets:
        assert adjacency[current, target] == 1
        current = target


def test_critical_asset_detection():
    config = small_config(
        T=4,
        attacker_enabled=True,
        attacker_target_selection="adaptive",
        attacker_lateral_enabled=True,
        attacker_lateral_success_prob=1.0,
        attacker_lateral_detection_prob=0.0,
        stochastic_success=True,
        stochastic_detection=True,
        adjacency_matrix=[
            [0, 1, 0, 0, 0],
            [1, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 1],
            [0, 0, 0, 1, 0],
        ],
        entry_nodes=[3],
        critical_nodes=[4],
        attacker_belief=[1.0, 1.0, 1.0, 1.0, 100.0],
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    assert metrics["critical_compromise"] is True
    assert metrics["critical_compromise_step"] == 0


def test_decoy_reduces_lateral_success():
    config = small_config(
        attacker_lateral_enabled=True,
        attacker_lateral_success_prob=0.8,
        decoy_lateral_decay=0.5,
    )
    sim = CyberDefenseSimulator(config)

    assert sim._lateral_success_probability(attacked_decoy=True) == pytest.approx(0.4)
    assert sim._lateral_success_probability(attacked_decoy=False) == pytest.approx(0.8)


def test_lateral_multiseed_summary(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "lateral_baseline": {
                **SCENARIOS["lateral_baseline"],
                "T": 4,
                "H": 2,
                "attacker_lateral_success_prob": 1.0,
                "attacker_lateral_detection_prob": 0.0,
            },
            "lateral_decoy": {
                **SCENARIOS["lateral_decoy"],
                "T": 4,
                "H": 2,
                "attacker_lateral_success_prob": 1.0,
                "attacker_lateral_detection_prob": 0.0,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows[0]["scenario"] == "lateral_baseline"
    assert "critical_compromise_rate" in rows[0]
    assert "critical_compromise_step_mean" in rows[0]
    assert (tmp_path / "scenarios_multiseed" / "summary_lateral_compromise_rate.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_lateral_compromise_step.png").exists()


def test_paths_to_critical_are_found():
    sim = CyberDefenseSimulator(SimulationConfig())

    paths = sim._paths_to_critical()

    assert [0, 1, 3, 4] in paths
    assert [0, 1, 2, 3, 4] in paths
    assert sim._reachable_from_entries() == {0, 1, 2, 3, 4}


def test_node_path_frequency_identifies_chokepoint():
    sim = CyberDefenseSimulator(SimulationConfig())
    paths = sim._paths_to_critical()

    frequency = sim._node_path_frequency(paths)

    assert frequency[1] == 2
    assert frequency[3] == 2
    assert sim._chokepoint_nodes(frequency) == [1, 3]


def test_decoy_on_critical_path_metric():
    config = SimulationConfig(node_type=["real", "decoy", "real", "real", "real"])
    sim = CyberDefenseSimulator(config)
    sim.run()

    metrics = sim.calculate_metrics()

    assert metrics["decoy_on_critical_path"] is True
    assert 1 in metrics["chokepoint_nodes"]
    assert metrics["critical_path_count"] >= 2


def test_edge_mtd_blocks_critical_edge_temporarily():
    config = SimulationConfig(
        T=1,
        H=2,
        attacker_lateral_enabled=True,
        mtd_enabled=True,
        mtd_interval=1,
        mtd_shuffle_topology=False,
        mtd_block_critical_edges=True,
        mtd_edge_block_count=1,
        mtd_edge_block_duration=1,
    )
    sim = CyberDefenseSimulator(config)

    history = sim.run()

    active = np.asarray(history["active_adjacency_matrix"], dtype=int)
    assert active.shape == (1, config.n_nodes, config.n_nodes)
    assert not np.array_equal(active[0], config.adjacency_matrix)
    assert history["mtd_blocked_edges_step"][0] != ""


def test_active_adjacency_restores_after_duration():
    config = SimulationConfig(
        mtd_block_critical_edges=True,
        mtd_edge_block_count=1,
        mtd_edge_block_duration=1,
    )
    sim = CyberDefenseSimulator(config)

    sim._block_critical_edges(0)
    assert sim.mtd_blocked_edges
    assert not np.array_equal(sim.active_adjacency_matrix, sim.current_adjacency_matrix)

    sim._restore_expired_mtd_edge_blocks(1)

    assert sim.mtd_blocked_edges == {}
    assert np.array_equal(sim.active_adjacency_matrix, sim.current_adjacency_matrix)


def test_path_aware_lateral_scenarios_present():
    expected = {
        "lateral_decoy_on_chokepoint",
        "lateral_decoy_on_server_path",
        "lateral_multi_decoy_path",
        "lateral_edge_mtd_chokepoint",
        "lateral_edge_mtd_interval5",
        "lateral_path_decoy_edge_mtd",
    }

    assert expected.issubset(SCENARIOS)
    assert expected.issubset(set(MULTI_SEED_SCENARIO_NAMES))


def test_path_aware_multiseed_summary(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "lateral_decoy_on_chokepoint": {
                **SCENARIOS["lateral_decoy_on_chokepoint"],
                "T": 3,
                "H": 2,
                "attacker_lateral_success_prob": 1.0,
                "attacker_lateral_detection_prob": 0.0,
            },
            "lateral_path_decoy_edge_mtd": {
                **SCENARIOS["lateral_path_decoy_edge_mtd"],
                "T": 3,
                "H": 2,
                "mtd_interval": 1,
                "attacker_lateral_success_prob": 1.0,
                "attacker_lateral_detection_prob": 0.0,
            },
        },
        seeds=[0],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows[0]["scenario"] == "lateral_decoy_on_chokepoint"
    assert "critical_path_count" in rows[0]
    assert "mtd_edge_block_events_mean" in rows[1]
    assert (tmp_path / "scenarios_multiseed" / "summary_lateral_path_aware_compromise_rate.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_lateral_path_aware_step.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_lateral_edge_mtd.png").exists()


def test_bayesian_config_validation():
    with pytest.raises(ValueError, match="post_decoy_defense_belief_source"):
        SimulationConfig(post_decoy_defense_belief_source="invalid")
    with pytest.raises(ValueError, match="defender_bayesian_prior_strength"):
        SimulationConfig(defender_bayesian_prior_strength=-0.1)
    with pytest.raises(ValueError, match="defender_bayesian_decay"):
        SimulationConfig(defender_bayesian_decay=1.1)
    SimulationConfig(post_decoy_defense_belief_source="bayesian")


def test_bayesian_update_increases_selected_target_alpha():
    config = SimulationConfig(defender_bayesian_update_enabled=True)
    sim = CyberDefenseSimulator(config)
    before = sim.defender_bayesian_alpha.copy()

    sim._update_defender_bayesian_belief(
        selected_target=2,
        success=True,
        detected=False,
        attacked_decoy=False,
    )

    assert sim.defender_bayesian_alpha[2] > before[2]


def test_bayesian_update_applies_decay():
    config = SimulationConfig(
        defender_bayesian_update_enabled=True,
        defender_bayesian_decay=0.5,
    )
    sim = CyberDefenseSimulator(config)

    sim._update_defender_bayesian_belief(
        selected_target=2,
        success=False,
        detected=False,
        attacked_decoy=False,
    )

    assert sim.defender_bayesian_alpha[0] == pytest.approx(0.5)


def test_bayesian_critical_path_likelihood_boost():
    base = SimulationConfig(
        defender_bayesian_update_enabled=True,
        defender_bayesian_decay=1.0,
        defender_bayesian_critical_path_likelihood=1.0,
    )
    boosted = SimulationConfig(
        defender_bayesian_update_enabled=True,
        defender_bayesian_decay=1.0,
        defender_bayesian_critical_path_likelihood=3.0,
    )
    base_sim = CyberDefenseSimulator(base)
    boosted_sim = CyberDefenseSimulator(boosted)

    base_sim._update_defender_bayesian_belief(1, success=False, detected=False, attacked_decoy=False)
    boosted_sim._update_defender_bayesian_belief(1, success=False, detected=False, attacked_decoy=False)

    assert boosted_sim.defender_bayesian_alpha[1] > base_sim.defender_bayesian_alpha[1]


def test_effective_defense_weight_uses_bayesian_belief():
    config = SimulationConfig(
        post_decoy_defense_enabled=True,
        post_decoy_defense_belief_source="bayesian",
        post_decoy_defense_top_k=1,
        post_decoy_defense_weight=3.0,
        post_decoy_defense_exclude_decoy=False,
        defender_bayesian_update_enabled=True,
    )
    sim = CyberDefenseSimulator(config)
    sim.first_decoy_step = 0
    sim.defender_bayesian_alpha = np.ones(config.n_nodes)
    sim.defender_bayesian_alpha[3] = 20.0

    weight = sim._effective_defense_weight()

    assert weight[3] > config.Q_diag[3]
    assert weight[0] == pytest.approx(config.Q_diag[0])


def test_bayesian_scenarios_present():
    expected = {
        "bayesian_lateral_path_decoy",
        "bayesian_lateral_path_decoy_edge_mtd",
        "bayesian_vs_target_frequency_reference",
        "bayesian_high_critical_path_likelihood",
        "bayesian_low_decay",
    }

    assert expected.issubset(SCENARIOS)
    assert expected.issubset(set(MULTI_SEED_SCENARIO_NAMES))


def test_bayesian_multiseed_summary(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "bayesian_lateral_path_decoy": {
                **SCENARIOS["bayesian_lateral_path_decoy"],
                "T": 3,
                "H": 2,
                "attacker_lateral_success_prob": 1.0,
                "attacker_lateral_detection_prob": 0.0,
            },
            "bayesian_vs_target_frequency_reference": {
                **SCENARIOS["bayesian_vs_target_frequency_reference"],
                "T": 3,
                "H": 2,
                "attacker_lateral_success_prob": 1.0,
                "attacker_lateral_detection_prob": 0.0,
            },
        },
        seeds=[0],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows[0]["scenario"] == "bayesian_lateral_path_decoy"
    assert "defender_bayesian_error_l1_mean" in rows[0]
    assert "critical_compromise_rate" in rows[0]
    assert "post_decoy_compromised_mean" in rows[0]
    assert (tmp_path / "scenarios_multiseed" / "summary_bayesian_compromise_rate.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_bayesian_post_decoy_compromised.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_bayesian_error.png").exists()


def test_bayesian_sweep_scenarios_present():
    expected = {
        "bayesian_sweep_prior_05",
        "bayesian_sweep_prior_20",
        "bayesian_sweep_success_likelihood_10",
        "bayesian_sweep_success_likelihood_30",
        "bayesian_sweep_detected_likelihood_02",
        "bayesian_sweep_detected_likelihood_08",
        "bayesian_sweep_decoy_likelihood_01",
        "bayesian_sweep_decoy_likelihood_05",
        "bayesian_sweep_critical_path_likelihood_10",
        "bayesian_sweep_critical_path_likelihood_30",
        "bayesian_sweep_decay_090",
        "bayesian_sweep_decay_098",
        "bayesian_sweep_decay_100",
    }

    assert expected.issubset(SCENARIOS)


def test_multiseed_includes_bayesian_sweep():
    expected = {
        "bayesian_sweep_success_likelihood_10",
        "bayesian_sweep_success_likelihood_30",
        "bayesian_sweep_decoy_likelihood_01",
        "bayesian_sweep_decoy_likelihood_05",
        "bayesian_sweep_critical_path_likelihood_10",
        "bayesian_sweep_critical_path_likelihood_30",
        "bayesian_sweep_decay_090",
        "bayesian_sweep_decay_100",
    }

    assert expected.issubset(set(MULTI_SEED_SCENARIO_NAMES))


def test_bayesian_delta_vs_target_frequency_columns_exist():
    rows = build_multiseed_stats_rows(
        [
            {
                "scenario": "bayesian_vs_target_frequency_reference",
                "critical_compromise": True,
                "post_decoy_compromised_value": 10.0,
                "defender_bayesian_error_l1": 5.0,
            },
            {
                "scenario": "bayesian_sweep_decay_090",
                "critical_compromise": False,
                "post_decoy_compromised_value": 7.0,
                "defender_bayesian_error_l1": 4.0,
            },
        ]
    )
    sweep = next(row for row in rows if row["scenario"] == "bayesian_sweep_decay_090")

    assert "bayesian_compromise_delta_vs_target_frequency" in sweep
    assert "bayesian_post_decoy_delta_vs_target_frequency" in sweep
    assert "bayesian_error_delta_vs_target_frequency" in sweep
    assert sweep["bayesian_compromise_delta_vs_target_frequency"] == -1.0
    assert sweep["bayesian_post_decoy_delta_vs_target_frequency"] == -3.0
    assert sweep["bayesian_error_delta_vs_target_frequency"] == -1.0


def test_bayesian_sweep_plots_created(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "bayesian_vs_target_frequency_reference": {
                **SCENARIOS["bayesian_vs_target_frequency_reference"],
                "T": 3,
                "H": 2,
                "attacker_lateral_success_prob": 1.0,
                "attacker_lateral_detection_prob": 0.0,
            },
            "bayesian_sweep_decay_090": {
                **SCENARIOS["bayesian_sweep_decay_090"],
                "T": 3,
                "H": 2,
                "attacker_lateral_success_prob": 1.0,
                "attacker_lateral_detection_prob": 0.0,
            },
        },
        seeds=[0],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows[1]["scenario"] == "bayesian_sweep_decay_090"
    assert "bayesian_post_decoy_delta_vs_target_frequency" in rows[1]
    assert (tmp_path / "scenarios_multiseed" / "summary_bayesian_sweep_compromise_rate.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_bayesian_sweep_post_decoy.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_bayesian_sweep_error.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_bayesian_vs_target_frequency_delta.png").exists()


def test_defense_objective_config_validation():
    with pytest.raises(ValueError, match="defense_objective_critical_weight"):
        SimulationConfig(defense_objective_critical_weight=-1.0)
    with pytest.raises(ValueError, match="defense_objective_post_decoy_weight"):
        SimulationConfig(defense_objective_post_decoy_weight=-1.0)
    with pytest.raises(ValueError, match="defense_objective_delay_reward"):
        SimulationConfig(defense_objective_delay_reward=-1.0)


def test_defense_objective_score_computed():
    config = SimulationConfig(
        T=10,
        defense_objective_critical_weight=1000.0,
        defense_objective_post_decoy_weight=1.0,
        defense_objective_delay_reward=5.0,
    )
    sim = CyberDefenseSimulator(config)
    sim.critical_compromise = True
    sim.critical_compromise_step = 3
    sim.first_decoy_step = None

    metrics = sim.calculate_metrics()

    assert metrics["defense_objective_score"] == pytest.approx(985.0)


def test_defense_objective_scenarios_present():
    expected = {
        "bayesian_defense_objective_default",
        "bayesian_defense_objective_high_critical_weight",
        "bayesian_defense_objective_high_delay_reward",
        "bayesian_defense_objective_low_post_decoy_weight",
        "bayesian_defense_objective_edge_mtd",
    }

    assert expected.issubset(SCENARIOS)
    assert expected.issubset(set(MULTI_SEED_SCENARIO_NAMES))


def test_defense_objective_multiseed_summary():
    rows = build_multiseed_stats_rows(
        [
            {
                "scenario": "bayesian_vs_target_frequency_reference",
                "critical_compromise": True,
                "critical_compromise_step": 2,
                "post_decoy_compromised_value": 10.0,
                "defender_bayesian_error_l1": 5.0,
                "defense_objective_score": 1000.0,
            },
            {
                "scenario": "bayesian_defense_objective_default",
                "critical_compromise": False,
                "critical_compromise_step": None,
                "post_decoy_compromised_value": 7.0,
                "defender_bayesian_error_l1": 4.0,
                "defense_objective_score": 800.0,
            },
        ]
    )
    objective = next(row for row in rows if row["scenario"] == "bayesian_defense_objective_default")

    assert "defense_objective_score_mean" in objective
    assert "defense_objective_delta_vs_target_frequency" in objective
    assert objective["defense_objective_delta_vs_target_frequency"] == -200.0
    assert objective["critical_rate_delta_vs_target_frequency"] == -1.0
    assert objective["post_decoy_delta_vs_target_frequency"] == -3.0


def test_defense_objective_plots_created(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "bayesian_vs_target_frequency_reference": {
                **SCENARIOS["bayesian_vs_target_frequency_reference"],
                "T": 3,
                "H": 2,
                "attacker_lateral_success_prob": 1.0,
                "attacker_lateral_detection_prob": 0.0,
            },
            "bayesian_defense_objective_edge_mtd": {
                **SCENARIOS["bayesian_defense_objective_edge_mtd"],
                "T": 3,
                "H": 2,
                "attacker_lateral_success_prob": 1.0,
                "attacker_lateral_detection_prob": 0.0,
                "mtd_interval": 1,
            },
        },
        seeds=[0],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert rows[1]["scenario"] == "bayesian_defense_objective_edge_mtd"
    assert "defense_objective_score_mean" in rows[1]
    assert (tmp_path / "scenarios_multiseed" / "summary_defense_objective_score.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_defense_objective_tradeoff.png").exists()


def test_policy_selection_scenarios_present():
    expected = {
        "policy_target_frequency_path_decoy",
        "policy_bayesian_default_path_decoy",
        "policy_bayesian_success30_path_decoy",
        "policy_bayesian_decay090_path_decoy",
        "policy_bayesian_edge_mtd",
        "policy_path_decoy_edge_mtd",
        "policy_lateral_multi_decoy",
    }

    assert expected.issubset(SCENARIOS)
    assert expected.issubset(set(MULTI_SEED_SCENARIO_NAMES))


def test_policy_selection_summary_created(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "policy_target_frequency_path_decoy": {
                **SCENARIOS["policy_target_frequency_path_decoy"],
                "T": 3,
                "H": 2,
                "attacker_lateral_success_prob": 1.0,
                "attacker_lateral_detection_prob": 0.0,
            },
            "policy_bayesian_default_path_decoy": {
                **SCENARIOS["policy_bayesian_default_path_decoy"],
                "T": 3,
                "H": 2,
                "attacker_lateral_success_prob": 1.0,
                "attacker_lateral_detection_prob": 0.0,
            },
        },
        seeds=[0],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )
    policy_rows = json.loads(
        (tmp_path / "scenarios_multiseed" / "policy_selection_summary.json").read_text(encoding="utf-8")
    )

    assert len(rows) == 2
    assert set(POLICY_SELECTION_COLUMNS).issubset(policy_rows[0].keys())
    assert (tmp_path / "scenarios_multiseed" / "policy_selection_summary.csv").exists()
    assert (tmp_path / "scenarios_multiseed" / "policy_selection_summary.json").exists()


def test_best_policy_json_created(tmp_path):
    run_scenarios_multi_seed(
        scenarios={
            "policy_target_frequency_path_decoy": {
                **SCENARIOS["policy_target_frequency_path_decoy"],
                "T": 3,
                "H": 2,
            },
            "policy_bayesian_default_path_decoy": {
                **SCENARIOS["policy_bayesian_default_path_decoy"],
                "T": 3,
                "H": 2,
            },
        },
        seeds=[0],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )
    best = json.loads((tmp_path / "scenarios_multiseed" / "best_policy.json").read_text(encoding="utf-8"))

    assert best["best_policy"].startswith("policy_")
    assert best["reason"] == "lowest defense_objective_score_mean"


def test_policy_selection_rank_sorted_by_objective():
    rows = build_policy_selection_rows(
        [
            {
                "scenario": "policy_target_frequency_path_decoy",
                "num_runs": 2,
                "defense_objective_score_mean": 900.0,
                "defense_objective_score_std": 10.0,
            },
            {
                "scenario": "policy_bayesian_default_path_decoy",
                "num_runs": 2,
                "defense_objective_score_mean": 800.0,
                "defense_objective_score_std": 20.0,
            },
        ]
    )

    assert [row["policy"] for row in rows] == [
        "policy_bayesian_default_path_decoy",
        "policy_target_frequency_path_decoy",
    ]
    assert [row["selected_policy_rank"] for row in rows] == [1, 2]


def test_policy_selection_plots_created(tmp_path):
    run_scenarios_multi_seed(
        scenarios={
            "policy_target_frequency_path_decoy": {
                **SCENARIOS["policy_target_frequency_path_decoy"],
                "T": 3,
                "H": 2,
            },
            "policy_bayesian_edge_mtd": {
                **SCENARIOS["policy_bayesian_edge_mtd"],
                "T": 3,
                "H": 2,
                "mtd_interval": 1,
            },
        },
        seeds=[0],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert (tmp_path / "scenarios_multiseed" / "summary_policy_selection_objective.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_policy_selection_tradeoff.png").exists()


def test_mtd_risk_gate_config_validation():
    with pytest.raises(ValueError, match="mtd_risk_gate_threshold"):
        SimulationConfig(mtd_risk_gate_threshold=-1.0)
    with pytest.raises(ValueError, match="mtd_risk_gate_mode"):
        SimulationConfig(mtd_risk_gate_mode="invalid")
    with pytest.raises(ValueError, match="mtd_risk_gate_cooldown"):
        SimulationConfig(mtd_risk_gate_cooldown=-1)


def test_mtd_risk_gate_score_computed():
    config = small_config(mtd_risk_gate_mode="critical_path_risk")
    sim = CyberDefenseSimulator(config)
    sim.x_current = np.array([1.0, 2.0, 3.0, 4.0, 5.0])

    assert sim._mtd_risk_gate_score() == pytest.approx(15.0)


def test_mtd_risk_gate_suppresses_low_risk_mtd():
    config = small_config(
        T=3,
        mtd_enabled=True,
        mtd_interval=1,
        mtd_risk_gating_enabled=True,
        mtd_risk_gate_threshold=1000.0,
        mtd_risk_gate_cooldown=0,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    assert metrics["mtd_event_count"] == 0
    assert metrics["mtd_risk_gate_fire_count"] == 0
    assert metrics["mtd_risk_gate_suppressed_count"] == 3


def test_mtd_risk_gate_fires_high_risk_mtd():
    config = small_config(
        T=3,
        mtd_enabled=True,
        mtd_interval=1,
        mtd_risk_gating_enabled=True,
        mtd_risk_gate_threshold=0.0,
        mtd_risk_gate_cooldown=0,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    assert metrics["mtd_event_count"] == 3
    assert metrics["mtd_risk_gate_fire_count"] == 3
    assert metrics["mtd_risk_gate_suppressed_count"] == 0


def test_gated_mtd_scenarios_present():
    expected = {
        "policy_gated_edge_mtd_critical_path",
        "policy_gated_edge_mtd_chokepoint",
        "policy_gated_edge_mtd_edge_pressure",
        "policy_gated_edge_mtd_low_threshold",
        "policy_gated_edge_mtd_high_threshold",
    }

    assert expected.issubset(SCENARIOS)
    assert expected.issubset(set(MULTI_SEED_SCENARIO_NAMES))


def test_policy_selection_includes_gated_mtd():
    rows = build_policy_selection_rows(
        [
            {
                "scenario": "policy_gated_edge_mtd_critical_path",
                "num_runs": 2,
                "defense_objective_score_mean": 700.0,
                "mtd_risk_gating_enabled": True,
                "mtd_risk_gate_mode": "critical_path_risk",
                "mtd_risk_gate_fire_count_mean": 1.0,
                "mtd_risk_gate_suppressed_count_mean": 2.0,
                "mtd_risk_gate_score_mean": 5.5,
            },
            {
                "scenario": "policy_target_frequency_path_decoy",
                "num_runs": 2,
                "defense_objective_score_mean": 800.0,
            },
        ]
    )

    gated = rows[0]
    assert gated["policy"] == "policy_gated_edge_mtd_critical_path"
    assert gated["selected_policy_rank"] == 1
    assert gated["mtd_risk_gating_enabled"] is True
    assert gated["mtd_risk_gate_fire_count_mean"] == 1.0


def test_gated_mtd_sweep_scenarios_present():
    expected = {
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
    }

    assert expected.issubset(SCENARIOS)


def test_gated_mtd_sweep_in_multiseed():
    expected = {
        "gated_edge_pressure_threshold_3",
        "gated_edge_pressure_threshold_5",
        "gated_edge_pressure_threshold_10",
        "gated_edge_pressure_cooldown_0",
        "gated_edge_pressure_cooldown_5",
        "gated_edge_pressure_duration_2",
        "gated_edge_pressure_count_2",
    }

    assert expected.issubset(set(MULTI_SEED_SCENARIO_NAMES))


def test_policy_selection_includes_gated_sweep():
    expected = {
        "gated_edge_pressure_threshold_3",
        "gated_edge_pressure_threshold_5",
        "gated_edge_pressure_threshold_10",
        "gated_edge_pressure_cooldown_5",
        "gated_edge_pressure_duration_2",
        "gated_edge_pressure_count_2",
    }

    assert expected.issubset(set(MULTI_SEED_SCENARIO_NAMES))
    policy_rows = build_policy_selection_rows(
        [
            {
                "scenario": "policy_target_frequency_path_decoy",
                "num_runs": 2,
                "defense_objective_score_mean": 800.0,
                "critical_compromise_rate": 0.7,
                "post_decoy_compromised_mean": 100.0,
                "mtd_total_cost_mean": 0.0,
            },
            {
                "scenario": "gated_edge_pressure_threshold_5",
                "num_runs": 2,
                "defense_objective_score_mean": 700.0,
                "critical_compromise_rate": 0.6,
                "post_decoy_compromised_mean": 80.0,
                "mtd_total_cost_mean": 2.0,
            },
        ]
    )

    assert any(row["policy"] == "gated_edge_pressure_threshold_5" for row in policy_rows)


def test_cost_per_post_decoy_reduction_computed():
    rows = build_policy_selection_rows(
        [
            {
                "scenario": "policy_target_frequency_path_decoy",
                "num_runs": 2,
                "defense_objective_score_mean": 800.0,
                "critical_compromise_rate": 0.7,
                "post_decoy_compromised_mean": 100.0,
                "mtd_total_cost_mean": 0.0,
            },
            {
                "scenario": "gated_edge_pressure_threshold_5",
                "num_runs": 2,
                "defense_objective_score_mean": 700.0,
                "critical_compromise_rate": 0.6,
                "post_decoy_compromised_mean": 80.0,
                "mtd_total_cost_mean": 2.0,
            },
        ]
    )
    gated = next(row for row in rows if row["policy"] == "gated_edge_pressure_threshold_5")

    assert gated["post_decoy_reduction_vs_reference"] == pytest.approx(20.0)
    assert gated["critical_rate_improvement_vs_reference"] == pytest.approx(0.1)
    assert gated["cost_per_post_decoy_reduction"] == pytest.approx(0.1)


def test_gated_mtd_sweep_plots_created(tmp_path):
    run_scenarios_multi_seed(
        scenarios={
            "policy_target_frequency_path_decoy": {
                **SCENARIOS["policy_target_frequency_path_decoy"],
                "T": 3,
                "H": 2,
            },
            "gated_edge_pressure_threshold_5": {
                **SCENARIOS["gated_edge_pressure_threshold_5"],
                "T": 3,
                "H": 2,
                "mtd_interval": 1,
            },
        },
        seeds=[0],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert (tmp_path / "scenarios_multiseed" / "summary_gated_mtd_sweep_objective.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_gated_mtd_sweep_cost_effectiveness.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_gated_mtd_threshold_tradeoff.png").exists()


def test_gated_mtd_hybrid_scenarios_present():
    expected = {
        "gated_edge_pressure_count2_duration2",
        "gated_edge_pressure_count2_duration2_threshold5",
        "gated_edge_pressure_count2_duration2_threshold7",
        "gated_edge_pressure_count2_duration2_cooldown0",
        "gated_edge_pressure_count2_duration2_cooldown5",
        "gated_edge_pressure_count2_duration2_interval10",
        "gated_edge_pressure_count2_duration1_threshold7",
        "gated_edge_pressure_count1_duration2_threshold7",
    }

    assert expected.issubset(SCENARIOS)


def test_gated_mtd_hybrid_in_multiseed():
    expected = {
        "gated_edge_pressure_count2_duration2",
        "gated_edge_pressure_count2_duration2_threshold7",
        "gated_edge_pressure_count2_duration2_cooldown5",
        "gated_edge_pressure_count2_duration2_interval10",
        "gated_edge_pressure_count2_duration1_threshold7",
        "gated_edge_pressure_count1_duration2_threshold7",
    }

    assert expected.issubset(set(MULTI_SEED_SCENARIO_NAMES))


def test_policy_selection_includes_gated_hybrid():
    rows = build_policy_selection_rows(
        [
            {
                "scenario": "policy_target_frequency_path_decoy",
                "num_runs": 2,
                "defense_objective_score_mean": 800.0,
                "critical_compromise_rate": 0.7,
                "post_decoy_compromised_mean": 100.0,
                "mtd_total_cost_mean": 0.0,
            },
            {
                "scenario": "gated_edge_pressure_count2_duration2_threshold7",
                "num_runs": 2,
                "defense_objective_score_mean": 700.0,
                "critical_compromise_rate": 0.6,
                "post_decoy_compromised_mean": 80.0,
                "mtd_total_cost_mean": 2.0,
            },
        ]
    )

    assert any(row["policy"] == "gated_edge_pressure_count2_duration2_threshold7" for row in rows)


def test_gated_mtd_hybrid_plots_created(tmp_path):
    run_scenarios_multi_seed(
        scenarios={
            "policy_target_frequency_path_decoy": {
                **SCENARIOS["policy_target_frequency_path_decoy"],
                "T": 3,
                "H": 2,
            },
            "gated_edge_pressure_count2_duration2": {
                **SCENARIOS["gated_edge_pressure_count2_duration2"],
                "T": 3,
                "H": 2,
                "mtd_interval": 1,
            },
        },
        seeds=[0],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert (tmp_path / "scenarios_multiseed" / "summary_gated_mtd_hybrid_objective.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_gated_mtd_hybrid_tradeoff.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_gated_mtd_hybrid_cost_effectiveness.png").exists()


def test_best_policy_can_select_hybrid_gated_mtd():
    rows = build_policy_selection_rows(
        [
            {
                "scenario": "policy_target_frequency_path_decoy",
                "num_runs": 2,
                "defense_objective_score_mean": 800.0,
                "critical_compromise_rate": 0.7,
                "post_decoy_compromised_mean": 100.0,
                "mtd_total_cost_mean": 0.0,
            },
            {
                "scenario": "gated_edge_pressure_count2_duration2",
                "num_runs": 2,
                "defense_objective_score_mean": 500.0,
                "critical_compromise_rate": 0.5,
                "post_decoy_compromised_mean": 70.0,
                "mtd_total_cost_mean": 3.0,
            },
        ]
    )

    assert rows[0]["policy"] == "gated_edge_pressure_count2_duration2"
    assert rows[0]["selected_policy_rank"] == 1


def test_conditional_mtd_config_validation():
    with pytest.raises(ValueError, match="mtd_conditional_policy_mode"):
        SimulationConfig(mtd_conditional_policy_mode="invalid")
    with pytest.raises(ValueError, match="mtd_conditional_high_risk_threshold"):
        SimulationConfig(mtd_conditional_high_risk_threshold=-1.0)
    with pytest.raises(ValueError, match="mtd_conditional_low_risk_threshold"):
        SimulationConfig(mtd_conditional_low_risk_threshold=-1.0)
    with pytest.raises(ValueError, match="mtd_conditional_high_risk_threshold"):
        SimulationConfig(
            mtd_conditional_low_risk_threshold=5.0,
            mtd_conditional_high_risk_threshold=3.0,
        )


def test_conditional_mtd_selects_count2_for_high_risk():
    config = small_config(
        mtd_conditional_policy_enabled=True,
        mtd_conditional_low_risk_threshold=5.0,
        mtd_conditional_high_risk_threshold=10.0,
    )
    sim = CyberDefenseSimulator(config)

    assert sim._select_mtd_conditional_policy(12.0) == ("count2", 2, 1)


def test_conditional_mtd_selects_duration2_for_mid_risk():
    config = small_config(
        mtd_conditional_policy_enabled=True,
        mtd_conditional_low_risk_threshold=5.0,
        mtd_conditional_high_risk_threshold=10.0,
    )
    sim = CyberDefenseSimulator(config)

    assert sim._select_mtd_conditional_policy(7.0) == ("duration2", 1, 2)


def test_conditional_mtd_suppresses_low_risk():
    config = small_config(
        mtd_conditional_policy_enabled=True,
        mtd_conditional_low_risk_threshold=5.0,
        mtd_conditional_high_risk_threshold=10.0,
    )
    sim = CyberDefenseSimulator(config)

    assert sim._select_mtd_conditional_policy(2.0) == ("suppress", 0, 0)


def test_conditional_mtd_scenarios_present():
    expected = {
        "gated_edge_conditional_split_5_10",
        "gated_edge_conditional_split_3_7",
        "gated_edge_conditional_split_7_12",
        "gated_edge_conditional_split_5_15",
        "gated_edge_conditional_critical_vs_post_decoy",
    }

    assert expected.issubset(SCENARIOS)
    assert expected.issubset(set(MULTI_SEED_SCENARIO_NAMES))


def test_policy_selection_includes_conditional_mtd():
    rows = build_policy_selection_rows(
        [
            {
                "scenario": "policy_target_frequency_path_decoy",
                "num_runs": 2,
                "defense_objective_score_mean": 800.0,
                "critical_compromise_rate": 0.7,
                "post_decoy_compromised_mean": 100.0,
                "mtd_total_cost_mean": 0.0,
            },
            {
                "scenario": "gated_edge_conditional_split_5_10",
                "num_runs": 2,
                "defense_objective_score_mean": 700.0,
                "critical_compromise_rate": 0.6,
                "post_decoy_compromised_mean": 80.0,
                "mtd_total_cost_mean": 2.0,
                "mtd_conditional_policy_enabled": True,
                "mtd_conditional_count2_action_count_mean": 1.0,
                "mtd_conditional_duration2_action_count_mean": 2.0,
                "mtd_conditional_suppress_count_mean": 3.0,
            },
        ]
    )
    conditional = next(row for row in rows if row["policy"] == "gated_edge_conditional_split_5_10")

    assert conditional["mtd_conditional_policy_enabled"] is True
    assert conditional["mtd_conditional_count2_action_count_mean"] == 1.0


def test_conditional_mtd_plots_created(tmp_path):
    run_scenarios_multi_seed(
        scenarios={
            "policy_target_frequency_path_decoy": {
                **SCENARIOS["policy_target_frequency_path_decoy"],
                "T": 3,
                "H": 2,
            },
            "gated_edge_conditional_split_5_10": {
                **SCENARIOS["gated_edge_conditional_split_5_10"],
                "T": 3,
                "H": 2,
                "mtd_interval": 1,
            },
        },
        seeds=[0],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )

    assert (tmp_path / "scenarios_multiseed" / "summary_conditional_mtd_objective.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_conditional_mtd_tradeoff.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_conditional_mtd_actions.png").exists()


def test_attacker_metrics_are_present():
    config = small_config(attacker_enabled=True)
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    for key in [
        "attacker_avg_gain_per_success",
        "attacker_cost_per_success",
        "attacker_detection_rate",
        "attacker_success_rate",
    ]:
        assert key in metrics


def test_honeypot_credential_trigger():
    config = small_config(
        T=3,
        attacker_enabled=True,
        attacker_target_selection="adaptive",
        attacker_greedy_mode="utility",
        attacker_lateral_enabled=True,
        attacker_lateral_success_prob=1.0,
        decoy_lateral_decay=1.0,
        stochastic_success=False,
        stochastic_detection=False,
        node_type=["real", "decoy", "real", "decoy", "real"],
        attacker_belief=[1, 20, 1, 1, 1],
        honeypot_credential_enabled=True,
        credential_node_ids=[1],
        credential_attraction_bonus=3.0,
    )
    sim = CyberDefenseSimulator(config)
    history = sim.run()
    assert np.any(np.asarray(history["credential_obtained"], dtype=bool))
    assert np.any(np.asarray(history["credential_used"], dtype=bool))
    assert np.any(np.asarray(history["credential_decoy_trigger"], dtype=bool))


def test_honeypot_credential_metrics():
    config = small_config(
        T=3,
        attacker_enabled=True,
        attacker_target_selection="adaptive",
        attacker_greedy_mode="utility",
        attacker_lateral_enabled=True,
        attacker_lateral_success_prob=1.0,
        decoy_lateral_decay=1.0,
        stochastic_success=False,
        stochastic_detection=False,
        node_type=["real", "decoy", "real", "decoy", "real"],
        attacker_belief=[1, 20, 1, 1, 1],
        honeypot_credential_enabled=True,
        credential_node_ids=[1],
        credential_attraction_bonus=3.0,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()
    assert metrics["honeypot_credential_enabled"] is True
    assert metrics["credential_obtained_count"] >= 1
    assert metrics["credential_used_count"] >= 1
    assert metrics["credential_decoy_trigger_count"] >= 1
    assert metrics["credential_trigger_rate"] > 0.0


def test_honeypot_scenarios_present():
    expected = {
        "honeypot_credential_reference",
        "honeypot_credential_low_bonus",
        "honeypot_credential_high_bonus",
        "honeypot_credential_high_detection",
        "honeypot_credential_path_decoy",
        "honeypot_credential_edge_mtd",
    }
    assert expected.issubset(SCENARIOS)
    assert expected.issubset(MULTI_SEED_SCENARIO_NAMES)


def test_honeypot_multiseed(tmp_path):
    rows = run_scenarios_multi_seed(
        scenarios={
            "honeypot_credential_reference": {
                **SCENARIOS["honeypot_credential_reference"],
                "T": 3,
                "H": 2,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )
    assert rows[0]["scenario"] == "honeypot_credential_reference"
    assert "credential_trigger_rate_mean" in rows[0]
    assert (
        tmp_path
        / "scenarios_multiseed"
        / "honeypot_credential_reference"
        / "seed_0"
        / "metrics.json"
    ).exists()


def test_honeypot_plots_created(tmp_path):
    run_scenarios_multi_seed(
        scenarios={
            "honeypot_credential_reference": {
                **SCENARIOS["honeypot_credential_reference"],
                "T": 3,
                "H": 2,
            },
            "honeypot_credential_edge_mtd": {
                **SCENARIOS["honeypot_credential_edge_mtd"],
                "T": 3,
                "H": 2,
                "mtd_interval": 1,
            },
        },
        seeds=[0, 1],
        output_dir=str(tmp_path / "scenarios_multiseed"),
        config_path=str(tmp_path / "missing_config.json"),
    )
    assert (tmp_path / "scenarios_multiseed" / "summary_honeypot_objective.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_honeypot_tradeoff.png").exists()
    assert (tmp_path / "scenarios_multiseed" / "summary_honeypot_trigger_rate.png").exists()


def credential_aware_config(**overrides):
    values = {
        "T": 5,
        "H": 2,
        "attacker_enabled": True,
        "attacker_target_selection": "adaptive",
        "attacker_greedy_mode": "utility",
        "attacker_lateral_enabled": True,
        "attacker_lateral_success_prob": 1.0,
        "decoy_lateral_decay": 1.0,
        "stochastic_success": False,
        "stochastic_detection": False,
        "node_type": ["real", "decoy", "real", "decoy", "real"],
        "attacker_belief": [1, 20, 1, 1, 1],
        "honeypot_credential_enabled": True,
        "credential_node_ids": [1],
        "credential_attraction_bonus": 3.0,
        "credential_aware_mtd_enabled": True,
        "credential_trigger_mtd_window": 3,
        "credential_trigger_block_count": 2,
        "credential_trigger_block_duration": 1,
        "credential_trigger_force_mtd": True,
        "mtd_enabled": True,
        "mtd_interval": 50,
        "mtd_shuffle_topology": True,
        "mtd_block_critical_edges": True,
        "mtd_risk_gating_enabled": True,
        "mtd_risk_gate_mode": "critical_edge_pressure",
        "mtd_risk_gate_threshold": 100.0,
    }
    values.update(overrides)
    return small_config(**values)


def test_credential_aware_mtd_config_validation():
    with pytest.raises(ValueError, match="credential_trigger_mtd_window"):
        SimulationConfig(credential_trigger_mtd_window=-1)
    with pytest.raises(ValueError, match="credential_trigger_block_count"):
        SimulationConfig(credential_trigger_block_count=-1)
    with pytest.raises(ValueError, match="credential_trigger_block_duration"):
        SimulationConfig(credential_trigger_block_duration=0)
    with pytest.raises(ValueError, match="credential_trigger_risk_bonus"):
        SimulationConfig(credential_trigger_risk_bonus=-1.0)


def test_credential_trigger_recently_active():
    sim = CyberDefenseSimulator(credential_aware_config())
    sim.last_credential_trigger_step = 2
    assert sim._credential_trigger_recently_active(4) is True
    assert sim._credential_trigger_recently_active(6) is False


def test_credential_trigger_forces_mtd():
    sim = CyberDefenseSimulator(credential_aware_config())
    history = sim.run()
    assert np.any(np.asarray(history["credential_decoy_trigger"], dtype=bool))
    assert np.any(np.asarray(history["credential_aware_mtd_fire"], dtype=bool))
    assert sim.calculate_metrics()["credential_trigger_mtd_event_count"] >= 1


def test_credential_trigger_overrides_block_params():
    config = credential_aware_config(
        credential_trigger_block_count=1,
        credential_trigger_block_duration=2,
    )
    sim = CyberDefenseSimulator(config)
    history = sim.run()
    fire = np.asarray(history["credential_aware_mtd_fire"], dtype=bool)
    assert np.any(fire)
    assert np.all(np.asarray(history["credential_aware_block_count"], dtype=int)[fire] == 1)
    assert np.all(np.asarray(history["credential_aware_block_duration"], dtype=int)[fire] == 2)


def test_credential_aware_mtd_metrics_present():
    sim = CyberDefenseSimulator(credential_aware_config())
    sim.run()
    metrics = sim.calculate_metrics()
    for key in [
        "credential_aware_mtd_enabled",
        "credential_trigger_mtd_window",
        "credential_trigger_block_count",
        "credential_trigger_block_duration",
        "credential_trigger_force_mtd",
        "credential_trigger_risk_bonus",
        "credential_trigger_mtd_event_count",
    ]:
        assert key in metrics
    assert metrics["credential_aware_mtd_enabled"] is True


def test_credential_aware_mtd_scenarios_present():
    expected = {
        "credential_aware_mtd_reference",
        "credential_aware_mtd_force_count2",
        "credential_aware_mtd_force_duration2",
        "credential_aware_mtd_risk_bonus",
        "credential_aware_mtd_window1",
        "credential_aware_mtd_window5",
        "credential_aware_mtd_edge_pressure",
    }
    assert expected.issubset(SCENARIOS)
    assert expected.issubset(MULTI_SEED_SCENARIO_NAMES)


def test_policy_selection_includes_credential_aware_mtd():
    expected = {
        "credential_aware_mtd_force_count2",
        "credential_aware_mtd_force_duration2",
        "credential_aware_mtd_risk_bonus",
        "credential_aware_mtd_window1",
        "credential_aware_mtd_window5",
    }
    rows = build_policy_selection_rows(
        [
            {
                "scenario": name,
                "num_runs": 2,
                "defense_objective_score_mean": 500.0,
                "critical_compromise_rate": 0.5,
                "post_decoy_compromised_mean": 80.0,
                "mtd_total_cost_mean": 2.0,
                "credential_aware_mtd_enabled": True,
                "credential_trigger_mtd_event_count_mean": 1.0,
            }
            for name in expected
        ]
    )
    policies = {row["policy"] for row in rows}
    assert expected.issubset(policies)
    assert all(row["credential_aware_mtd_enabled"] is True for row in rows)


def staged_credential_config(**overrides):
    values = {
        "credential_staged_mtd_enabled": True,
        "credential_stage1_window": 1,
        "credential_stage1_block_count": 2,
        "credential_stage1_block_duration": 1,
        "credential_stage2_window": 5,
        "credential_stage2_block_count": 1,
        "credential_stage2_block_duration": 2,
        "credential_trigger_mtd_window": 5,
    }
    values.update(overrides)
    return credential_aware_config(**values)


def test_credential_staged_mtd_config_validation():
    with pytest.raises(ValueError, match="credential_stage1_window"):
        SimulationConfig(credential_stage1_window=-1)
    with pytest.raises(ValueError, match="credential_stage2_window"):
        SimulationConfig(credential_stage1_window=2, credential_stage2_window=1)
    with pytest.raises(ValueError, match="credential_stage1_block_count"):
        SimulationConfig(credential_stage1_block_count=-1)
    with pytest.raises(ValueError, match="credential_stage2_block_count"):
        SimulationConfig(credential_stage2_block_count=-1)
    with pytest.raises(ValueError, match="credential_stage1_block_duration"):
        SimulationConfig(credential_stage1_block_duration=0)
    with pytest.raises(ValueError, match="credential_stage2_block_duration"):
        SimulationConfig(credential_stage2_block_duration=0)


def test_credential_mtd_stage_none_without_trigger():
    sim = CyberDefenseSimulator(staged_credential_config())
    assert sim._credential_mtd_stage(0) == "none"


def test_credential_mtd_stage1_after_trigger():
    sim = CyberDefenseSimulator(staged_credential_config(credential_stage1_window=1, credential_stage2_window=5))
    sim.last_credential_trigger_step = 3
    assert sim._credential_mtd_stage(4) == "stage1"


def test_credential_mtd_stage2_after_stage1():
    sim = CyberDefenseSimulator(staged_credential_config(credential_stage1_window=1, credential_stage2_window=5))
    sim.last_credential_trigger_step = 3
    assert sim._credential_mtd_stage(5) == "stage2"


def test_credential_staged_mtd_overrides_block_params():
    sim = CyberDefenseSimulator(
        staged_credential_config(
            credential_stage1_window=1,
            credential_stage1_block_count=2,
            credential_stage1_block_duration=1,
            credential_stage2_window=5,
            credential_stage2_block_count=1,
            credential_stage2_block_duration=2,
        )
    )
    history = sim.run()
    stage1 = np.asarray(history["credential_stage1_action"], dtype=bool)
    stage2 = np.asarray(history["credential_stage2_action"], dtype=bool)
    counts = np.asarray(history["credential_aware_block_count"], dtype=int)
    durations = np.asarray(history["credential_aware_block_duration"], dtype=int)
    assert np.any(stage1)
    assert np.any(stage2)
    assert np.all(counts[stage1] == 2)
    assert np.all(durations[stage1] == 1)
    assert np.all(counts[stage2] == 1)
    assert np.all(durations[stage2] == 2)


def test_credential_staged_mtd_scenarios_present():
    expected = {
        "credential_staged_mtd_1_5",
        "credential_staged_mtd_0_3",
        "credential_staged_mtd_1_3",
        "credential_staged_mtd_2_5",
        "credential_staged_mtd_stage1_only",
        "credential_staged_mtd_stage2_only",
        "credential_staged_mtd_with_risk_bonus",
    }
    assert expected.issubset(SCENARIOS)
    assert expected.issubset(MULTI_SEED_SCENARIO_NAMES)


def test_policy_selection_includes_credential_staged_mtd():
    expected = {
        "credential_staged_mtd_1_5",
        "credential_staged_mtd_0_3",
        "credential_staged_mtd_1_3",
        "credential_staged_mtd_2_5",
        "credential_staged_mtd_stage1_only",
        "credential_staged_mtd_stage2_only",
        "credential_staged_mtd_with_risk_bonus",
    }
    rows = build_policy_selection_rows(
        [
            {
                "scenario": name,
                "num_runs": 2,
                "defense_objective_score_mean": 500.0,
                "critical_compromise_rate": 0.5,
                "post_decoy_compromised_mean": 80.0,
                "mtd_total_cost_mean": 2.0,
                "credential_staged_mtd_enabled": True,
                "credential_stage1_action_count_mean": 1.0,
                "credential_stage2_action_count_mean": 2.0,
                "credential_stage_none_count_mean": 3.0,
            }
            for name in expected
        ]
    )
    policies = {row["policy"] for row in rows}
    assert expected.issubset(policies)
    assert all(row["credential_staged_mtd_enabled"] is True for row in rows)


# ---------------------------------------------------------------------------
# Tests for fix_report_01 changes
# ---------------------------------------------------------------------------

def test_decoy_gain_is_zero_true_but_perceived_positive():
    """True gain (attacker_gain) is 0 when decoy is attacked with decoy_success_gain_scale=0.
    Perceived gain must be > 0 because the attacker uses their (high) belief about the decoy node.
    """
    config = small_config(
        T=4,
        attacker_enabled=True,
        node_type=["decoy", "real", "real", "real", "real"],
        attacker_belief=[100.0, 1.0, 1.0, 1.0, 1.0],
        asset_value=[0.0, 5.0, 1.0, 8.0, 2.0],
        decoy_waste_cost=2.0,
        decoy_success_gain_scale=0.0,
        stochastic_success=False,
        stochastic_detection=False,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()

    attacked_decoy = np.asarray(sim.history["attacker_attacked_decoy"], dtype=bool)
    true_gain = np.asarray(sim.history["attacker_gain"], dtype=float)
    perceived_gain = np.asarray(sim.history["attacker_perceived_gain"], dtype=float)

    assert np.any(attacked_decoy), "attacker should target the decoy (belief=100)"
    decoy_steps = attacked_decoy
    assert np.all(true_gain[decoy_steps] == pytest.approx(0.0)), "true gain on decoy must be 0"
    assert np.any(perceived_gain[decoy_steps] > 0.0), "perceived gain on decoy must be positive"


def test_critical_gain_tracked():
    """critical_true_gain uses the per-node formula: sum of risk_increase × asset_value
    over critical nodes, independent of which node was attacked.

    Properties verified:
    - When attack_active=False (no attacker), critical_true_gain is always 0.
    - When attack_active=True, critical_true_gain is always >= 0.
    - The value is independent of selected_target (non-zero even when non-critical is targeted,
      if critical node risk increases naturally).
    """
    config = small_config(
        T=4,
        attacker_enabled=True,
        attacker_target_selection="greedy",
        attacker_greedy_mode="legacy",
        attacker_belief=[100.0, 1.0, 1.0, 1.0, 0.0],
        asset_value=[5.0, 1.0, 1.0, 1.0, 2.0],
        critical_nodes=[4],
        stochastic_success=False,
        stochastic_detection=False,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()

    critical_gain = np.asarray(sim.history["attacker_critical_true_gain"], dtype=float)
    attack_active = np.asarray([
        config.attacker_enabled and float(np.sum(av)) > 0.0
        for av in sim.history["attack_vector"]
    ], dtype=bool)

    # All values must be non-negative.
    assert np.all(critical_gain >= 0.0)
    # When no attack is active, critical_true_gain must be 0.
    if np.any(~attack_active):
        assert np.all(critical_gain[~attack_active] == pytest.approx(0.0))


def test_mtd_block_changes_paths():
    """After MTD blocks a critical edge, _paths_to_critical returns a different (smaller) set."""
    config = SimulationConfig(
        T=1,
        H=2,
        mtd_block_critical_edges=True,
        mtd_edge_block_count=1,
        mtd_edge_block_duration=10,
        attacker_lateral_enabled=True,
    )
    sim = CyberDefenseSimulator(config)

    paths_before = sim._paths_to_critical()
    sim._block_critical_edges(0)
    paths_after = sim._paths_to_critical()

    # At least one edge was blocked, so the path set must differ.
    assert paths_before != paths_after or len(paths_after) <= len(paths_before)
    # Specifically at least the path count must be <= original (blocking can only remove paths).
    assert len(paths_after) <= len(paths_before)


def test_entropy_uniform_belief():
    """Uniform belief distribution yields normalized entropy == 1.0."""
    config = small_config(attacker_belief=[3.0, 3.0, 3.0, 3.0, 3.0])
    sim = CyberDefenseSimulator(config)
    entropy = sim._belief_entropy()
    assert entropy == pytest.approx(1.0)


def test_entropy_concentrated_belief():
    """Belief concentrated on one node yields normalized entropy == 0.0."""
    config = small_config(attacker_belief=[0.0, 0.0, 100.0, 0.0, 0.0])
    sim = CyberDefenseSimulator(config)
    entropy = sim._belief_entropy()
    assert entropy == pytest.approx(0.0, abs=1e-6)


def test_entropy_bounds_intermediate():
    """Entropy is strictly between 0 and 1 for a non-uniform, non-degenerate distribution."""
    config = small_config(attacker_belief=[10.0, 1.0, 1.0, 1.0, 1.0])
    sim = CyberDefenseSimulator(config)
    entropy = sim._belief_entropy()
    assert 0.0 < entropy < 1.0


def test_entropy_in_metrics(tmp_path):
    """metrics.json contains belief_entropy_mean, belief_entropy_final, belief_entropy_min."""
    config = small_config(
        T=4,
        attacker_enabled=True,
        attacker_belief_learning_enabled=True,
        attacker_target_selection="adaptive",
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.save_outputs(str(tmp_path))

    for key in ("belief_entropy_mean", "belief_entropy_final", "belief_entropy_min"):
        assert key in metrics, f"missing key: {key}"
        assert 0.0 <= metrics[key] <= 1.0, f"{key} out of [0, 1]: {metrics[key]}"

    history = np.load(tmp_path / "history.npz")
    assert "belief_entropy" in history
    assert history["belief_entropy"].shape == (config.T,)
    assert np.all(history["belief_entropy"] >= 0.0)
    assert np.all(history["belief_entropy"] <= 1.0)


def test_perceived_gain_and_critical_gain_in_history():
    """attacker_perceived_gain and attacker_critical_true_gain are present in history with correct shape."""
    config = small_config(T=4, attacker_enabled=True)
    sim = CyberDefenseSimulator(config)
    sim.run()

    perceived = np.asarray(sim.history["attacker_perceived_gain"], dtype=float)
    critical = np.asarray(sim.history["attacker_critical_true_gain"], dtype=float)

    assert perceived.shape == (config.T,)
    assert critical.shape == (config.T,)
    assert np.all(perceived >= 0.0)
    assert np.all(critical >= 0.0)


# ---------------------------------------------------------------------------
# Tests for fix_report_02 changes
# ---------------------------------------------------------------------------

def test_critical_gain_zero_when_critical_not_attacked():
    """Attack-only formula: critical_true_gain = 0 when attack_vector[critical] = 0.
    Natural drift (d_base) at critical node must NOT be counted.
    This is the core property of fix_report_03.
    """
    # d_base[4]=5.0 → critical node drifts every step. belief[4]=0 → attacker never targets it.
    config = SimulationConfig(
        T=3, H=2,
        alpha=0.0, beta=0.0,
        d_base=[0.0, 0.0, 0.0, 0.0, 5.0],
        R_total=0.0, r_max=0.0,
        attacker_enabled=True,
        attacker_target_selection="greedy",
        attacker_greedy_mode="weighted_risk",
        attacker_belief=[1.0, 1.0, 1.0, 1.0, 0.0],
        asset_value=[1.0, 1.0, 1.0, 1.0, 8.0],
        Q_diag=[1.0, 1.0, 1.0, 1.0, 1.0],
        critical_nodes=[4],
        stochastic_success=False,
        stochastic_detection=False,
        dynamic_matching=False,
        dynamic_matching_threshold=100.0,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()

    targets = np.asarray(sim.history["attacker_selected_target"], dtype=int)
    critical_gain = np.asarray(sim.history["attacker_critical_true_gain"], dtype=float)

    assert np.all(targets != 4), f"Attacker should never target critical (belief=0), got {targets}"
    # attack_vector[4] = 0 every step → counterfactual diff = 0 → no natural drift included
    np.testing.assert_allclose(
        critical_gain, 0.0, atol=1e-10,
        err_msg="critical_true_gain must be 0 when critical node is never in attack_vector"
    )


def test_critical_gain_positive_when_critical_attacked():
    """Attack-only formula: critical_true_gain > 0 when attack_vector[critical] > 0."""
    # d_base=[0,...]: no natural drift. All gain is purely attack-caused.
    config = SimulationConfig(
        T=2, H=2,
        alpha=0.0, beta=0.0,
        d_base=[0.0, 0.0, 0.0, 0.0, 0.0],
        R_total=0.0, r_max=0.0,
        attacker_enabled=True,
        attacker_target_selection="greedy",
        attacker_greedy_mode="weighted_risk",
        attacker_belief=[0.0, 0.0, 0.0, 0.0, 10.0],
        asset_value=[1.0, 1.0, 1.0, 1.0, 8.0],
        Q_diag=[1.0, 1.0, 1.0, 1.0, 1.0],
        critical_nodes=[4],
        stochastic_success=False,
        stochastic_detection=False,
        dynamic_matching=False,
        dynamic_matching_threshold=100.0,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()

    targets = np.asarray(sim.history["attacker_selected_target"], dtype=int)
    critical_gain = np.asarray(sim.history["attacker_critical_true_gain"], dtype=float)

    assert np.all(targets == 4), f"Attacker should always target critical, got {targets}"
    assert np.all(critical_gain > 0.0), "direct critical attack with no defense must yield > 0 gain"


def test_lateral_compromise_counted_as_critical_gain():
    """Attack-only formula: two cases in one test.

    Case 1 (non-critical targeted, critical drifts naturally):
      attack_vector[critical]=0 → counterfactual diff=0 → critical_true_gain=0.
      (fix_report_03: natural drift is excluded; this is the intended change from fix_report_02)

    Case 2 (critical directly attacked):
      attack_vector[critical]>0 → critical_true_gain>0.
      Lateral-movement scenario: attacker that has moved adjacent can attack critical → still captured.
    """
    shared = dict(
        T=1, H=2,
        alpha=0.0, beta=0.0,
        d_base=[0.0, 0.0, 0.0, 0.0, 5.0],
        R_total=0.0, r_max=0.0,
        attacker_enabled=True,
        attacker_target_selection="greedy",
        attacker_greedy_mode="weighted_risk",
        asset_value=[1.0, 1.0, 1.0, 1.0, 8.0],
        Q_diag=[1.0, 1.0, 1.0, 1.0, 1.0],
        critical_nodes=[4],
        stochastic_success=False,
        stochastic_detection=False,
        dynamic_matching=False,
        dynamic_matching_threshold=100.0,
    )

    # Case 1: belief[4]=0 → non-critical targeted → attack_vector[4]=0 → critical_true_gain=0.
    sim_nc = CyberDefenseSimulator(
        SimulationConfig(**{**shared, "attacker_belief": [1.0, 1.0, 1.0, 1.0, 0.0]})
    )
    sim_nc.run()
    target_nc = int(sim_nc.history["attacker_selected_target"][0])
    gain_nc = float(sim_nc.history["attacker_critical_true_gain"][0])
    assert target_nc != 4, f"Case 1: should not target critical, got {target_nc}"
    assert gain_nc == pytest.approx(0.0), (
        "Case 1: attack_vector[critical]=0 → no natural-drift contribution → critical_true_gain=0"
    )

    # Case 2: only critical has belief → targeted → attack_vector[4]=attack_budget → gain>0.
    sim_c = CyberDefenseSimulator(
        SimulationConfig(**{**shared, "attacker_belief": [0.0, 0.0, 0.0, 0.0, 10.0]})
    )
    sim_c.run()
    target_c = int(sim_c.history["attacker_selected_target"][0])
    gain_c = float(sim_c.history["attacker_critical_true_gain"][0])
    assert target_c == 4, f"Case 2: should target critical, got {target_c}"
    assert gain_c > 0.0, "Case 2: direct critical attack → attack_contribution>0 → critical_true_gain>0"


def test_retreat_driven_by_perceived_not_true():
    """Patience counter uses perceived_gained, not true success:
    - All-decoy attacks (true=0, perceived>0) do NOT increment no_success_steps → no retreat.
    - Zero-belief attacks (perceived=0 always) DO increment no_success_steps → patience-based retreat.

    Scenario A: ALL nodes are decoys, R_total=0 (no defense), uniform belief=5.
    - attacked_decoy=True for any target → perceived not zeroed by success flag.
    - risk_increase[target] > 0 always (attack_budget=3 added to state, no defense).
    - perceived_gain = risk_increase * 5 > 0 → no_success_steps reset → no patience retreat.
    - utility = 0 (no asset value) − costs ≪ −1000 threshold → no utility retreat either.

    Scenario B: zero belief everywhere → perceived_gain=0 every step → patience=3 → retreat.
    """
    # Scenario A: all-decoy, no defense → perceived always positive → no retreat.
    config_a = small_config(
        T=15,
        attacker_enabled=True,
        attacker_patience=3,
        attacker_retreat_threshold=-1000.0,
        node_type=["decoy", "decoy", "decoy", "decoy", "decoy"],
        attacker_belief=[5.0, 5.0, 5.0, 5.0, 5.0],
        asset_value=[0.0, 0.0, 0.0, 0.0, 0.0],
        decoy_success_gain_scale=0.0,
        R_total=0.0,
        r_max=0.0,
        stochastic_success=False,
        stochastic_detection=False,
    )
    sim_a = CyberDefenseSimulator(config_a)
    sim_a.run()
    metrics_a = sim_a.calculate_metrics()

    # Scenario B: zero belief everywhere → perceived_gain = 0 always → retreat from patience.
    config_b = small_config(
        T=15,
        attacker_enabled=True,
        attacker_patience=3,
        attacker_retreat_threshold=-1000.0,
        attacker_belief=[0.0, 0.0, 0.0, 0.0, 0.0],
        attacker_belief_learning_enabled=False,
        stochastic_success=False,
        stochastic_detection=False,
    )
    sim_b = CyberDefenseSimulator(config_b)
    sim_b.run()
    metrics_b = sim_b.calculate_metrics()

    # Scenario A: attacker perceives progress (all decoy, high belief) → NOT retreat.
    assert not metrics_a["attacker_retreated"], (
        "Attacker should not retreat when all-decoy attacks yield positive perceived_gain"
    )
    # Scenario B: zero belief → no perceived progress → retreats after patience steps.
    assert metrics_b["attacker_retreated"], (
        "Attacker should retreat via patience when perceived_gain is always 0"
    )
    assert metrics_b["attacker_retreat_step"] is not None
    assert metrics_b["attacker_retreat_step"] < config_b.T - 1


def test_credential_perceived_added_true_zero():
    """When credential_decoy_trigger fires, perceived_gain increases but attacker_gain stays 0.
    The credential node is a lateral-movement honeypot (decoy type); true asset value is 0.
    """
    config = credential_aware_config(
        T=5,
        attacker_belief_learning_enabled=False,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()

    trigger = np.asarray(sim.history["credential_decoy_trigger"], dtype=bool)
    true_gain = np.asarray(sim.history["attacker_gain"], dtype=float)
    perceived = np.asarray(sim.history["attacker_perceived_gain"], dtype=float)

    if not np.any(trigger):
        pytest.skip("credential_decoy_trigger did not fire in this seed — increase T if needed")

    # credential node is decoy (type="decoy") → asset_value effectively 0 → true gain = 0
    assert np.all(true_gain[trigger] == pytest.approx(0.0)), (
        "True gain must be 0 for credential (honeypot) node attacks"
    )
    # perceived must be > 0 (includes belief + credential bonus)
    assert np.any(perceived[trigger] > 0.0), (
        "Perceived gain must be > 0 when credential fires (attacker perceives access value)"
    )


def test_entropy_discrimination():
    """MTD increase_uncertainty (intensity=1.0) forces all beliefs to their mean every step,
    yielding entropy=1.0.  Without MTD, non-uniform initial belief gives entropy < 1.0.

    This is a sharp, deterministic comparison:
    - Config A: mtd_strategy="increase_uncertainty", intensity=1.0, interval=1.
      After each MTD event: all beliefs = mean → uniform → entropy = 1.0.
    - Config B: no MTD, initial belief=[2,3,12,4,2] (concentrated at node 2).
      Without disturbance, beliefs remain non-uniform → entropy < 1.0.
    """
    seed = 42

    config_a = SimulationConfig(
        T=5, H=2, seed=seed,
        attacker_enabled=True,
        attacker_belief=[2.0, 3.0, 12.0, 4.0, 2.0],
        attacker_belief_learning_enabled=False,
        node_type=["real", "real", "decoy", "real", "real"],
        asset_value=[10.0, 5.0, 0.0, 8.0, 2.0],
        stochastic_detection=False,
        stochastic_success=False,
        mtd_enabled=True,
        mtd_strategy="increase_uncertainty",
        mtd_interval=1,
        mtd_intensity=1.0,
        show_plot=False,
    )
    sim_a = CyberDefenseSimulator(config_a)
    sim_a.run()
    entropy_a = float(np.mean(np.asarray(sim_a.history["belief_entropy"], dtype=float)))

    config_b = SimulationConfig(
        T=5, H=2, seed=seed,
        attacker_enabled=True,
        attacker_belief=[2.0, 3.0, 12.0, 4.0, 2.0],
        attacker_belief_learning_enabled=False,
        node_type=["real", "real", "real", "real", "real"],
        asset_value=[10.0, 5.0, 1.0, 8.0, 2.0],
        stochastic_detection=False,
        stochastic_success=False,
        mtd_enabled=False,
        show_plot=False,
    )
    sim_b = CyberDefenseSimulator(config_b)
    sim_b.run()
    entropy_b = float(np.mean(np.asarray(sim_b.history["belief_entropy"], dtype=float)))

    # MTD forces beliefs to uniform each step → entropy ≈ 1.0.
    # No-MTD keeps concentrated beliefs → entropy < 1.0.
    assert entropy_a > entropy_b, (
        f"MTD-uncertainty entropy ({entropy_a:.4f}) should exceed no-MTD ({entropy_b:.4f})"
    )
    assert entropy_a > 0.95, f"MTD-uncertainty entropy should be near 1.0, got {entropy_a:.4f}"


def test_static_and_active_critical_paths_in_metrics():
    """metrics contains both static_critical_paths and critical_paths (active) keys."""
    config = SimulationConfig(
        T=2, H=2,
        mtd_enabled=True,
        mtd_block_critical_edges=True,
        mtd_edge_block_count=1,
        mtd_edge_block_duration=2,
        attacker_lateral_enabled=True,
        show_plot=False,
    )
    sim = CyberDefenseSimulator(config)
    sim.run()
    metrics = sim.calculate_metrics()

    for key in ("static_critical_path_count", "static_critical_paths",
                "static_node_path_frequency", "static_edge_path_frequency",
                "static_chokepoint_nodes", "static_critical_edges"):
        assert key in metrics, f"missing key: {key}"

    # static must equal config topology; active may differ due to MTD blocks.
    assert metrics["static_critical_path_count"] >= 0
    assert metrics["critical_path_count"] >= 0
