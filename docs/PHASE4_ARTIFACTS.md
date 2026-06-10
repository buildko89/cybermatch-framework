# Phase4 Artifacts

Phase4 outputs are generated under `output/`. The `output/` directory is intentionally ignored by git, so this document is the publication index for regenerating and reviewing Phase4 artifacts.

Regenerate representative publication artifacts:

```powershell
python .\scripts\run_phase4.py --quick
```

Regenerate the full Phase4 publication workflow:

```powershell
python .\scripts\run_phase4.py --publication
```

## Artifact Index

Each Phase4 output directory follows the same artifact pattern:

- summary csv/json: `*_summary.csv`, `*_summary.json`
- plots: `*.png`
- report: `PHASE*_REPORT.md`
- run-level details: `runs/summary_runs.csv`, `runs/summary_stats.json`

| Phase | Output directory | Summary artifacts | Plot artifacts | Markdown report |
| --- | --- | --- | --- | --- |
| Phase4.1 | `output/phase4_adaptive_defender/` | `adaptive_defender_summary.csv`, `adaptive_defender_summary.json` | `adaptive_defender_*.png` | `PHASE4_ADAPTIVE_DEFENDER_REPORT.md` |
| Phase4.2 | `output/phase4_cns_guided/` | `cns_guided_summary.csv`, `cns_guided_summary.json` | `cns_guided_*.png` | `PHASE4_CNS_GUIDED_REPORT.md` |
| Phase4.3 | `output/phase4_step_adaptive/` | `step_adaptive_summary.csv`, `step_adaptive_summary.json` | `step_adaptive_*.png` | `PHASE4_STEP_ADAPTIVE_REPORT.md` |
| Phase4.4 | `output/phase4_nonstationary/` | `nonstationary_summary.csv`, `nonstationary_summary.json` | `nonstationary_*.png` | `PHASE4_NONSTATIONARY_REPORT.md` |
| Phase4.5 | `output/phase4_switch_benefit/` | `switch_benefit_summary.csv`, `switch_benefit_summary.json` | `switch_benefit_*.png` | `PHASE4_SWITCH_BENEFIT_REPORT.md` |
| Phase4.6 | `output/phase4_specialized_policy/` | `specialized_policy_summary.csv`, `specialized_policy_summary.json` | `specialized_policy_*.png` | `PHASE4_SPECIALIZED_POLICY_REPORT.md` |
| Phase4.7 | `output/phase47_mission_profiles/` | `mission_profile_summary.csv`, `mission_profile_summary.json` | `mission_profile_*.png` | `PHASE47_MISSION_PROFILE_REPORT.md` |
| Phase4.8 | `output/phase48_mission_aware/` | `mission_aware_summary.csv`, `mission_aware_summary.json` | `mission_aware_*.png` | `PHASE48_MISSION_AWARE_REPORT.md` |
| Phase4.9 | `output/phase49_mission_belief/` | `mission_belief_summary.csv`, `mission_belief_summary.json` | `mission_belief_*.png` | `PHASE49_MISSION_BELIEF_REPORT.md` |
| Phase4.10 | `output/phase410_state_belief/` | `state_belief_summary.csv`, `state_belief_summary.json` | `state_belief_*.png` | `PHASE410_STATE_BELIEF_REPORT.md` |
| Phase4.11 | `output/phase411_virtual_topology/` | `virtual_topology_summary.csv`, `virtual_topology_summary.json` | `virtual_topology_*.png` | `PHASE411_VIRTUAL_TOPOLOGY_REPORT.md` |
| Phase4.12 | `output/phase412_critical_path/` | `critical_path_summary.csv`, `critical_path_summary.json` | `critical_path_*.png` | `PHASE412_CRITICAL_PATH_REPORT.md` |
| Phase4.13 | `output/phase413_intelligence_defender/` | `intelligence_summary.csv`, `intelligence_summary.json` | `intelligence_*.png`, `risk_level_transition.png` | `PHASE413_INTELLIGENCE_DEFENDER_REPORT.md` |
| Phase4.14 | `output/phase414_weight_sweep/` | `weight_sweep_summary.csv`, `weight_sweep_summary.json` | `weight_sweep_*.png` | `PHASE414_WEIGHT_SWEEP_REPORT.md` |
| Phase4.15 | `output/phase415_decision_matrix/` | `decision_matrix_summary.csv`, `decision_matrix_summary.json` | `decision_matrix_*.png` | `PHASE415_DECISION_MATRIX_REPORT.md` |
| Phase4.16 | `output/phase416_defense_campaign/` | `defense_campaign_summary.csv`, `defense_campaign_summary.json` | `defense_campaign_*.png` | `PHASE416_DEFENSE_CAMPAIGN_REPORT.md` |
| Phase4.17 | `output/phase417_campaign_profiles/` | `campaign_profile_summary.csv`, `campaign_profile_summary.json` | `campaign_profile_*.png` | `PHASE417_CAMPAIGN_PROFILE_REPORT.md` |
| Phase4.18 | `output/phase418_mission_objectives/` | `mission_objective_summary.csv`, `mission_objective_summary.json` | `mission_*.png`, `strategy_by_mission.png` | `PHASE418_MISSION_OBJECTIVE_REPORT.md` |
| Phase4.19 | `output/phase419_mission_sensitivity/` | `mission_sensitivity_summary.csv`, `mission_sensitivity_summary.json` | `mission_sensitivity_*.png` | `PHASE419_MISSION_SENSITIVITY_REPORT.md` |
| Phase4.20 | `output/phase420_adaptive_mission/` | `adaptive_mission_summary.csv`, `adaptive_mission_summary.json` | `adaptive_mission_*.png` | `PHASE420_ADAPTIVE_MISSION_REPORT.md` |
| Phase4.21 | `output/phase421_mission_mutation/` | `mission_mutation_summary.csv`, `mission_mutation_summary.json` | `mission_mutation_*.png` | `PHASE421_MISSION_MUTATION_REPORT.md` |
| Phase4.22 | `output/phase422_adaptive_intelligence/` | `adaptive_intelligence_summary.csv`, `adaptive_intelligence_summary.json` | `mission_reclassification.png`, `defense_reoptimization.png`, `phase422_vs_phase421.png` | `PHASE422_ADAPTIVE_INTELLIGENCE_REPORT.md` |
| Phase4.23 | `output/phase423_intent_deception/` | `intent_deception_summary.csv`, `intent_deception_summary.json` | `intent_deception_*.png`, `phase423_vs_phase422.png` | `PHASE423_INTENT_DECEPTION_REPORT.md` |
| Phase4.24 | `output/phase424_signal_extraction/` | `signal_extraction_summary.csv`, `signal_extraction_summary.json` | `signal_extraction_*.png` | `PHASE424_SIGNAL_EXTRACTION_REPORT.md` |
| Phase4.25 | `output/phase425_adversarial_signal/` | `adversarial_signal_summary.csv`, `adversarial_signal_summary.json` | `fake_signal_count.png`, `signal_confusion_score.png`, `phase425_vs_phase424.png` | `PHASE425_ADVERSARIAL_SIGNAL_REPORT.md` |

## Representative Publication Set

The quick publication runner refreshes these representative milestones:

- Phase4.13: Intelligence Defender
- Phase4.18: Mission Objectives
- Phase4.22: Adaptive Intelligence Defender
- Phase4.25: Adversarial Signal

These four points cover the final Phase4 arc from intelligence-driven defense to mission-aware objective selection, mutation tracking, and adversarial signal robustness.
