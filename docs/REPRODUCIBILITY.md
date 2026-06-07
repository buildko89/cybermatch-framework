# Reproducibility

## Setup

Use Python 3.12 or a compatible Python 3 environment.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## Install

```powershell
python -m pip install -r requirements.txt
```

Required packages are listed in `requirements.txt`:

- numpy
- matplotlib
- cvxpy
- pytest

## Pytest

```powershell
python -m pytest
```

Expected current result:

```text
205 passed
```

## Compile Check

```powershell
python -m compileall cybermatch.py run_scenarios.py
```

## Evaluation

Run Phase1 only:

```powershell
python .\scripts\run_phase1.py
```

Run Phase2 only:

```powershell
python .\scripts\run_phase2.py
```

Run Phase3-A Adaptive Attacker Validation only:

```powershell
python .\scripts\run_phase3a.py
```

Run Phase3-B Rational Attacker Validation only:

```powershell
python .\scripts\run_phase3b.py
```

Run all publication evaluations:

```powershell
python .\scripts\run_all.py
```

Run the legacy full scenario script:

```powershell
python .\run_scenarios.py
```

Primary Phase2 outputs:

- `output/phase2_ai_cost/`
- `output/phase2_ai_weight_sweep/`
- `output/phase2_cognitive_neutralization/`
- `output/phase2_policy_selection/`
- `output/phase2_cns_objective/`
- `output/phase2_final_summary.json`

Primary Phase3-A outputs:

- `output/phase3_adaptive_attacker/`
- `output/phase3_preference_attacker/`
- `output/phase3_path_attacker/`
- `output/phase3_planning_attacker/`
- `output/phase3_trust_attacker/`
- `output/phase3_publication/phase3_adaptive_attacker/`
- `output/phase3_publication/phase3_preference_attacker/`
- `output/phase3_publication/phase3_path_attacker/`
- `output/phase3_publication/phase3_planning_attacker/`
- `output/phase3_publication/phase3_trust_attacker/`

Expected Phase3-A artifacts:

- `output/phase3_publication/phase3_adaptive_attacker/PHASE3_ADAPTIVE_ATTACKER_REPORT.md`
- `output/phase3_publication/phase3_preference_attacker/PHASE3_PREFERENCE_ATTACKER_REPORT.md`
- `output/phase3_publication/phase3_path_attacker/PHASE3_PATH_ATTACKER_REPORT.md`
- `output/phase3_publication/phase3_planning_attacker/PHASE3_PLANNING_ATTACKER_REPORT.md`
- `output/phase3_publication/phase3_trust_attacker/PHASE3_TRUST_ATTACKER_REPORT.md`
- `output/phase3_trust_attacker/trust_summary.csv`
- `output/phase3_trust_attacker/trust_summary.json`
- `output/phase3_trust_attacker/trust_cns.png`
- `output/phase3_trust_attacker/trust_retreat_rate.png`
- `output/phase3_trust_attacker/trust_collapse.png`
- `output/phase3_trust_attacker/PHASE3_TRUST_ATTACKER_REPORT.md`
- `output/phase3_publication/*/*_summary.csv`
- `output/phase3_publication/*/*_summary.json`
- `output/phase3_publication/*/runs/summary_runs.csv`
- `output/phase3_publication/*/runs/summary_stats.json`

Primary Phase3-B outputs:

- `output/phase3_expected_utility/`

Expected Phase3-B artifacts:

- `output/phase3_expected_utility/expected_summary.csv`
- `output/phase3_expected_utility/expected_summary.json`
- `output/phase3_expected_utility/expected_cns.png`
- `output/phase3_expected_utility/expected_retreat_rate.png`
- `output/phase3_expected_utility/expected_target_switch.png`
- `output/phase3_expected_utility/PHASE3_EXPECTED_UTILITY_REPORT.md`
- `output/phase3_expected_utility/runs/summary_runs.csv`
- `output/phase3_expected_utility/runs/summary_stats.json`
