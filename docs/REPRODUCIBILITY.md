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

Expected Phase2 finalization result:

```text
199 passed
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
