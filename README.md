# CyberMatch Framework

CyberMatch Framework is a source-available cyber-defense research framework for evaluating attacker neutralization.

It evaluates defense policies not only by detection rate or attack success rate, but by:

- Critical asset protection
- Attacker utility suppression
- Deception and attacker waste
- Attack progress friction
- Retreat induction

## License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.

CyberMatch Framework is source-available for research, education, evaluation, and other noncommercial purposes.

Commercial use is not permitted without separate permission from the repository owner.

See [LICENSE](./LICENSE) for details.

## Phase1 Status

Phase1 is completed.

Main outcome:
CyberMatch Phase1 defines and evaluates attack neutralization using a composite Neutralization Score.

Best targeted neutralization policy:
credential_aware_mtd

Neutralization Score:
0.742

## Key Findings

- Naive decoy alone is weak
- Path-aware decoy improves attack delay
- Edge-level MTD is useful when combined with path-aware defense
- Belief estimation accuracy does not always correlate with defense performance
- Credential-aware MTD achieved the highest targeted neutralization score
- Retreat induction remains a Phase2 challenge

## Repository Structure

- cybermatch.py
- run_scenarios.py
- tests/
- docs/
- docs/images/
- docs/data/

## Quick Start

```bash
python -m pytest
python cybermatch.py
python run_scenarios.py
```

## Phase1 Report

See:

docs/CYBERMATCH_PHASE1_FINAL_REPORT.md

## Neutralization Report

See:

docs/NEUTRALIZATION_REPORT.md

## Phase2 Roadmap

- Perceived utility
- Attacker frustration model
- Dynamic retreat model
- Multi-seed neutralization scoring
- Defender-visible observation model
- Online adaptive defense

## Commercial Use

Commercial use of this project requires separate permission from the repository owner.

If you are interested in commercial use, licensing, collaboration, or applied research based on CyberMatch Framework, please contact the repository owner.
