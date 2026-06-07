# CyberMatch Framework

CyberMatch is a cyber-defense evaluation framework for both:

- Defense Neutralization
- Decision Neutralization

It evaluates whether a defense protects critical assets, reduces attacker progress, and neutralizes attacker decision-making. Phase1 focuses on defense effectiveness. Phase2 focuses on attacker cognition and decision cost. Phase3 validates Decision Neutralization against adaptive attackers.

## Quick Start

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run tests:

```bash
python -m pytest
```

### Phase1

Goal:
Evaluate defense effectiveness.

Metrics:

- critical compromise
- neutralization score
- post-decoy compromise
- defense objective score
- MTD cost and actions

Run:

```bash
python scripts/run_phase1.py
```

### Phase2

Goal:
Evaluate attacker decision neutralization.

Metrics:

- perceived utility
- confidence
- frustration
- AI decision cost
- Cognitive Neutralization Score
- CNS objective score

Run:

```bash
python scripts/run_phase2.py
```

### Phase3 - Adaptive Attacker Validation

Goal:
Evaluate whether Decision Neutralization remains effective against adaptive attackers.

Implemented attacker models:

- Memory attacker
- Node preference attacker
- Path preference attacker
- Path planning attacker
- Trust-aware planning attacker

Current finding:

- Decision Neutralization remains effective under all evaluated adaptive attacker models.

Run:

```bash
python scripts/run_phase3a.py
```

### All Evaluations

Run:

```bash
python scripts/run_all.py
```

## Results

### Phase1 Summary

Phase1 introduces Defense Neutralization, using a composite Neutralization Score and related compromise, delay, deception, and retreat metrics.

Main Phase1 policy finding:

- `gated_edge_pressure_count_2`

Phase1 comparison best used in Phase2 ranking:

- `phase2_ai_balanced`

### Phase2 Summary

Phase2 introduces Decision Neutralization. It adds perceived utility, confidence, Human Frustration, AI Decision Cost, Cognitive Neutralization Score, and CNS Objective ranking.

Main Phase2 policy finding:

- `phase2_frustration_decoy`

### Phase3 Summary

Phase3-A introduces Adaptive Attacker Validation. It evaluates memory, node preference, path preference, path planning, and trust-aware planning attackers without introducing RL/DQN/PPO.

Main Phase3-A finding:

- Decision Neutralization remains stable through Memory -> Preference -> Path Preference -> Planning -> Trust-Aware Planning.

### Recommended Policies

- Defense Neutralization: `gated_edge_pressure_count_2`
- Decision Neutralization: `phase2_frustration_decoy`

## Publications / Reports

Phase1:

- [Phase1 index](docs/phase1/README.md)
- [Phase1 final report](docs/CYBERMATCH_PHASE1_FINAL_REPORT.md)
- [Phase1 artifacts](docs/PHASE1_ARTIFACTS.md)

Phase2:

- [Phase2 index](docs/phase2/README.md)
- [Phase2 final report](docs/CYBERMATCH_PHASE2_FINAL_REPORT.md)
- [Phase2 artifacts](docs/PHASE2_ARTIFACTS.md)

Phase3-A:

- [Phase3-A final report](docs/CYBERMATCH_PHASE3A_FINAL_REPORT.md)
- [Phase3-A artifacts](docs/PHASE3A_ARTIFACTS.md)

Release and reproducibility:

- [GitHub release notes](docs/GITHUB_RELEASE_NOTES.md)
- [GitHub release plan](docs/GITHUB_RELEASE_PLAN.md)
- [Reproducibility](docs/REPRODUCIBILITY.md)

## Repository Structure

```text
cybermatch-framework/
  README.md
  LICENSE
  requirements.txt
  cybermatch.py
  run_scenarios.py
  scripts/
    run_phase1.py
    run_phase2.py
    run_phase3.py
    run_phase3a.py
    run_all.py
  tests/
  docs/
    phase1/
    phase2/
    images/
    data/
```

## License

This project is licensed under the PolyForm Noncommercial License 1.0.0.

CyberMatch Framework is source-available for research, education, evaluation, and other noncommercial purposes. Commercial use is not permitted without separate permission from the repository owner.

See [LICENSE](LICENSE) for details.
