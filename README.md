# CyberMatch Framework

CyberMatch is a cyber-defense evaluation framework for both:

- Defense Neutralization
- Decision Neutralization

It evaluates whether a defense protects critical assets, reduces attacker progress, and neutralizes attacker decision-making. Phase1 focuses on defense effectiveness. Phase2 focuses on attacker cognition and decision cost. Phase3 validates Decision Neutralization against adaptive and rational attackers.
Phase4 extends CyberMatch from adaptive defense to intelligence-driven active defense.

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

### Phase3-A - Adaptive Attacker Validation

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

### Phase3-B - Rational Attacker Validation

Goal:
Evaluate whether Decision Neutralization remains effective against a rational attacker.

Implemented attacker model:

- Expected Utility attacker

Current finding:

- Expected Utility attacker is the strongest attacker model evaluated so far.
- Decision Neutralization still remains effective.

Run:

```bash
python scripts/run_phase3b.py
```

### Phase4 - Intelligence-Driven Active Defense

Goal:
Extend CyberMatch from adaptive defense to intelligence-driven active defense.

Major components:

- Adaptive Defender
- Mission Belief
- State Belief
- Virtual Enterprise Topology
- Critical Path Intelligence
- Intelligence Decision Matrix
- Defense Campaign
- Mission Mutation
- Intent Deception
- Noise Injection
- Adversarial Signal Robustness

Final interpretation:

CyberMatch now evaluates attacker-defender co-evolution under mission mutation, deception, noise, and adversarial signal conditions.

Run representative Phase4 publication milestones:

```bash
python scripts/run_phase4.py --quick
```

Run the full Phase4.1-Phase4.25 publication workflow:

```bash
python scripts/run_phase4.py --publication
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

### Phase3-A Summary

Phase3-A introduces Adaptive Attacker Validation. It evaluates memory, node preference, path preference, path planning, and trust-aware planning attackers without introducing RL/DQN/PPO.

Main Phase3-A finding:

- Decision Neutralization remains stable through Memory -> Preference -> Path Preference -> Planning -> Trust-Aware Planning.

### Phase3-B Summary

Phase3-B introduces Rational Attacker Validation. It evaluates the Expected Utility attacker without introducing RL/DQN/PPO.

Main Phase3-B finding:

- Expected Utility is the strongest attacker model evaluated so far, and Decision Neutralization still remains effective.

### Phase4 Summary

Phase4 introduces Intelligence-Driven Active Defense. It adds mission belief, state belief, virtual topology, observable critical-path events, intelligence decision matrices, defense campaigns, mission mutation, intent deception, noise injection, adversarial signal evaluation, and consistency-check robustness.

Main Phase4 finding:

- CyberMatch evolved from an adaptive defense simulator into an intelligence-driven active defense co-evolution simulator.

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

Phase3-B:

- [Phase3-B final report](docs/CYBERMATCH_PHASE3B_FINAL_REPORT.md)
- [Phase3-B artifacts](docs/PHASE3B_ARTIFACTS.md)

Phase4:

- [Phase4 final report](docs/CYBERMATCH_PHASE4_FINAL_REPORT.md)
- [Phase4 artifacts](docs/PHASE4_ARTIFACTS.md)

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
    run_phase3b.py
    run_phase4.py
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
