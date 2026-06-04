# Phase1: Defense Neutralization

Phase1 evaluates defense effectiveness against compromise and attacker progress.

Primary metrics:

- critical compromise rate
- neutralization score
- post-decoy compromise
- defense objective score
- MTD cost and action counts

Main result:

- Phase1 best policy in the current publication baseline: `gated_edge_pressure_count_2`
- Phase2 comparison baseline: `phase2_ai_balanced`

Entry point:

```bash
python scripts/run_phase1.py
```

Related reports:

- `docs/CYBERMATCH_PHASE1_FINAL_REPORT.md`
- `docs/PHASE1_ARTIFACTS.md`
- `docs/NEUTRALIZATION_REPORT.md`
