# GitHub Release Plan

## Existing

Phase1 is complete and should remain available as the baseline release material.

Recommended Phase1 items:

- `docs/CYBERMATCH_PHASE1_FINAL_REPORT.md`
- `docs/PHASE1_ARTIFACTS.md`
- `docs/NEUTRALIZATION_REPORT.md`
- Phase1 plots and data under `docs/images/`, `docs/data/`, or release assets.

## New

Phase2 adds Decision Neutralization evaluation:

- Perceived Utility
- Human Frustration
- AI Decision Cost
- Cognitive Neutralization Score
- CNS-driven policy selection
- CNS objective ranking

Recommended Phase2 items:

- `docs/CYBERMATCH_PHASE2_FINAL_REPORT.md`
- `docs/PHASE2_ARTIFACTS.md`
- `docs/REPRODUCIBILITY.md`
- `output/phase2_final_summary.json`
- selected Phase2 plots and summary CSV/JSON outputs.

## Recommended Directory Structure

```text
docs/
  phase1/
  phase2/
  images/
  data/
```

Suggested mapping:

- Keep the current final reports at the existing top-level `docs/` paths for compatibility.
- Use `docs/phase1/README.md` and `docs/phase2/README.md` as publication entry indexes.
- Move or copy final reports and artifact indexes into `docs/phase1/` and `docs/phase2/` only when preparing a clean release branch.
- Put selected PNG plots in `docs/images/`.
- Put compact CSV/JSON summaries in `docs/data/`.
- Keep full `output/` directories as generated artifacts or release assets when size is acceptable.

## Move Candidates

No files were moved during the publication refactor. The following are candidates for a release branch cleanup:

- `docs/CYBERMATCH_PHASE1_FINAL_REPORT.md` -> `docs/phase1/PHASE1_FINAL_REPORT.md`
- `docs/PHASE1_ARTIFACTS.md` -> `docs/phase1/ARTIFACTS.md`
- `docs/CYBERMATCH_PHASE2_FINAL_REPORT.md` -> `docs/phase2/PHASE2_FINAL_REPORT.md`
- `docs/PHASE2_ARTIFACTS.md` -> `docs/phase2/ARTIFACTS.md`

## Release Notes Outline

- Scope: source-available cyber-defense research framework.
- Phase1: composite neutralization score baseline.
- Phase2: decision neutralization and cognitive neutralization.
- Best Phase2 recommendation: `phase2_frustration_decoy`.
- Reproducibility: run `python -m pytest`, then selected evaluation functions or `python run_scenarios.py`.
- License: PolyForm Noncommercial License 1.0.0.
