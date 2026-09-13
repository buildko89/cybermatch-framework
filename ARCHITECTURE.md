# CyberMatch architecture

## Direction

CyberMatch is an evaluation workbench whose primary output is auditable
evidence, not only charts or a simulator history. The dependency direction is:

```text
CLI / Streamlit
    -> application services
        -> evaluation, agentic, hunting, fuzzing workflows
            -> simulation and domain models
                -> versioned contracts and schemas
```

The `cybermatch_core` package is the stable 1.x facade. Implementations remain
under `src.cybermatch`; historical root modules are compatibility boundaries.
See `PUBLIC_API.md` for the lifecycle policy.

## Phase 1 boundaries

- `src.cybermatch.contracts` owns canonical JSON, hashes, run manifests,
  metrics, evidence bundles, and the schema registry.
- `src.cybermatch.evaluation.statistics` and `artifact_io` contain pure or
  side-effect-specific helpers removed from the monolithic evaluation runner.
- `src.cybermatch.simulation.probability` is the first pure state-operation
  seam extracted from the simulator.
- `src.cybermatch.application.process_control` and `artifacts` let the
  Streamlit layer delegate process lifecycle and result discovery.
- `scripts/validate_assets.py` is the CI and operator entry point for all
  registered JSON assets.

Further decomposition should proceed behind these tested seams. A wholesale
rewrite of `runner.py` or `simulator.py` is explicitly out of scope for Phase 1
because it would combine behavior changes with structural changes.

## Versioned data flow

Every evaluation should converge on `EvaluationRun` and `EvidenceBundle`.
Inputs are checked by `SchemaRegistry`; outputs carry a contract version and
canonical SHA-256 hashes. Domain-specific artifacts may remain, but their
manifest must be able to reference the common evidence records without
changing their hashes.

## Phase 2 flagship protocol

`agentic.mode_runner` keeps potential/actual events separate from detector
telemetry and evaluates the same seeded realization under no defense, static
defense, hunting only, containment only, closed loop, and active deception.
`agentic.protocol` reports distributions, 95% confidence intervals, paired
rank-biserial effects, standard sensitivity axes, and explicitly reproduced
failure regions. Runtime independence checks reject oracle fields, future
evidence, label-bearing IDs, and findings that cite unobserved events.

Agentic benchmark artifacts and fuzzing counterexamples now use the common
Evidence Bundle. The bundle records code revision, dependency-lock hash, input
hashes, seed set, replay instructions, and hashes for each evidence artifact.

## Current limitations

- Existing workflows do not all emit the common evidence bundle yet; the
  contract and migration boundary now exist for incremental adoption.
- Root compatibility modules and the `src` namespace remain until a 2.0
  package-name migration.
- Ubuntu behavior is validated by GitHub Actions after a push; local Phase 1
  verification is Windows-only.
