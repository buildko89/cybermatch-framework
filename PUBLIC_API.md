# CyberMatch public API policy

## Supported API for the 1.x series

`cybermatch_core` is the stable Python import namespace. Its facade modules are
the supported integration boundary:

- `cybermatch_core.contracts`
- `cybermatch_core.agentic_security`
- `cybermatch_core.threat_hunting`
- `cybermatch_core.benchmarks`, `metrics`, `products`, `scenarios`, and
  `topologies`

The command-line entry points declared in `pyproject.toml` are also public.
The canonical evidence contract is versioned independently through
`RUN_CONTRACT_VERSION`; repository JSON assets are versioned by the schema
registry.

## Compatibility and deprecation

The root-level modules and `src.cybermatch.*` remain supported implementation
and compatibility paths throughout 1.x. New external integrations should not
depend on them. A public symbol will be deprecated for at least one minor
release before removal, and removal will occur no earlier than 2.0.

The project intentionally does not expose a `cybermatch` package during 1.x:
the existing `cybermatch.py` module already owns that import name. Resolving
that historical collision is a 2.0 migration, avoiding two module identities
for the same runtime types.

## Stability boundary

Public facades, CLI arguments, evidence/schema versions, and documented output
filenames require compatibility review. Functions under `src.cybermatch` that
are not re-exported by a facade are internal and may change between minor
versions. Data-contract changes require a new version and a migration note.
