# Dependency Policy

`pyproject.toml` is the source of truth for supported Python versions,
runtime dependency ranges, and optional features.

## Dependency groups

| Group | Packages | Purpose |
|---|---|---|
| core | NumPy, Matplotlib, CVXPY | simulation, optimization, metrics, and existing compatibility exports |
| hunting | scikit-learn | optional K-Means and Isolation Forest hunting plugins |
| ui | Streamlit | local dashboard |
| dev | pytest, build, pip-tools | tests, package validation, and lock generation |

ProfileCore is an optional repository submodule integration. It is not a
Python package dependency and must not be represented by a machine-specific
editable path. External SUTs are connected through data adapters and likewise
must not become unconditional core dependencies.

## Installation

```powershell
# Core only
python -m pip install -e .

# Full local application
python -m pip install -e ".[hunting,ui]"

# Development environment
python -m pip install -e ".[hunting,ui,dev]"
```

## Lock maintenance

Both committed locks are generated directly from `pyproject.toml`, so dependency
ranges have a single source of truth.

```powershell
python -m piptools compile --resolver=backtracking --strip-extras --extra hunting --extra ui --output-file=requirements.lock pyproject.toml
python -m piptools compile --resolver=backtracking --strip-extras --extra hunting --extra ui --extra dev --output-file=requirements-dev.lock pyproject.toml
```

Review dependency changes in both `pyproject.toml` and the generated lock diff.
Never add local absolute paths to a committed dependency file.

To reproduce the exact development environment, install the lock before the
project itself:

```powershell
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e .
```
