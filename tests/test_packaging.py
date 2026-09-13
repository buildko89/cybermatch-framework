from pathlib import Path
import re
import tomllib


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_dependency_contract_has_minimal_core_and_explicit_extras():
    with (REPOSITORY_ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]

    assert set(project["dependencies"]) == {
        "cvxpy>=1.4,<2",
        "jsonschema>=4.21,<5",
        "matplotlib>=3.8,<4",
        "numpy>=1.26,<3",
    }
    assert set(project["optional-dependencies"]) == {"all", "dev", "hunting", "ui"}
    assert project["requires-python"] == ">=3.12"
    assert {
        "cybermatch-agentic-benchmark",
        "cybermatch-fuzz",
        "cybermatch-hunt",
        "cybermatch-scenario",
        "cybermatch-validate-assets",
    }.issubset(project["scripts"])


def test_committed_dependency_files_never_contain_local_or_git_dependencies():
    forbidden = re.compile(r"(?im)(^\s*-e\s|git\+|file://|[a-z]:[\\/])")

    for name in ("requirements.txt", "requirements.lock", "requirements-dev.lock"):
        content = (REPOSITORY_ROOT / name).read_text(encoding="utf-8")
        assert forbidden.search(content) is None, f"non-portable dependency in {name}"


def test_compatibility_requirements_uses_the_runtime_lock():
    lines = [
        line.strip()
        for line in (REPOSITORY_ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert lines == ["-r requirements.lock"]
