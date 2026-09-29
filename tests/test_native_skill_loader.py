"""S1 native SOP loaderのsnapshot・path・front matter境界を検証する。"""

from pathlib import Path

import pytest

from cybermatch_core.agent_skills import NativeSkillLoadError, NativeSkillLoader


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ROOT / "configs/agent_skills/packages"


def write_skill(root: Path, skill_id: str, body: str = "# 手順\n") -> Path:
    package = root / skill_id
    package.mkdir(parents=True)
    (package / "SKILL.md").write_text(
        f"---\nname: {skill_id}\ndescription: 読み取り専用の合成評価手順\n---\n\n{body}",
        encoding="utf-8",
    )
    return package


def test_native_sop_snapshot_is_deterministic_and_does_not_execute_content():
    loader = NativeSkillLoader(PACKAGES)
    first = loader.load("cm-credential-path")
    second = loader.load("cm-credential-path")
    assert first == second
    assert first.metadata.name == "cm-credential-path"
    assert first.skill_size_bytes > 0
    assert len(first.skill_sha256) == 64
    assert len(first.snapshot_hash) == 64
    assert first.to_dict()["metadata"]["description"]


def test_native_sop_snapshot_is_independent_of_checkout_line_endings(tmp_path):
    lf_root = tmp_path / "lf" / "packages"
    crlf_root = tmp_path / "crlf" / "packages"
    write_skill(lf_root, "cm-example")
    crlf_package = write_skill(crlf_root, "cm-example")
    lf_bytes = (crlf_package / "SKILL.md").read_bytes()
    normalized = lf_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    (crlf_package / "SKILL.md").write_bytes(normalized.replace(b"\n", b"\r\n"))

    lf_snapshot = NativeSkillLoader(lf_root).load("cm-example")
    crlf_snapshot = NativeSkillLoader(crlf_root).load("cm-example")

    assert crlf_snapshot == lf_snapshot


@pytest.mark.parametrize("skill_id", ["../cm-credential-path", "CM-UPPER", "cm-a/other", "cm-"])
def test_loader_rejects_unsafe_or_invalid_package_identifier(skill_id):
    with pytest.raises(NativeSkillLoadError):
        NativeSkillLoader(PACKAGES).load(skill_id)


def test_loader_rejects_unexpected_file_and_malformed_front_matter(tmp_path):
    root = tmp_path / "packages"
    package = write_skill(root, "cm-example")
    (package / "script.py").write_text("raise RuntimeError('never execute')", encoding="utf-8")
    with pytest.raises(NativeSkillLoadError, match="SKILL.md以外"):
        NativeSkillLoader(root).load("cm-example")
    (package / "script.py").unlink()
    (package / "SKILL.md").write_text("---\nname: other\ndescription: x\n---\n", encoding="utf-8")
    with pytest.raises(NativeSkillLoadError, match="name"):
        NativeSkillLoader(root).load("cm-example")


def test_loader_rejects_oversized_and_non_utf8_content(tmp_path):
    root = tmp_path / "packages"
    package = write_skill(root, "cm-example")
    (package / "SKILL.md").write_bytes(b"\xff\xfe")
    with pytest.raises(NativeSkillLoadError, match="UTF-8"):
        NativeSkillLoader(root).load("cm-example")
    (package / "SKILL.md").write_bytes(b"x" * (NativeSkillLoader.MAX_SKILL_BYTES + 1))
    with pytest.raises(NativeSkillLoadError, match="サイズ"):
        NativeSkillLoader(root).load("cm-example")
