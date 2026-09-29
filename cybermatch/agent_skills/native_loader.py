"""自作Agent Skills SOPを実行せず、固定snapshotとして読むS1 loader。"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from cybermatch.contracts import canonical_sha256


NATIVE_SKILL_SNAPSHOT_VERSION = "1.0"
_SKILL_ID = re.compile(r"cm-[a-z0-9-]+\Z")


class NativeSkillLoadError(ValueError):
    """native SOPのパス、サイズ、front matter、またはsnapshotが不正。"""


@dataclass(frozen=True)
class NativeSkillMetadata:
    """Agent Skillsの最小metadata。本文やallowed-toolsを実行解釈しない。"""

    name: str
    description: str


@dataclass(frozen=True)
class NativeSkillSnapshot:
    """改行をLFへ正規化したUTF-8 byte列から作る、不変のpackage snapshot。"""

    skill_id: str
    package_path: str
    metadata: NativeSkillMetadata
    skill_sha256: str
    skill_size_bytes: int
    snapshot_hash: str
    schema_version: str = NATIVE_SKILL_SNAPSHOT_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "skill_id": self.skill_id,
            "package_path": self.package_path,
            "metadata": {"name": self.metadata.name, "description": self.metadata.description},
            "skill_sha256": self.skill_sha256,
            "skill_size_bytes": self.skill_size_bytes,
            "snapshot_hash": self.snapshot_hash,
        }


class NativeSkillLoader:
    """指定root直下の自作SOPだけを読み込む、read-only loader。

    v1は`SKILL.md`だけを許可する。resourceやscriptを含むpackageは、
    無視せずfail closedにする。外部package、ネットワーク、subprocess、
    動的import、YAML object constructionは一切扱わない。
    """

    MAX_SKILL_BYTES = 64 * 1024
    _ALLOWED_PACKAGE_FILES = frozenset({"SKILL.md"})

    def __init__(self, package_root: str | Path):
        root = Path(package_root)
        if root.is_symlink():
            raise NativeSkillLoadError("package rootにsymlinkを指定できません")
        try:
            resolved = root.resolve(strict=True)
        except OSError as exc:
            raise NativeSkillLoadError("package rootを解決できません") from exc
        if not resolved.is_dir() or resolved.is_symlink():
            raise NativeSkillLoadError("package rootは通常directoryでなければなりません")
        self._root = resolved

    def load(self, skill_id: str) -> NativeSkillSnapshot:
        if not isinstance(skill_id, str) or _SKILL_ID.fullmatch(skill_id) is None:
            raise NativeSkillLoadError("skill_idはcm-で始まる安全な識別子で指定してください")
        requested = self._root / skill_id
        if requested.is_symlink() or not requested.exists() or not requested.is_dir():
            raise NativeSkillLoadError("skill packageが存在しないか、安全なdirectoryではありません")
        package = requested.resolve(strict=True)
        if package.parent != self._root or not package.is_relative_to(self._root):
            raise NativeSkillLoadError("package root外のSOPを読み込めません")
        entries = tuple(sorted(package.iterdir(), key=lambda item: item.name))
        if {item.name for item in entries} != self._ALLOWED_PACKAGE_FILES or any(item.is_symlink() for item in entries):
            raise NativeSkillLoadError("v1のnative packageにはsymlinkやSKILL.md以外を含められません")
        skill_file = package / "SKILL.md"
        if not skill_file.is_file() or skill_file.is_symlink():
            raise NativeSkillLoadError("SKILL.mdは通常fileでなければなりません")
        try:
            raw = skill_file.read_bytes()
        except OSError as exc:
            raise NativeSkillLoadError("SKILL.mdを読み取れません") from exc
        if not raw or len(raw) > self.MAX_SKILL_BYTES:
            raise NativeSkillLoadError("SKILL.mdのサイズが許容範囲外です")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NativeSkillLoadError("SKILL.mdはUTF-8でなければなりません") from exc
        metadata = self._parse_front_matter(text, skill_id)
        # Gitのautocrlf設定に左右されないreview snapshotにする。SOPはUTF-8
        # textだけを許可しているため、CRLF/CRをLFへ統一してからhashとsizeを記録する。
        canonical_raw = text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
        sha256 = hashlib.sha256(canonical_raw).hexdigest()
        package_path = f"{self._root.name}/{skill_id}/"
        semantic = {
            "schema_version": NATIVE_SKILL_SNAPSHOT_VERSION,
            "skill_id": skill_id,
            "package_path": package_path,
            "metadata": {"name": metadata.name, "description": metadata.description},
            "skill_sha256": sha256,
            "skill_size_bytes": len(canonical_raw),
        }
        return NativeSkillSnapshot(
            skill_id=skill_id,
            package_path=package_path,
            metadata=metadata,
            skill_sha256=sha256,
            skill_size_bytes=len(canonical_raw),
            snapshot_hash=canonical_sha256(semantic),
        )

    @staticmethod
    def _parse_front_matter(text: str, skill_id: str) -> NativeSkillMetadata:
        lines = text.splitlines()
        if not lines or lines[0] != "---":
            raise NativeSkillLoadError("SKILL.mdの先頭にfront matterが必要です")
        try:
            end = lines.index("---", 1)
        except ValueError as exc:
            raise NativeSkillLoadError("front matterの終端がありません") from exc
        values: dict[str, str] = {}
        for line in lines[1:end]:
            if line.count(":") != 1:
                raise NativeSkillLoadError("v1 front matterは単純なkey: valueだけを許可します")
            key, value = (part.strip() for part in line.split(":", 1))
            if key not in {"name", "description"} or not value or key in values:
                raise NativeSkillLoadError("front matterには重複なしのnameとdescriptionだけが必要です")
            values[key] = value
        if set(values) != {"name", "description"} or values["name"] != skill_id:
            raise NativeSkillLoadError("front matterのnameはpackage名と一致する必要があります")
        return NativeSkillMetadata(name=values["name"], description=values["description"])


__all__ = [
    "NATIVE_SKILL_SNAPSHOT_VERSION",
    "NativeSkillLoadError",
    "NativeSkillLoader",
    "NativeSkillMetadata",
    "NativeSkillSnapshot",
]
