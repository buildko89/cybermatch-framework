"""固定commitから持ち込んだ外部Skillを実行せずに審査するS4b処理。"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

class ExternalSkillReviewError(ValueError):
    """外部Skillのpath、サイズ、hash、license、またはmanifestが不正。"""


@dataclass(frozen=True)
class ExternalPackageSnapshot:
    skill_id: str
    name: str
    file_count: int
    total_bytes: int
    snapshot_hash: str
    license_sha256: str
    risk_signals: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "skill_id": self.skill_id, "name": self.name, "file_count": self.file_count,
            "total_bytes": self.total_bytes, "snapshot_hash": self.snapshot_hash,
            "license_sha256": self.license_sha256, "risk_signals": list(self.risk_signals),
        }


MAX_PACKAGE_BYTES = 10 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_SKILL_BYTES = 64 * 1024
MAX_FILES = 128
_SAFE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_RISK_PATTERNS = {
    "network_reference": re.compile(rb"https?://|requests\.|urllib|socket\.", re.I),
    "credential_or_secret_operation": re.compile(rb"credential|api[_ -]?key|secret|token", re.I),
    "external_command_or_install": re.compile(rb"subprocess|os\.system|pip install|curl |\| sh", re.I),
    "filesystem_write_or_delete": re.compile(rb"open\([^\n]{0,120}['\"]w|unlink\(|remove\(|rmtree", re.I),
    "tor_or_hidden_service": re.compile(rb"\btor\b|\.onion|socks5", re.I),
}


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _is_reparse(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400)


def snapshot_external_package(package_root: str | Path, skill_id: str) -> ExternalPackageSnapshot:
    root = Path(package_root).resolve(strict=True)
    if _SAFE_ID.fullmatch(skill_id) is None:
        raise ExternalSkillReviewError("外部Skill IDが安全な形式ではありません")
    package = (root / skill_id).resolve(strict=True)
    if package.parent != root or not package.is_dir() or _is_reparse(package):
        raise ExternalSkillReviewError("外部packageがroot外、symlink、またはreparse pointです")
    files = tuple(sorted((path for path in package.rglob("*") if path.is_file()), key=lambda p: p.as_posix()))
    if not files or len(files) > MAX_FILES:
        raise ExternalSkillReviewError("外部packageのfile数が上限外です")
    entries: list[dict[str, object]] = []
    blobs: list[bytes] = []
    total = 0
    for path in files:
        if _is_reparse(path) or not path.resolve().is_relative_to(package):
            raise ExternalSkillReviewError("外部packageに不正なpathがあります")
        raw = path.read_bytes()
        relative = path.relative_to(package).as_posix()
        limit = MAX_SKILL_BYTES if relative == "SKILL.md" else MAX_FILE_BYTES
        if not raw or len(raw) > limit:
            raise ExternalSkillReviewError(f"{relative}のサイズが上限外です")
        total += len(raw)
        entries.append({"path": relative, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        blobs.append(raw)
    if total > MAX_PACKAGE_BYTES:
        raise ExternalSkillReviewError("外部packageの合計サイズが上限を超えています")
    skill_path = package / "SKILL.md"
    license_path = package / "LICENSE"
    if not skill_path.is_file() or not license_path.is_file():
        raise ExternalSkillReviewError("SKILL.mdとLICENSEが必要です")
    try:
        skill_text = skill_path.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise ExternalSkillReviewError("SKILL.mdはUTF-8でなければなりません") from exc
    front = skill_text.split("---", 2)
    if len(front) < 3:
        raise ExternalSkillReviewError("SKILL.mdにfront matterがありません")
    name_match = re.search(r"(?m)^name:\s*['\"]?([^'\"\r\n]+)", front[1])
    if not name_match or name_match.group(1).strip() != skill_id:
        raise ExternalSkillReviewError("front matterのnameがpackage名と一致しません")
    combined = b"\n".join(blobs)
    signals = tuple(sorted(name for name, pattern in _RISK_PATTERNS.items() if pattern.search(combined)))
    return ExternalPackageSnapshot(
        skill_id=skill_id, name=skill_id, file_count=len(files), total_bytes=total,
        snapshot_hash=_canonical_sha256({"skill_id": skill_id, "files": entries}),
        license_sha256=hashlib.sha256(license_path.read_bytes()).hexdigest(),
        risk_signals=signals,
    )


def review_external_packages(
    *, source_root: str | Path, manifest_path: str | Path,
) -> dict[str, object]:
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "1.0" or manifest.get("execution_mode") != "recipe_only":
        raise ExternalSkillReviewError("S4b manifestのversionまたはexecution_modeが不正です")
    root = Path(source_root).resolve(strict=True)
    git_dir = root / ".git"
    head = (git_dir / "HEAD").read_text(encoding="utf-8").strip() if git_dir.is_dir() else ""
    if head.startswith("ref: "):
        head = (git_dir / head[5:]).read_text(encoding="utf-8").strip()
    if head != manifest.get("source_revision"):
        raise ExternalSkillReviewError("外部source revisionがmanifestと一致しません")
    rows = []
    for candidate in manifest.get("candidates", []):
        snapshot = snapshot_external_package(root / "skills", str(candidate["skill_id"]))
        if snapshot.snapshot_hash != candidate.get("snapshot_hash"):
            raise ExternalSkillReviewError(f"{snapshot.skill_id}のsnapshot hashが一致しません")
        if snapshot.license_sha256 != manifest.get("license_sha256"):
            raise ExternalSkillReviewError(f"{snapshot.skill_id}のLICENSE hashが一致しません")
        rows.append({**snapshot.to_dict(), "decision": candidate["decision"],
                     "reason_codes": candidate["reason_codes"]})
    semantic = {"source_revision": manifest["source_revision"], "packages": rows,
                "script_execution_count": 0, "external_binding_count": 0}
    return {"schema_version": "1.0", **semantic, "result_hash": _canonical_sha256(semantic)}


def write_external_review_outputs(
    result: dict[str, object], output_dir: str | Path, *, repository_root: str | Path,
) -> dict[str, str]:
    from cybermatch.contracts import write_evidence_bundle

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    result_path = output / "external_skill_review.json"
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rows = result["packages"]
    assert isinstance(rows, list)
    report = ["# 外部Agent Skills S4b審査レポート", "", f"- 固定revision: `{result['source_revision']}`",
              f"- 対象package数: {len(rows)}", "- 外部script実行数: 0", "- 外部binding数: 0", "",
              "## 採用判定", "", "| Skill | 判定 | risk signal | 理由 |", "|---|---|---|---|"]
    for row in rows:
        report.append(f"| `{row['skill_id']}` | {row['decision']} | {', '.join(row['risk_signals']) or '-'} | {', '.join(row['reason_codes'])} |")
    report += ["", "hash一致は改変検知であり、内容の無害性を証明しません。全packageのscriptは未実行で、既存recipeとの意味的同値性が未確認のためbindingしていません。"]
    report_path = output / "report.md"
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
    bundle = write_evidence_bundle(
        output, repository_root=repository_root, run_id=output.name,
        runner="external_agent_skills_review", scenario_id="s4b-fixed-external-review", seed=0,
        input_payloads={"review": {"source_revision": result["source_revision"]}},
        metrics={"package_count": len(rows), "script_execution_count": 0,
                 "external_binding_count": 0, "result_hash": str(result["result_hash"])},
        artifact_paths=(result_path, report_path),
    )
    return {"result_hash": str(result["result_hash"]), "bundle_hash": str(bundle.bundle_hash)}


__all__ = ["ExternalPackageSnapshot", "ExternalSkillReviewError", "review_external_packages",
           "snapshot_external_package", "write_external_review_outputs"]
