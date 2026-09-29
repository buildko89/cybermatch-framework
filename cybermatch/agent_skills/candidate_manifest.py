"""review_pendingのnative Skill候補と、実際のsnapshotを照合するS1処理。"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from cybermatch.contracts import AssetSchemaError, SchemaRegistry

from .native_loader import NativeSkillLoadError, NativeSkillLoader, NativeSkillSnapshot


class NativeManifestSnapshotError(ValueError):
    """候補manifest、package path、または固定snapshot hashが一致しない。"""


@dataclass(frozen=True)
class NativeManifestSnapshot:
    """審査に渡す読み取り専用の照合結果。実行許可ではない。"""

    manifest_id: str
    status: str
    review_decision: str
    snapshots: tuple[NativeSkillSnapshot, ...]

    @property
    def executable(self) -> bool:
        """S1は常にFalse。承認済みでもselector/runnerは別工程である。"""
        return False


def load_native_manifest_snapshots(
    *, repository_root: str | Path, manifest_path: str | Path,
) -> NativeManifestSnapshot:
    """信頼root内のmanifestを読んで、記録済みhashとSOPを照合する。"""
    root = Path(repository_root).resolve(strict=True)
    requested = Path(manifest_path)
    if requested.is_absolute() or requested.is_symlink():
        raise NativeManifestSnapshotError("manifestはrepository内の相対通常fileで指定してください")
    path = (root / requested).resolve(strict=True)
    if not path.is_relative_to(root) or path.is_symlink():
        raise NativeManifestSnapshotError("manifestはrepository root外またはsymlinkです")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NativeManifestSnapshotError("manifestをJSONとして読み取れません") from exc
    return verify_native_manifest_payload(payload, repository_root=root)


def verify_native_manifest_payload(
    payload: Mapping[str, object], *, repository_root: str | Path,
) -> NativeManifestSnapshot:
    """JSON objectを検証する。テスト・審査ツール用であり実行処理を持たない。"""
    root = Path(repository_root).resolve(strict=True)
    try:
        SchemaRegistry().validate("skill_candidate_manifest", payload)
    except AssetSchemaError as exc:
        raise NativeManifestSnapshotError(f"candidate manifestが不正です: {exc}") from exc
    packages = payload["packages"]
    bindings = payload["bindings"]
    review = payload["review"]
    assert isinstance(packages, list) and isinstance(bindings, list) and isinstance(review, Mapping)
    package_ids = {str(item["skill_id"]) for item in packages if isinstance(item, Mapping)}
    binding_ids = {str(item["skill_id"]) for item in bindings if isinstance(item, Mapping)}
    if package_ids != binding_ids or len(package_ids) != len(packages):
        raise NativeManifestSnapshotError("packageとbindingのSkill ID集合が一致しません")
    expected_root = root / "configs" / "agent_skills" / "packages"
    try:
        loader = NativeSkillLoader(expected_root)
    except NativeSkillLoadError as exc:
        raise NativeManifestSnapshotError("native package rootを利用できません") from exc
    snapshots = []
    for item in sorted(packages, key=lambda value: str(value["skill_id"])):
        assert isinstance(item, Mapping)
        skill_id = str(item["skill_id"])
        expected_path = f"configs/agent_skills/packages/{skill_id}/"
        if item["package_path"] != expected_path or item["snapshot_status"] != "captured":
            raise NativeManifestSnapshotError("package pathまたはsnapshot状態がS1 profileと一致しません")
        try:
            snapshot = loader.load(skill_id)
        except NativeSkillLoadError as exc:
            raise NativeManifestSnapshotError(f"{skill_id}をsnapshot化できません") from exc
        if item.get("snapshot_hash") != snapshot.snapshot_hash:
            raise NativeManifestSnapshotError(f"{skill_id}のsnapshot hashがmanifestと一致しません")
        snapshots.append(snapshot)
    return NativeManifestSnapshot(
        manifest_id=str(payload["manifest_id"]),
        status=str(payload["status"]),
        review_decision=str(review["decision"]),
        snapshots=tuple(snapshots),
    )


__all__ = [
    "NativeManifestSnapshot",
    "NativeManifestSnapshotError",
    "load_native_manifest_snapshots",
    "verify_native_manifest_payload",
]
