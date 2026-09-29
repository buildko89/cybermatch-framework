"""S1候補manifestとnative SOPのhash照合を検証する。"""

import json
from pathlib import Path

import pytest

from cybermatch_core.agent_skills import (
    NativeManifestSnapshotError,
    load_native_manifest_snapshots,
    verify_native_manifest_payload,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = "configs/agent_skills/manifests/native_skills_candidate_v1.json"


def payload() -> dict[str, object]:
    return json.loads((ROOT / MANIFEST_PATH).read_text(encoding="utf-8"))


def test_manifest_snapshot_matches_all_native_sops_without_granting_execution():
    result = load_native_manifest_snapshots(repository_root=ROOT, manifest_path=MANIFEST_PATH)
    assert result.manifest_id == "native-skills-candidate-v1"
    assert result.status == "review_pending"
    assert result.review_decision == "pending"
    assert not result.executable
    assert [snapshot.skill_id for snapshot in result.snapshots] == sorted(snapshot.skill_id for snapshot in result.snapshots)
    assert len(result.snapshots) == 5


def test_manifest_snapshot_rejects_drift_and_package_binding_mismatch():
    changed = payload()
    changed["packages"][0]["snapshot_hash"] = "0" * 64
    with pytest.raises(NativeManifestSnapshotError, match="hash"):
        verify_native_manifest_payload(changed, repository_root=ROOT)
    changed = payload()
    changed["bindings"] = changed["bindings"][1:]
    with pytest.raises(NativeManifestSnapshotError, match="集合"):
        verify_native_manifest_payload(changed, repository_root=ROOT)
