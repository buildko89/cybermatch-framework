import json
from pathlib import Path

import pytest

from cybermatch.agent_skills import (
    ExternalSkillReviewError,
    review_external_packages,
    snapshot_external_package,
    write_external_review_outputs,
)
from cybermatch.contracts import load_evidence_bundle


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "configs/agent_skills/external_review/s4b_external_candidates_v1.json"
SOURCE = ROOT / "tmp/anthropic-cybersecurity-skills-full"


@pytest.mark.skipif(not SOURCE.is_dir(), reason="固定外部source checkoutがない環境ではCI jobが別途取得する")
def test_s4b_fixed_external_packages_are_hash_verified_and_never_bound(tmp_path):
    result = review_external_packages(source_root=SOURCE, manifest_path=MANIFEST)
    assert result["source_revision"] == "54a798831d2266a3ca61ce68a7acb80b81160d57"
    assert len(result["packages"]) == 8
    assert result["script_execution_count"] == 0
    assert result["external_binding_count"] == 0
    assert {row["decision"] for row in result["packages"]} == {"reviewed_not_bound", "excluded"}
    output = tmp_path / "review"
    hashes = write_external_review_outputs(result, output, repository_root=ROOT)
    assert hashes["bundle_hash"] == load_evidence_bundle(output).bundle_hash
    assert "外部Agent Skills S4b審査レポート" in (output / "report.md").read_text(encoding="utf-8")


def test_external_loader_rejects_snapshot_drift(tmp_path):
    source = tmp_path / "source"
    package = source / "example-skill"
    package.mkdir(parents=True)
    (package / "SKILL.md").write_text("---\nname: example-skill\ndescription: test\n---\n# Test\n", encoding="utf-8")
    (package / "LICENSE").write_text("Apache License 2.0\n", encoding="utf-8")
    snapshot = snapshot_external_package(source, "example-skill")
    manifest = {
        "schema_version": "1.0", "execution_mode": "recipe_only",
        "source_revision": "0" * 40, "license_sha256": snapshot.license_sha256,
        "candidates": [{"skill_id": "example-skill", "snapshot_hash": "f" * 64,
                        "decision": "excluded", "reason_codes": ["test"]}],
    }
    # git revision検査より前に不明なsourceを受理しない。
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises((ExternalSkillReviewError, FileNotFoundError)):
        review_external_packages(source_root=tmp_path, manifest_path=path)
