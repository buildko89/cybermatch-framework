"""合成デモの再現性、証跡の再読込、上書き拒否を検証する。"""

import json
from pathlib import Path

import pytest

from cybermatch_core.contracts import load_evidence_bundle
from cybermatch_core.scoped_response import run_scoped_response_demo
from scripts.run_scoped_response_demo import main

ROOT = Path(__file__).resolve().parents[1]


def test_demo_is_deterministic_and_evidence_is_reloadable(tmp_path):
    a = run_scoped_response_demo(repository_root=ROOT, output_dir=tmp_path / "a")
    b = run_scoped_response_demo(repository_root=ROOT, output_dir=tmp_path / "b")
    assert a["result_hash"] == b["result_hash"]
    assert a["bundle_hash"] == b["bundle_hash"]
    assert load_evidence_bundle(tmp_path / "a").bundle_hash == a["bundle_hash"]
    payload = json.loads((tmp_path / "a" / "scoped_response_result.json").read_text(encoding="utf-8"))
    assert [row["target_blocked"] for row in payload["timeline"]] == [False, True, True, False, False]
    assert not any(row["other_blocked"] for row in payload["timeline"])
    assert [r["status"] for r in payload["receipts"]] == ["applied", "expired"]
    assert "対象限定対処" in (tmp_path / "a" / "scoped_response_report.md").read_text(encoding="utf-8")
    with pytest.raises(FileExistsError):
        run_scoped_response_demo(repository_root=ROOT, output_dir=tmp_path / "a")


def test_cli_reports_result_and_refuses_overwrite(tmp_path, capsys):
    args = ["--output", str(tmp_path / "demo")]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["evidence_class"] == "synthetic-only"
    assert main(args) == 2
    assert "実行できませんでした" in capsys.readouterr().err

