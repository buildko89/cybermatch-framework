"""networkなし・read-only mountのS4b worker境界を実測する。"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import socket
import sys
from pathlib import Path


def _load_review_module(repository_root: Path):
    path = repository_root / "cybermatch" / "agent_skills" / "external_package_review.py"
    spec = importlib.util.spec_from_file_location("external_package_review_worker", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("外部Skill審査moduleを読み込めません")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_is_blocked(root: Path) -> bool:
    marker = root / ".cybermatch_s4b_write_probe"
    try:
        marker.write_text("probe", encoding="utf-8")
    except OSError:
        return True
    try:
        marker.unlink()
    except OSError:
        pass
    return False


def _egress_is_blocked() -> bool:
    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=2):
            return False
    except OSError:
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description="S4b No-Egress workerの拒否probeを実行します")
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    repository = Path(args.repository_root).resolve(strict=True)
    source = Path(args.source_root).resolve(strict=True)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    module = _load_review_module(repository)
    review = module.review_external_packages(source_root=source, manifest_path=args.manifest)
    probe = {
        "schema_version": "1.0",
        "platform": sys.platform,
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "egress_blocked": _egress_is_blocked(),
        "repository_write_blocked": _write_is_blocked(repository),
        "external_source_write_blocked": _write_is_blocked(source),
        "cloud_credentials_present": any(os.environ.get(name) for name in (
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS"
        )),
        "package_count": len(review["packages"]),
        "script_execution_count": review["script_execution_count"],
        "review_result_hash": review["result_hash"],
    }
    probe["passed"] = all((
        probe["platform"] == "linux", probe["egress_blocked"],
        probe["repository_write_blocked"], probe["external_source_write_blocked"],
        not probe["cloud_credentials_present"], probe["package_count"] >= 5,
        probe["script_execution_count"] == 0,
    ))
    (output / "sandbox_probe.json").write_text(
        json.dumps(probe, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(probe, ensure_ascii=False, sort_keys=True))
    return 0 if probe["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
