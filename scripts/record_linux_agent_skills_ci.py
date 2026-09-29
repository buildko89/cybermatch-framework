"""Linux CIで得たAgent Skills評価・sandbox結果を一つの記録にまとめる。"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-metrics", required=True)
    parser.add_argument("--external-review", required=True)
    parser.add_argument("--sandbox-probe", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    native = json.loads(Path(args.native_metrics).read_text(encoding="utf-8"))
    external = json.loads(Path(args.external_review).read_text(encoding="utf-8"))
    probe = json.loads(Path(args.sandbox_probe).read_text(encoding="utf-8"))
    record = {
        "schema_version": "1.0", "platform": sys.platform,
        "platform_release": platform.release(), "python_version": platform.python_version(),
        "native_result_hash": native["result_hash"],
        "external_review_result_hash": external["result_hash"],
        "sandbox_passed": probe["passed"], "source_revision": external["source_revision"],
    }
    if sys.platform != "linux" or not probe["passed"]:
        raise SystemExit("Linux CIまたはsandbox probeが未達です")
    Path(args.output).write_text(json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
