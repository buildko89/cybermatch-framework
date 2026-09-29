"""対象限定対処の合成デモを実行し、日本語レポートとEvidence Bundleを保存する。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from cybermatch_core.scoped_response import run_scoped_response_demo

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="新規の出力ディレクトリ（既存は上書きしない）")
    args = parser.parse_args(argv)
    destination = args.output if args.output.is_absolute() else ROOT / args.output
    try:
        result = run_scoped_response_demo(repository_root=ROOT, output_dir=destination)
    except (OSError, ValueError) as exc:
        print(f"実行できませんでした: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

