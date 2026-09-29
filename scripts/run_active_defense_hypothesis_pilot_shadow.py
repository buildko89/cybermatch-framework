"""T4b: 検証済み仮説候補に対するallowlist型shadow Pilotを実行する。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cybermatch.threat_hunting.active_defense.hypothesis_pilot import (
    build_hypothesis_pilot_view, run_hypothesis_pilot_shadow, write_hypothesis_pilot_shadow,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluation-output", required=True, type=Path,
                        help="Evidence Bundleとhypotheses.jsonlを持つT2/T4a出力directory")
    parser.add_argument("--output", required=True, type=Path, help="新規のshadow出力directory")
    args = parser.parse_args(argv)
    try:
        view = build_hypothesis_pilot_view(args.evaluation_output)
        result = run_hypothesis_pilot_shadow(view)
        paths = write_hypothesis_pilot_shadow(view, result, args.output)
    except (OSError, ValueError) as exc:
        print(f"実行できませんでした: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"], "execution_authorized": False,
                      "view_hash": result["view_hash"], "outputs": [str(path) for path in paths]},
                     ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
