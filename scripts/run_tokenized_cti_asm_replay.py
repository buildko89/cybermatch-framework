"""T4a: 事前token化済みCTI・ASM snapshotの検知適合性をread-only評価する。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cybermatch.threat_hunting.active_defense.tokenized_replay_report import write_tokenized_replay_outputs
from cybermatch.threat_hunting.active_defense.tokenized_replay_runner import (
    TokenizedReplayRunner, load_tokenized_replay_inputs,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SPEC = "configs/active_defense/runs/t4a_tokenized_replay_v1.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", default=DEFAULT_SPEC, help="repository相対のT4a run spec")
    parser.add_argument("--output", required=True, type=Path, help="新規出力directory")
    args = parser.parse_args(argv)
    destination = args.output if args.output.is_absolute() else ROOT / args.output
    try:
        inputs = load_tokenized_replay_inputs(ROOT, args.spec)
        summary = write_tokenized_replay_outputs(
            result=TokenizedReplayRunner(inputs).run(), inputs=inputs,
            output_dir=destination, repository_root=ROOT)
    except FileExistsError:
        print(f"実行できませんでした: 出力先が既に存在します: {destination}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"実行できませんでした: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
