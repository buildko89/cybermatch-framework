"""T3の4モード・ログ健全性・対象限定対処を合成世界で比較評価する。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cybermatch.threat_hunting.active_defense.active_defense_evaluation_report import (
    write_active_defense_evaluation_outputs,
)
from cybermatch.threat_hunting.active_defense.active_defense_evaluation_runner import (
    ActiveDefenseEvaluationRunner, load_active_defense_evaluation_inputs,
)
from cybermatch.threat_hunting.active_defense.contract_validation import ActiveDefenseContractError

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SPEC = "configs/active_defense/runs/t3_synthetic_closed_loop_evaluation_v1.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", default=DEFAULT_SPEC, help="repository相対のT3評価spec JSON")
    parser.add_argument("--output", required=True, type=Path, help="新規の出力directory（上書きしません）")
    args = parser.parse_args(argv)
    destination = args.output if args.output.is_absolute() else ROOT / args.output
    try:
        inputs = load_active_defense_evaluation_inputs(ROOT, args.spec)
        result = ActiveDefenseEvaluationRunner(inputs).run()
        summary = write_active_defense_evaluation_outputs(
            result=result, inputs=inputs, output_dir=destination, repository_root=ROOT)
    except FileExistsError:
        print(f"実行できませんでした: 出力先が既に存在します: {destination}", file=sys.stderr)
        return 2
    except (OSError, ValueError, ActiveDefenseContractError) as exc:
        print(f"実行できませんでした: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
