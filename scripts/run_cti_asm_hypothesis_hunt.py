"""T2: CTI・ASM相関から仮説を作り、予算内で内部ログを調べる合成runを実行する。

出力（新規directoryのみ。既存は上書きしない）:
  matches.jsonl / hypotheses.jsonl / scheduler_decisions.jsonl / binding_executions.jsonl /
  finding_trace.jsonl / findings.jsonl / metrics.json / context_hunting_result.json /
  report.md（日本語）/ Evidence Bundle
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from cybermatch_core.active_defense import (
    ActiveDefenseContractError, ContextHuntingRunner, load_context_hunting_inputs,
    write_context_hunting_outputs,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SPEC = "configs/active_defense/runs/t2_synthetic_context_hunting_v1.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--spec", default=DEFAULT_SPEC, help=f"repository相対のrun spec JSON（既定: {DEFAULT_SPEC}）")
    parser.add_argument("--output", required=True, type=Path, help="新規の出力ディレクトリ（既存は上書きしない）")
    args = parser.parse_args(argv)
    destination = args.output if args.output.is_absolute() else ROOT / args.output
    try:
        inputs = load_context_hunting_inputs(ROOT, args.spec)
        result = ContextHuntingRunner(inputs).run()
        summary = write_context_hunting_outputs(result=result, inputs=inputs, output_dir=destination,
                                                repository_root=ROOT)
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
