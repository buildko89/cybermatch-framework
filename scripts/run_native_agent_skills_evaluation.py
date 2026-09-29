"""承認済みnative Agent Skillsの合成評価を実行するCLI。"""

from __future__ import annotations

import argparse
from pathlib import Path

from cybermatch.agent_skills import evaluate_native_skills_spec, write_native_skills_evaluation


def main() -> int:
    parser = argparse.ArgumentParser(description="native Agent Skillsの合成評価を再生します")
    parser.add_argument("--spec", default="configs/agent_skills/evaluation_specs/synthetic_skills_evaluation_v1.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    result = evaluate_native_skills_spec(repository_root=root, spec_path=args.spec)
    write_native_skills_evaluation(result, args.output, repository_root=root)
    print(f"評価完了: result_hash={result.result_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
