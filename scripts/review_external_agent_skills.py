"""固定済み外部Agent Skillsを実行せずに審査するS4b CLI。"""

from __future__ import annotations

import argparse
from pathlib import Path

from cybermatch.agent_skills import review_external_packages, write_external_review_outputs


def main() -> int:
    parser = argparse.ArgumentParser(description="固定済み外部Agent Skillsのhash・license・risk signalを審査します")
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--manifest", default="configs/agent_skills/external_review/s4b_external_candidates_v1.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    manifest = Path(args.manifest)
    if not manifest.is_absolute():
        manifest = repository / manifest
    result = review_external_packages(source_root=args.source_root, manifest_path=manifest)
    written = write_external_review_outputs(result, args.output, repository_root=repository)
    print(f"外部Skill審査完了: result_hash={written['result_hash']} bundle_hash={written['bundle_hash']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
