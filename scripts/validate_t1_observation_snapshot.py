"""T1合成観測を指定stepのsnapshotとして検証する。成果物は書き換えない。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from cybermatch_core.threat_hunting import T0ObservationAdapter, T0ObservationAdapterError


ROOT = Path(__file__).resolve().parents[1]


def _relative_json_path(value: str) -> Path:
    requested = Path(value)
    if requested.is_absolute():
        raise argparse.ArgumentTypeError("入力はrepository内の相対JSON pathで指定してください")
    path = (ROOT / requested).resolve()
    if not path.is_relative_to(ROOT) or path.suffix.lower() != ".json":
        raise argparse.ArgumentTypeError("入力はrepository内の相対JSON pathで指定してください")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, type=_relative_json_path, help="観測envelope JSON（複数指定可）")
    parser.add_argument("--run-id", required=True, help="期待するrun ID")
    parser.add_argument("--tenant-id", required=True, help="期待するtenant ID")
    parser.add_argument("--scenario-id", required=True, help="出力HuntEventのscenario ID")
    parser.add_argument("--current-step", required=True, type=int, help="観測を利用するsimulation step")
    args = parser.parse_args(argv)
    try:
        payloads = tuple(json.loads(path.read_text(encoding="utf-8")) for path in args.input)
        adapter = T0ObservationAdapter(run_id=args.run_id, tenant_id=args.tenant_id, scenario_id=args.scenario_id)
        events = adapter.adapt_snapshot(payloads, current_step=args.current_step)
    except (OSError, json.JSONDecodeError, T0ObservationAdapterError) as exc:
        print(f"検証できませんでした: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "event_count": len(events),
        "event_ids": [event.event_id for event in events],
        "observed_steps": [event.step for event in events],
        "available_steps": [event.attributes["available_step"] for event in events],
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
