"""Run the versioned Agentic Cyber Resilience flagship benchmark."""

import argparse

from src.cybermatch.agentic.protocol import run_agentic_resilience_protocol


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark", default="benchmarks/cybermatch_agentic_resilience_v2.json"
    )
    parser.add_argument(
        "--output-dir", default="output/agentic_security/cybermatch_agentic_resilience_v2"
    )
    args = parser.parse_args(argv)
    result = run_agentic_resilience_protocol(args.benchmark, args.output_dir)
    print(result["evidence_bundle_hash"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
