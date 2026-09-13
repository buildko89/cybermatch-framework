"""Validate all registered repository assets against their JSON Schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cybermatch_core.contracts import AssetSchemaError, SchemaRegistry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root containing the registered asset paths (default: cwd).",
    )
    args = parser.parse_args(argv)
    try:
        summary = SchemaRegistry().validate_repository(args.root)
    except AssetSchemaError as exc:
        parser.exit(2, f"asset validation failed: {exc}\n")
    print(
        json.dumps(
            {
                "schema_version": summary.schema_version,
                "total": summary.total,
                "counts": summary.counts,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
