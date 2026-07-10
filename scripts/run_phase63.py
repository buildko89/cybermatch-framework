"""Run a selected Phase6.3 mission-aware product evaluation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a selected CyberMatch Phase6.3 product evaluation.")
    parser.add_argument("--mission", dest="missions", action="append", required=True, help="Mission to evaluate; repeat for multiple missions.")
    parser.add_argument("--product", dest="products", action="append", required=True, help="Product profile JSON path; repeat for multiple products.")
    parser.add_argument("--topology", required=True, help="Topology preset name or JSON path.")
    parser.add_argument("--output-dir", default="output/phase63_mission_products")
    parser.add_argument("--seed", dest="seeds", action="append", type=int, help="Seed; repeat for multiple seeds.")
    args = parser.parse_args()

    from run_scenarios import run_phase63_mission_aware_product_evaluation

    run_phase63_mission_aware_product_evaluation(
        seeds=args.seeds,
        output_dir=args.output_dir,
        missions=args.missions,
        product_profile_paths=args.products,
        topology_preset=args.topology,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
