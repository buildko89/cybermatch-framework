"""Benchmark orchestration for agentic containment and intelligence integrity."""

from __future__ import annotations

import shutil
from pathlib import Path

from benchmark_loader import load_benchmark
from scenario_loader import load_scenario
from src.cybermatch.threat_hunting.models import canonical_json

from .scenario_runner import run_agentic_security_evaluation


def run_agentic_security_benchmark(
    benchmark_path: str = "benchmarks/cybermatch_agentic_security_v1.json",
    output_dir: str = "output/agentic_security/cybermatch_agentic_security_v1",
) -> list[dict[str, object]]:
    config = load_benchmark(benchmark_path)
    if config["metadata"].get("type") != "agentic_security":
        raise ValueError("benchmark metadata.type must be agentic_security")
    root = Path(output_dir).resolve()
    if root.exists():
        raise FileExistsError(f"output path already exists: {root}")
    root.mkdir(parents=True, exist_ok=False)
    rows: list[dict[str, object]] = []
    try:
        for scenario_path in config["scenarios"]:
            scenario = load_scenario(scenario_path)
            name = str(scenario["metadata"]["name"])
            report = run_agentic_security_evaluation(
                scenario, output_dir=str(root / "runs" / name)
            )
            row: dict[str, object] = {"scenario_name": name, "status": "succeeded"}
            if "agentic" in report:
                metrics = report["agentic"]["metrics"]
                comparison = report["agentic"]["comparison"]
                row.update(
                    {
                        "risk_score": metrics["risk_score"],
                        "prevented_event_count": metrics["prevented_event_count"],
                        "security_invariant_survival_rate": metrics["security_invariant_survival_rate"],
                        "risk_score_reduction": comparison["risk_score_reduction"],
                        "prevented_event_lift": comparison["prevented_event_lift"],
                    }
                )
                learning = report["agentic"].get("learning")
                if learning is not None:
                    row["reward_hacking_propensity_reduction"] = learning["comparison"][
                        "final_propensity_reduction"
                    ]
            if "threat_intelligence" in report:
                metrics = report["threat_intelligence"]["metrics"]
                row.update(
                    {
                        "fabricated_advisory_acceptance_rate": metrics[
                            "fabricated_advisory_acceptance_rate"
                        ],
                        "valid_advisory_acceptance_rate": metrics["valid_advisory_acceptance_rate"],
                    }
                )
            rows.append(row)
        summary = {
            "schema_version": "1.0",
            "benchmark_name": config["metadata"]["name"],
            "runner": "agentic_security_evaluation",
            "scenario_count": len(config["scenarios"]),
            "succeeded_cases": len(rows),
            "benchmark_completeness": len(rows) / len(config["scenarios"]),
            "rows": rows,
        }
        (root / "agentic_security_benchmark_summary.json").write_text(
            canonical_json(summary) + "\n", encoding="utf-8", newline="\n"
        )
        return rows
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


__all__ = ["run_agentic_security_benchmark"]
