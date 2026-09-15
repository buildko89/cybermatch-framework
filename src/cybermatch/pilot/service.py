"""Application service for the first approved external-replay pilot slice."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from src.cybermatch.contracts import canonical_json, canonical_sha256
from src.cybermatch.threat_hunting.replay import run_external_replay_evaluation

from .ai import LLMGateway, grounded_explanation
from .config import build_explanation_gateway
from .contracts import require_approved_run_spec, validate_contract
from .grounding import build_result_view


class PilotEvaluationService:
    def __init__(
        self,
        repository_root: str | Path,
        *,
        output_root: str | Path | None = None,
        gateway: LLMGateway | None = None,
        llm_config_path: str | Path | None = None,
    ):
        if gateway is not None and llm_config_path is not None:
            raise ValueError("gateway and llm_config_path are mutually exclusive")
        self.root = Path(repository_root).resolve()
        self.output_root = (
            Path(output_root).resolve() if output_root is not None else self.root / "output" / "pilot"
        )
        self.catalog = {
            "source": "replays/anonymized/ocsf_boundary_escape_v1.jsonl",
            "truth": "replays/anonymized/ocsf_boundary_escape_v1.ground_truth.json",
            "mapping": "mappings/telemetry/ocsf_security_finding_v1.json",
            "recipe": "recipes/threat_hunting/agentic_boundary_pressure_v1.json",
            "reference": "replays/synthetic_reference/agentic_boundary_pressure_v1.json",
        }
        self.gateway = gateway or build_explanation_gateway(
            self.root, config_path=llm_config_path
        )

    def catalog_view(self) -> dict[str, object]:
        return {
            "sources": ["ocsf-boundary-escape-fixture-v1"],
            "mappings": ["ocsf_security_finding_v1"],
            "recipes": ["agentic_boundary_pressure_v1"],
            "scenarios": ["agentic-boundary-pressure-external"],
            "evidence_classes": ["replay-backed"],
        }

    def gateway_status(self) -> dict[str, object]:
        """Return non-secret runtime details safe to display before execution."""

        return {
            "provider_id": self.gateway.provider_id,
            "model_id": self.gateway.model_id,
            "mode": (
                "offline-template"
                if self.gateway.provider_id == "deterministic-template"
                else "ai-assisted"
            ),
        }

    def validate(self, run_spec: Mapping[str, object]) -> None:
        validate_contract("run_spec", run_spec)

    def execute(
        self, run_spec: Mapping[str, object], *, gateway: LLMGateway | None = None
    ) -> dict[str, object]:
        require_approved_run_spec(run_spec)
        output = self.output_root / str(run_spec["run_id"])
        summary = run_external_replay_evaluation(
            source_path=self.root / self.catalog["source"],
            mapping_path=self.root / self.catalog["mapping"],
            recipe_path=self.root / self.catalog["recipe"],
            ground_truth_path=self.root / self.catalog["truth"],
            synthetic_reference_path=self.root / self.catalog["reference"],
            output_dir=output,
            campaign_id="phase3-anonymized-replay",
            scenario_id=str(run_spec["scenario_id"]),
            evidence_class=str(run_spec["evidence_class"]),
            seed=int(run_spec["seed"]),
            repository_root=self.root,
        )
        view = build_result_view(output)
        explanation = grounded_explanation(view, gateway or self.gateway)
        record = {
            "run_spec": dict(run_spec),
            "summary": summary,
            "result_view": view,
            "explanation": explanation,
        }
        (output / "pilot_result.json").write_text(
            canonical_json(record) + "\n", encoding="utf-8", newline="\n"
        )
        return record

    def record_decision(
        self, run_id: str, *, decision: str, rationale: str, decided_by: str
    ) -> Path:
        if decision not in {"accept", "additional_validation", "reject"}:
            raise ValueError("unsupported pilot decision")
        output = self.output_root / run_id
        view = build_result_view(output)
        result_path = output / "pilot_result.json"
        if not result_path.is_file():
            raise FileNotFoundError(f"pilot result does not exist: {result_path}")
        result = json.loads(result_path.read_text(encoding="utf-8"))
        explanation = result.get("explanation") if isinstance(result, Mapping) else None
        audit = explanation.get("audit") if isinstance(explanation, Mapping) else None
        if not isinstance(audit, Mapping):
            raise ValueError("pilot result does not contain an LLM audit")
        validate_contract("llm_audit", audit)
        saved_view = result.get("result_view") if isinstance(result, Mapping) else None
        if not isinstance(saved_view, Mapping) or dict(saved_view) != view:
            raise ValueError("pilot result view does not match the verified result")
        if audit.get("result_view_hash") != canonical_sha256(view):
            raise ValueError("LLM audit result-view hash does not match the verified result")
        if audit.get("bundle_hash") != view["bundle_hash"]:
            raise ValueError("LLM audit bundle hash does not match the verified result")
        payload = {
            "schema_version": "1.0",
            "run_id": run_id,
            "decision": decision,
            "rationale": rationale,
            "decided_by": decided_by,
            "bundle_hash": view["bundle_hash"],
            "llm_audit_hash": canonical_sha256(audit),
        }
        path = output / "human_decision.json"
        if path.exists():
            raise FileExistsError(f"decision already exists: {path}")
        path.write_text(canonical_json(payload) + "\n", encoding="utf-8", newline="\n")
        return path


__all__ = ["PilotEvaluationService"]
