"""Run the internal OR-4 comparison without displaying answers to pilot users."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Mapping

from src.cybermatch.pilot.ai import LLMGateway, TemplateExplanationGateway
from src.cybermatch.pilot.config import build_explanation_gateway
from src.cybermatch.pilot.environment import load_pilot_environment
from src.cybermatch.pilot.local_qwen import LocalQwenError, LocalQwenExplanationGateway
from src.cybermatch.pilot.orcarouter import OrcaRouterExplanationGateway
from src.cybermatch.pilot.prompts import SYSTEM_PROMPT, build_explanation_prompt
from src.cybermatch.pilot.shadow import run_shadow_evaluation, write_shadow_report
from src.cybermatch.contracts import canonical_json, canonical_sha256


ROOT = Path(__file__).resolve().parents[1]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run CyberMatch OR-4 shadow evaluation.")
    parser.add_argument("--pilot-result", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("output/pilot/shadow"))
    parser.add_argument("--runs", type=int, choices=range(3, 6), default=3)
    parser.add_argument("--skip-local", action="store_true")
    parser.add_argument("--skip-orca", action="store_true")
    parser.add_argument(
        "--preview-only",
        action="store_true",
        help="Write the exact provider payload preview without running any gateway.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    load_pilot_environment(ROOT)
    source = _repository_path(args.pilot_result)
    payload = json.loads(source.read_text(encoding="utf-8"))
    result_view = payload.get("result_view") if isinstance(payload, Mapping) else None
    if not isinstance(result_view, Mapping):
        raise ValueError("pilot result does not contain a Result View")

    gateways: dict[str, LLMGateway] = {"template": TemplateExplanationGateway()}
    unavailable: dict[str, str] = {}
    if not args.skip_local and not args.preview_only:
        try:
            gateways["local-qwen"] = LocalQwenExplanationGateway(ROOT)
        except LocalQwenError:
            unavailable["local-qwen"] = "pinned_model_unavailable_or_invalid"

    config_path = os.environ.get("CYBERMATCH_PILOT_LLM_CONFIG")
    api_key = os.environ.get("ORCAROUTER_API_KEY")
    if args.skip_orca:
        unavailable["orcarouter"] = "explicitly_skipped"
    elif config_path and api_key and not args.preview_only:
        gateways["orcarouter"] = build_explanation_gateway(
            ROOT, config_path=config_path
        )
    else:
        unavailable["orcarouter"] = "api_key_or_operational_config_not_configured"

    output_dir = _repository_output(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    user_prompt = build_explanation_prompt(result_view)
    preview_gateway = next(
        (
            gateway
            for gateway in gateways.values()
            if isinstance(gateway, OrcaRouterExplanationGateway)
        ),
        None,
    )
    if preview_gateway is None and config_path:
        configured_preview = build_explanation_gateway(ROOT, config_path=config_path)
        if isinstance(configured_preview, OrcaRouterExplanationGateway):
            preview_gateway = configured_preview
    request_body = (
        preview_gateway.build_request_body(result_view)
        if preview_gateway is not None
        else {
            "model": "orcarouter/free",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
    )
    preview_path = output_dir / "provider_send_preview.json"
    preview_path.write_text(
        canonical_json(
            {
                "schema_version": "1.0",
                "destination": "Orca Router /chat/completions when explicitly enabled",
                "request_body": request_body,
                "user_prompt_sha256": canonical_sha256(json.loads(user_prompt)),
                "contains_api_key": False,
            }
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Provider send preview: {preview_path}")
    if args.preview_only:
        print("Preview only: no gateway was called")
        return 0
    report = run_shadow_evaluation(
        result_view, gateways, runs=args.runs, unavailable=unavailable
    )
    json_path, markdown_path = write_shadow_report(report, output_dir)
    print(f"Shadow JSON: {json_path}")
    print(f"Shadow report: {markdown_path}")
    return 0


def _repository_path(path: Path) -> Path:
    candidate = path if path.is_absolute() else ROOT / path
    resolved = candidate.resolve()
    if not resolved.is_relative_to(ROOT):
        raise ValueError("pilot result path must remain inside the repository")
    return resolved


def _repository_output(path: Path) -> Path:
    if path.is_absolute():
        raise ValueError("shadow output path must be repository-relative")
    resolved = (ROOT / path).resolve()
    if not resolved.is_relative_to(ROOT):
        raise ValueError("shadow output path escapes the repository")
    return resolved


if __name__ == "__main__":
    raise SystemExit(main())
