"""対象限定の失効要求を5stepで再生し、日本語レポートと証跡を出力する。"""

from __future__ import annotations

import json
from pathlib import Path

from cybermatch.contracts import (
    SchemaRegistry, ScopedResponseAction, canonical_json, canonical_sha256,
    write_evidence_bundle,
)
from .models import Finding, HuntEvent
from .scoped_response import ScopedResponseController


def run_scoped_response_demo(*, repository_root: Path, output_dir: Path) -> dict[str, object]:
    """実機操作なし。対象identityだけがstep 1/2で拒否される固定回帰デモ。"""
    source = repository_root / "configs/scoped_response/actions/identity_revocation_example.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    SchemaRegistry().validate("scoped_response_action", payload, source=str(source))
    request = ScopedResponseAction.from_dict(payload)
    if (
        request.action_type != "revoke_identity" or request.requested_step != 0
        or request.effective_step != 1 or request.expires_step != 3
        or len(request.subject_refs) != 1 or len(request.finding_ids) != 1
    ):
        raise ValueError("このデモにはstep 0要求・1開始・3終了の単一identityサンプルが必要です")
    target = request.subject_refs[0]
    other = "identity-unrelated"
    if target == other:
        raise ValueError("対象と比較用identityが重複しています")
    control = ScopedResponseController(
        run_id=request.run_id, tenant_id=request.tenant_id,
        subjects={"identity": (target, other)}, policy_hashes=(request.policy_hash,),
    )
    observation = HuntEvent(
        schema_version="1.0", event_id="obs-001", step=0, campaign_id="stream-example",
        scenario_id="scoped-response-demo-v1", seed=0, actor_id=None, coalition_id=None,
        event_type="credential_use", source_node=0, target_node=1,
        source_role=None, target_role=None, signal_class="telemetry",
        attributes={"run_id": request.run_id, "tenant_id": request.tenant_id,
                    "available_step": 0, "identity_ref": target},
    )
    finding = Finding(
        schema_version="1.0", finding_id=request.finding_ids[0], recipe_id="demo_observation",
        recipe_version="1.0", severity="high", score=0.9, campaign_id=observation.campaign_id,
        actor_id=None, start_step=0, end_step=0, title="合成認証イベントの確認",
        reason="契約検証用の固定Finding。検知精度の測定ではありません",
        evidence_event_ids=(observation.event_id,),
    )
    timeline = []
    for step in range(5):
        control.tick(step)
        if step == 0:
            control.register_finding(finding, (observation,))
            control.submit(request)
            control.submit(request)
        timeline.append({
            "step": step, "target_blocked": control.is_blocked("identity", target),
            "other_blocked": control.is_blocked("identity", other),
            "receipt_count": len(control.receipts),
        })
    result = {
        "schema_version": "1.0", "evidence_class": "synthetic-only",
        "action": request.to_dict(), "receipts": [item.to_dict() for item in control.receipts],
        "timeline": timeline,
        "limitations": ["実アカウント・既存session・OS・ネットワークへの操作は行わない",
                        "固定Findingを用いる契約デモであり、攻撃検知性能の評価ではない"],
    }
    result_hash = canonical_sha256(result)
    output_dir.mkdir(parents=True, exist_ok=False)
    result_path = output_dir / "scoped_response_result.json"
    result_path.write_text(canonical_json(result) + "\n", encoding="utf-8")
    report_path = output_dir / "scoped_response_report.md"
    rows = "\n".join(
        f"| {row['step']} | {'拒否' if row['target_blocked'] else '許可'} | "
        f"{'拒否' if row['other_blocked'] else '許可'} | {row['receipt_count']} |"
        for row in timeline
    )
    fence = chr(96) * 3
    report = (
        "# 対象限定対処の実行結果\n\n"
        "合成観測に基づく要求をstep 0で予約し、step 1から対象identityだけを拒否しました。"
        "step 3で期限切れとなります。実機操作は行いません。\n\n"
        f"{fence}mermaid\nstateDiagram-v2\n    [*] --> pending: step 0 要求\n"
        f"    pending --> applied: step 1\n    applied --> expired: step 3\n{fence}\n\n"
        "| step | 対象identity | 無関係なidentity | receipt累計 |\n"
        "|---|---|---|---|\n" + rows + "\n\n"
        f"決定論的結果hash: {result_hash}\n\n"
        "## 解釈上の制約\n\n" + "\n".join(f"- {v}" for v in result["limitations"]) + "\n"
    )
    report_path.write_text(report, encoding="utf-8")
    bundle = write_evidence_bundle(
        output_dir, repository_root=repository_root, run_id=request.run_id,
        runner="scoped_response_demo", scenario_id="scoped-response-demo-v1", seed=0,
        input_payloads={"action": payload, "observation": observation.to_dict(), "finding": finding.to_dict()},
        metrics={"applied_action_count": sum(r.status == "applied" for r in control.receipts),
                 "rejected_action_count": sum(r.status == "rejected" for r in control.receipts),
                 "unrelated_subject_block_count": sum(row["other_blocked"] for row in timeline),
                 "result_hash": result_hash},
        artifact_paths=(result_path, report_path),
    )
    return {"result_hash": result_hash, "bundle_hash": bundle.bundle_hash,
            "report": str(report_path), "evidence_class": "synthetic-only"}

