"""Deterministic Extraction and Hybrid LLM Triage Pipeline for CyberMatch Pilot."""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping

DEFAULT_TRIAGE_SYSTEM_PROMPT = """あなたは隔離検証ラボの設備操作に関するセキュリティ調査支援AIです。
システムによって事前照合された【操作の事実情報】と【差分照合結果】に基づき、調査担当者が状況を即座に把握できるサマリーレポートを簡潔な日本語で作成してください。

【厳格な指示】
1. 事実のみに基づき、不要な憶測や動機の創作はしないでください。
2. 事実と矛盾する記述（逸脱があるのに「承認範囲内」と書く等）や、過度な断定（「安全」「攻撃」等）は禁止します。
3. トリアージ判定（assessment）の設定規則:
   - システム機械判定がbenign（差分なし）の場合は「benign」
   - 承認範囲外の操作や状態変更が検知された場合は「suspicious」
   - 判断材料が不足している場合は「unknown」
4. 優先度（priority）の設定規則:
   - 許可外の状態変更が成功した場合は「high」
   - 承認範囲内の正常操作は「low」
   - 判断材料不足は「medium」
5. summaryは『誰が・何を実行し・状態がどうなったか』を2文以内で過不足なくまとめてください。
6. 出力は指定されたJSON形式のみとし、マークダウンや前置きは含めないでください。"""


def extract_context(events: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Extract deterministic facts and diffs from structured evidence events."""
    info: dict[str, Any] = {
        "when": "",
        "zone": "",
        "device": "",
        "terminal": "",
        "operator": "",
        "account": "",
        "purpose": "",
        "ticket_id": "",
        "approved_operation": "",
        "initial_state": "",
        "actual_operation": "",
        "actual_status": "",
        "final_state": "",
        "evidence_ids": {},
    }

    for ev in events:
        eid = ev.get("event_id", "")
        text = str(ev.get("summary", ""))

        # 作業背景
        if "【作業背景】" in text:
            info["evidence_ids"]["background"] = eid
            m_time = re.search(r"(\d{4}-\d{2}-\d{2}\s+[\d:〜]+(?:\s+JST)?)", text)
            if m_time:
                info["when"] = m_time.group(1)
            m_zone = re.search(r"lab_[a-zA-Z0-9_]+", text)
            if m_zone:
                info["zone"] = m_zone.group(0)
            m_dev = re.search(r"対象[^、]*?([A-Z]+-[0-9]+)", text)
            if m_dev:
                info["device"] = m_dev.group(1)
            else:
                m_dev2 = re.search(r"(?:CTRL|FW|HA|IAM|MON|RCP|LOG|RBAC|JOB|HIST|AUD|ACL)-[0-9]+", text)
                if m_dev2:
                    info["device"] = m_dev2.group(0)
            m_term = re.search(r"LAB-PC-[a-zA-Z0-9_]+", text)
            if m_term:
                info["terminal"] = m_term.group(0)
            m_op = re.search(r"LAB-OP-[0-9]+", text)
            if m_op:
                info["operator"] = m_op.group(0)
            m_acc = re.search(r"lab_maint_[0-9]+", text)
            if m_acc:
                info["account"] = m_acc.group(0)
            m_purp = re.search(r"作業目的は([^。]+)", text)
            if m_purp:
                info["purpose"] = m_purp.group(1).strip()

        # 承認票原文
        if "【承認票原文" in text:
            info["evidence_ids"]["ticket"] = eid
            m_tk = re.search(r"(LAB-CHG-\w+)", text)
            if m_tk:
                info["ticket_id"] = m_tk.group(1)
            m_app = re.search(r"許可操作は『([^』]+)』", text)
            if m_app:
                info["approved_operation"] = m_app.group(1)

        # 権限・初期状態
        if "【権限・初期状態】" in text:
            info["evidence_ids"]["initial"] = eid
            m_init = re.search(r"『([^』]+)』", text)
            if m_init:
                info["initial_state"] = m_init.group(1)

        # 操作監査
        if "【操作監査" in text:
            info["evidence_ids"]["operation"] = eid
            m_req = re.search(r"request='([^']+)'", text)
            if m_req:
                info["actual_operation"] = m_req.group(1)
            m_st = re.search(r"status=(\w+)", text)
            if m_st:
                info["actual_status"] = m_st.group(1)

        # 結果照合
        if "【結果照合" in text:
            info["evidence_ids"]["verification"] = eid
            m_res = re.search(r"『([^』]+)』", text)
            if m_res:
                info["final_state"] = m_res.group(1)

    # 決定論的差分判定
    diff_detected = False
    diff_details = []

    if info["approved_operation"] and info["actual_operation"]:
        if info["approved_operation"] == info["actual_operation"]:
            diff_details.append(f"操作種別: 承認操作『{info['approved_operation']}』と完全一致")
        else:
            diff_detected = True
            diff_details.append(
                f"操作種別の逸脱: 承認は『{info['approved_operation']}』ですが、実際には『{info['actual_operation']}』が実行されました"
            )

    if info["initial_state"] and info["final_state"]:
        if info["initial_state"] == info["final_state"]:
            diff_details.append(f"設備状態: 初期状態『{info['initial_state']}』から変更なし")
        else:
            diff_detected = True
            diff_details.append(
                f"設備状態の変更: 初期値『{info['initial_state']}』から『{info['final_state']}』へ変更確認"
            )

    if diff_detected:
        machine_assessment = "suspicious"
        machine_summary = "承認範囲外の操作または状態変更を検知"
    else:
        machine_assessment = "benign"
        machine_summary = "承認範囲内の操作（状態変更なし）"

    info["diff_detected"] = diff_detected
    info["diff_details"] = diff_details
    info["machine_assessment"] = machine_assessment
    info["machine_summary"] = machine_summary

    return info


def build_triage_user_prompt(ctx: Mapping[str, Any]) -> str:
    """Format extracted context and machine diffs into structured user text."""
    diff_str = "\n".join(f"- {d}" for d in ctx.get("diff_details", []))
    return (
        f"【操作の事実情報】\n"
        f"- 実施日時: {ctx.get('when', '')}\n"
        f"- 対象設備: {ctx.get('device', '')} (ゾーン: {ctx.get('zone', '')}) / 操作端末: {ctx.get('terminal', '')}\n"
        f"- 担当者: {ctx.get('operator', '')} (アカウント: {ctx.get('account', '')})\n"
        f"- 作業目的: {ctx.get('purpose', '')} (承認票: {ctx.get('ticket_id', '')})\n"
        f"- 承認された操作: {ctx.get('approved_operation', '')}\n"
        f"- 実際に実行された操作: {ctx.get('actual_operation', '')} (ステータス: {ctx.get('actual_status', '')})\n"
        f"- 初期状態: {ctx.get('initial_state', '')}\n"
        f"- 操作後の状態照合: {ctx.get('final_state', '')}\n\n"
        f"【システムによる差分照合】\n"
        f"{diff_str}\n"
        f"システム機械判定: {ctx.get('machine_assessment', '')} ({ctx.get('machine_summary', '')})\n\n"
        f"上記に基づき、JSONでサマリーレポートを出力してください。"
    )


def render_triage_report(ctx: Mapping[str, Any], ai_resp: Mapping[str, Any]) -> str:
    """Render a comprehensive 5W1H human-readable Markdown report."""
    diff_lines = "\n".join(f"- {d}" for d in ctx.get("diff_details", []))
    ev_ids = ", ".join(ctx.get("evidence_ids", {}).values())

    assessment_ja = {
        "benign": "承認範囲内（通常）",
        "suspicious": "要調査（逸脱検知）",
        "unknown": "判断保留（情報不足）",
    }.get(str(ai_resp.get("assessment", "")), str(ai_resp.get("assessment", "")))

    priority_ja = {
        "low": "低 (Low)",
        "medium": "中 (Medium)",
        "high": "高 (High)",
    }.get(str(ai_resp.get("priority", "")), str(ai_resp.get("priority", "")))

    return f"""# 設備操作トリアージレポート: {ctx.get('session_id', 'Unknown')}

## 1. 総合判定
- **トリアージ判定**: **{assessment_ja}** (機械判定: {ctx.get('machine_assessment', '')})
- **調査優先度**: **{priority_ja}**
- **状況サマリー**: {ai_resp.get('summary', '')}

---

## 2. 5W1H 詳細分析

| 項目 | 内容 | 根拠・照合情報 |
|---|---|---|
| **いつ (When)** | {ctx.get('when', '')} | ラボ同期時刻 |
| **どこで (Where)** | ゾーン: `{ctx.get('zone', '')}`<br/>対象設備: `{ctx.get('device', '')}`<br/>操作端末: `{ctx.get('terminal', '')}` | 端末認証・監査ログ |
| **誰が (Who)** | 担当者: `{ctx.get('operator', '')}`<br/>アカウント: `{ctx.get('account', '')}` | 個別アカウント認証 |
| **何を・結果 (What)** | **実操作**: `{ctx.get('actual_operation', '')}` (Status: {ctx.get('actual_status', '')})<br/>**承認操作**: `{ctx.get('approved_operation', '')}`<br/>**状態変化**: `{ctx.get('initial_state', '')}` → `{ctx.get('final_state', '')}` | 操作監査・結果照合 |
| **なぜ (Why)** | 申請作業目的: **{ctx.get('purpose', '')}** | 承認票 `{ctx.get('ticket_id', '')}` |
| **どのように (How)** | 操作端末 `{ctx.get('terminal', '')}` から個人認証付きHTTPS管理API経由で実行 | セッション記録 |

---

## 3. 判断理由と調査アクション

### 判定・優先度の理由
- **判断理由**: {ai_resp.get('decision_reason', '')}
- **優先度の理由**: {ai_resp.get('priority_reason', '')}

### 差分照合結果 (システム検出)
{diff_lines}

### 推奨アクション
- **{ai_resp.get('action_recommendation', '')}**

---
*参照根拠イベントID: {ev_ids}*
"""


class TemplateTriageGateway:
    """Deterministic fallback gateway for triage summarization."""

    provider_id = "deterministic-template"
    model_id = "pilot-triage-fallback-v1"

    def summarize(self, ctx: Mapping[str, Any]) -> dict[str, Any]:
        assessment = ctx.get("machine_assessment", "unknown")
        priority = (
            "high"
            if ctx.get("diff_detected")
            else ("low" if assessment == "benign" else "medium")
        )
        op = ctx.get("actual_operation", "不明な操作")
        dev = ctx.get("device", "対象設備")
        op_user = ctx.get("operator", "担当者")

        if ctx.get("diff_detected"):
            summary = (
                f"{op_user}が{dev}に対して承認外の操作（{op}）を実行し、"
                f"設備状態の変更が検知されました。"
            )
            reason = "承認された操作と実際の操作または設備状態に差異が存在するため要調査と判定。"
            priority_reason = "承認範囲外の変更が検知されたため高優先度で調査を実施。"
            action = "操作ログおよび承認票の照合を再確認し、不正アクセスや誤操作の有無を調査する。"
        else:
            summary = (
                f"{op_user}が{dev}に対して承認操作（{op}）を実行し、"
                f"状態は正常に維持されています。"
            )
            reason = "承認操作と実操作が一致し、設備状態にも不正な変更が認められないため。"
            priority_reason = (
                "承認範囲内の正常操作であり、異常な状態変更が確認されていないため低優先度。"
            )
            action = "操作記録を確認し、通常の監視運用を継続する。"

        return {
            "assessment": assessment,
            "summary": summary,
            "decision_reason": reason,
            "priority": priority,
            "priority_reason": priority_reason,
            "action_recommendation": action,
        }


class TriagePipeline:
    """Orchestrator for deterministic context extraction, AI summarization, and 5W1H report rendering."""

    def __init__(self, gateway: Any | None = None) -> None:
        self.gateway = gateway or TemplateTriageGateway()

    def run_triage(
        self,
        events: list[Mapping[str, Any]],
        session_id: str = "",
    ) -> dict[str, Any]:
        ctx = extract_context(events)
        ctx["session_id"] = session_id
        ai_resp = self.gateway.summarize(ctx)
        report = render_triage_report(ctx, ai_resp)
        return {
            "session_id": session_id,
            "context": ctx,
            "ai_response": ai_resp,
            "report_markdown": report,
        }

