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
   - システム機械判定がbenign（差分なし・承認範囲内）の場合は「benign」
   - 承認範囲外の操作や不正な状態変更が検知された場合は「suspicious」
   - 判断材料が不足している（エビデンス欠落・形式異常等）場合は必ず「unknown」
   - システム機械判定がunknownの場合、AIが独断でbenignやsuspiciousに変更してはなりません（Fail-Safe原則）。
4. 優先度（priority）の設定規則:
   - 許可外の状態変更が成功した場合は「high」
   - 承認範囲内の正常操作は「low」
   - 判断材料不足（unknown）は「medium」
5. summaryは『誰が・何を実行し・状態がどうなったか』を2文以内で過不足なくまとめてください。
6. 出力は指定されたJSON形式のみとし、マークダウンや前置きは含めないでください。"""


def extract_context(events: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Extract deterministic facts, diffs, and Fail-Safe status from structured evidence events."""
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
        "missing_elements": [],
    }

    # 入力欠落チェック (Fail-Safe: 空入力)
    if not events:
        info["machine_assessment"] = "unknown"
        info["diff_detected"] = False
        info["diff_details"] = ["入力イベントが存在しません (空リスト)。判断材料が不足しています (Fail-Safe)。"]
        info["machine_summary"] = "エビデンス欠落のため判定保留 (Fail-Safe)"
        info["missing_elements"].append("events_empty")
        return info

    for ev in events:
        eid = str(ev.get("event_id", ""))
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

    # 形式異常・未対応形式の検査 (Fail-Safe: 抽出エビデンスが1件も存在しない)
    if not info["evidence_ids"]:
        info["machine_assessment"] = "unknown"
        info["diff_detected"] = False
        info["diff_details"] = ["未対応形式のログイベントです。必要な照合タグを抽出できませんでした (Fail-Safe)。"]
        info["machine_summary"] = "形式未対応のため判定保留 (Fail-Safe)"
        info["missing_elements"].append("no_structured_tags_matched")
        return info

    # 必須エビデンスの欠落チェック
    if not info["actual_operation"]:
        info["missing_elements"].append("missing_actual_operation")
    if not info["approved_operation"]:
        info["missing_elements"].append("missing_approved_operation")

    # 監査ログまたは承認票が欠落している場合は差分照合不能のため unknown
    if info["missing_elements"]:
        missing_str = "、".join(info["missing_elements"])
        info["machine_assessment"] = "unknown"
        info["diff_detected"] = False
        info["diff_details"] = [f"必須エビデンス欠落 ({missing_str}): 差分照合に必要な情報が不足しています (Fail-Safe)。"]
        info["machine_summary"] = "エビデンス欠落のため判定保留 (Fail-Safe)"
        return info

    # 決定論的差分判定
    diff_detected = False
    diff_details = []

    # 操作種別の比較
    app_op = info["approved_operation"]
    act_op = info["actual_operation"]
    is_state_changing_approved = any(
        app_op.startswith(m) for m in ("PUT", "POST", "PATCH", "DELETE")
    ) or "変更" in info.get("purpose", "")

    if app_op == act_op:
        diff_details.append(f"操作種別: 承認操作『{app_op}』と完全一致")
        op_matched = True
    elif is_state_changing_approved and len(app_op.split()) > 1 and act_op.startswith(app_op.split()[0] + " " + app_op.split()[1]):
        diff_details.append(f"操作種別: 承認操作パス『{app_op}』と一致")
        op_matched = True
    else:
        diff_detected = True
        op_matched = False
        diff_details.append(
            f"操作種別の逸脱: 承認は『{app_op}』ですが、実際には『{act_op}』が実行されました"
        )

    # 設備状態の比較 (正常な保守PUT操作のモデル化: R07対応)
    if info["initial_state"] and info["final_state"]:
        if info["initial_state"] == info["final_state"]:
            diff_details.append(f"設備状態: 初期状態『{info['initial_state']}』から変更なし")
        else:
            # 状態変化が存在する
            if op_matched and is_state_changing_approved:
                # 承認された操作が状態変更であり、操作が一致している場合は正常な保守変更と判定
                diff_details.append(
                    f"設備状態の変更: 承認された保守操作に従い、初期値『{info['initial_state']}』から『{info['final_state']}』へ正常に変更確認 (承認範囲内)"
                )
            else:
                # GET等の非変更操作のはずが状態変化している、または未承認操作による状態変化
                diff_detected = True
                diff_details.append(
                    f"設備状態の変更: 初期値『{info['initial_state']}』から『{info['final_state']}』へ変更確認 (承認外または未許可の変更)"
                )

    if diff_detected:
        machine_assessment = "suspicious"
        machine_summary = "承認範囲外の操作または不正な状態変更を検知"
    else:
        machine_assessment = "benign"
        if is_state_changing_approved and info["initial_state"] != info["final_state"]:
            machine_summary = "承認範囲内の保守操作（許可された設定変更を確認）"
        else:
            machine_summary = "承認範囲内の操作（状態変更なし）"

    info["diff_detected"] = diff_detected
    info["diff_details"] = diff_details
    info["machine_assessment"] = machine_assessment
    info["machine_summary"] = machine_summary

    return info


def build_triage_user_prompt(ctx: Mapping[str, Any]) -> str:
    """Format extracted context and machine diffs into structured user text."""
    diff_str = "\n".join(f"- {d}" for d in ctx.get("diff_details", []))
    prompt = (
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
    )

    if ctx.get("machine_assessment") == "unknown":
        prompt += (
            "【重要指示】\n"
            "システム機械判定は unknown です。判断材料が不足しているため、推測での断定や自動遮断の指示は避け、"
            "assessment は必ず「unknown」を設定してください。\n\n"
        )

    prompt += "上記に基づき、JSONでサマリーレポートを出力してください。"
    return prompt


def render_triage_report(ctx: Mapping[str, Any], ai_resp: Mapping[str, Any]) -> str:
    """Render a comprehensive 5W1H human-readable Markdown report with Fail-Safe and Fallback alerts."""
    diff_lines = "\n".join(f"- {d}" for d in ctx.get("diff_details", []))
    ev_ids = ", ".join(ctx.get("evidence_ids", {}).values())

    assessment_ja = {
        "benign": "承認範囲内（通常）",
        "suspicious": "要調査（逸脱検知）",
        "unknown": "判断保留（情報不足・Fail-Safe）",
    }.get(str(ai_resp.get("assessment", "")), str(ai_resp.get("assessment", "")))

    priority_ja = {
        "low": "低 (Low)",
        "medium": "中 (Medium)",
        "high": "高 (High)",
    }.get(str(ai_resp.get("priority", "")), str(ai_resp.get("priority", "")))

    fallback_alert = ""
    if ai_resp.get("fallback_used"):
        fallback_alert = (
            f"> [!NOTE]\n"
            f"> 本レポートは推論ゲートウェイ障害（理由: {ai_resp.get('fallback_reason', '')}）に伴い、"
            f"確定的な事前定義テンプレートへフォールバックして生成されました。\n\n"
        )

    unknown_alert = ""
    if ctx.get("machine_assessment") == "unknown":
        unknown_alert = (
            "> [!WARNING]\n"
            "> 本事象はエビデンス不足または未対応形式（Fail-Safe）により判定保留（unknown）です。"
            "自動遮断・防護ルールの自動適用は禁止されています。\n\n"
        )

    return f"""# 設備操作トリアージレポート: {ctx.get('session_id', 'Unknown')}

{fallback_alert}{unknown_alert}## 1. 総合判定
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
        op = ctx.get("actual_operation", "不明な操作")
        dev = ctx.get("device", "対象設備")
        op_user = ctx.get("operator", "担当者")

        if assessment == "unknown":
            priority = "medium"
            summary = (
                f"{dev}に関する操作情報またはエビデンスが不足しており、"
                f"自動判定を保留（unknown）とします。"
            )
            reason = "必須フィールドまたはログエビデンスが不足しているため、差分を確定的に照合できないため (Fail-Safe)。"
            priority_reason = "情報不足のため即時遮断は行わず、追加ログの収集および手動確認が必要。"
            action = "不足している承認票または操作監査ログを収集・再投入し、安全が確認されるまで自動遮断は保留すること。"
        elif ctx.get("diff_detected"):
            priority = "high"
            summary = (
                f"{op_user}が{dev}に対して承認外の操作（{op}）を実行し、"
                f"設備状態の変更が検知されました。"
            )
            reason = "承認された操作と実際の操作または設備状態に差異が存在するため要調査と判定。"
            priority_reason = "承認範囲外の変更が検知されたため高優先度で調査を実施。"
            action = "操作ログおよび承認票の照合を再確認し、不正アクセスや誤操作の有無を調査する。"
        else:
            priority = "low"
            if "許可された設定変更を確認" in ctx.get("machine_summary", ""):
                summary = (
                    f"{op_user}が{dev}に対して承認された保守操作（{op}）を実行し、"
                    f"設定変更が正常に完了しました。"
                )
                reason = "承認操作と実操作が一致し、状態変更も承認範囲内であることが確認されたため。"
                priority_reason = "承認範囲内の正常な保守変更であり、異常な逸脱は認められないため低優先度。"
                action = "操作記録を確認・保存し、通常の監視運用を継続する。"
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
        timeout_seconds: float = 30.0,
    ) -> dict[str, Any]:
        ctx = extract_context(events)
        ctx["session_id"] = session_id

        fallback_used = False
        fallback_reason: str | None = None
        fallback_provider: str | None = None

        try:
            # Gateway 呼び出し
            ai_resp = self.gateway.summarize(ctx)

            # AI応答スキーマ・整合性の検証 (R08)
            required_keys = (
                "assessment",
                "summary",
                "decision_reason",
                "priority",
                "priority_reason",
                "action_recommendation",
            )
            if not isinstance(ai_resp, dict) or not all(k in ai_resp for k in required_keys):
                raise ValueError("Gateway returned malformed or incomplete response")

        except Exception as exc:
            fallback_used = True
            fallback_reason = f"{type(exc).__name__}: {str(exc)}"
            fallback_provider = getattr(TemplateTriageGateway, "provider_id", "deterministic-template")
            ai_resp = TemplateTriageGateway().summarize(ctx)

        # Fail-Safe 規則強制: 機械判定が unknown の場合、AI応答が勝手に変更することを禁止 (R03)
        if ctx.get("machine_assessment") == "unknown":
            ai_resp["assessment"] = "unknown"
            ai_resp["priority"] = "medium"

        if fallback_used:
            ai_resp["fallback_used"] = True
            ai_resp["fallback_reason"] = fallback_reason
            ai_resp["fallback_provider"] = fallback_provider

        report = render_triage_report(ctx, ai_resp)
        return {
            "session_id": session_id,
            "context": ctx,
            "ai_response": ai_resp,
            "report_markdown": report,
            "fallback_used": fallback_used,
            "fallback_reason": fallback_reason,
        }
