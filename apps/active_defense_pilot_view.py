"""T4b hypothesis Pilot用の独立UI renderer。runnerや評価処理を含めない。"""

from __future__ import annotations

from collections.abc import Mapping


def render_active_defense_pilot_view(ui: object, view: Mapping[str, object], shadow: Mapping[str, object]) -> None:
    """Streamlit互換の最小interfaceへ、sanitized viewとshadow結果だけを描画する。"""
    ui.subheader("CTI・ASM仮説 Pilot（shadow）")
    ui.caption(f"run: {view['run_id']} / evidence: {view['evidence_class']}")
    ui.metric("候補仮説", len(view["candidates"]))
    ui.json({"execution_authorized": shadow["execution_authorized"], "status": shadow["status"],
             "proposal": shadow["proposal"]})
    ui.warning("shadow提案です。自動対処・閾値変更・allowlist外recipe実行は行いません。")


__all__ = ["render_active_defense_pilot_view"]
