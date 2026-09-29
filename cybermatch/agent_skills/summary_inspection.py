"""合成要約に含まれる明示的な隠蔽指示だけを検査する。"""

from __future__ import annotations

import re
from dataclasses import dataclass


_CONCEALMENT = (
    re.compile(r"(?:ignore|omit|hide|remove)\s+(?:the\s+)?(?:record|evidence|alert)", re.I),
    re.compile(r"(?:記録|証拠|警告).{0,12}(?:隠す|省略|削除|無視)"),
)


@dataclass(frozen=True)
class SummaryInspection:
    summary_id: str
    verdict: str
    matched_spans: tuple[str, ...]
    visible_record_refs: tuple[str, ...]
    detector_version: str = "explicit-concealment-v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "summary_id": self.summary_id, "detector_version": self.detector_version,
            "verdict": self.verdict, "matched_spans": list(self.matched_spans),
            "visible_record_refs": list(self.visible_record_refs),
        }


def inspect_summary(*, summary_id: str, summary_text: str, visible_record_refs: tuple[str, ...]) -> SummaryInspection:
    if not summary_text.strip():
        return SummaryInspection(summary_id, "abstain", (), visible_record_refs)
    spans = tuple(match.group(0) for pattern in _CONCEALMENT for match in pattern.finditer(summary_text))
    return SummaryInspection(summary_id, "flag" if spans else "clear", spans, visible_record_refs)


__all__ = ["SummaryInspection", "inspect_summary"]
