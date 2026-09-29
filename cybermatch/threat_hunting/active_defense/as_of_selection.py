"""時点tで利用可能な観測版だけを選ぶ。未来の観測・置換済みの版を相関へ渡さない。"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar

from .contract_validation import ActiveDefenseContractError


class _Versioned(Protocol):
    @property
    def record_id(self) -> str: ...
    tenant_id: str
    observed_step: int
    available_step: int
    valid_until_step: int
    supersedes_id: str | None


RecordT = TypeVar("RecordT", bound=_Versioned)


@dataclass(frozen=True)
class AsOfView(Generic[RecordT]):
    """step時点の分類。activeとstaleは置換されていない最新版だけを含む。"""

    step: int
    active: tuple[RecordT, ...]
    stale: tuple[RecordT, ...]
    superseded_ids: tuple[str, ...]
    pending_count: int


def validate_supersession(
    records: Sequence[RecordT], *, name: str, subject_key: Callable[[RecordT], object] | None = None,
) -> None:
    """ID一意、置換先の存在、同一subject、分岐・循環なしを検査する。

    置換は不変recordの追加で表す。同じ版を二つの新版が置換する分岐は、どちらが
    正しいかを勝手に決めないため入力エラーとする。
    """
    by_id: dict[str, RecordT] = {}
    for record in records:
        if record.record_id in by_id:
            raise ActiveDefenseContractError(f"{name}: IDが重複しています: {record.record_id}")
        by_id[record.record_id] = record
    replaced: set[str] = set()
    for record in records:
        target_id = record.supersedes_id
        if target_id is None:
            continue
        target = by_id.get(target_id)
        if target is None:
            raise ActiveDefenseContractError(f"{name}: 置換先が存在しません: {target_id}")
        if target.tenant_id != record.tenant_id:
            raise ActiveDefenseContractError(f"{name}: tenantをまたぐ置換はできません")
        if subject_key is not None and subject_key(target) != subject_key(record):
            raise ActiveDefenseContractError(f"{name}: 別subjectの観測を置換できません")
        if target.observed_step > record.observed_step:
            raise ActiveDefenseContractError(f"{name}: 後の観測を古い観測で置換できません")
        if target_id in replaced:
            raise ActiveDefenseContractError(f"{name}: 同じ観測を複数の新版が置換しています: {target_id}")
        replaced.add(target_id)
    for record in records:
        seen = {record.record_id}
        cursor = record.supersedes_id
        while cursor is not None:
            if cursor in seen:
                raise ActiveDefenseContractError(f"{name}: 置換が循環しています")
            seen.add(cursor)
            cursor = by_id[cursor].supersedes_id


def select_as_of(records: Sequence[RecordT], *, step: int) -> AsOfView[RecordT]:
    """available_step<=stepの版から、同step時点で置換されていないものを選ぶ。

    置換版が未到着なら旧版を使い続ける。期限（valid_until_step<=step）の版はstaleに
    分類し、選択には用いないが件数化できるよう残す。
    """
    available = [record for record in records if record.available_step <= step]
    superseded = {record.supersedes_id for record in available if record.supersedes_id is not None}
    current = sorted((r for r in available if r.record_id not in superseded), key=lambda r: r.record_id)
    return AsOfView(
        step=step,
        active=tuple(r for r in current if r.valid_until_step > step),
        stale=tuple(r for r in current if r.valid_until_step <= step),
        superseded_ids=tuple(sorted(superseded)),
        pending_count=len(records) - len(available),
    )


__all__ = ["AsOfView", "select_as_of", "validate_supersession"]
