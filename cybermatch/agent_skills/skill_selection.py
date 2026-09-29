"""承認済みnative Skill bindingを決定論的に選ぶS2 selector。"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cybermatch.contracts import AssetSchemaError, SchemaRegistry, canonical_sha256
from cybermatch.threat_hunting.recipes import ThreatHuntingRecipeLoader, default_recipe_root

from .candidate_manifest import load_native_manifest_snapshots


class SkillSelectionError(ValueError):
    """承認状態、binding、recipe、または選択入力が不正。"""


@dataclass(frozen=True)
class ApprovedSkillBinding:
    binding_id: str
    skill_id: str
    task_kind: str
    recipe_id: str
    recipe_hash: str
    required_fields: tuple[str, ...]
    priority: int


@dataclass(frozen=True)
class SkillSelection:
    selection_id: str
    task_id: str
    candidate_ids: tuple[str, ...]
    selected_ids: tuple[str, ...]
    selector_version: str
    abstain_reason: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "selection_id": self.selection_id,
            "task_id": self.task_id,
            "candidate_ids": list(self.candidate_ids),
            "selected_ids": list(self.selected_ids),
            "selector_version": self.selector_version,
            "abstain_reason": self.abstain_reason,
        }


def load_approved_bindings(
    *, repository_root: str | Path, manifest_path: str | Path,
) -> tuple[ApprovedSkillBinding, ...]:
    """信頼rootの承認manifestとpackage/recipe hashを同時に検証する。"""
    root = Path(repository_root).resolve(strict=True)
    relative = Path(manifest_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise SkillSelectionError("manifestはrepository内の相対pathで指定してください")
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or path.is_symlink():
        raise SkillSelectionError("manifestが信頼root外またはsymlinkです")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        SchemaRegistry().validate("skill_candidate_manifest", payload, source=relative.as_posix())
    except (OSError, json.JSONDecodeError, AssetSchemaError) as exc:
        raise SkillSelectionError("承認manifestを検証できません") from exc
    snapshot_set = load_native_manifest_snapshots(
        repository_root=root, manifest_path=relative,
    )
    review = payload["review"]
    if (
        payload["status"] != "approved"
        or snapshot_set.review_decision != "approved"
        or not isinstance(review, Mapping)
        or not review.get("reviewer")
    ):
        raise SkillSelectionError("承認済みでないmanifestは選択に使用できません")
    recipe_loader = ThreatHuntingRecipeLoader(default_recipe_root())
    bindings: list[ApprovedSkillBinding] = []
    for raw in payload["bindings"]:
        if not isinstance(raw, Mapping) or raw["review_state"] != "approved":
            raise SkillSelectionError("全bindingが個別承認済みでなければなりません")
        recipe = recipe_loader.load(f"{raw['recipe_id']}.json")
        if raw.get("recipe_hash") != recipe.recipe_hash:
            raise SkillSelectionError(f"{raw['binding_id']}のrecipe hashが一致しません")
        bindings.append(
            ApprovedSkillBinding(
                binding_id=str(raw["binding_id"]),
                skill_id=str(raw["skill_id"]),
                task_kind=str(raw["task_kind"]),
                recipe_id=recipe.recipe_id,
                recipe_hash=recipe.recipe_hash,
                required_fields=tuple(str(value) for value in raw["required_fields"]),
                priority=int(raw["priority"]),
            )
        )
    return tuple(sorted(bindings, key=lambda item: item.binding_id))


class DeterministicSkillSelector:
    """task kind完全一致とfield充足だけで最大3件を選ぶ。"""

    VERSION = "selector-v1"

    def __init__(self, bindings: Sequence[ApprovedSkillBinding], *, max_selected: int = 3):
        if isinstance(max_selected, bool) or not isinstance(max_selected, int) or not 1 <= max_selected <= 3:
            raise SkillSelectionError("max_selectedは1から3の整数です")
        self._bindings = tuple(bindings)
        self._max_selected = max_selected

    def select(
        self, *, task_id: str, task_kind: str, available_fields: Sequence[str], scope: Mapping[str, str] | None = None,
    ) -> SkillSelection:
        if not task_id or not task_kind or isinstance(available_fields, (str, bytes)):
            raise SkillSelectionError("task_id、task_kind、available_fieldsが必要です")
        fields = frozenset(available_fields)
        if any(not isinstance(value, str) or not value for value in fields):
            raise SkillSelectionError("available_fieldsは空でない文字列の配列です")
        candidates = tuple(item for item in self._bindings if item.task_kind == task_kind)
        eligible = tuple(item for item in candidates if set(item.required_fields) <= fields)
        ordered = tuple(sorted(eligible, key=lambda item: (-item.priority, item.skill_id)))
        selected = ordered[: self._max_selected]
        reason = None
        if not candidates:
            reason = "no_binding"
        elif not eligible:
            reason = "missing_fields"
        semantic = {
            "task_id": task_id,
            "task_kind": task_kind,
            "available_fields": sorted(fields),
            "scope": dict(sorted((scope or {}).items())),
            "candidate_ids": [item.skill_id for item in candidates],
            "selected_ids": [item.skill_id for item in selected],
            "selector_version": self.VERSION,
            "abstain_reason": reason,
        }
        return SkillSelection(
            selection_id=f"selection_{canonical_sha256(semantic)[:24]}",
            task_id=task_id,
            candidate_ids=tuple(item.skill_id for item in candidates),
            selected_ids=tuple(item.skill_id for item in selected),
            selector_version=self.VERSION,
            abstain_reason=reason,
        )


__all__ = [
    "ApprovedSkillBinding", "DeterministicSkillSelector", "SkillSelection",
    "SkillSelectionError", "load_approved_bindings",
]
