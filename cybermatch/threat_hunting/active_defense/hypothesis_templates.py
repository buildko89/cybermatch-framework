"""固定の仮説templateとrecipe bindingを選ぶ。自由なpredicate・閾値・コードは受け付けない。

仮説のscopeは観測subject（仮名化identityまたはnode）だけであり、攻撃者の真のactor IDや
campaign truthを補完しない。scope filterはtenant/subjectの固定equalityに限定する。
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from cybermatch.contracts import canonical_sha256

from ..models import stable_identifier
from ..recipes import RecipeLoadError, RecipeValidationError, ThreatHuntingRecipe, ThreatHuntingRecipeLoader
from . import contract_validation as cv
from .contract_validation import ActiveDefenseContractError
from .exposure_correlation import ExposureMatch

SUBJECT_KINDS = ("identity", "node")
_SUBJECT_FILTER_FIELD = MappingProxyType({"identity": "identity_ref", "node": "node_ref"})
_TEMPLATE_MATCH_KINDS = ("identity_service", "endpoint_exact")
_CATALOG_FIELDS = {"schema_version", "catalog_id", "catalog_version", "templates"}
_TEMPLATE_FIELDS = {"template_id", "template_version", "subject_kind", "match_kinds",
                    "recipe_file", "window_steps", "description"}


@dataclass(frozen=True)
class HypothesisTemplate:
    template_id: str
    template_version: str
    subject_kind: str
    match_kinds: tuple[str, ...]
    recipe: ThreatHuntingRecipe
    recipe_file: str
    window_steps: int
    description: str

    def accepts(self, match: ExposureMatch) -> str | None:
        """条件を満たせばsubject refを返す。CTIがmatchedでなければ仮説を作らない。"""
        if match.status != "matched" or match.match_kind not in self.match_kinds:
            return None
        return match.identity_ref if self.subject_kind == "identity" else match.node_ref

    def to_dict(self) -> dict[str, object]:
        return {
            "template_id": self.template_id, "template_version": self.template_version,
            "subject_kind": self.subject_kind, "match_kinds": list(self.match_kinds),
            "recipe_file": self.recipe_file, "window_steps": self.window_steps,
            "description": self.description,
        }


@dataclass(frozen=True)
class HypothesisTemplateCatalog:
    catalog_id: str
    catalog_version: str
    templates: tuple[HypothesisTemplate, ...]

    @property
    def catalog_hash(self) -> str:
        return canonical_sha256(self.to_dict())

    @property
    def recipe_hashes(self) -> dict[str, str]:
        return {t.recipe.recipe_id: t.recipe.recipe_hash for t in self.templates}

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION, "catalog_id": self.catalog_id,
                "catalog_version": self.catalog_version,
                "templates": [template.to_dict() for template in self.templates]}

    @classmethod
    def from_dict(cls, payload: Mapping[str, object], *, recipe_loader: ThreatHuntingRecipeLoader,
                  max_window_steps: int) -> "HypothesisTemplateCatalog":
        data = cv.exact_fields(payload, _CATALOG_FIELDS, "HypothesisTemplateCatalog")
        cv.version(data["schema_version"], "HypothesisTemplateCatalog.schema_version")
        raw_templates = data["templates"]
        if not isinstance(raw_templates, list) or not raw_templates:
            raise ActiveDefenseContractError("templates: 1件以上の配列が必要です")
        loaded: dict[str, ThreatHuntingRecipe] = {}  # 同じrecipeを複数templateで共有できるようにする
        templates = tuple(_template(item, recipe_loader, max_window_steps, loaded) for item in raw_templates)
        ids = [template.template_id for template in templates]
        if ids != sorted(set(ids)):
            raise ActiveDefenseContractError("templates: template_idの重複なし昇順が必要です")
        return cls(catalog_id=cv.ref(data["catalog_id"], "catalog_id"),
                   catalog_version=cv.ref(data["catalog_version"], "catalog_version"), templates=templates)


def _template(payload: object, loader: ThreatHuntingRecipeLoader, max_window_steps: int,
              loaded: dict[str, ThreatHuntingRecipe]) -> HypothesisTemplate:
    data = cv.exact_fields(payload, _TEMPLATE_FIELDS, "HypothesisTemplate")
    subject_kind = cv.choice(data["subject_kind"], SUBJECT_KINDS, "subject_kind")
    raw_kinds = data["match_kinds"]
    if not isinstance(raw_kinds, list) or not raw_kinds or raw_kinds != sorted(set(raw_kinds)):
        raise ActiveDefenseContractError("match_kinds: 重複なし昇順の配列が必要です")
    kinds = tuple(cv.choice(kind, _TEMPLATE_MATCH_KINDS, "match_kinds") for kind in raw_kinds)
    if subject_kind == "identity" and kinds != ("identity_service",):
        raise ActiveDefenseContractError("identity subjectはidentity_service matchだけに限定します")
    window = cv.positive_int(data["window_steps"], "window_steps")
    if window > max_window_steps:
        raise ActiveDefenseContractError("window_stepsがschedulerのmax_lookback_stepsを超えています")
    recipe_file = data["recipe_file"]
    if not isinstance(recipe_file, str):
        raise ActiveDefenseContractError("recipe_file: recipe root相対のJSON pathが必要です")
    try:
        recipe = loaded.get(recipe_file) or loader.load(recipe_file)
    except (RecipeLoadError, RecipeValidationError) as exc:
        raise ActiveDefenseContractError(f"recipeを読み込めません: {exc}") from exc
    loaded[recipe_file] = recipe
    description = data["description"]
    if not isinstance(description, str) or not description.strip():
        raise ActiveDefenseContractError("description: 説明が必要です")
    return HypothesisTemplate(
        template_id=cv.ref(data["template_id"], "template_id"),
        template_version=cv.ref(data["template_version"], "template_version"),
        subject_kind=subject_kind, match_kinds=kinds, recipe=recipe, recipe_file=recipe_file,
        window_steps=window, description=description,
    )


@dataclass(frozen=True)
class RecipeBinding:
    """仮説とrecipe（ID/hash固定）と観測scopeの対応。schedulerの実行単位。"""

    binding_id: str
    hypothesis_id: str
    recipe_id: str
    recipe_hash: str
    required_fields: tuple[str, ...]
    scope_filter: Mapping[str, str]
    window_steps: int

    def to_dict(self) -> dict[str, object]:
        return {"binding_id": self.binding_id, "hypothesis_id": self.hypothesis_id,
                "recipe_id": self.recipe_id, "recipe_hash": self.recipe_hash,
                "required_fields": list(self.required_fields),
                "scope_filter": dict(sorted(self.scope_filter.items())), "window_steps": self.window_steps}


@dataclass(frozen=True)
class HypothesisSpec:
    hypothesis_id: str
    tenant_id: str
    template_id: str
    template_version: str
    match_refs: tuple[str, ...]
    subject_kind: str
    subject_ref: str
    recipe_bindings: tuple[RecipeBinding, ...]
    created_step: int
    expires_step: int
    priority_bp: int
    reason_codes: tuple[str, ...]

    @property
    def dedupe_key(self) -> tuple[str, str, str, str]:
        return (self.template_id, self.template_version, self.subject_kind, self.subject_ref)

    def active_at(self, step: int) -> bool:
        return self.created_step <= step < self.expires_step

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION, "hypothesis_id": self.hypothesis_id,
            "tenant_id": self.tenant_id, "template_id": self.template_id,
            "template_version": self.template_version, "match_refs": list(self.match_refs),
            "scope": {"subject_kind": self.subject_kind, "subject_ref": self.subject_ref},
            "recipe_bindings": [binding.to_dict() for binding in self.recipe_bindings],
            "created_step": self.created_step, "expires_step": self.expires_step,
            "priority_bp": self.priority_bp, "reason_codes": list(self.reason_codes),
        }


class HypothesisGenerator:
    """matched相関からtemplateを適用する。同じtemplate×subjectの有効な仮説は重複作成しない。"""

    def __init__(self, *, tenant_id: str, catalog: HypothesisTemplateCatalog):
        self._tenant_id = cv.ref(tenant_id, "tenant_id")
        self._catalog = catalog

    def generate(self, *, step: int, matches: Sequence[ExposureMatch],
                 existing: Iterable[HypothesisSpec]) -> tuple[HypothesisSpec, ...]:
        cv.step(step, "step")
        active_keys = {spec.dedupe_key for spec in existing if spec.active_at(step)}
        grouped: dict[tuple[str, str, str, str], tuple[HypothesisTemplate, str, list[ExposureMatch]]] = {}
        for template in self._catalog.templates:
            for match in matches:
                if match.tenant_id != self._tenant_id:
                    raise ActiveDefenseContractError("tenantをまたぐmatchから仮説を作れません")
                subject = template.accepts(match)
                if subject is None or match.valid_until_step is None or match.valid_until_step <= step:
                    continue
                key = (template.template_id, template.template_version, template.subject_kind, subject)
                if key in active_keys:
                    continue
                grouped.setdefault(key, (template, subject, []))[2].append(match)
        created = [self._spec(step, template, subject, members)
                   for template, subject, members in grouped.values()]
        return tuple(sorted(created, key=lambda spec: spec.hypothesis_id))

    def _spec(self, step: int, template: HypothesisTemplate, subject: str,
              matches: list[ExposureMatch]) -> HypothesisSpec:
        # 同step・同subjectの複数予兆は一つの仮説へまとめ、最大priorityと最短期限を使う。
        match_refs = tuple(sorted({match.match_id for match in matches}))
        expires = min(match.valid_until_step for match in matches if match.valid_until_step is not None)
        priority = max(match.priority_bp or 0 for match in matches)
        hypothesis_id = stable_identifier("hypothesis", {
            "tenant_id": self._tenant_id, "template_id": template.template_id,
            "template_version": template.template_version, "subject_kind": template.subject_kind,
            "subject_ref": subject, "created_step": step, "match_refs": list(match_refs),
        })
        recipe = template.recipe
        binding = RecipeBinding(
            binding_id=stable_identifier("binding", {"hypothesis_id": hypothesis_id,
                                                      "recipe_id": recipe.recipe_id,
                                                      "recipe_hash": recipe.recipe_hash}),
            hypothesis_id=hypothesis_id, recipe_id=recipe.recipe_id, recipe_hash=recipe.recipe_hash,
            required_fields=recipe.required_fields,
            scope_filter=MappingProxyType({"attributes.tenant_id": self._tenant_id,
                                           f"attributes.{_SUBJECT_FILTER_FIELD[template.subject_kind]}": subject}),
            window_steps=template.window_steps,
        )
        kinds = sorted({f"match_kind_{match.match_kind}" for match in matches})
        return HypothesisSpec(
            hypothesis_id=hypothesis_id, tenant_id=self._tenant_id, template_id=template.template_id,
            template_version=template.template_version, match_refs=match_refs,
            subject_kind=template.subject_kind, subject_ref=subject, recipe_bindings=(binding,),
            created_step=step, expires_step=expires, priority_bp=priority,
            reason_codes=tuple(["template_conditions_met", *kinds]),
        )

    def recipe_for(self, recipe_id: str) -> ThreatHuntingRecipe:
        for template in self._catalog.templates:
            if template.recipe.recipe_id == recipe_id:
                return template.recipe
        raise ActiveDefenseContractError(f"catalogにないrecipeです: {recipe_id}")


__all__ = [
    "HypothesisGenerator", "HypothesisSpec", "HypothesisTemplate", "HypothesisTemplateCatalog",
    "RecipeBinding", "SUBJECT_KINDS",
]
