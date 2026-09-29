"""仮説のrecipe bindingを、step毎の調査予算内で決定論的に選ぶscheduler。

選択規則v1:
1. scope内に到着済み観測があり、前回実行時から観測集合が変わったbindingだけを候補にする。
2. 最大待機（max_wait_steps）に達した候補を、仮説作成step→binding ID順で先に取り出す。
3. 残り枠をpriority降順→binding ID昇順で埋める。予算超過は次stepへ繰り越す。
4. 候補のまま仮説が失効したbindingは`expired_unexecuted`として記録する。
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from cybermatch.contracts import canonical_sha256

from ..models import HuntEvent
from ..operators import event_row
from . import contract_validation as cv
from .contract_validation import ActiveDefenseContractError
from .hypothesis_templates import HypothesisSpec, RecipeBinding

_POLICY_FIELDS = {"schema_version", "policy_id", "policy_version", "max_bindings_per_step",
                  "max_lookback_steps", "max_wait_steps", "description"}
NOT_EVALUABLE_MISSING_FIELDS = "not_evaluable:missing_fields"


@dataclass(frozen=True)
class SchedulerPolicy:
    policy_id: str
    policy_version: str
    max_bindings_per_step: int
    max_lookback_steps: int
    max_wait_steps: int
    description: str

    @property
    def policy_hash(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": cv.ACTIVE_DEFENSE_CONTRACT_VERSION, "policy_id": self.policy_id,
                "policy_version": self.policy_version, "max_bindings_per_step": self.max_bindings_per_step,
                "max_lookback_steps": self.max_lookback_steps, "max_wait_steps": self.max_wait_steps,
                "description": self.description}

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "SchedulerPolicy":
        data = cv.exact_fields(payload, _POLICY_FIELDS, "SchedulerPolicy")
        cv.version(data["schema_version"], "SchedulerPolicy.schema_version")
        description = data["description"]
        if not isinstance(description, str) or not description.strip():
            raise ActiveDefenseContractError("SchedulerPolicy.description: 説明が必要です")
        return cls(
            policy_id=cv.ref(data["policy_id"], "SchedulerPolicy.policy_id"),
            policy_version=cv.ref(data["policy_version"], "SchedulerPolicy.policy_version"),
            max_bindings_per_step=cv.positive_int(data["max_bindings_per_step"], "max_bindings_per_step"),
            max_lookback_steps=cv.positive_int(data["max_lookback_steps"], "max_lookback_steps"),
            max_wait_steps=cv.step(data["max_wait_steps"], "max_wait_steps"),
            description=description,
        )


@dataclass(frozen=True)
class SchedulerDecision:
    """あるstepでの一bindingの扱い。予算待ち・失効も黙って捨てずに残す。"""

    step: int
    binding_id: str
    hypothesis_id: str
    decision: str
    selection_reason: str | None
    wait_steps: int
    priority_bp: int
    input_fingerprint: str | None

    def to_dict(self) -> dict[str, object]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class SelectedBinding:
    hypothesis: HypothesisSpec
    binding: RecipeBinding
    events: tuple[HuntEvent, ...]
    missing_fields: tuple[str, ...]


@dataclass
class _BindingState:
    last_fingerprint: str | None = None
    pending_since: int | None = None


class HypothesisScheduler:
    """状態（前回実行した観測集合・待機開始step）だけを持つ。truthやFindingの正誤は見ない。"""

    def __init__(self, policy: SchedulerPolicy):
        if not isinstance(policy, SchedulerPolicy):
            raise ActiveDefenseContractError("policyはSchedulerPolicyで指定してください")
        self._policy = policy
        self._states: dict[str, _BindingState] = {}
        self._last_step: int | None = None

    @property
    def policy(self) -> SchedulerPolicy:
        return self._policy

    def pending_binding_ids(self) -> tuple[str, ...]:
        """horizon終了時点で予算待ちのまま残ったbinding（右打切り）。"""
        return tuple(sorted(key for key, state in self._states.items() if state.pending_since is not None))

    @staticmethod
    def scope_events(binding: RecipeBinding, events: Sequence[HuntEvent], step: int) -> tuple[HuntEvent, ...]:
        """tenant/subjectの固定equalityと、発生stepが(step−window, step]の到着済み観測。"""
        selected = []
        for event in events:
            available = event.attributes.get("available_step")
            if not isinstance(available, int) or isinstance(available, bool) or available > step:
                raise ActiveDefenseContractError("schedulerへ未到着の観測が渡されました")
            if event.step <= step - binding.window_steps or event.step > step:
                continue
            if all(event.attributes.get(key.removeprefix("attributes.")) == value
                   for key, value in binding.scope_filter.items()):
                selected.append(event)
        return tuple(sorted(selected, key=lambda event: (event.step, event.event_id)))

    def select(self, *, step: int, hypotheses: Sequence[HypothesisSpec],
               events: Sequence[HuntEvent]) -> tuple[tuple[SchedulerDecision, ...], tuple[SelectedBinding, ...]]:
        cv.step(step, "step")
        if self._last_step is not None and step <= self._last_step:
            raise ActiveDefenseContractError("schedulerのstepは単調増加が必要です")
        self._last_step = step
        decisions: list[SchedulerDecision] = []
        candidates: list[tuple[HypothesisSpec, RecipeBinding, tuple[HuntEvent, ...], str, int]] = []
        for hypothesis in sorted(hypotheses, key=lambda spec: spec.hypothesis_id):
            for binding in hypothesis.recipe_bindings:
                state = self._states.setdefault(binding.binding_id, _BindingState())
                if not hypothesis.active_at(step):
                    if hypothesis.expires_step <= step and state.pending_since is not None:
                        decisions.append(self._decision(step, hypothesis, binding, "expired_unexecuted",
                                                        None, step - state.pending_since, None))
                        state.pending_since = None
                    continue
                scoped = self.scope_events(binding, events, step)
                if not scoped:
                    continue
                fingerprint = canonical_sha256([event.event_id for event in scoped])
                if fingerprint == state.last_fingerprint:
                    continue  # as-of stepで新しい観測がなければ再実行しない
                if state.pending_since is None:
                    state.pending_since = step
                candidates.append((hypothesis, binding, scoped, fingerprint, step - state.pending_since))

        overdue = sorted((c for c in candidates if c[4] >= self._policy.max_wait_steps),
                         key=lambda c: (c[0].created_step, c[1].binding_id))
        overdue_ids = {c[1].binding_id for c in overdue}
        by_priority = sorted((c for c in candidates if c[1].binding_id not in overdue_ids),
                             key=lambda c: (-c[0].priority_bp, c[1].binding_id))
        ordered = [*overdue, *by_priority]
        selected: list[SelectedBinding] = []
        for index, (hypothesis, binding, scoped, fingerprint, wait) in enumerate(ordered):
            if index < self._policy.max_bindings_per_step:
                reason = "max_wait_reached" if binding.binding_id in overdue_ids else "priority"
                decisions.append(self._decision(step, hypothesis, binding, "executed", reason, wait, fingerprint))
                state = self._states[binding.binding_id]
                state.last_fingerprint, state.pending_since = fingerprint, None
                selected.append(SelectedBinding(hypothesis, binding, scoped, self._missing(binding, scoped)))
            else:
                decisions.append(self._decision(step, hypothesis, binding, "deferred_budget", None, wait, fingerprint))
        return tuple(decisions), tuple(selected)

    @staticmethod
    def _missing(binding: RecipeBinding, events: Sequence[HuntEvent]) -> tuple[str, ...]:
        """recipeの必須fieldがキーごと欠けている観測。engineのエラーとschema破損を区別する。"""
        missing = {name for event in events for name in binding.required_fields
                   if name not in event_row(event).values}
        return tuple(sorted(missing))

    @staticmethod
    def _decision(step: int, hypothesis: HypothesisSpec, binding: RecipeBinding, decision: str,
                  reason: str | None, wait: int, fingerprint: str | None) -> SchedulerDecision:
        return SchedulerDecision(step=step, binding_id=binding.binding_id, hypothesis_id=hypothesis.hypothesis_id,
                                 decision=decision, selection_reason=reason, wait_steps=wait,
                                 priority_bp=hypothesis.priority_bp, input_fingerprint=fingerprint)


__all__ = ["HypothesisScheduler", "NOT_EVALUABLE_MISSING_FIELDS", "SchedulerDecision",
           "SchedulerPolicy", "SelectedBinding"]
