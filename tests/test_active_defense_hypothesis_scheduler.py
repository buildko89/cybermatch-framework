"""schedulerの予算・priority順・最大待機・再実行抑止・失効・field欠損を検証する。"""

from types import MappingProxyType

import pytest

from cybermatch.threat_hunting.active_defense import (
    ActiveDefenseContractError, HypothesisScheduler, HypothesisSpec, RecipeBinding, SchedulerPolicy,
)
from cybermatch.threat_hunting.models import HuntEvent

REQUIRED = ("campaign_id", "event_id", "event_type", "step", "attributes.identity_ref", "attributes.auth_result")


def policy(budget=3, wait=5, lookback=20) -> SchedulerPolicy:
    return SchedulerPolicy.from_dict({
        "schema_version": "1.0", "policy_id": "test-scheduler", "policy_version": "1",
        "max_bindings_per_step": budget, "max_lookback_steps": lookback, "max_wait_steps": wait,
        "description": "テスト用",
    })


def hypothesis(name: str, priority: int, *, created=0, expires=50, window=20) -> HypothesisSpec:
    binding = RecipeBinding(
        binding_id=f"binding-{name}", hypothesis_id=f"hyp-{name}", recipe_id="identity_process_chain_v1",
        recipe_hash="0" * 64, required_fields=REQUIRED,
        scope_filter=MappingProxyType({"attributes.tenant_id": "tenant-a", "attributes.identity_ref": f"id-{name}"}),
        window_steps=window,
    )
    return HypothesisSpec(
        hypothesis_id=f"hyp-{name}", tenant_id="tenant-a", template_id="identity_lateral_v1", template_version="1",
        match_refs=(f"match-{name}",), subject_kind="identity", subject_ref=f"id-{name}", recipe_bindings=(binding,),
        created_step=created, expires_step=expires, priority_bp=priority, reason_codes=("template_conditions_met",),
    )


def event(name: str, step: int, *, available=None, tenant="tenant-a", with_auth=True) -> HuntEvent:
    attributes = {"tenant_id": tenant, "identity_ref": f"id-{name}",
                  "available_step": step if available is None else available}
    if with_auth:
        attributes["auth_result"] = "success"
    return HuntEvent(schema_version="1.0", event_id=f"ev-{name}-{step}-{tenant}", step=step, campaign_id="stream-1",
                     scenario_id="scheduler-test", seed=0, actor_id=None, coalition_id=None,
                     event_type="credential_use", source_node=None, target_node=None, source_role=None,
                     target_role=None, signal_class="telemetry", attributes=attributes)


def executed(decisions):
    return [(d.binding_id, d.selection_reason) for d in decisions if d.decision == "executed"]


def test_budget_orders_by_priority_then_binding_id_and_carries_over():
    scheduler = HypothesisScheduler(policy(budget=2))
    hyps = [hypothesis("a", 100), hypothesis("b", 900), hypothesis("c", 500), hypothesis("d", 900)]
    events = [event(name, 0) for name in "abcd"]
    decisions, selected = scheduler.select(step=0, hypotheses=hyps, events=events)
    assert executed(decisions) == [("binding-b", "priority"), ("binding-d", "priority")]
    assert sorted(d.binding_id for d in decisions if d.decision == "deferred_budget") == ["binding-a", "binding-c"]
    assert [item.events for item in selected] == [(events[1],), (events[3],)]
    # 新しい観測がなくても、未実行の繰越し候補は次stepで実行される。実行済みは再実行しない。
    decisions, _ = scheduler.select(step=1, hypotheses=hyps, events=events)
    assert executed(decisions) == [("binding-c", "priority"), ("binding-a", "priority")]
    assert [d.wait_steps for d in decisions] == [1, 1]
    decisions, selected = scheduler.select(step=2, hypotheses=hyps, events=events)
    assert decisions == () and selected == ()


def test_max_wait_candidate_is_taken_before_higher_priority():
    scheduler = HypothesisScheduler(policy(budget=1, wait=2))
    hyps = [hypothesis("high", 9000), hypothesis("low", 10)]
    events = [event("low", 0)]
    reasons = []
    for step in range(3):
        events.append(event("high", step))  # 高priority側に毎step新しい観測が届く
        decisions, _ = scheduler.select(step=step, hypotheses=hyps, events=events)
        reasons.append(executed(decisions))
    assert reasons == [[("binding-high", "priority")], [("binding-high", "priority")],
                       [("binding-low", "max_wait_reached")]]


def test_candidate_expiring_while_waiting_is_recorded():
    scheduler = HypothesisScheduler(policy(budget=1))
    hyps = [hypothesis("high", 9000), hypothesis("low", 10, expires=2)]
    events = [event("low", 0)]
    decisions = []
    for step in range(3):
        events.append(event("high", step))
        decisions.extend(scheduler.select(step=step, hypotheses=hyps, events=events)[0])
    expired = [d for d in decisions if d.decision == "expired_unexecuted"]
    assert [(d.step, d.binding_id, d.wait_steps) for d in expired] == [(2, "binding-low", 2)]
    assert scheduler.pending_binding_ids() == ()


def test_scope_is_fixed_tenant_subject_and_window():
    scheduler = HypothesisScheduler(policy())
    hyp = hypothesis("a", 100, window=3)
    events = [event("a", 1), event("a", 5), event("a", 5, tenant="tenant-b"), event("b", 5)]
    _, selected = scheduler.select(step=5, hypotheses=[hyp], events=events)
    assert [e.event_id for e in selected[0].events] == ["ev-a-5-tenant-a"]  # step 1は(2, 5]の窓外


def test_missing_required_field_is_reported_not_raised():
    scheduler = HypothesisScheduler(policy())
    _, selected = scheduler.select(step=0, hypotheses=[hypothesis("a", 1)],
                                   events=[event("a", 0, with_auth=False)])
    assert selected[0].missing_fields == ("attributes.auth_result",)


def test_rejects_unarrived_observation_and_non_monotonic_step():
    scheduler = HypothesisScheduler(policy())
    with pytest.raises(ActiveDefenseContractError, match="未到着"):
        scheduler.select(step=0, hypotheses=[hypothesis("a", 1)], events=[event("a", 0, available=1)])
    scheduler = HypothesisScheduler(policy())
    scheduler.select(step=3, hypotheses=[], events=[])
    with pytest.raises(ActiveDefenseContractError, match="単調"):
        scheduler.select(step=3, hypotheses=[], events=[])


def test_policy_validation():
    with pytest.raises(ActiveDefenseContractError):
        policy(budget=0)
    with pytest.raises(ActiveDefenseContractError):
        SchedulerPolicy.from_dict({**policy().to_dict(), "max_wait_steps": True})
