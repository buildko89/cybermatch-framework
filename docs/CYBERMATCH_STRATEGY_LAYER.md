# CyberMatch Strategy Layer

## Layer Model

Phase9.5 introduces a Strategy Layer between Mission and Behavior.

The working model is:

```text
Mission
Strategy
Behavior
Events
```

This is an interpretation layer. It does not create new attackers, defenders,
policies, RL behavior, LLM behavior, external API calls, benchmark changes, or
ProfileCore internals.

## Mission

Mission is the broad attacker objective class.

Examples:

- profit
- achievement
- persistence
- critical_hunter

Mission answers: what is the attacker trying to optimize?

## Strategy

Strategy is the operational approach inferred between Mission and Behavior.

Initial Phase9.5 strategy classes:

- credential_hunter
- critical_asset_hunter
- persistence_builder
- trust_collapse
- disruption_campaign
- resource_exhaustion

Strategy answers: how is the attacker trying to pursue the mission?

Mission and Strategy are separate concepts. For example:

- Mission = profit, Strategy = credential_hunter
- Mission = persistence, Strategy = persistence_builder
- Mission = achievement, Strategy = critical_asset_hunter

## Behavior

Behavior is the observed behavioral expression, represented by behavior
profiles and feature activity.

Behavior answers: what pattern is visible in the observed actions?

Phase9.0 to Phase9.4 showed that Behavior Profile can be too coarse for some
questions. Strategy is introduced to explain behavior at a level below Mission
but above raw events.

## Events

Events are concrete simulation observations and histories such as utility,
critical-path activity, deception interactions, lateral movement, trust
collapse, adaptation, and campaign disruption.

Events answer: what happened?

## Features Used

Phase9.5 uses existing CyberMatch features only:

- critical_progress
- critical_focus
- stealth_activity
- trust_collapse_activity
- utility_activity
- objective_activity
- deception_activity
- adaptation_activity
- campaign_disruption_activity
- lateral_movement_activity
- survival_activity
- planned_critical_activity

## Future Integration

A future direction is:

```text
Mission
Strategy
Archetype
Behavior
```

This is documentation only in Phase9.5. Prediction, transition modeling,
intent-aware defense, and adaptive countermeasure selection are not implemented
in this phase.
