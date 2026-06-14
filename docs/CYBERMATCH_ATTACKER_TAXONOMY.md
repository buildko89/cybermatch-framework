# CyberMatch Attacker Taxonomy

Phase9.6 decomposes attacker decision labels into a hierarchy:

```text
Intent
Mission
Target
Strategy
Behavior
Events
```

This is documentation and analysis only. Phase9.6 does not add attackers,
defenders, RL, LLMs, external APIs, ProfileCore changes, benchmark changes, or
simulation logic.

## Intent

Intent is the high-level reason behind the attack.

Initial intents:

- financial_gain
- espionage
- disruption
- destruction
- control
- long_term_presence

## Mission

Mission is the operational form used to pursue intent.

Initial mission layer:

- ransomware_operation
- credential_theft
- data_exfiltration
- service_disruption
- infrastructure_takeover
- long_term_persistence
- supply_chain_compromise

Existing CyberMatch missions such as `profit`, `achievement`, `persistence`,
and `critical_hunter` are treated as composite labels that can imply multiple
intent, mission, and target combinations.

## Target

Target is the asset class or relationship class the attacker is acting on.

Initial targets:

- identity_infrastructure
- critical_database
- business_application
- cloud_control_plane
- backup_system
- research_system
- industrial_control_system
- trust_relationship

Target is separate from Mission. For example, credential theft can target
identity infrastructure, while infrastructure takeover can target a cloud
control plane or industrial control system.

## Strategy

Strategy is the approach used to act on a target.

Phase9.5 introduced:

- credential_hunter
- critical_asset_hunter
- persistence_builder
- trust_collapse
- disruption_campaign
- resource_exhaustion

## Behavior

Behavior is the observable pattern produced by a strategy. Behavior Profiles
and Archetypes summarize behavior but do not replace Intent, Mission, Target,
or Strategy.

## Events

Events are concrete observed histories and metrics: critical-path events,
deception interactions, utility, lateral movement, trust collapse, adaptation,
and campaign disruption.

## Phase9.6 Role

Phase9.6 provides the taxonomy foundation for moving CyberMatch from
Mission-Aware toward Intent-Aware. It makes Target explicit so future work can
evaluate whether the same mission has different defensive meaning depending on
the targeted asset class.
