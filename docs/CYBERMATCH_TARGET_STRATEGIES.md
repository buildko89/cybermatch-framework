# CyberMatch Target-Specific Strategies

Phase9.7 defines target-specific strategy labels. These are classification
labels only; they are not new attackers, defenders, policies, or simulation
logic.

## Identity Infrastructure

Strategies:

- credential_hunter
- identity_mapper
- trust_abuser

Identity targets are about accounts, roles, credentials, and trust paths.

## Cloud Control Plane

Strategies:

- permission_escalator
- secret_hunter
- api_abuser

Cloud targets emphasize permissions, secrets, and control-plane APIs.

## Research System

Strategies:

- research_explorer
- credential_hunter

Research targets emphasize discovery and access to sensitive knowledge assets.

## Backup System

Strategies:

- backup_destroyer
- resource_exhaustion

Backup targets emphasize recovery disruption and resource pressure.

## Industrial Control System

Strategies:

- process_manipulator
- controller_hunter
- availability_attacker

OT targets emphasize process manipulation, controller access, and availability.

## Trust Relationship

Strategies:

- trust_abuser
- persistence_builder

Trust targets emphasize durable access through relationships and delegated trust.

## Purpose

Phase9.6 showed that Target could be separated from Mission, but Target to
Strategy collapsed into one dominant strategy in observed outputs. Phase9.7
adds target-specific strategy candidates so the analysis layer can test whether
strategy separation becomes visible when target class is explicit.
