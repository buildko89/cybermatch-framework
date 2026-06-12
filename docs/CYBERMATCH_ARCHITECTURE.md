# CyberMatch Architecture

CyberMatch is organized as a layered decision-evaluation framework. The layers are intentionally lightweight and deterministic so that experiments remain reproducible and suitable for publication.

```text
Scenario / Configuration / Product Profiles
                |
                v
Layer 1 -> Layer 2 -> Layer 3 -> Layer 4 -> Layer 5 -> Artifacts
                |
                v
       Future AI Integration Hooks
```

## Layer 1: Attacker Modeling

This layer models attacker behavior without RL or LLM decision loops.

Current capabilities include:

- Baseline attacker progression
- Adaptive attacker behavior
- Preference and path-aware attackers
- Planning and expected-utility attackers
- Trust-aware attackers
- Coalition attackers with handoff and coordination cost
- Counter-deception aware and hunting attackers

The purpose is not to create an unconstrained autonomous agent. The purpose is to create controlled attacker models that can be compared across defense conditions.

## Layer 2: Mission / Belief / State

This layer captures the decision context that drives attacker and defender behavior.

Core elements:

- Mission objective: profit, achievement, persistence, critical asset hunting, or mixed goals
- Mission belief: defender inference about attacker intent
- State belief: inferred campaign state and risk context
- Attacker confidence and perceived utility
- Trust in assets, paths, credentials, and coalition partners

This layer makes CyberMatch decision-centric rather than event-centric.

## Layer 3: Defense Campaign

This layer evaluates defense policies over repeated campaign steps.

Current capabilities include:

- Moving target defense
- Decoys and fake assets
- Adaptive defender policies
- CNS-guided defense selection
- Mission-aware defense
- Critical path intelligence
- Virtual enterprise topology
- Intelligence decision matrix
- Defense campaign profiles
- Mission mutation and adaptive intelligence

The layer measures whether the defender changed attacker outcomes, not only whether it executed an action.

## Layer 4: Counter-Deception

This layer models active defender manipulation of attacker perception.

Current capabilities include:

- Intent deception
- Noise injection
- Adversarial signal robustness
- Counter-deception defender behavior
- Counter-deception aware attacker behavior
- Counter-deception hunting

The key question is whether deception remains effective after attacker awareness and validation behavior emerge.

## Layer 5: Product Evaluation

This layer turns CyberMatch toward defense strategy and security product evaluation.

Current Phase6 capabilities include:

- Product Plugin Interface
- Product categories: IDS, IPS, honeypot, deception, XDR
- Product profile import from JSON
- Lightweight product attribute model
- Product effectiveness metrics
- Operational cost and false-positive scoring
- Mission-aware product evaluation matrix

CyberMatch does not connect to real products in the current implementation. Product profiles are controlled evaluation inputs used to test whether the framework can distinguish product behavior across missions.

Future hooks:

- Enterprise Product Profile
- Vendor Product Profile
- Scenario Specific Product Profile

## Layer 6: Future AI Integration

This layer is intentionally a future hook.

Possible future integrations:

- Scenario generation support
- Analyst behavior modeling
- Explanation and reporting assistance
- External telemetry interpretation
- Product adapter reasoning

Any future AI integration should preserve the current evaluation principle: attacker and defender outcomes must remain measurable, reproducible, and comparable without depending on opaque runtime decisions.
