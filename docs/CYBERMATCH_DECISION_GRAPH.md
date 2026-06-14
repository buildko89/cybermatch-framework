# CyberMatch Decision Graph

Phase9.9 integrates the attacker interpretation layers built in Phase9.0 to
Phase9.8 into a single Decision Graph.

The graph is analysis-only. It does not add attackers, defenders, simulation
logic, RL, LLMs, external APIs, ProfileCore changes, benchmarks, or historical
result changes.

## Decision Model

CyberMatch now represents attacker decision structure as:

```text
Intent
  -> Mission
  -> Target
  -> Strategy
  -> Behavior
  -> Archetype
```

## Node Types

Intent describes the broad attacker objective, such as financial gain,
espionage, disruption, destruction, control, or long-term presence.

Mission describes the operational objective, such as credential theft, data
exfiltration, service disruption, infrastructure takeover, or persistence.

Target describes the class of asset or relationship being attacked, such as
identity infrastructure, cloud control plane, backup system, research system,
industrial control system, or trust relationship.

Strategy describes the target-specific approach, such as credential hunting,
secret hunting, trust abuse, process manipulation, or resource exhaustion.

Behavior Profile describes the observed behavior pattern inferred from existing
CyberMatch histories and metrics.

Archetype describes the discovered or observed behavior archetype. When no
archetype label is present in the source row, Phase9.9 uses
`archetype_unobserved` as a missing-data marker, not as a new discovered
archetype.

## Edges

The graph uses directed edges:

- Intent -> Mission
- Mission -> Target
- Target -> Strategy
- Strategy -> Behavior
- Behavior -> Archetype

Each edge count represents how often that transition appears in the existing
analysis rows.

## Path Analysis

A decision path is a full chain across all graph layers:

```text
financial_gain
  -> credential_theft
  -> identity_infrastructure
  -> credential_hunter
  -> utility_seeking
  -> Archetype-1
```

Phase9.9 enumerates unique paths and generates a short explanation for each
path.

Example:

```text
financial_gain intent resulted in credential_theft mission, targeting
identity_infrastructure, using credential_hunter strategy, producing
utility_seeking behavior and Archetype-1 archetype.
```

## Metrics

`decision_graph_nodes` counts all nodes across all layers.

`decision_graph_edges` counts observed directed transitions between adjacent
layers.

`decision_graph_density` compares observed edges with possible adjacent-layer
edges.

`decision_graph_connectivity` measures whether nodes are connected to at least
one incoming or outgoing edge.

`decision_graph_consistency` measures whether each source node maps
concentratedly to a dominant next-layer node.

`decision_graph_entropy` measures how dispersed the graph edge counts are.

`decision_path_count` counts unique full decision paths.

## Future Defense Concept Mapping

Phase10 Defense Concept Evaluation can map defenses to graph locations.

Runtime Delegation can be interpreted as affecting Target Selection and
Strategy Selection.

Adaptive Deception can be interpreted as affecting Behavior and Archetype-level
expression.

This future mapping is documented only in Phase9.9. It is not implemented here.
