# Phase5-A Coalition Foundation

Phase5-A closes the first Coalition Foundation block for CyberMatch. It combines Phase5.1, Phase5.2, and Phase5.2b so future Phase5 work can build on a validated multi-attacker base.

## Phase5.1: Multi-Attacker Coalition

Phase5.1 introduced a lightweight coalition attacker model with role-based delegation:

- Recon specialist
- Access specialist
- Objective specialist

The phase validated coalition establishment, handover events, stronger coalition performance than a single attacker, and campaign delegation.

## Phase5.2: Coordination Cost

Phase5.2 added realistic limits to coalition execution:

- Coordination cost
- Information loss during handover
- Trust degradation after failed handover
- Effective and failed handover metrics
- Coordination, trust, and handover-failure histories

The purpose was not to weaken coalition attackers artificially. The purpose was to model realistic attacker-network constraints and validate coalition robustness.

## Phase5.2b: Test Runtime Optimization

Phase5.2b added test execution profiles without changing simulation behavior:

- `smoke` tests for routine validation
- phase-specific markers such as `phase5`
- `slow` marker for end-to-end artifact-generation tests
- `scripts/run_tests.py` as the standard validation entry point

Recommended commands:

```bash
python scripts/run_tests.py --smoke
python scripts/run_tests.py --phase phase5
python scripts/run_tests.py --full
```

## Main Results

```text
Single success rate: 0.640
Phase5.1 Coalition success rate: 1.000
Coordination-cost Coalition success rate: 0.731
Mean failed handover: 2.000
Mean coordination efficiency: 0.500
```

## Interpretation

Coalition attackers are stronger than single attackers, but coordination cost, information loss, and trust degradation introduce realistic limits.

日本語補足:

Phase5-A では、Coalition が Single Attacker より強いことを確認したうえで、handover が常に成功するという非現実的な仮定を外した。Coordination Cost、Information Loss、Trust Degradation により、攻撃者ネットワークにも現実的な制約と失敗可能性があることを確認した。これにより、Phase5.3 以降では Coalition を前提にしたより高度な attacker-defender co-evolution 評価へ進める。
