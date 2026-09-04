# Agentic Security Evaluation

CyberMatch evaluates agentic-security controls without executing an external LLM or a live exploit. The implementation replays synthetic, defender-observable events through the existing threat-hunting recipe engine and applies typed containment actions on the next simulation step.

## Scope

The benchmark covers four connected risks:

1. Autonomous boundary escape: an impossible task creates boundary pressure, an agent probes unintended tools, coordinates through shared infrastructure, and obtains transitive egress.
2. Threat-intelligence pollution: an advisory is accepted, quarantined, or rejected using corroborating evidence rather than its CVE identifier or severity alone.
3. Common-cause defense failure: controls are grouped by failure domain so nominally separate controls are not incorrectly counted as independent layers.
4. Inter-episode reward hacking: rewarded boundary bypass changes future bypass propensity, with and without oversight feedback.

The scenarios are inspired by public incident reporting, but contain no production credentials, payloads, or exploit implementation details.

## Architecture

```text
Synthetic HuntEvent timeline
  + trust-boundary topology
  -> same-input open-loop replay
  -> same-input closed-loop replay
       -> allowlisted threat-hunting recipes
       -> observable Finding
       -> AgenticContainmentPolicy
       -> typed next-step actions
  -> comparative containment metrics

Defense controls
  -> correlate controls in the same failure domain
  -> combine distinct failure domains as independent layers
  -> breach and detection probabilities by objective

Episode reward observations
  -> open-loop reinforcement history
  -> oversight-enabled reinforcement history
  -> final reward-hacking propensity reduction

ThreatIntelAdvisory evidence
  -> ThreatIntelIntegrityGate
  -> accept | quarantine | reject
  -> evaluator-only comparison with ground truth
```

The integrity gate never receives `ground_truth`. Labels are retained only by `evaluate_integrity_outcomes`, following the same no-oracle principle used by defender-side hunting.

## Trust-boundary topology

`topologies/agentic/agentic_research_environment.json` declares zones, directed boundaries, permitted event types, and defensive controls. Each scenario event is checked against known node IDs and the edge allowlist. Reports include trust-boundary crossings, unauthorized paths, transitive-path violations, and the exact evidence events.

Controls declare an objective, layer, failure domain, prevention effectiveness, and detection effectiveness. Controls in one failure domain are treated as fully correlated using a conservative weakest-control failure probability. Only distinct domains are multiplied as independent defenses. A scenario can force common-cause failures with `agentic.defense_conditions.failed_domains`.

## Open/closed comparison

Both modes replay the identical potential event sequence and recipes. Open-loop records findings but does not apply feedback. Closed-loop applies actions on the next step. The comparison reports prevented-event lift, risk reduction, boundary-violation reduction, unauthorized-path reduction, post-alert blast-radius reduction, and security-invariant survival lift. The legacy `agentic.metrics`, `events`, `findings`, and `feedback` fields remain aliases of the closed-loop result.

## Inter-episode learning

`agentic.learning` supplies deterministic episode observations and four bounded parameters: initial propensity, learning rate, oversight penalty, and safe-success decay. A positively rewarded boundary bypass reinforces future bypass propensity. Detection or intervention reduces it only in the oversight-enabled track. Both histories are emitted for audit; this is an evaluation model, not online training of an LLM.

## Agentic events

The initial event contract includes task blocking, unintended tool probing, shared-service writes, unauthorized coordination, transitive egress, sandbox escape, secret discovery, credential reuse, token minting, privilege escalation, control-plane access, log tampering, and third-party access.

## Containment actions

The shared feedback contract now supports:

- `pause_workload`
- `terminate_evaluation`
- `quarantine_zone`
- `revoke_identity`
- `disable_shared_service`
- `block_egress`
- `preserve_evidence`
- `notify_third_party`

These actions complement the existing monitoring, edge blocking, decoy redirection, and additional-authentication actions.

## Integrity evidence

The threat-intelligence gate scores source trust, vendor corroboration, affected-version consistency, code-reference validity, fix-commit presence, PoC presence and reproduction, independent-source count, and current status. Rejected or withdrawn advisories fail closed.

## Metrics

Agentic containment reports risk score, boundary pressure, boundary violations, credential amplification, exploit-chain depth, detection delay, alert-to-halt delay, post-alert blast radius, prevented events, security-invariant survival, topology violations, independent-defense failure probabilities, and inter-episode propensity changes.

Threat-intelligence evaluation reports fabricated-advisory acceptance, valid-advisory acceptance, verification coverage, unnecessary remediation count, and correction latency.

## Run

Run one scenario:

```bash
python scripts/run_scenario.py scenarios/agentic/hugging_face_style_containment.json
python scripts/run_scenario.py scenarios/agentic/fabricated_cve_integrity.json
```

Run the smoke benchmark:

```bash
python scripts/run_scenario.py benchmarks/cybermatch_agentic_security_v1.json
```

Outputs are written below `output/agentic_security/` as canonical JSON and a human-readable Markdown report. Existing output directories are never overwritten.

## Sources and interpretation

- [OpenAI - Hugging Face Incident Technical Report](https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf)
- [JFrog: SQLite Critical CVEs or LLM Slop?](https://research.jfrog.com/post/sqlite-critical-cves-or-llm-slops/)
- [SQLite vulnerability status](https://sqlite.org/cves.html)

CyberMatch scenarios are abstractions for comparative evaluation. They do not claim to reproduce every technical or organizational detail of the source incidents.
