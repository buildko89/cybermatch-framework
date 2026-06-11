# CyberMatch Evaluation Matrix

CyberMatch evaluates security controls by campaign impact. The central question is not only whether a control detects activity, but how it changes attacker decisions and mission outcomes.

| Category | CyberMatch Evaluation Focus | Example Metrics |
| --- | --- | --- |
| IDS | Detection visibility and signal quality | detection rate, observable events, signal-to-noise ratio |
| IPS | Attack prevention and critical asset protection | critical compromise, success probability, defense objective score |
| Honeypot | Attacker waste and exposure | decoy attack rate, honey node visits, detection count |
| Deception Platform | Belief distortion and mission disruption | fake asset interactions, fake path follows, campaign disruption score |
| SOAR | Response policy effectiveness | adaptive policy switches, response cost, risk reduction |
| XDR | Cross-signal decision confidence | state belief accuracy, mission belief error, decision confidence |
| Mission-Aware Defense | Mission-specific protection | mission success score, mission satisfaction, objective score |
| Counter-Deception Defense | Active attacker manipulation | counter-deception score, diversion score, fake credential traps |

## Evaluation Axes

CyberMatch should evaluate each product or strategy across these axes:

- Critical asset protection
- Attacker mission success
- Attacker confidence
- Attacker expected utility
- Attacker trust degradation
- Path diversion
- Observable event generation
- False signal robustness
- Adaptive defender value
- Counter-deception robustness
- Coalition robustness

## Product Comparison Principle

CyberMatch should avoid reducing product evaluation to alert volume. A product that creates fewer alerts but strongly reduces mission success can be better than a product that detects more events without changing attacker behavior.

## v1.0 Matrix Requirement

For v1.0, each supported product category should have:

- A scenario template
- Required telemetry assumptions
- Supported metrics
- Baseline comparison mode
- Report output
- Known limitations
