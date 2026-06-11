# CyberMatch Vision

## What is CyberMatch?

CyberMatch is a cyber decision-making simulator that reproduces attacker decision processes and enables comparative evaluation of defense strategies and security products.

日本語定義:

CyberMatch は、攻撃者の意思決定を再現し、防御戦略やセキュリティ製品を比較評価できるサイバー意思決定シミュレータである。

CyberMatch does not only ask whether an attack was detected. It asks whether the defender changed the attacker's mission outcome, confidence, trust, expected utility, path choice, coalition behavior, and adaptation loop.

## Why CyberMatch?

Most cyber evaluation systems focus on one of three surfaces:

- Whether a known technique can be replayed.
- Whether a detection fired.
- Whether an autonomous agent completed a task.

CyberMatch focuses on the decision system between those surfaces. It evaluates attacker-defender interaction as a repeated campaign where both sides observe, adapt, deceive, coordinate, and learn.

## Difference from ATT&CK Replay

ATT&CK replay is useful for validating that telemetry, detections, and response playbooks recognize known behaviors. It is less suited to answering decision-centric questions:

- Did the defense reduce attacker confidence?
- Did the defense change target selection?
- Did deception alter the perceived mission utility?
- Did the attacker avoid, validate, or hunt deception?
- Did coalition coordination fail under realistic cost?

CyberMatch complements ATT&CK replay by modeling campaign-level decision pressure, not just technique execution.

## Difference from LLM Agent Evaluation

LLM agent evaluation often measures whether an agent can complete a cyber task in an environment. CyberMatch instead treats attacker behavior as a controllable decision model that can be evaluated across many defense policies, missions, and deception conditions.

CyberMatch can use agent-like concepts, but its core value is not prompt performance. Its core value is repeatable comparison of attacker decision outcomes under defense intervention.

## Core Concepts

### Mission

Mission defines what the attacker is trying to optimize: profit, achievement, persistence, critical asset compromise, or a mixed objective.

### State

State captures the inferred campaign phase and operational context. It connects raw events to defender policy selection and attacker progression.

### Belief

Belief represents what the attacker or defender thinks is true. CyberMatch tracks attacker belief, mission belief, state belief, defender belief, and how deception or noise distorts them.

### Trust

Trust represents whether the attacker continues to rely on nodes, credentials, paths, or coalition partners. It is a decision variable, not only a social concept.

### Deception

Deception changes attacker perception through decoys, fake signals, intent masking, fake credentials, fake assets, fake paths, and honey nodes.

### Coalition

Coalition models multiple attackers with role delegation, handover, coordination cost, information loss, and trust degradation.

### Adaptive Defense

Adaptive Defense selects policies based on observed risk, mission inference, campaign stage, and defense effectiveness memory.

### Counter-Deception

Counter-Deception is active manipulation by the defender. The defender does not only detect or filter attacker deception; it misdirects the attacker.

### Co-Evolution

Co-Evolution is the central CyberMatch loop:

```text
attacker adapts
defender adapts
attacker deceives
defender counter-deceives
attacker becomes aware
attacker hunts deception
```

CyberMatch v1.0 should make this loop measurable, reproducible, and usable for defense comparison.
