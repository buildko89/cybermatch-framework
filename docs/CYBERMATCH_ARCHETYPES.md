# CyberMatch Archetypes

## What Archetype Means

An Archetype is a discovered behavior cluster in the CyberMatch feature space.
It is not a new attacker, defender, mission, policy, or simulation rule.

Phase9.3 assigns labels such as `Archetype-1` and `Archetype-2` from existing
behavior feature vectors. Phase9.4 interprets those labels by comparing feature
means, feature variance, mission distribution, behavior profile distribution,
and activity levels.

Phase9.4 does not automatically name archetypes. It only describes them with
signatures such as:

- high utility_activity
- low deception_activity
- medium adaptation_activity

## Difference From Mission

Mission is the attacker objective class, such as profit, achievement,
persistence, or critical hunting.

Archetype is behavior-centered. It can cut across mission labels when different
missions produce similar observable behavior. This makes Archetype useful when
the research question is not "what mission is this?" but "what behavior
principle is this actor following?"

Mission remains useful as a ground-truth objective label. Archetype adds a
behavior-understanding lens that can reveal when mission labels are too coarse
or when several missions converge on the same operational pattern.

## Difference From Behavior Profile

Behavior Profile is a rule-based abstraction of observed behavior.

Archetype is discovered from numeric feature geometry. It may align with
Behavior Profile, but it is not defined by the profile rules. Phase9.4 measures
this relationship through `archetype_profile_overlap`.

Low profile overlap means the discovered archetypes separate behavior in a way
that is not simply a restatement of existing profile labels.

## Relationship To PCA

Phase9.3 uses PCA as a bridge from high-dimensional CyberMatch feature vectors
to interpretable components and archetype candidates.

PCA is not the meaning of the archetype. It is the projection method used to
support discovery. Phase9.4 moves from discovery toward interpretation by
studying feature means, variance, distances, mission overlap, profile overlap,
and stability.

## Phase9.4 Metrics

Phase9.4 reports:

- `archetype_signature`: descriptive high/medium/low feature statements.
- `archetype_feature_distance`: pairwise distance between archetype feature centroids.
- `archetype_mission_overlap`: how much mission distribution overlaps across archetypes.
- `archetype_profile_overlap`: how much behavior profile distribution overlaps across archetypes.
- `archetype_stability`: inverse within-archetype feature variance.
- `archetype_interpretability_score`: combined distinctness, overlap, and stability score.

## Intent-Aware Defense Direction

Archetype interpretation is the first step from Behavior-Aware analysis toward
Behavior-Understanding.

The long-term direction is to use archetypes as behavior principles that can
inform defense choices without relying only on mission labels.

Future Phase9.5+ candidates:

- Archetype Prediction
- Archetype Transition
- Intent-Aware Defense
- Adaptive Countermeasure Selection

These are future directions only. Phase9.4 does not implement them.
