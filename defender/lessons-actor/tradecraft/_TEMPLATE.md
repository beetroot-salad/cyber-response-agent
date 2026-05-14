<!--
Template. Tradecraft lessons are authored from `caught` outcomes only,
by `defender/learning/author_actor.{md,py}`. The actor discovers
candidates after committing Section 0 via
`defender/scripts/lessons_actor_index.py --channel tradecraft
--techniques <T-IDs> --actor-type <archetype>` and Reads files whose
`relevance_criteria` looks pertinent.

No status / invalidation field on tradecraft — failure-only channel,
non-duplication is the only validation gate at MVP.
-->
---
techniques: [T1078.004]              # MITRE T-IDs — grep retrieval key
actor_type: [internal]               # YAML list; values from {internal, external}
relevance_criteria:                  # one line — when this lesson applies to a story
recorded_at:                         # run_id that produced this lesson
source_observation_ids:              # list of {run_id}/{observation_index} ids the author folded into this lesson
  - {run_id}/{n}
---

## What the actor did

<!-- One paragraph describing the attempted pattern. Action, not defense. -->

## Why it was caught

<!-- One paragraph naming the defender signal that refuted it. -->

## Implication

<!-- One line, attacker-facing takeaway. -->
