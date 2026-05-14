<!--
Template. Tradecraft lessons are authored from `caught` outcomes only.
The actor discovers candidates after committing Section 0 via
`defender/scripts/lessons_actor_index.py --channel tradecraft
--techniques <T-IDs> --actor-type <archetype>` and Reads the files
whose `relevance_criteria` looks pertinent. Authoring + invalidation
mechanics land in item #6 (author_actor) of
tasks/actor-learning-loop.md.
-->
---
techniques: [T1078.004]              # MITRE T-IDs — grep retrieval key
actor_type: [internal]               # YAML list; values from {internal, external}
relevance_criteria:                  # one line — when this lesson applies to a story
recorded_at:                         # run_id that produced this lesson
---

## What the actor did

<!-- One paragraph describing the attempted pattern. Action, not defense. -->

## Why it was caught

<!-- One paragraph naming the defender signal that refuted it. -->

## Implication

<!-- One line, attacker-facing takeaway. -->
