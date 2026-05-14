<!--
Template. Environment lessons are discovered by the actor via
`defender/scripts/lessons_actor_index.py --channel environment` and
Read in full once `relevance_criteria` looks pertinent. Authoring +
invalidation/equivalence schema (subject, status, superseded_by — or
whatever shape proves needed) land in item #6 (author_actor) of
tasks/actor-learning-loop.md.
-->
---
actor_type: [internal, external]     # YAML list; values from {internal, external}
relevance_criteria:                  # one line — when this assertion bears on a story
recorded_at:                         # run_id that produced this lesson
---

## Assertion

<!--
Attacker-framed fact about the deployment. State what the *world*
produces (audit artifacts, schedule windows, ambient noise, telemetry
shapes, authorization patterns). Do not mention defender, leads,
queries, or lead positions.
-->
