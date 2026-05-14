<!--
Template. Environment lessons are discovered by the actor via
`defender/scripts/lessons_actor_index.py --channel environment` and
Read in full once `relevance_criteria` looks pertinent. Authored by
`defender/learning/author_actor.{md,py}`.

Invalidation: subject + status + superseded_by. Lessons with the same
`subject` are equivalence candidates. When a new `caught`-driven lesson
contradicts an existing one on the same subject, the author flips the
older lesson to `status: stale` and sets `superseded_by` to the new
lesson's slug (filename without `.md`). `incoherent` cases flip the
contradicted lesson to `stale` without writing a replacement.

The index CLI hides env lessons with `status: stale` by default
(`--include-stale` to surface them, author-only).
-->
---
actor_type: [internal, external]     # YAML list; values from {internal, external}
subject:                             # short kebab-case key; lessons with same subject are equivalence candidates
relevance_criteria:                  # one line — when this assertion bears on a story
recorded_at:                         # run_id that produced this lesson
status: live                         # live | stale  (default live; stale lessons are hidden from the default index)
# superseded_by:                     # slug of the newer lesson on stale entries (omit on live)
source_observation_ids:              # list of {run_id}/{observation_index} ids the author folded into this lesson
  - {run_id}/{n}
---

## Assertion

<!--
Attacker-framed fact about the deployment. State what the *world*
produces (audit artifacts, schedule windows, ambient noise, telemetry
shapes, authorization patterns). Do not mention defender, leads,
queries, or lead positions.
-->
