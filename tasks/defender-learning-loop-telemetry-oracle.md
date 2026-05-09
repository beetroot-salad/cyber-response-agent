---
title: Telemetry oracle between actor and judge
status: doing
groups: defender, learning-loop
---

**Goal.** Insert a telemetry oracle agent between actor and judge in the
defender learning loop. The oracle's only job: given the alert, the
actor's malicious story, the defender's full lead sequence, and per-lead
exemplar events from `gather_raw/{position}.json`, output the events
the attack would have produced lead by lead. The judge then compares
oracle-projected events against the leads' actual results.

**Why.** The current judge reasons about whether the actor's prose
survives the lead set. That framing is soft — it lets the judge handwave
about "load-bearing claims" without putting story and lead results into
the same observation space. Per-lead event projection gives the judge
concrete, comparable artifacts.

## Scope

- New prompt: `defender/learning/oracle.md`. Pure mechanical translation.
  No coverage labels, no rationale, no citations — judge owns all
  interpretation. Output is `projections: [{position, system, template,
  events: [{...}]}]`.
- `defender/learning/loop.py`:
  - new `assemble_exemplar_bundle(source_run_dir, lead_sequence_text)`
    helper concatenates each lead's `gather_raw/{position}.json` as the
    schema reference,
  - new `invoke_oracle(...)` step between actor and judge,
  - new `validate_oracle_doc(...)` (count/position match, projection
    schema, events-list-of-mappings), bad output is `LoopError`,
  - persist `projected_telemetry.yaml` in `learning_run_dir`,
  - judge gains a fourth `=== projected_telemetry.yaml ===` input section.
- `defender/learning/judge.md`:
  - fourth input section,
  - encounter-analysis section restructured around per-lead
    projected-vs-actual comparison,
  - outcome enum redefined in event-comparison terms,
  - citation `source` enum gains `projected_telemetry`.
- Unit tests: `defender/learning/test_loop.py` covers validator + bundler.

## Out of scope

- CLI `--sample-event` modes (followup if exemplar shape drift becomes
  the dominant failure mode for empty-result leads).
- Author-side oracle co-evolution (actor still sees only the gray-box
  projection — the actor/oracle split is structural).

## Done when

- `loop.py` runs end-to-end against an existing real run dir and
  produces `projected_telemetry.yaml` plus a judge output that cites
  oracle events.
- `pytest defender/learning/test_loop.py -v` is green.
- PR merged.
