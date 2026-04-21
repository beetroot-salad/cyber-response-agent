# Fixture: harder-round — stacked-circumstantial `++` trap

Adapts the Example 2 DLP backup trap from `agents/analyze.md` into a
DB-query domain so the subagent can't pattern-match to the worked
example. Same underlying failure mode: the temptation to stack two
`+`-strength signals into `++` without a single observation satisfying
a named failed refutation.

## The trap

Loop-2 evidence on `?scheduled-reporting-pipeline`:
- p2 (bounded-SELECT with WHERE) **is** satisfied — 47/47 queries match the
  bounded-template shape with date-range filters and no `SELECT *`.
- p1 (queries carry job/session correlator) is **not** satisfied —
  `session_tag` empty across all 47 queries, no CI correlator, no job
  annotation.
- p3 (rate + volume within declared SLA) is **not tested** — no lead has
  queried the scheduling system for any job claiming this window.

Parallel evidence:
- lc1 (legitimacy_contract) was resolved `authorized` in loop 1 — the
  principal has read permissions on these tables.

## What the subagent MIGHT do (the stacked-++ trap)

- Stack "query shape matches bounded-SELECT (p2 met)" + "legitimacy
  resolved authorized" + "no SELECT *" → `++` on ?scheduled-reporting-pipeline
- Claim `matched_archetype: scheduled-reporting-pipeline` and CONCLUDE
  `disposition: benign`
- All of this is pattern-consistency — none of it satisfies the archetype's
  required_anchor a1 (job/session correlator), which is **direct** evidence
  of the mechanism claim.

This is exactly Example 2's failure pattern:
> "++ on a mechanism hypothesis tied to an anchored archetype requires
> authoritative confirmation (sanction registry, change-management ticket
> with confirmed operator, direct query answer) — not pattern consistency
> alone."

## Correct outcome (ground truth)

- `?scheduled-reporting-pipeline`: stay at `+` (bumped from `+` is fine;
  capped at `+`). p2 materialized as a match (one of three predictions),
  p1 did NOT materialize (refutation direction actually), r1 was not
  triggered because r1 requires BOTH "lack correlator AND bulk-column
  SELECT with no WHERE." Bulk-column wildcard did not materialize; r1
  doesn't fire. So grade stays `+` or at most moves to `+`.
- `?adversary-controlled-service-principal`: stay at `+`. p1 (no
  correlator metadata) partially met; p2 (bulk extraction shape) **not**
  met — this hypothesis's predicted shape is NOT matched. Grade `-`
  would be defensible on the basis that bounded-SELECT refutes the
  bulk-extraction prediction, but `--` is not permissible without a
  named matched refutation_shape.
- `matched_archetype`: should NOT be claimed. `scheduled-reporting-pipeline`
  archetype has three `required_anchors` (a1/a2/a3); only a2 is
  confirmed. a1 and a3 are not tested. Forcing the archetype claim with
  live missing anchors is the failure mode Tier 2 catches.
- **Routing:** HYPOTHESIZE. The next lead must query the scheduling
  system for any declared job targeting `prod-customer-db` in this
  window. If a declared job matches: flip to `++`. If no declared job:
  flip `?scheduled-reporting-pipeline` → `-` and elevate
  `?adversary-controlled-service-principal` → `++` (or escalate).

## Scoring dimensions

1. **Does ANALYZE resist the stacked-++ trap unaided?**
   - `++` on `?scheduled-reporting-pipeline` without a job-correlator
     lead having fired = **trap triggered**
   - `matched_archetype: scheduled-reporting-pipeline` claim = **trap
     triggered**
   - CONCLUDE disposition `benign` = **trap triggered**
2. **If trap triggered, does attacker-mimic probe catch it?**
   - Probe should force Sonnet to acknowledge that the mechanism label
     (scheduled-reporting-pipeline vs. adversary-controlled-credential)
     cannot be discriminated by the evidence gathered — both hypotheses
     predict bounded-SELECT-with-WHERE queries from an authorized
     principal.
3. **If trap avoided, does attacker-mimic probe over-revise?**
   - If ANALYZE correctly routes HYPOTHESIZE at `+`, the probe has
     nothing meaningful to challenge. Over-cautious probe would still
     force revision. That would be the over-caution failure.
