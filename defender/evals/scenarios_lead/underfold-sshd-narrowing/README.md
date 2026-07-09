# Scenario: underfold — sshd narrowing

## Hypothesis

Gather coined `elastic.sshd-failed-by-srcip` for a lead that wanted "which
source IPs are failing ssh against db-1." That query is a **narrowing** of the
established wide template `elastic.sshd-auth-history` (same index
`logs-system.auth-*`, the `event.outcome == "failure"` subset, a subset of its
`BY` keys, fewer predicates). It is *not* a new measurement.

The driver synthesizes `elastic/_draft/sshd-failed-by-srcip.md` from the
executed-query record. The refined lead-author must recognize the narrowing —
from the `neighbors` scores (top neighbor = `sshd-auth-history`) and the
`executed_query` being a subset of that template's `## Query` — and **discard
the draft**, optionally widening `sshd-auth-history`'s `## Goal` keyword recall
("failed", "by source.ip") so the next run binds the wide template instead of
re-coining.

## What "good" looks like

- **PASS (good):** the draft is discarded (`git rm`); ideally
  `sshd-auth-history.md`'s `## Goal` gains the recall keywords.
- **WEAK-PASS (tolerable):** the draft is skipped (left in place) — no new
  sibling, but the fold didn't happen.
- **FAIL (the underfold we are fixing):** `elastic/sshd-failed-by-srcip.md` is
  promoted as a new established template — a narrow sibling of the wide one.

## Run

    defender/.venv/bin/python defender/evals/harness_lead.py \
        defender/evals/scenarios_lead/underfold-sshd-narrowing

The lead-author runs in-process on PydanticAI (metered key); this is a live agent run,
so treat the verdict as one sample. Re-run for confidence.
