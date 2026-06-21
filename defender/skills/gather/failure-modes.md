---
name: defender-gather-failure-modes
description: Recovery for the lean gather when a query errors or returns an empty / all-zero / null / garbage result — the adapter exit-code branch, the positive-control tool-fault test, and field-drift recovery. Read this on a non-sane result; the happy path never needs it.
---

You are here because a query errored or returned a result you could not
immediately explain. Work the one branch that matches, take a SINGLE recovery
step, then go back to your VERIFY step. The bound is a positive control plus one
narrowing/shape step — if that can't settle it, stop and report the quirk plainly
in your summary (so the offline lead-author picks it up); do not flail. Never
report a raw unchecked zero or a null.

## Branch on the adapter exit code

- **exit 2 — connectivity / auth / config:** the source is **unreachable**.
  Escalate immediately with the adapter's error and stop. Do **not** probe the
  connection or the harness (no `netstat`/`ss`/`docker`/`/dev/tcp`), do **not**
  hunt `.env`/credentials, do **not** re-run "to confirm" — a `2` is a data-source
  outage for a human to resolve, not something you can fix.
- **exit 64 — usage error:** *you* invoked the adapter wrong. Read the `usage:`
  line in stderr, fix the invocation, re-run. Not an outage; don't escalate.
- **exit 1 — query error / not-found:** fix the query and re-run, or treat a clean
  not-found as the genuine-absence case (verify it with the empty-result branch).
- **exit 0:** the source answered but the result isn't sane — use the content
  branches below.

## Empty / all-zero result (exit 0)

The `WHERE` matched nothing: a *filtering* mistake, a genuine absence, or a
silently-broken adapter. Disambiguate:

1. Re-run with the suspect predicate dropped (or `... | WHERE <one live filter> |
   LIMIT 1`) to tell "nothing there" from "wrong filter."
2. **Positive control** — run a query you KNOW should match (the alerting entity,
   or a broad `FROM <index> | LIMIT 1`). If even that comes back empty, it's a
   **tool fault**, not a real zero — escalate like an exit 2, citing the control.
3. Report the verified result, e.g. "0 accepted, verified: src has 0 events to
   this host in window; src is live elsewhere."

## Null / garbage columns (exit 0)

A `STATS ... BY <field>` grouped on a wrong or renamed field. Check the system
SKILL's "Known data-source quirks", then read the current field shape with the
same query truncated before the aggregation — `FROM ... | WHERE <filters> | LIMIT
10` — fix the field name and re-run. Do **not** silently swap in a field you
"know" without confirming it against the live shape.

## Result looks truncated

`row_count` is exactly 1000 → ES|QL's default row cap clipped a high-cardinality
`BY` (the aggregation scalars are still exact, but groups are missing). Narrow the
`BY`, tighten the `WHERE`, or add an explicit `LIMIT` and treat the `SORT`ed top-N
as partial. (`COUNT_DISTINCT` is approximate — HyperLogLog++ — not an exact unique
count.)
