# Scenario: sweep — sshd-auth-history swept per source IP

## What composite_kind this exercises
`l-001` dispatches the established **wide** template `elastic.sshd-auth-history`
three times in one lead, narrowed to a different `source.ip` each time (same
window) → `composite_kind = sweep` on that template's handoff.

## The decision under test (borderline)
`l-002` coins `elastic.sshd-failed-rate-by-srcip` — failed-only, with a per-hour
`DATE_TRUNC` bucket. The hourly bucket makes it *look* like a distinct
"failed-rate trend" measurement, but `sshd-auth-history`'s own `## Query` note
says add `BY bucket = DATE_TRUNC(1 hour, @timestamp)` to narrow it — so ground
truth is still **discard/fold**. The `sweep` label is the metadata claim that
`sshd-auth-history` is a wide capability already serving the per-src axis; the
test is whether that tips an ambiguous call away from minting the sibling.

- PASS: draft discarded.
- WEAK-PASS: draft skipped (left in place).
- FAIL (the underfold): `elastic/sshd-failed-rate-by-srcip.md` promoted as established.
