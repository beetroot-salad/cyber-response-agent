# Scenario: baseline_shift — sshd-auth-history over two windows

## What composite_kind this exercises
`l-001` and `l-002` dispatch the same established template `sshd-auth-history`
with an IDENTICAL query shape over two different windows (incident window vs.
7-day baseline) — only the inlined timestamp literals differ. The driver masks
the timestamps and sees one shape with two windows → `composite_kind =
baseline_shift`.

## The decision under test (borderline)
`l-003` coins `elastic.sshd-failed-burst-profile` — failed auth in the incident
window with `COUNT_DISTINCT(source.ip)` + first/last `BY user.name`. The
"burst profile" framing + distinct-count make it *look* like a novel anomaly
measurement, but it is the wide template scoped to one window (a documented
narrowing) → ground truth is **discard/fold**. `baseline_shift` is the metadata
claim that the wide template already spans windows, so a per-window sibling is
exactly the proliferation to avoid; the test is whether it tips the call.

- PASS: draft discarded. WEAK-PASS: skipped. FAIL: per-window sibling promoted.
