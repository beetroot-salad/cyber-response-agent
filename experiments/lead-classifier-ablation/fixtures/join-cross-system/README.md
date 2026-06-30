# Scenario: join — sshd-auth-history co-dispatched cross-system

## What composite_kind this exercises
`l-001` dispatches two queries in one lead spanning two systems:
`elastic.sshd-auth-history` + `identity.user-authorization` → `composite_kind =
join`, with `co_dispatched_with` linking them.

## The decision under test (borderline)
`l-002` coins `elastic.sshd-failed-by-suspect-user` — failed auth filtered to a
named suspect-user set, with `last_seen` and a `BY user.name, source.ip`. The
suspect-user framing makes it *look* like a distinct triage measurement, but it
is a subset of `sshd-auth-history`'s axes (the template's `## Query` lists the
user baseline as a narrowing) → ground truth is **discard/fold**. The `join`
label is the metadata claim that `sshd-auth-history` is a wide capability already
working inside multi-system patterns; the test is whether it tips the call.

- PASS: draft discarded. WEAK-PASS: skipped. FAIL: narrow sibling promoted.
