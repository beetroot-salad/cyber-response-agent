# NEG-1 — synthetic 5710, advisory redundant

## Story

Exact replay of the most recurring 5710 corpus pattern — `172.22.0.10` +
`nagios`. CMDB has no entry for the source (the documented monitoring
host is `172.22.0.20`); IAM has `nagios: active:false`. The investigation
resolves cleanly on the two registry checks.

## Construction

Entity values copied verbatim from the recurring corpus pattern (e.g.
`/tmp/defender-runs/20260518T040450Z-alert`,
`20260519T065544Z-live-5710`). This is the *trivial-resolution* case for
this signature.

## Why this is "negative" (advisory redundant)

The right leads are obvious from the alert content + the structure of
5710 itself (source legitimacy + account provisioning). Any baseline
agent should pick `cmdb-source-lookup` + `iam-account-lookup` on loop 1
without precedent. Advisory has nothing marginal to suggest — and arm D
(always-fire) pays the call cost for zero added information.

## What we expect to see

- A: clean resolution, 1 PLAN loop, ~2 leads, disposition `malicious`.
- B/C: same as A if the agent correctly skips advisory; otherwise small
  cost penalty.
- D: same outcome as A, with measurable cost overhead (token + wall-clock)
  from the unconditional advisory call.
