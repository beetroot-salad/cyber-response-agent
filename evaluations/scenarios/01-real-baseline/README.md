# 01-real-baseline

Real findings from `livetest-5710` — the only batch we have produced
end-to-end as of 2026-05-10. No pre-seeded lessons; empty corpus.

## Findings

- `livetest-5710/1` — `lead-set`: investigation never tested whether the
  source-IP host (`172.22.0.10`) was itself compromised. Tightening
  variant of the actor story would survive the existing leads.

The batch's second finding (a missing system: no way to attest
container/host integrity for internal RFC1918 endpoints) was dropped from
the seed by #1234: a deployment gap is reported to the user, never taught
as a lesson, so it is no longer a finding type the curator receives.

## What "good" looks like

- One new lesson (the lead-gap pitfall).
- Lesson body is **case-agnostic** — no `172.22.0.10`, `livetest-5710`,
  `wazuh`, etc. The teaching is "for SSH-invalid-user-style bait, verify
  source-host integrity".
- The `forward-check` gate GOOD → committed.

## What would be a regression

- Splitting the one pitfall into several lessons.
- Lesson body verbatim-quoting the finding (translation failure).
- Lesson framing-as-good-pattern instead of pitfall.
