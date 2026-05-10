# 01-real-baseline

Real findings from `livetest-5710` — the only batch we have produced
end-to-end as of 2026-05-10. No pre-seeded lessons; empty corpus.

## Findings

- `livetest-5710/1` — `lead-set`: investigation never tested whether the
  source-IP host (`172.22.0.10`) was itself compromised. Tightening
  variant of the actor story would survive the existing leads.
- `livetest-5710/2` — `observability`: `defender/skills/` has no system
  that can attest container/host integrity for internal RFC1918
  endpoints, so the supply-chain-compromise story is structurally
  unfalsifiable.

## What "good" looks like

- Two new lessons (different pitfalls — lead-gap vs missing system).
- Lesson bodies are **case-agnostic** — no `172.22.0.10`, `livetest-5710`,
  `wazuh`, etc. The teaching is "for SSH-invalid-user-style bait, verify
  source-host integrity" and "stop planning gather steps that need
  container/runtime-integrity systems we don't have".
- Both `forward-check` gates GOOD → committed.

## What would be a regression

- Folding two distinct pitfalls into one lesson.
- Lesson body verbatim-quoting the finding (translation failure).
- Lesson framing-as-good-pattern instead of pitfall.
