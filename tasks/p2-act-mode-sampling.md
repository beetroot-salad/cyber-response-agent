---
title: act mode: sampling and override tracking infrastructure
status: backlog
groups: phase-2
---

Act mode depends on knowing how often the agent's auto-closed decisions
get overridden by humans post-hoc. This task captures the sampling +
tracking pipeline that produces the signal `p2-act-mode-auto-downgrade.md`
consumes. Design reference: `docs/design-v3-architecture.md` §6.5.

What's needed:

- A **sampling policy** — does every auto-closed ticket get re-reviewed,
  or a percentage? Scaled by signature maturity? Driven by cost budget?
- An **override signal source** — how the loop learns that a human later
  reopened a ticket the agent closed, or marked it as a false negative.
  Webhook from the ticketing system? Periodic poll? Manual feedback
  command in the plugin?
- **Override storage** — append-only log next to `runs/action_audit.jsonl`,
  probably `runs/action_overrides.jsonl` with a stable schema
  (`run_id, ticket_id, signature_id, override_timestamp, outcome,
  reviewer`).
- **Rate computation** — rolling-window override rate per signature, so
  the auto-downgrade hook can threshold against it.

Depends on `p2-act-mode.md` landing. Blocks `p2-act-mode-auto-downgrade.md`.
