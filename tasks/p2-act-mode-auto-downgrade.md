---
title: act mode: auto-downgrade on >2% override rate
status: backlog
groups: phase-2
---

Once act mode is landed for `close_ticket` (see `p2-act-mode.md`), we need
the feedback loop that prevents a regressing signature from silently
auto-closing real threats. Design reference:
`docs/design-v3-architecture.md` §6.5 (Quality Monitoring).

The mechanic: periodically sample act-mode-closed tickets and compare the
agent's disposition against whatever the human later marks. If the override
rate on a signature crosses a configured threshold (design says ~2%),
automatically demote it from `mode.default: act` back to
`mode.default: recommend` — force every subsequent alert through the
human-review gate until the signature is re-graduated.

Depends on:
- `p2-act-mode.md` landing (hook, audit log, ActionContract).
- `p2-act-mode-sampling.md` — sampling + override tracking produces the
  input signal this task acts on.

Open questions:
- Where does the override signal come from? Webhook from the ticketing
  system? Periodic poll via the adapter? A manual feedback command?
- What demotion mechanism? Edit `permissions.yaml` in-place? Flip a
  runtime flag in a sidecar state file? The former gives a clean git
  audit trail; the latter survives PR churn.
- How does a human re-graduate a demoted signature? Explicit
  opt-in command so demotion can't silently flip back.
