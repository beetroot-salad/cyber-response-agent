# Validation pass (N=1 per arm per fixture, 8 live runs)

Date: 2026-06-30. Model: claude-sonnet-4-6 (harness default). Live `claude -p`.

## Well-formedness: PASS
- All 8 runs completed (rc=0), verdict fired, both worktrees ran.
- Patch applies/commits clean; proposed arm has no `composite_kind`.
- Confirmed `composite_kind` IS present on the established `sshd-auth-history`
  handoff in the current arm: sweep×3 / join / baseline_shift×2 (deterministic
  build_handoff check). The coined-draft handoff is `atomic` (single execution)
  — so the metadata's effect on the discard decision is INDIRECT (it sits on the
  wide neighbor the draft narrows, not on the draft). This is faithful to
  production: a coined narrow query is always one execution → atomic.

## Verdicts (N=1 — one sample of a non-deterministic agent, NOT conclusive)
| fixture | current | proposed |
|---|---|---|
| atomic-control | PASS | PASS |
| sweep-srcip-host | PASS | PASS |
| join-cross-system | PASS | PASS |
| baseline-shift-two-window | PASS | PASS |

All PASS = draft discarded in every cell. Δ underfold = 0.0% on all fixtures.

## Read
Early signal leans "delete" (the agent discards correctly with or without the
metadata, even on the hardened borderline drafts), but N=1 cannot establish the
underfold base rate or rule out a small marginal effect. Scale-up needed to
quantify. Structural note: because composite_kind rides the skip-defaulted
established handoff, it is weakly positioned to change the discard decision —
which makes "no effect" the likely (and production-faithful) outcome.
