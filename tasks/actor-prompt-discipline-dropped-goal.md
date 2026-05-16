---
title: Actor prompt — drop Section 2 (Goal); fix loop.py text-mode truncation
status: done
groups: defender, learning-loop, actor
---

**Result (2026-05-16).** Two production changes shipped:

1. `defender/learning/actor.md`: Section 2 (Goal) deleted, Bypass
   renumbered 3 → 2, output-format preamble updated to "three sections".
2. `defender/learning/loop.py`: `_run_claude` switched from
   `--output-format text` to `--output-format stream-json` + concatenate
   assistant text messages. Production was silently dropping Section 0
   whenever the actor consulted the lessons-actor corpus mid-output
   (≈50% of runs that read lessons). Affects actor, oracle, judge alike.

Full writeup, per-cell grades, harness, and rubric:
`experiments/actor-prompt-discipline-2026-05-16/`.

**What did NOT ship.** Three E2 magnitude-tier formulations tested
(freeform-rule, explicit-axes, load-bearing-aware) — each succeeded on
one fixture and failed on another. The discipline doesn't generalize
across alert shapes from a preamble nudge alone. Either reformulate it
as a structural output-format instruction or scope per-signature.
Filed as deferred follow-up below.

## Deferred follow-ups

- **Magnitude-tier discipline that generalizes** — actors writing
  supply-chain / FIM narratives keep committing to specific payload
  sizes and proxy-hop counts despite the rule. Brute-force / auth
  shapes apply it cleanly. Next attempt should put the rule in
  actor.md's Output-format section (alongside "first character is `0`")
  rather than the preamble.
- **Defense in depth for the actor-tools split** — `actor.md` instructs
  "use lessons between Section 0 and Section 1." Now safe under the
  loop.py fix, but could be rephrased to "use lessons before writing
  any output" so future I/O changes can't reintroduce truncation.
- **Cross-fixture generality on a third alert shape** (e.g., Falco)
  before declaring the dropped-goal change immortal.
