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

**Update (2026-05-17).** The `freeform-rule` magnitude-tier append is
now shipping in this PR after a follow-up sanity check
(`experiments/actor-overspecificity-2026-05-17/`). At N=4 on the
previously-failing `b02-fim` fixture under the streamed harness it
passes 4/4 discipline; pooled with the PR's original stage-2 (1/3) =
5/7. The "doesn't generalize on b02" conclusion was largely seed
noise. Load-bearing density holds within 0.5 of baseline at N=4.

Two alternative formulations were also tested in stage 0:
- `e3-allow-estimates` (Section 1 wording relaxed to permit
  category-level placeholders) — 1/2 discipline on b02, with the
  lowest load-bearing density. Positive-permission framing didn't
  deter invented counts.
- `e4-forbid-enums` (Section 1 augmented with a negative instruction
  against invented enumerations) — 2/2, indistinguishable from
  freeform-rule at N=2. Larger edit, no clear win. Deferred.

## Deferred follow-ups

- **Defense in depth for the actor-tools split** — `actor.md` instructs
  "use lessons between Section 0 and Section 1." Now safe under the
  loop.py fix, but could be rephrased to "use lessons before writing
  any output" so future I/O changes can't reintroduce truncation.
- **Cross-fixture generality on a third alert shape** (e.g., Falco)
  before declaring the dropped-goal change immortal.
