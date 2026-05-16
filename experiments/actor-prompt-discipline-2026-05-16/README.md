# Actor-prompt discipline (2026-05-16)

Question: do tighter framings in `defender/learning/actor.md` produce
attack stories that follow discipline (no end-to-end goal sprawl, no
over-committed operational parameters) while preserving story quality
(falsifiable-claim count, especially the load-bearing subset)?

Tested actor variants standalone — actor → story → rubric judge — to
sidestep the judge-of-pipeline foul issue flagged in the kickoff recap.

## Final outcome — what shipped

**One actor.md change + one loop.py change**, both in this PR:

1. `defender/learning/actor.md`: delete Section 2 (Goal), renumber
   Bypass 3 → 2, rewrite output-format preamble to "three sections".
   Section 2 (Goal) was end-to-end narrative scaffolding that
   contributes no defender-disposition signal — the actor's
   over-commitment lives in Section 1, and removing the goal section
   doesn't measurably reduce load-bearing claims on either tested
   fixture.
2. `defender/learning/loop.py`: `_run_claude` switches from
   `--output-format text` to `--output-format stream-json` + concat
   all assistant text messages. Production was silently dropping
   Section 0 whenever the actor consulted the lessons-actor corpus
   between Sections 0 and 1 (≈50% of runs that read lessons). Text
   mode returns only the final assistant message; stream-json concat
   preserves all of them.

**What did NOT ship:** the E2 magnitude-tier patches (freeform-rule,
explicit-axes, load-bearing-aware). All three formulations succeed on
one fixture and fail on another — they don't generalize across alert
shapes. See `results/stage1b-grades.md` and `results/stage2-grades.md`.

## Reading order

- `plan.md` — methodology and staging
- `results/stage1a-grades.md` — E1 goal-width on live-5710 (N=4 per variant)
- `results/stage1b-grades.md` — E2 spec-granularity layered on E1 winner (N=4)
- `results/stage2-grades.md` — generality check on b02-fim (N=2-3 per cohort)
- `variants/*.md` — per-variant prompt deltas (specs; harness owns the patches)
- `rubric.md` — judge prompt
- `harness.py` — driver: `python harness.py {generate|grade|run} --variant X --fixture Y --seeds N,N,N`

## Headline numbers (means)

| Variant | Live-5710 (SSH) | b02-fim (FIM) |
|---|---|---|
| current (baseline) | n/a / 27.0t / 6.75lb | n/a / 24.67t / 6.33lb |
| **dropped-only (E1, SHIPS)** | **4/4 / 25.0t / 5.5lb** | **3/3 / 23.67t / 6.67lb** |
| combined-freeform | 4/4 / 25.25t / 6.75lb | 1/3 / 24.0t / 6.67lb |
| combined-load-bearing | 1/2 / 20.5t / 6.0lb | 2/2 / 27.0t / 5.5lb |

`X/Y` = discipline pass rate, `Nt` = total falsifiable claims (mean),
`Nlb` = load-bearing claims (mean). Baseline discipline is `n/a`
because the current prompt has no constraint to violate.

## Key findings beyond the ship decision

- **The harness text-mode bug was pre-existing in production loop.py.**
  Affected ~50% of actor runs that consulted lessons (e.g. 2/4 baseline
  cells on live-5710, 2/3 on b02 lost Section 0). Baseline rubric's
  trivial-pass discipline masked it; variant rubrics surfaced it.
  Loop.py fix in this PR closes that silently-truncated path for actor,
  oracle, and judge alike.
- **Picking variant winners on a single fixture is unsafe.** The Stage-1b
  winner on live-5710 (`combined-dropped-freeform`) regressed to 1/3
  discipline on b02 — even after the loop bug was fixed. Picking E1+E2
  combined and shipping would have hurt b02 specifically.
- **The magnitude-tier rule is fixture-sensitive.** Actors writing
  brute-force / authentication narratives can apply it; actors writing
  supply-chain / FIM narratives keep slipping back to specific
  payload sizes and proxy-hop counts. Three different prompt
  formulations couldn't bridge that gap. Future work would either
  reformulate the rule structurally (output-format section, not
  preamble) or per-signature scope it.

## Cost & artifacts

~$10 in claude-p calls across 48 actor runs + 48 rubric grades.
Run dirs preserved under `runs/{stage}/{variant}/{fixture-seed}/` with
per-cell `story.md`, `grade.json`, `actor.md.patched`,
`actor_archetype.txt`, `actor_menu.txt`.

## Follow-ups not addressed

- Magnitude-tier discipline that generalizes across alert shapes
  (file as a separate task if pursued; the data here is the starting
  context).
- The actor.md "use lessons between Section 0 and Section 1"
  instruction is now safe under the loop.py fix, but it could be
  reframed to "use lessons before writing Section 0" as a defense
  in depth.
- Cross-fixture generality check on a third alert shape (e.g., Falco)
  before declaring the dropped-goal change immortal.
