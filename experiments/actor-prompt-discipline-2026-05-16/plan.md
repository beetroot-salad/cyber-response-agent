# Actor-prompt discipline — experiment plan

**Date:** 2026-05-16
**Branch:** `actor-prompt-discipline-2026-05-16`
**Status:** stage-1a pilot pending

## Question

Do tighter framings in `defender/learning/actor.md` produce stories that
(a) **follow discipline** — no end-to-end goal sprawl, no over-committed
operational parameters — while (b) **preserving story quality** at or
above the current prompt's level (operationalized as
falsifiable-claim count)?

Actor changes are evaluated **standalone** — actor → story → rubric judge.
No defender pipeline, no oracle, no outcome judge. This sidesteps the
known judge-foul contamination flagged in the recap; judge-rule changes
(independence + resolution) get tested separately, end-to-end, on a fixed
actor in a later experiment.

## Two prompt knobs, tested sequentially

### E1 — Goal-section width

Section 2 of `actor.md` currently asks for end-to-end narrative
(entry → lateral → exfil objective). The recap argues this is sprawl
that doesn't influence defender disposition and invites cheap judge
refutations.

| Variant | Section 2 treatment |
|---|---|
| `e1-current-goal` (regression) | Unchanged baseline |
| `e1-terse-goal` | One sentence: immediate upstream constraint only |
| `e1-dropped-goal` | Deleted; Bypass renumbered to Section 2 |

Variants live in `variants/e1-*.md` as full Section-2 replacement text.
The harness patches `actor.md` accordingly.

### E2 — Operational-parameter granularity (gated on E1)

The preamble currently says "concrete and specific, but no more
elaborate than the operation requires." Recap argues this admits
specific-value commitments (e.g., "every 70 seconds") that the judge
will refute on cosmetic detail rather than load-bearing axes.

| Variant | Preamble treatment |
|---|---|
| `e2-current-spec` (regression) | Unchanged baseline |
| `e2-explicit-axes` | Enumerate count / cadence / fan-out / breadth / dwell; magnitude-tier only; specific values forbidden |
| `e2-freeform-rule` | State the magnitude-tier rule; trust actor to apply |

Run after an E1 winner is picked; E2 variants ride on top of the E1
winner's `actor.md`.

## Rubric — judge each story on two axes

Per story, the rubric judge emits a JSON object with two binary scores
plus brief justifications. Rubric prompt: `rubric.md`.

| Axis | Definition | What "pass" looks like |
|---|---|---|
| **Discipline** | Does the story comply with the variant's framing? | E1: no end-to-end goal beyond the asked scope. E2: ops parameters committed at magnitude tier only (no specific values like "every 70 seconds", "3 hosts"). |
| **Quality (total)** | Total falsifiable-claim count ≥ baseline | Count every concrete prediction a defender lead could in principle refute. Compared against the current-actor cell on the same fixture. |
| **Quality (load-bearing)** | Load-bearing claim count ≥ baseline | Sub-count of predictions whose refutation would refute the story's central malicious thesis (not cosmetic detail). Guards against padding with throwaway predictions. |

Discipline is the new behavior. Quality is the regression guardrail —
we won't accept a prompt that follows discipline by being thinner.

**Discipline is variant-conditional.** A "current" variant trivially
passes discipline (no new constraint). Discipline is meaningful only
for terse / dropped / explicit-axes / freeform.

**Quality is variant-relative within a fixture.** The current-actor
cell's mean falsifiable-claim count on that fixture is the bar; new
variants must equal or exceed it.

**Rubric judge is unvalidated.** N is small (≤12 per stage) — every
story gets eyeball-checked alongside the auto-grade. The auto-grade
is decision-support, not the ground truth.

## Staging

### Stage 1a — E1 on one fixture (pilot)

- Fixture: `defender/fixtures/held-out/b04-nagios-auth-failures/`
  (5710, mirrors the live-run foul shape from the recap)
- 3 variants × N=4 = 12 actor runs
- Cost: ~$2.40 (actor) + ~$0.60 (rubric) ≈ $3
- Decision: pick the E1 winner, or "no clear winner → keep current."

### Stage 1b — E2 on the same fixture, layered on the E1 winner

- Same fixture
- 3 variants × N=4 = 12 actor runs
- Cost: ~$3
- Decision: pick the E2 winner.

### Stage 2 — Generality, gated on Stage-1 wins

Only run if Stage 1 produces a clear winner that's worth confirming.

- Additional fixtures: `m01-ssh-bruteforce-dict` (malicious 5710), and
  one non-SSH fixture: TBD between `b02-fim-apt-update` (FIM) and a
  Falco shape (`b03-falco-orchestrator-probe`). Pick one to keep cost
  bounded; cross-signature generality is the goal, not exhaustive
  coverage.
- 2 winning variants (E1 + E2 combined into a single prompt) ×
  2 fixtures × N=3 = 12 actor runs
- Cost: ~$3
- Decision: confirm winner generalizes, or surface fixture-specific
  effects.

## Model & thinking parity

Actor invocation pins **`claude-sonnet-4-6`**, no `--effort` flag.
This matches the production default in `defender/learning/loop.py`
(`ACTOR_MODEL = os.environ.get("ACTOR_MODEL", "claude-sonnet-4-6")`;
no `ACTOR_EFFORT` variable exists). The harness invokes the existing
`defender.learning.loop.invoke_actor()` with `ACTOR_PROMPT`
monkey-patched to the variant path, so menu sampling, archetype
assignment, user-prompt shape, settings file, and lessons-actor
add-dir all stay identical to production.

Rubric judge uses `claude-sonnet-4-6`, no `--effort`, for consistency.
This is a judgment call, not a parity requirement.

## Layout

```
experiments/actor-prompt-discipline-2026-05-16/
  plan.md                          # this file
  rubric.md                        # rubric judge system prompt
  variants/
    e1-current-goal.md             # baseline marker (no-op patch)
    e1-terse-goal.md               # Section 2 replacement text
    e1-dropped-goal.md             # Section 2 = delete + renumber
    e2-current-spec.md             # baseline marker (no-op patch)
    e2-explicit-axes.md            # preamble append text
    e2-freeform-rule.md            # preamble append text
  harness.py                       # variant + fixture + seed → story + grade
  runs/
    stage1a-e1/{variant}/{seed}/   # story.md, grade.json, raw harness output
    stage1b-e2/{variant}/{seed}/
    stage2/{variant}/{fixture}/{seed}/
  results/
    stage1a-grades.md              # tabulation + eyeball notes + decision
    stage1b-grades.md
    stage2-grades.md
```

## Pending follow-on (not in this experiment)

- **Judge independence + resolution rules** — co-required for the
  judge-of-pipeline to stop fouling on the kinds of stories these
  variants produce. Tested in a separate experiment, end-to-end,
  with the E1 + E2 winners pinned.
- **Outcome-tile demotion** — visualizer change from the recap;
  ships independently.
- **Final-pass judge with malicious read** — recap §"Separately
  flagged for future."
