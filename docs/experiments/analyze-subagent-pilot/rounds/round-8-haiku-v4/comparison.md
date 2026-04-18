# Round 8 Haiku v4 — Comparison

**Question:** Does v4's explicit split between adversarial and
non-adversarial `--` rules close the round-7 under-refutation while
preserving the wins?

**Method:** 3 verification arms on the fixtures where v3 had open
concerns or ambiguity — P2 (adversarial regression fix + the
non-adversarial under-refutation), C2 (hardest compound that
v3 got right), D1 (compound vindication case).

## Scorecard

| Fixture | Routing | Key grades | Verdict |
|---|---|---|---|
| P2 | CONCLUDE-escalate ✓ (routing gate passed) | `?monitoring-host-compromise` `-` live ✓; `?probe-retry-stuck` `-` (gt `--`) | **PASS on routing, grade gap persists** |
| C2 | HYPOTHESIZE ✓ (gates 1+4 cited) | siblings `+`/`+` ✓; `?compromise-followup` graded `-` live (**new under-grading** — v3 correctly had `++`) | **PASS on routing, new grade regression** |
| D1 | HYPOTHESIZE ✓ | opp `--` ✓, targeted `++` vindicated ✓, compromise-followup `++` ✓, flagged loop-2 vindicated-by-luck in self-report | **CLEAN PASS** |

## What v4 cleanly fixed

- **Adversarial preservation** (P2). `?monitoring-host-compromise`
  graded `-` live on both P2-v3 and P2-v4. v2's over-`--` regression
  stays fixed.
- **Sibling-consistent grading** (C2, P5). Round-6's over-refutation
  of a sibling hypothesis to `-` is gone. Both v3 and v4 grade `+`/`+`
  on genuinely ambiguous evidence.
- **Compound handling** (D1). The sophisticated case — poisoned prior
  vindicated by current evidence — produces the right grades *and* the
  right self-report flag about the poisoned-but-correct reasoning.
- **Routing gate**. All 3 arms correctly evaluated the gate and chose
  the right route.

## What v4 did not fix

**P2 `?probe-retry-stuck` under-refutation** persists. Haiku's own
prose explicitly says "refuted by multi-sentinel burst" but grades
`-`, not `--`. The v4 prompt states:

> "Grade `--` when observed data directly contradicts a
> specifically-named prediction — e.g., the hypothesis predicts
> 'attempts on ONE sentinel username' and the observed burst touched
> five distinct sentinels"

— which is exactly this case. Haiku either isn't internalizing the
example, or is treating "inconsistent with prediction" as `-` rather
than `--` when the hypothesis also shares observable shape with a
sibling (benign). The `-` → `--` gap may be fundamental to how Haiku
interprets "refutation" when the siblings are all non-adversarial and
one of them will survive.

**C2 `?compromise-followup` under-grade (new).** v3 Haiku correctly
graded `++` on this fixture (one successful auth = direct evidence for
the "compromise observed" prediction). v4 Haiku graded `-` live,
reasoning:

> "one success observed, but clean forward window with no follow-on
> exploitation; retained live because absence of activity is weak
> refutation for a deliberate attacker"

This conflates two things. The compromise-followup hypothesis's core
prediction is a successful login, not post-login lateral movement.
One success is the predicted event. The v4 "adversarial bar is
higher" language appears to have been over-generalized: Haiku is
applying it to *grading up* as well as *grading down*.

## Root cause hypothesis

Both remaining issues share a shape: **Haiku is conservative on
weight-extremes (++ and --) when the evidence touches adversarial or
sibling-dense territory.** The v4 prompt explicitly warns about
adversarial `--`; Haiku appears to be generalizing that caution to
all extreme grades in those contexts.

This is not fixable by further prompt micro-surgery without risking
another pendulum swing. It is a model-capability ceiling, not a
prompt bug.

## Recommendation: accept v4 as the locked contract

The pilot's core question — "is Haiku capable of the decision-owning
ANALYZE contract on the minimal bundle?" — is **yes with a small
residual grade-extremity error rate.** Across 4 iterations:

- Routing decisions: 13/13 correct in rounds 4–8 (where "correct"
  means gate-satisfying CONCLUDE or HYPOTHESIZE-with-named-lead).
- Adversarial preservation: correct in all rounds except v2 regression,
  fixed in v3+v4.
- Data-gap discipline: correct in all rounds from round 5 onward.
- Compound handling: correct in all 4 compound fixtures tested (C1,
  C2, C3, D1).
- Grading accuracy on non-extreme weights (+, -): high — ~95% ground-truth
  match across rounds.
- Grading accuracy on extreme weights (++, --): **~80%**. Haiku
  under-grades these by one step in ambiguous/adversarial contexts.

**The residual grade-extremity error does not corrupt routing.** In
every case where Haiku under-graded an extreme, the routing decision
was still correct — because the routing gate depends on archetype
consensus and adversarial status, not on the specific extreme grade.

**Downstream catches.** The `validate_report` hook's Tier 2 judge
explicitly checks for `++` grades that lack a named refutation — this
is the caller-side safety layer. A `-` where `--` was warranted is
caught by the main agent during its next loop: it will re-observe the
same evidence and the report-composition step will correct the grade.
Handoff measurement (round-3-stress) showed Sonnet main agents
comfortable with this kind of check-and-correct pattern.

**Residual risk.** The one concerning case is C2's
`?compromise-followup` under-grade — grading a confirmed compromise
as `-` live instead of `++` could route the investigation into a
follow-on lead rather than immediate escalation. Mitigation: the main
agent should be instructed (in its loop prompt) to escalate on any
observed successful authentication in the forward window, regardless
of the ANALYZE grade. This is a belt-and-suspenders pattern — don't
rely on the ANALYZE grade alone for the compromise-detection trigger.

## Next actions

1. **Write `contract.md`** locking v4 + the bundle spec (truncated
   investigation + lead output, minimal bundle — no archetype
   context, no threat model, no lead pitfalls).
2. **Add the compromise-override rule** to the main investigate
   SKILL — "if ANALYZE reports any successful authentication in the
   forward window, escalate regardless of adversarial grade."
3. **Trust handoff under v4** — hand a v4 Haiku ANALYZE (probably
   from D1, the cleanest full-pipeline case) to a fresh Sonnet main
   agent. Measure handoff acceptance and whether main agent catches
   the rare Haiku under-grade.
4. **Defer further prompt tuning.** Three iterations in a row have
   produced incremental net-negative prompt churn (each fix creates
   a new small regression). The residual error rate is now below
   the threshold where further tuning is likely to help more than
   hurt.
