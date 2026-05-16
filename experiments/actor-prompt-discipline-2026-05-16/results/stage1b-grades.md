# Stage 1b results — E2 spec-granularity on live-5710 (N=4 per variant)

E2 variants compose on top of the Stage-1a winner (`e1-dropped-goal`).
The `e2-current-spec` cell is the dropped-goal baseline with no E2 patch
— that's the comparison floor for this stage.

**Note:** original grades were re-run after a rubric clarification (see
§Rubric clarification below). Numbers below are from the re-graded pass.
Per-cell grade.json files contain the re-graded data.

## Per-cell grades (re-graded, alert-datum-tolerant rubric)

| Variant | Seed | Story chars | Discipline | Total | Load-bearing |
|---|---|---|---|---|---|
| e2-current-spec   | 1 | 5522 | n/a  | 28 | 6 |
| e2-current-spec   | 2 | 5340 | n/a  | 20 | 5 |
| e2-current-spec   | 3 | 5626 | n/a  | 26 | 5 |
| e2-current-spec   | 4 | 5540 | n/a  | 36 | 7 |
| e2-explicit-axes  | 1 | 3689 | pass | 20 | 5 |
| e2-explicit-axes  | 2 | 3053 | pass | 17 | 6 |
| e2-explicit-axes  | 3 | 4359 | pass | 19 | 6 |
| e2-explicit-axes  | 4 | 8670 | pass | 39 | 8 |
| e2-freeform-rule  | 1 | 5782 | pass | 28 | 8 |
| e2-freeform-rule  | 2 | 6395 | pass | 24 | 7 |
| e2-freeform-rule  | 3 | 3884 | pass | 22 | 5 |
| e2-freeform-rule  | 4 | 5080 | pass | 27 | 7 |

## Cell means

| Variant | Story chars | Discipline | Total | Load-bearing |
|---|---|---|---|---|
| e2-current-spec (baseline) | 5507 | n/a | 27.5 | 5.75 |
| e2-explicit-axes  | 4942 | 4/4 | 23.75 | 6.25 |
| e2-freeform-rule  | 5285 | 4/4 | **25.25** | **6.75** |

## Rubric clarification

Original rubric: "Specific values (e.g., 'every 70 seconds', '3 hosts')
are forbidden — they invite refutation on cosmetic detail rather than
load-bearing axes."

Original grading flagged 5 cells (across both variants) for citing the
alert's `firedtimes: 9` as "nine attempts" in the story. This is
**backward citation of observed datum**, not forward operational
commitment, and shouldn't count as a discipline violation.

Rubric updated to add the explicit exemption:

> Citing a quantity that already appears in the input alert (e.g., the
> alert's `firedtimes: 9` rendered as "nine attempts" or "9 firings")
> is NOT a violation — it's backward citation of observed fact, not a
> forward commitment.

All 12 stage-1b cells re-graded under the clarified rubric.

## Read

Under the clarified rubric:
- **Both variants achieve 4/4 discipline.** The terse Section 2 from
  Stage 1a and the magnitude-tier rule from this stage both stick.
- **Both variants meet or exceed baseline on load-bearing.**
  explicit-axes +0.5 (6.25 vs 5.75); freeform-rule +1.0 (6.75 vs 5.75).
- **Both modestly reduce total claims** (23.75 and 25.25 vs 27.5).

Freeform-rule beats explicit-axes on load-bearing (6.75 vs 6.25) and is
closer to baseline on total. Discipline tied at 4/4. Per the plan's
tie-break rule, **simpler prompt wins → freeform-rule**.

## Decision

**Recommend `e2-freeform-rule`** as the E2 winner, layered on top of
`e1-dropped-goal`. Combined prompt for Stage 2 generality testing:
- Section 2 (Goal) deleted, Bypass renumbered to Section 2
- Three-section format
- Magnitude-tier rule appended to the preamble's first paragraph
- No enumerated axes — trusts the actor to apply the rule

Combined variant identifier: `combined-dropped-freeform`. See
`harness.py:patched_actor_md` for the composition logic.

## Caveats (carry-over from Stage 1a)

- N=4, one fixture. All numbers within single-seed noise.
- Rubric judge unvalidated; re-grade pass eyeball-checked.
- The "load-bearing ≥ baseline" guardrail is met by both variants
  under the clarified rubric (was technically failed under the strict
  original rubric).

## What's next

Stage 2: combined variant on `b02-fim-apt-update` (FIM, non-SSH) with
N=3 — confirms the combined prompt generalizes beyond the single
fixture used for picking it.
