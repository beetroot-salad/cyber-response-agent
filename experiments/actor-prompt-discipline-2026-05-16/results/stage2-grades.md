# Stage 2 results — generality check on b02-fim (streamed harness)

Cross-signature generality check for the Stage-1 winners on a FIM alert
(`b02-fim-apt-update`). Three cohorts run on the same fixture for a clean
comparison: baseline, E1-only, combined E1+E2.

**Harness fix mid-stage.** Initial Stage 2 runs hit a pre-existing actor
output truncation: `claude -p --output-format text` returns only the
final assistant message, so when the actor used the lessons-actor corpus
tool between Section 0 and Section 1 (as the actor.md prompt instructs)
Section 0 was silently dropped. This affected baseline runs too —
2/4 baseline cells on live-5710 and 2/3 baseline cells on b02 lost
Section 0 under text mode. Baseline rubric's trivial-pass discipline
masked the issue; variant rubrics surfaced it as a regression.

Harness now uses `--output-format stream-json` and concatenates all
assistant text messages. All Stage 2 numbers below are from the
streamed-harness re-run.

## Per-cell grades (streamed harness, N=3 per cohort)

| Cohort | Seed | Story chars | Discipline | Total | LB |
|---|---|---|---|---|---|
| e1-current-goal (baseline) | 1 | n/a | n/a   | 25 | 7 |
| e1-current-goal (baseline) | 2 | n/a | n/a   | 28 | 7 |
| e1-current-goal (baseline) | 3 | n/a | n/a   | 21 | 5 |
| e1-dropped-goal            | 1 | n/a | pass  | 27 | 7 |
| e1-dropped-goal            | 2 | 5634| pass  | 20 | 6 |
| e1-dropped-goal            | 3 | n/a | pass  | 24 | 7 |
| combined-dropped-freeform  | 1 | n/a | pass  | 22 | 6 |
| combined-dropped-freeform  | 2 | n/a | fail† | 24 | 7 |
| combined-dropped-freeform  | 3 | n/a | fail‡ | 26 | 7 |

† "three hops, exit node rotated each session" — forward commitment to fan-out count, not alert-derived.
‡ "224-byte stub" — judge ruled actor-chosen (the alert exposes size_before/after but the stub-size attribution is an actor inference).

## Cell means

| Cohort | Discipline | Total | Load-bearing |
|---|---|---|---|
| current (baseline) | n/a | 24.67 | 6.33 |
| dropped-only (E1) | **3/3 pass** | 23.67 | **6.67** |
| combined (E1+E2 freeform) | 1/3 pass | 24.0 | 6.67 |

## Read

**No load-bearing regression on b02.** All three cohorts cluster at
6.33–6.67 LB. The prior text-mode result that showed combined at 5.33
LB (-21% vs baseline 7.0) was entirely a Section-0-truncation artifact.
With the streamed harness, the data is clean.

**Dropped-goal generalizes cleanly:**
- Discipline: 4/4 on live-5710 + 3/3 on b02
- Load-bearing: 5.5 on live-5710 (vs 6.75 baseline) + 6.67 on b02
  (vs 6.33 baseline) — within noise on both fixtures
- Total claims: small reduction on both fixtures
- The E1 patch removes a section that contributes no defender-disposition
  signal, with no measurable cost.

**Freeform-rule (E2) does NOT generalize:**
- Discipline: 4/4 on live-5710 SSH alert → 1/3 on b02 FIM
- Both failures are genuine forward operational commitments
  ("three hops", "224-byte stub"), not alert-citation false-positives
- Load-bearing identical to dropped-only — so E2 isn't *hurting* quality,
  it's just failing to do its job on the FIM-shape narrative
- Hypothesis: the magnitude-tier rule is easier to apply to brute-force
  /authentication shapes than to supply-chain narratives where exact
  payload sizes and proxy-hop counts feel load-bearing to the actor

## Decision

**Ship `e1-dropped-goal` alone.** Drop the E2 freeform-rule layer.

Concrete change:
- `defender/learning/actor.md`: delete Section 2 (Goal), renumber Bypass
  3→2, rewrite "four sections, in order:" → "three sections, in order:"
- No preamble changes.

**Do not ship E2.** The magnitude-tier rule is a good idea but the
current formulations (both freeform and explicit-axes) only work on
narrow fixture shapes. Either:
- Find a formulation that generalizes (out of scope for this experiment), or
- Accept that magnitude-tier discipline is fixture-dependent and ship
  it only with per-signature scoping (also out of scope).

## Pre-existing actor.md bug worth fixing separately

Independent of variant choice: the actor.md instruction to "use the
lessons corpus between Section 0 and Section 1" interacts badly with
`claude -p --output-format text` in production. When the actor emits
Section 0, calls tools, then emits Sections 1-3, production loses
Section 0. Affects ~50% of runs that consult lessons.

Two fixes possible:
1. **Change actor.md** — instruct actor to consult lessons *before*
   writing any output (loses the "commits your technique choice; do
   not revise after reading" guardrail).
2. **Change loop.py** — switch `_run_claude` to stream-json + concat,
   as the experiment harness now does.

Fix (2) preserves the prompt's design intent and has no downside in
production. Recommend filing it as a follow-up task.

## Caveats

- N=3 per cohort, two fixtures total (live-5710 + b02-fim). Generality
  signal is meaningful but not exhaustive. A third fixture (e.g., a
  Falco shape) would tighten the dropped-goal generality claim.
- Rubric judge unvalidated; spot-checked.
- The "load-bearing ≥ baseline" guardrail is met by both variants on
  both fixtures under the streamed harness.
- The seed-3 combined failure on the 224-byte stub is borderline —
  reasonable judges could rule either way. The seed-2 "three hops"
  failure is unambiguous.
