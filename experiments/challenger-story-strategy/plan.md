# Challenger story-generation strategy — A/B

Context: issue #774's write-time challenge gate. The challenger writes a counter-disposition
story from the investigation + the executed leads + the real payloads. How it composes that
story is unsettled. Runnable now as a bare prompt harness — it needs no part of PR 1.

## Question

**Engineering** — when composing a counter-disposition story from a completed investigation, does
refining one draft (loosely, or through per-lead lenses) beat composing it in one shot, and at
what cost?

## Variants

There is no incumbent — the whitebox challenger does not exist. **`one-shot` is the regression
validator**: the simplest thing that could work, and the arm both proposals must beat to justify
their extra calls.

### `one-shot` (baseline / regression)

```
Inputs: investigation.md, the joined lead+query table, every gather_raw payload,
        the draft disposition.
One call. Compose the counter-disposition story. Emit the story plus a structured
tail: the list of load-bearing claims, each as (entity, field, asserted value,
which lead would show it).
```

### `iterative-loose`

```
Same inputs. Call 1 composes a rough story — mechanism class only, no entity
binding. Calls 2..N each receive the current story plus ALL inputs and are asked
to sharpen it one level: mechanism class -> entities -> timing -> field values.
Coarse-to-fine, N fixed at 4. Same structured tail at the end.
```

### `per-lead-lens`

```
Same inputs. Call 1 composes a rough story as above. Then one call PER EXECUTED
LEAD, in parallel, each seeing the rough story and only that lead's payload,
asked: what does this lead force the story to change, add, or concede? A final
call folds the lens outputs into one story + structured tail.
Cost: 2 + L calls, L = executed leads (6-22 on the fixtures below).
```

The single variable is composition strategy. Inputs, model, and output schema are identical
across arms.

## Fixtures

The pool is the 21 complete run dirs under `/tmp/defender-runs/` — those with
`investigation.md`, `report.md`, and a non-empty `gather_raw`.

**The pool is badly skewed, and it bounds what this experiment can answer.** The gate skips
`inconclusive`, leaving 14 eligible runs: **13 malicious, 1 benign.** So the FP-hunt direction
(argue benign against a malicious call) has 13 fixtures and the FN-hunt direction has **one**.
That is not sampling noise — these are oracle-golden-set captures of attacks, malicious by
construction, and the environment has not produced benign captures at this volume. Held-out
recruitment, which would fix this, has not landed (`fixtures/held-out/` holds only a README).

**Decision this forces:** either accept that the experiment measures the FP-hunt direction and
say so in the result, or recruit benign runs first. Recommending the former — the strategy
question is about composition, which is direction-agnostic — with the caveat recorded.

Validation set (3, spanning payload volume and alert class):

- `golden-case-018-squid-egress-officews1` — 22 payloads, **the only `benign`**; the sole
  FN-direction fixture, and the one whose result cannot be replicated.
- `golden-case-005-cross-tier-probe-db1-2` — 22 payloads, malicious; the widest lead set, where
  `per-lead-lens` pays its highest call cost.
- `golden-case-014-authkeys-db1` — 6 payloads, malicious; the narrow end, where the lens arm has
  least to work with and one-shot should be hardest to beat.

Scale-up set: the remaining 11 eligible runs. `golden-case-013-crosstier-web1-2` is excluded —
it has a report but zero payloads, so there is nothing for a whitebox challenger to read.

## Trials

Validation: 1 trial per variant per validation fixture (3 arms x 3 fixtures = 9).

Scale-up: N=3 trials per variant per fixture over all 14 eligible (126 stories). Stories are
stochastic and the primary metric is a mean over survivors, so a single trial per cell cannot
separate the arms.

Mid-run analysis at 36 stories (~29%). `analyze.py` is written before scale-up launches.

## Metrics

**The trap: every cheap metric rewards vagueness.** A vague story survives the oracle comparison
more easily (nothing specific to refute) and produces more silent rows (it turns on dimensions
nothing measured). Survival alone and discriminator-yield alone both rank the worst story first.

So the primary metric is joint:

- **commitment** — count of load-bearing claims in the structured tail that name an entity, a
  field, and an asserted value. Countable, and the tail is needed for the oracle anyway.
- **survival** — the oracle comparison over executed leads returns no refutation.
- **Primary: mean commitment among surviving stories**, with survival rate as support `n`.
  Ranked per-occurrence, not count-weighted.

Guards, reported alongside:

- **critic pass rate** — coherence. An arm that wins on commitment while writing incoherent
  stories has not won.
- **calls per surviving story** — `per-lead-lens` costs 2+L where one-shot costs 1. On the
  22-payload fixtures that is a 24x call ratio, and it has to buy something.
- **silent-row yield** — reported, never optimized. It is the gate's output, but it is exactly
  the number vagueness inflates.

## Decision criteria

- **`per-lead-lens` or `iterative-loose` wins** if mean commitment among survivors exceeds
  `one-shot` by ≥25% with no drop in critic pass rate, and cost per surviving story is within
  3x. A large win at 24x cost is not a win at write time.
- **`one-shot` retained** if the refinement arms produce equal or lower commitment among
  survivors, or if their gain is confined to fixtures with the widest lead sets (i.e. it is
  buying breadth of input, not a better composition strategy — testable against the 6-payload
  fixture).
- **Abort at mid-run** if survival rate is near 100% or near 0% across all arms. Either means the
  oracle comparison is not discriminating and the harness, not the strategy, is what is being
  measured.

## Open risk

The oracle comparison used to score survival is the same mechanism issue #774 is redesigning. If
it is miscalibrated, all three arms are scored by a broken ruler and the comparison between them
is still valid while the absolute survival rates are not. Read the arms against each other, never
the survival rate on its own.

## Layout

```
experiments/challenger-story-strategy/
  plan.md          # this file
  variants/        # the three prompt files
  fixtures/        # pointers into /tmp/defender-runs (not copies)
  runs/            # per-trial story + tail + oracle/critic outputs
  analyze.py       # written before scale-up
  results/         # mid-run + final
```
