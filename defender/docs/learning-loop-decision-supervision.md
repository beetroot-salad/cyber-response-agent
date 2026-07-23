# Learning-loop decision supervision — architecture (2026-07-23)

Companion to `defender/docs/learning-loop.md` and issue #696. This doc
recasts #696's reference-defender proposal as a pipeline architecture.
It keeps the issue's fork boundary, contrast set, and finding classes,
but relocates the intelligence: the discriminating structure is emitted
as *data* by scenario generation, and every downstream phase — reference
defender, judge, curator — consumes that structure instead of
re-deriving it by open-ended reasoning.

Status: **architecture proposal.** Nothing here is implemented. When
this doc and #696 disagree on mechanism, this doc is the intended
direction; when it disagrees on scope or dependencies, the issue wins.

## The invariant this loop is built on

The learning pipeline exists to make error detection in the defender
systematic. The design invariant, stated once: **each phase's output is
the coordinate system in which the next phase's job is trivial.** A
phase discharges its obligation not by being smart but by leaving the
next phase a comparison instead of an investigation.

Today the invariant holds at some seams and not others:

- **oracle → judge**: holds. The oracle emits per-lead signed diffs
  over baseline; the judge's coverage comparison is a per-lead join of
  projection against actuals.
- **judge → curator**: holds. Findings arrive typed
  (`lead-set | lead-quality | analyze-discipline | observability`),
  anchored, and cited; the curator's new/fold/skip decision reads them
  directly from the pending queue.
- **actor → oracle**: partial. One freeform story per case; the oracle
  can project it, but nothing downstream can compare *against* it —
  there is no structure describing which facts of the story are
  load-bearing.
- **inside the judge**: does not hold. Root-causing *why* the defender
  missed something is open-ended causal inference over freeform traces
  — the one uncalibrated free-reasoning step left in the loop, and the
  step #692 exists to distrust.

#696 attacks the judge seam by giving the judge a second decision path
to compare against (a scenario-aware reference defender forked at the
GATHER boundary). That is the right instinct — comparison beats
speculation — but as drafted the comparison objects are still two prose
traces plus two calls, so the judge's job stays inferential. The
architecture below finishes the move.

## The failure taxonomy is a factorization, not a checklist

#696's six divergence classes are, read in order, a pipeline model of
what PLAN *is*:

1. **World enumeration** — hypothesize the live worlds compatible with
   the evidence.
2. **Prediction** — per world, the observables that would differ if it
   were true.
3. **Discrimination** — the measurements that separate live worlds.
4. **Allocation** — ranking of measurements under remaining budget.
5. **Dispatch** — compilation of the winner into a gather contract
   (`system` / `goal` / `what_to_summarize`).
6. **Posterior maintenance** — ANALYZE's update of the live-world set
   from prior results, feeding rung 1 of the next iteration.

Each rung's output is a function of the previous rung's output plus the
shared pre-fork state. That gives the taxonomy its completeness: any
wrong gather call must first diverge from a correct decision path at
*some* rung, so "earliest causally sufficient divergence" is
well-defined — provided both paths' rung outputs are explicit and
aligned. The existing finding classes are the projection of the ladder
onto curatable categories and do not change:

| earliest divergent rung | finding class |
|---|---|
| 1 (world missing) | `lead-set` |
| 2–3 (world present, wrong observable / unseparated pair) | `lead-set` or `lead-quality` per the issue's mapping |
| 4 (separator known, weaker allocation) | `analyze-discipline` |
| 5 (intent right, contract can't retrieve) | `lead-quality` |
| 6 (frontier corrupted upstream) | `analyze-discipline` |
| no reachable separator exists at any rung | `observability` |

The architectural consequence: **don't hand the judge the six rungs as
questions to reason about; hand it both sides' rung outputs in the same
coordinates, so each rung is a diff and the finding is the first
mismatch.**

## The coordinate system: the contrast set as answer key

The coordinates are the worlds of the contrast set itself. Every rung
output, on both the source and reference side, is expressible in them:

- a **hypothesis** is a world-coverage claim — which worlds it spans;
- a **prediction** is a per-world observable delta — what differs, on
  which telemetry surface, if that world is true;
- a **lead** is a row of the **discriminator matrix**:
  `measurement × world → expected observable`, where "discriminates"
  means the row's values differ across live worlds. The benign control
  world is just another column — escalation-without-discrimination
  shows up as a constant row against it.

The load-bearing observation, and the reason the matrix can be data
rather than reasoning: **single-axis causal perturbations carry their
own answer key.** When world B is the fork-blind anchor mutated only on
credential provenance, the discriminating observable between A and B is
known *at generation time* — it is the mutation axis plus its expected
telemetry delta. #696 already stores `expected telemetry surfaces` on
historical scenario records; this architecture makes that field
mandatory for every world (fresh, mutated, historical, benign-control)
and makes the matrix the primary deliverable of scenario generation.
The oracle then validates and grounds each cell by projection — its
existing per-lead job, pointed at matrix cells instead of only at the
source's executed leads.

Everything downstream inherits triviality from this one move.

## Pipeline

```
completed run
     │
     ▼
[1] fork capture ──── pre-GATHER boundary state (frozen)
     │
     ▼
[2] scenario generation ── world set + discriminator matrix (data)
     │
     ▼
[3] oracle grounding ───── validated matrix cells;
     │                     per-world projection of BOTH calls
     ▼
[4] reference selection ── chosen matrix row; dummy call as witness
     │
     ▼
[5] judge ──────────────── parse source ladder → align → first
     │                     mismatch → minimal repair → typed finding
     ▼
[6] curator (unchanged) ── generalize the matrix row into a lesson
```

### [1] Fork capture

Freeze the source defender's state at the GATHER boundary: full
pre-fork session, the committed `:H`/`:L` plan, and the actual gather
call — the *whole* assistant turn, since sibling gather calls in one
response are the atomic decision unit. Nothing after the boundary (no
gather results, no post-fork reasoning, no report/disposition) crosses
into the fork or the judge. Remaining-budget figures are recorded as
judge metadata; the fork itself runs on an isolated budget. Mechanism
(session reconstruction, salt persistence, budget portability) is
deliberately out of scope here — see #696's fork-boundary section.

### [2] Scenario generation — deliverable is the matrix

Per learning run, the contrast set of #696's converged direction: one
fresh fork-blind anchor, two-to-three single-axis causal perturbations,
one re-grounded historical world, one benign/routine control world,
each tagged with provenance
(`fresh_blind | mutation | historical | adaptive_gray_box`). Unchanged
from the issue — except the output contract. The generator must emit,
alongside the worlds:

- per world: the expected observable deltas (surface, direction,
  rough shape), i.e. rung-2 ground truth;
- per world pair that the set is meant to separate: the mutation axis
  and the measurement(s) whose expected values differ, i.e. the
  discriminator matrix.

For mutations this is nearly free — the axis *is* the perturbation the
generator chose. Mutation validation gains a mechanical criterion:
retain a mutation only if it changes at least one matrix cell. Worlds
carry a plausibility stratum (how strongly the pre-fork visible facts
support them), consumed at rung 4 and by chargeability (below).
`adaptive_gray_box` worlds may enter the set for gap discovery but are
excluded from unbiased detection-quality estimates, as in the issue.

### [3] Oracle grounding

The oracle projects, per world: (a) each matrix cell the generator
claimed, confirming the expected delta actually manifests in that
world's telemetry; (b) the **source's actual call** and (c) the
**reference's candidate rows**, under its existing four-mode discipline
(distinguishable `+` / additive noise `+` / suppression `−` /
untouched `0`). No gather executes; projection replaces execution
everywhere. This is what turns two previously unfalsifiable judgments
into lookups: "the reference call is materially more discriminating"
and "the source's contract would not have retrieved the discriminator"
are both reads of projected cells, not opinions about a trace.

The cost of this honesty: the oracle is now load-bearing for the reward
signal itself, not only for coverage comparison. #693 (oracle
calibration, trust, abstention) is a hard prerequisite, harder than
#696 states. An uncalibrated oracle slice means the matrix cells it
grounded are untrusted and the fork maps to no-update.

### [4] Reference selection — the teacher demoted to a selector

Given the frozen state, the vocabulary of reachable measurements, and
the grounded matrix, the reference defender's job is **selection**:
pick the reachable row (or minimal row set) that separates the live
worlds within remaining budget. Its public output is unchanged from
#696 — one dummy gather call, statically validated, never executed —
but the call is now a *witness* of the selected row, not the primary
comparison object. This makes the reference auditable in a way no
freeform teacher policy can be: whether it selected a maximal reachable
row against the matrix is checkable after the fact.

A second, scenario-blind reference fork — same frozen state, no world
set — runs as the chargeability baseline (see Residual judgment). Its
cadence (always-on vs sampled) is an open question.

### [5] Judge — a differ with three small judgments at its edges

Judge inputs: the frozen pre-fork state; both calls; both traces; the
world set **itself** (not only provenance — an enumeration gap in
#696's input list); the grounded matrix with per-cell oracle trust; the
blind-baseline's output when present; remaining-budget metadata.

The judge's mechanical core:

1. **Parse** the source's rung outputs from its trace — the invlang
   `:H`/`:L` discipline already emits most of the ladder natively.
2. **Align** source hypotheses to worlds (bipartite matching with
   abstention).
3. **Walk** the rungs, source against matrix, and report the first
   material mismatch.
4. **Minimal repair** as a matrix operation: substitute the reference's
   output at the divergent rung only; if a covering row does not then
   get selected, the claimed cause is a symptom — walk on.
5. Emit the finding in the existing typed shape (class, anchors,
   citations into both traces, both calls, the divergent rung, the
   matrix row, provenance and conditionality), or abstain
   (`no-update`) when the matrix is untrusted, the reference row is
   unreachable or hindsight-only, or alignment fails.

Every finding is **conditional on the world-set version**: a "missing
hypothesis" is missing relative to the worlds someone constructed. The
finding carries the set's version/hash so a later audit of a bad
contrast set can invalidate its downstream lessons.

What this narrows honestly: the judge answers "at this boundary, was
the chosen lead weaker than a grounded teacher's selection, and at
which rung did the paths first diverge" — one-step decision
supervision. It does not answer #696's stated target question ("would
the source have caught the attacker within its investigation budget"),
which is a property of a whole trajectory this design deliberately
truncates on both paths. The detection-quality metric is one-step lead
coverage of the world set, declared as a proxy. Rung-6 findings carry
reduced confidence by construction: their repair lies before the fork,
where this mechanism can diagnose but never validate.

### [6] Curator — unchanged contract, aligned semantics

The curator's input contract does not change: typed findings from the
pending queue, gated by the same-case forward-check (`verify_forward`,
not renamed or overloaded) and, when it lands, cross-case verification
(#397). What changes is that the generalization axis now arrives *in*
the finding: a lesson is a discriminator-matrix row abstracted over its
mutation axis. #696's own exemplar — "when account identity is
dual-consistent with authorized and stolen-credential use, route to
process/session provenance before clearing" — is literally a matrix row
read aloud: two worlds differing on one axis, plus the surface that
separates them. That the issue's best lesson example is already in
these coordinates is the strongest evidence they are the natural ones.

## Residual judgment — the honest ledger

Three judgments survive mechanization. They are the *right* residue:
each is small, local, and calibratable, unlike open-ended root-causing.
#692's calibration program should be recast to target exactly these.

1. **Parse and alignment** (judge steps 1–2). Extracting rung outputs
   from freeform invlang and matching hypotheses to worlds. Shrinkable
   at the source: a modest strengthening of the invlang contract —
   leads name which hypotheses they separate as structure, not prose —
   lets the defender emit its own ladder, applying the same invariant
   to the runtime phase itself. How far to push that is an open
   question (it trades prompt burden against parse ambiguity).
2. **Semantic call equivalence** (rung 5). Whether the source's
   contract retrieves the same discriminator as the reference's row —
   grounded by the dual oracle projection in [3]; the judgment left is
   reading two projected cells, not imagining gather behavior.
3. **Chargeability** (rung 1). Every world in the set is
   alert-compatible by construction, but compatible ≠ worth a
   hypothesis slot under a sane prior. The scenario-blind baseline
   factors it: source-vs-blind gap is chargeable decision error;
   blind-vs-aware gap is the value of hidden knowledge — an
   observability/coverage fact, not a defender failure. Without the
   baseline, rung-1 findings systematically overcharge the defender
   for hindsight-only hypotheses.

## What the architecture buys

- **Systematic error detection.** The judge's finding is the first
  mismatch in an aligned walk — reproducible, explainable, and
  falsifiable in a way "the judge reasons about six questions" is not.
- **Hindsight bias handled structurally**, not by prompt admonition:
  reachability is a static check, discrimination is a grounded lookup,
  chargeability is a measured gap against a blind baseline. The
  no-update paths are explicit states, not judge restraint.
- **Calibration becomes tractable.** #692 no longer has to calibrate
  open causal inference; it calibrates a parser/matcher, an
  equivalence read over projected cells, and an abstention discipline.
- **The curator seam strengthens.** Lessons arrive with their
  generalization axis attached, so "generalize the decision gap, don't
  copy the call" stops being an instruction and starts being the shape
  of the input.

## Boundaries and non-goals

- **No gather executes anywhere in the fork.** Projection is the only
  telemetry source. (#696's Open Question 1: resolved — the validation
  standard is grounded matrix cells, not execution.)
- **One-step supervision only.** No post-fork trajectory simulation,
  no full-rerun comparison in the core loop. Full ORIENT reruns answer
  a different (policy-level) question; if wanted, they are a separate,
  sampled calibration instrument, per #696's hybrid leaning.
- **Existing gates unchanged.** `verify_forward` remains the same-case
  candidate-lesson gate; cross-case verification remains #397; lesson
  attribution/scoring remains #695. This loop produces findings, not
  promotions.
- **Scenario-set relativity accepted.** The judge never evaluates
  whether the world set is representative; that is scenario
  generation's obligation, discharged by validation and provenance,
  and findings stay conditional on the set version.

## Open questions

1. **Boundary selection.** A run can have dozens of GATHER boundaries;
   forking all of them multiplies cost by an order of magnitude. First
   boundary, widest-frontier boundary, or sampled — undecided, and the
   dominant cost knob.
2. **Blind-baseline cadence.** Always-on doubles reference cost;
   sampled leaves chargeability estimated rather than measured per
   finding.
3. **Plausibility strata.** How world priors are assigned and whether
   rung-4 divergence should be judged against budget-weighted rather
   than uniform coverage.
4. **Invlang strengthening.** How much ladder structure to demand from
   the runtime defender natively versus recover by parsing.

## Dependencies

- **#693 — oracle calibration**: promoted from dependency to
  prerequisite; matrix grounding makes the oracle the reward signal's
  foundation, and uncalibrated slices must map to no-update.
- **#692 — judge calibration**: recast onto the three residual
  judgments above.
- **#397 — cross-case verification** and **#695 — lesson
  attribution/scoring**: unchanged, downstream.
- **#696**: this doc proposes amending the issue's judge and
  scenario-generation contracts (matrix as deliverable, world set in
  judge inputs, witness-call framing, narrowed target question,
  blind baseline) while keeping its fork boundary, contrast-set
  composition, provenance taxonomy, and finding classes as-is.
