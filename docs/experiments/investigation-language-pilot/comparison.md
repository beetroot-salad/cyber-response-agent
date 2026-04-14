# Pilot Comparison — A.1 shell-in-container

Inputs: `alert.json`, `spec-condensed.md`, `retrieval-sim.yaml` (identical for
all four arms). Artifacts: `reference.md` (Sonnet, with commentary),
`haiku-1.yaml`, `haiku-2.yaml`, `haiku-3.yaml` (three independent Haiku runs,
no cross-context).

The goal is qualitative: **where does writing the companion break down, and
are Haiku's breakdowns bloat or systematic?**

---

## 1. Structural comparison at a glance

| Dimension                          | Reference (Sonnet)                           | Haiku-1                           | Haiku-2                             | Haiku-3                              |
|------------------------------------|----------------------------------------------|-----------------------------------|-------------------------------------|--------------------------------------|
| Vertices                           | 6 (no host; dropped intentionally)           | 6 (kept host, dangling)           | 6 (kept host, linked via bad edge)  | 5 (kept host dangling, **no user**)  |
| Edges                              | 5                                            | 4                                 | 5                                   | 4                                    |
| Hypotheses                         | 7 (4 initial + 3 relocated)                  | 4 (no relocation)                 | 4 (no relocation)                   | 3 (**dropped ?ci-pipeline seed**)    |
| Leads                              | 2 (scope + trust, distinct)                  | 2 (scope + trust)                 | 2 (scope labeled, conflated inside) | **1** (scope conflates both)         |
| Relocation performed?              | ✓                                            | ✗                                 | ✗                                   | ✗                                    |
| Catalog violation                  | 1 (triggered_by → session, flagged)          | predictions-shape notation drift  | **runs_in container→host** invented | **runs_in container→host** invented  |
| Disposition                        | benign                                       | benign ✓                          | benign ✓                            | **true_positive** ✗                  |
| Termination category               | trust-root                                   | trust-root                        | trust-root                          | adversarial-refuted                  |

Three out of four arms get the semantic ending right (benign + kubectl
operator). One (Haiku-3) gets the disposition label backward despite reasoning
correctly through the walk.

---

## 2. Validator rule compliance

Running the §9 write-time validator rules against each arm:

| Rule                                                       | Ref | H1   | H2   | H3   |
|------------------------------------------------------------|-----|------|------|------|
| 1. Schema validity (fields, enums, ID format)              | ✓   | ✓    | ✓    | ✓    |
| 2. Classification vocabulary from §6                       | ✓   | ✓    | ✗¹   | ✓    |
| 3. Relation catalog from §7                                | ✗²  | ✓    | ✗³   | ✗³   |
| 4. Authority rule (strong weights ← strong authority)      | ✓   | ✓    | ✓    | ✓    |
| 5. Refutation text match (verbatim in refutation_shape)    | ✓   | ✓    | ✓    | ✓    |
| 6. Prediction text match (verbatim in predictions list)    | ✓   | **✗**| **✗**| **✗**|
| 7. ID references resolve                                   | ✓   | ✓    | ✓    | ✓    |
| 8. Append-only                                             | ✓   | ✓    | ✓    | ✓    |

Notes:
- **¹** Haiku-2 classified `system:serviceaccount:kube-system:cluster-admin` as
  `employee-with-exec-rbac`. That identifier is an automation identity, not
  an employee. Classification/identifier mismatch — not strictly a vocabulary
  violation (the value is in §6) but a misapplication.
- **²** Reference stretched `triggered_by` to `process → session`. The
  catalog row lists `process → process` or `edge → edge`. Flagged in P4 of
  `reference.md`.
- **³** H2 and H3 invented `runs_in: container → host`. `runs_in` in §7 is
  `process → container` only. Both agents needed to express
  "container is hosted on this node" and had no relation for it — same gap
  the reference commentary calls out in P1.
- **Rule 6 failure is the biggest finding.** All three Haikus wrote
  `matched_prediction_text` as a **paraphrase of the observation** instead of
  a literal substring from the hypothesis's `predictions` list. A strict
  validator would block and retry all three. Details below.

### Rule 6 detail — refutation-shape discipline

| Arm | `matched_prediction_text` as written                                                                 | Appears verbatim in `predictions`?                                  |
|-----|------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| Ref | "kube-audit returns an exec action on v-002 within ±5s of the alert"                                 | ✓ — pulled directly from h-005.predictions                          |
| H1  | "e-{triggered_by} relation with siem-event authority; v-{user} is employee-with-exec-rbac"            | ✗ — concatenated structured description, not list text              |
| H2  | "verified session authenticated as employee with exec RBAC; kube-audit confirms kubectl exec ..."    | ✗ — paraphrase of conclusion, not a predictions-list entry           |
| H3  | "kube-audit documents kubectl exec by employee-with-exec-rbac at 2026-04-14T14:03:27.412Z to ..."    | ✗ — narrative restatement of the observed evidence                   |

All three Haikus wrote what they **observed** in the evidence, not what the
hypothesis **predicted**. The text-match rule is meant to force a link from
the observation back to a pre-declared prediction; the three runs
short-circuited the link.

Interestingly, refutation-text match (rule 5) passed in all three runs. The
asymmetry suggests refutation shapes are easier to anchor because they name
a *specific contradiction*, while predictions are often positive statements
that get restated differently during ANALYZE.

---

## 3. Error classification: bloat vs systematic

**Bloat** = one-off, random, not-repeated errors. Fixable with better
examples or a slightly larger/smarter model.
**Systematic** = errors repeated across runs. Fixable only by changing the
spec, the write tooling, or the validator.

### Systematic (3 of 3 Haikus exhibit)

**S1 — Hypothesis relocation dropped.** All three Haikus kept initial
hypotheses attached to v-001 (bash) throughout the walk. None created
successor hypotheses on v-003 (runc). The spec's one-paragraph instruction
is too subtle to enact in a single pass; none of the Haikus even mentioned
relocation in their self-reports, and Haiku-2 explicitly said "the case
doesn't show this in action (we only walked back one level)" — which is
wrong, the case has exactly the shape relocation was designed for.

This is the **most important finding of the pilot.** Relocation is the
heaviest bookkeeping in the spec, and it's also the first thing to get
dropped when the agent doesn't have worked examples. My reference commentary
(P3, P5, P6) flagged the same thing as the heaviest friction; three Haiku
runs independently confirmed it by silently skipping it.

**S2 — Rule 6 violation via paraphrased prediction text.** 3 of 3 Haikus
wrote `matched_prediction_text` as observation-restatement instead of
list-substring. This is a pure text-discipline failure. In a strict
validator regime, every `++` resolution would retry. My reference
commentary (P7) flagged the same discipline as unnatural.

**S3 — Catalog gap on container→host relationship.** 2 of 3 Haikus invented
`runs_in container → host`. The third kept the host vertex dangling (no
edge). None found a catalog-clean encoding because there isn't one. My
reference commentary (P1) dropped the host vertex entirely; two Haikus did
the wrong thing and one did an awkward thing. All three demonstrate the
catalog is incomplete for obvious structural relations.

### Partial-systematic (2 of 3 Haikus exhibit)

**P1 — Lead mode conflation (scope vs trust).** Haiku-2 labeled l-001 as
`scope` but queried kube-audit inside it (which would be a trust lead).
Haiku-3 collapsed both the scope and trust operations into a single
`container-exec-history` lead labeled `scope` but setting `trust_root` on
a session vertex. The three-mode distinction (materialize/scope/trust) is
not landing cleanly. Only Haiku-1 and the reference ran two distinct leads.

**P2 — Host vertex kept + orphaned or linked via invented edge.** See S3;
counted once there and once here because the disposition of the host
vertex is its own small decision.

### One-off (bloat-ish)

**O1 — Haiku-3 disposition label error.** Walked the case correctly,
concluded `matched_archetype: null` with reasoning that matches a benign
kubectl-operator scenario, then wrote `disposition: true_positive` in the
trailing comment block. Narrative slip, not schema confusion. But it's the
kind of slip that matters: the schema reasoning is right and the final
label contradicts it.

**O2 — Haiku-3 dropped ?ci-pipeline-maintenance seed.** The retrieval-sim
explicitly listed four seed hypotheses; Haiku-3 instantiated three. No
stated reason. One-off.

**O3 — Haiku-2 identifier/classification mismatch on v-006.** Wrote
`classification: employee-with-exec-rbac` with identifier
`system:serviceaccount:kube-system:cluster-admin`. The identifier is an
automation identity; the classification should have been `automation-identity`.
Haiku-2's self-report mentioned difficulty with authority-kind boundaries
but not with classification-identifier alignment — the error likely
indicates Haiku grabbed the first plausible classification rather than
reasoning from the identifier shape.

**O4 — Haiku-1 empty resolution block on l-001.** Did not record any
weight transitions at loop 1 after the scope lead materialized the runc
parent. My reference recorded h-003 → `--` at this step. Haiku-1 simply
left `resolution: []` and resolved h-003 at loop 2 instead. Not wrong per
se (the refutation still happens), but it delays the walk unnecessarily.

### Classification summary

| Category          | Count                             |
|-------------------|-----------------------------------|
| Systematic (3/3)  | 3 (S1 relocation, S2 rule 6, S3 catalog gap) |
| Partial (2/3)     | 2 (P1 lead modes, P2 host)        |
| One-off           | 4 (O1–O4, each in one run)        |

**Ratio: 5 systematic-or-partial to 4 one-off.** Majority systematic. The
cost of the schema isn't "Haiku is sloppy" — it's that specific design
choices in the spec repeatedly trip the agent in predictable ways.

---

## 4. Corroboration with reference commentary

The reference wrote 13 friction points (P1–P13). Haiku's systematic errors
map onto them:

| Reference friction | Haiku systematic error     | Match? |
|--------------------|----------------------------|--------|
| P1 (host vertex, no catalog relation) | S3 (catalog gap) | ✓ |
| P3 (attachment level ambiguity)       | S1 (no relocation) | partial |
| P4 (triggered_by stretch)             | S3 via different mechanism | partial |
| P5 (relocation bookkeeping cost)      | S1 (no relocation) | ✓ |
| P6 (relocated hypothesis predictions) | S1 (no relocation) | ✓ |
| P7 (pre-declaring refutation text)    | S2 (rule 6 violation) | ✓ |
| P10 (lead mode semantics)             | partial P1 (lead confusion) | ✓ |

**7 of the 13 friction points in the reference are independently confirmed
by Haiku's systematic errors.** The other 6 are smaller (naming, data_quality
granularity, termination precedence) and didn't surface in Haiku's output
because Haiku didn't write deeply enough on those dimensions to hit them.

The convergence is meaningful. The friction points that showed up in the
reference walkthrough — written by a more capable model with full self-
awareness of pauses — are the same friction points that Haiku either
silently skipped or got wrong. This is corroborating evidence that the
issues are **in the spec**, not in the model writing against it.

---

## 5. What this says about the review's two points

Recall the two condensed review concerns:
1. **Retrieval correctness at scale** (key drift, canonicalization SPOF)
2. **Heavy write burden**

The pilot only touches #2 directly. On that:

- **Write burden is real but bounded.** All four arms produced walkable,
  readable companions. No one gave up. The schema can be written.
- **The specific write burden concentrates in four places**, and they are
  *not* distributed evenly across the spec:
  1. Hypothesis relocation (S1, P3/P5/P6) — biggest source of complexity
  2. Refutation/prediction text-match discipline (S2, P7) — biggest source
     of validator-retry risk
  3. Catalog incompleteness (S3, P1/P4) — biggest source of ad-hoc
     stretching and corpus drift
  4. Lead-mode three-way distinction (partial, P10) — doesn't cleanly land
- **The validator's strictness dial directly controls three of those four.**
  Rule 6 (strict prediction text match) is the single dial that separates
  "3/3 Haikus retry" from "3/3 Haikus pass as-is." Softening it to a
  semantic-match (e.g., Haiku judge deciding whether the observation
  corresponds to a listed prediction) would likely clear all three Haiku
  outputs with no other changes.
- **Relocation needs a worked example in the spec and probably a schema
  field (`relocated_to: h-id`).** No Haiku did it without one, and I hit
  it as two separate pauses myself. This isn't a lenience-vs-strictness
  dial — it's a missing affordance.

Nothing in the pilot speaks to retrieval correctness. That needs a
separate experiment with more runs and real canonicalization tests.

---

## 6. Concrete next-step recommendations

Ordered by expected impact per unit effort:

1. **Add a worked example of relocation to §4 of the spec**, using the
   exact A.1 shell-in-container walk. Two loops, three hypotheses
   relocating from v-001 to v-003, with the full before/after YAML.
   Costs one page of doc; would likely eliminate S1 in a rerun.

2. **Add `hypothesis.relocated_to: h-id` and `hypothesis.relocated_from:
   h-id` fields.** Makes the linkage first-class, removes ambiguity about
   inheritance of predictions, gives the distiller something clean to
   walk. Minimal schema churn.

3. **Soften rule 6 to "semantic match, Haiku-judged."** Pipeline: validator
   tries literal-substring match first; on miss, invokes a tiny Haiku
   judge with the predictions list and the proposed match text, asks
   "does this correspond to any listed prediction." Caches by (hypothesis
   hash, match text hash). Same for rule 5 optionally. This is the single
   dial that would flip 3/3 failures to 3/3 passes on this case.

4. **Add `runs_in` container→host OR add a new relation `hosted_on`.**
   Pick one; document. Closes S3 for this class of case. Also think
   about whether process→socket etc. need similar "hosting/containment"
   relations for non-process resources.

5. **Rerun the same pilot after 1–4 land.** If the systematic errors
   disappear, lock the design. If they don't, the spec has deeper issues
   than the condensed format exposed.

6. **Run a harder case (A.3 or A.4) before scaling further.** This pilot
   was deliberately easy — a 2-loop walk with clean trust-root
   termination. The design questions that matter most at scale (severity
   ceilings, trust chain promotion, revision handling) didn't fire. Run
   at least one case that exercises each before committing to the full
   §12 retrofit path.

---

## 7. Open question for design discussion

The pilot surfaces one genuine ambiguity that isn't a fixable bug: **at
loop 0, before any lead runs, do hypotheses describe the immediate parent
edge or the ultimate semantic cause?** Three Haikus and one Sonnet made
four different calls on this:

- Ref: ultimate cause, relocate on materialization
- H1: ultimate cause (user), no relocation
- H2: ultimate cause (session), no relocation
- H3: ultimate cause (session/user mixed), no relocation

The spec's "single backward edge" framing implies immediate parent, but
all four arms interpreted it as ultimate cause because that's where
discrimination happens. This isn't a rule 6 problem — it's a conceptual
one. Two options:

- **(a)** Keep single-edge framing, require that the immediate parent
  question is mechanical (answered by one scope lead) and hypotheses
  proper start at the discrimination level. Means "loop 0 hypotheses"
  don't really exist; you hypothesize after the first mechanical lead.
- **(b)** Let hypotheses describe N-hop chains at the predictions level,
  with `proposed_edge` as "the discriminating edge anywhere in the chain."
  Relocation becomes optional.

Recommendation: **(a), explicitly**. It matches how four independent
writers actually walked the case, and it makes relocation a conceptual
non-issue because the "level shift" happens before hypothesizing, not
during.
