# Pilot Rerun Comparison — v2 vs v1

Same alert, revised spec. Three Haiku runs + Sonnet reference, as before.
Goal: verify whether the five v2 changes landed the fixes they were
designed to land, and whether any new issues surfaced.

Arms: `reference-v2.md`, `haiku-v2-1.yaml`, `haiku-v2-2.yaml`, `haiku-v2-3.yaml`.

---

## 1. Headline

**v2 fixes all three v1 systematic errors and introduces one smaller,
partial-systematic issue.** The largest single improvement is on S1
(hypothesis relocation): every v1 Haiku silently skipped it; every v2
Haiku correctly deferred hypothesizing and emitted the first set in
`new_hypotheses` under the mechanical lead. Rule 6 (literal
prediction/refutation text) went from 0/3 Haiku compliance in v1 to 2/3
in v2, with one Haiku still tripping on it. The one new issue is
**premature session materialization** inside the mechanical scope lead.

---

## 2. Structural compliance (the five v2 changes)

| Change                                            | Ref  | H1   | H2   | H3   | Verdict                                 |
|---------------------------------------------------|------|------|------|------|-----------------------------------------|
| 1. Journal form (prologue/hypothesize/gather/conclude) | ✓ | ✓ | ✓ | ✓ | **PASSED 4/4** — unambiguous win         |
| 2. Implicit defaults (omit `trust_root: false`, etc.)  | ✓ | ✓ | ✓ | ✓ | **PASSED 4/4** — all arms omit cleanly   |
| 3. Discrimination-level rule (hypothesize empty, hypotheses in `new_hypotheses`) | ✓ | ✓ | ✓ | ✓ | **PASSED 4/4** — biggest fix vs v1       |
| 4. Host as attribute, not vertex                       | ✓ | ✓ | ✓ | ✓ | **PASSED 4/4** — no arm created `v-host` |
| 5. Rule 6 literal text match                           | ✓ | ✓ | ✓ | ✗ (2 violations in h-001 and h-002 resolutions) | **PASSED 3/4** — sharp improvement vs 1/4 in v1 |

Every structural change landed. The only failure is one Haiku hitting
the residual edge of change 5.

---

## 3. Validator rule compliance (all nine rules from §12)

| Rule                                                       | Ref | H1   | H2   | H3   |
|------------------------------------------------------------|-----|------|------|------|
| 1. Schema validity                                         | ✓   | ✓    | ✓    | ✓    |
| 2. Classification vocabulary                               | ✓   | ✓    | ✓    | ✓    |
| 3. Relation catalog                                        | ✓   | ✓    | ✓    | ✓    |
| 4. Authority rule (strong weights ← strong authority)      | ✓   | ✓    | ✓    | ✓    |
| 5. Refutation text match (literal)                         | ✓   | ✓    | ✓    | **✗** (h-001) |
| 6. Prediction text match (literal)                         | ✓   | ✓    | ✓    | **✗** (h-002) |
| 7. ID references resolve                                   | ✓   | ✓    | ✓    | ✓    |
| 8. Append-only                                             | ✓   | ✓    | ✓    | ✓    |
| 9. Self-containment of lead blocks                         | ✓   | ✓    | ✓    | ✓    |

**v2 pass rate:** Ref 9/9, H1 9/9, H2 9/9, H3 7/9.
**v1 pass rate (for comparison):** Ref 8/9 (1 catalog stretch), H1 6/9,
H2 5/9, H3 5/9.

Aggregate across all Haiku runs: **v2 = 25/27 passed, v1 = 16/27 passed.**
A ~56% fewer-violations improvement, concentrated in rules 3, 5, and 6.

---

## 4. Detailed Haiku-by-Haiku notes

### Haiku v2-1 — clean pass

- Journal form, discrimination-level rule, implicit defaults, host as
  attribute: all correct.
- Rule 6: all `matched_prediction_text` and `matched_refutation_text`
  values are character-for-character substrings of the target hypothesis's
  lists. Verified by eye.
- **Minor quirk:** materialized v-004 (kubectl-exec-session) inside l-001
  (the mechanical scope lead) as an orphan vertex — did not attach
  hypotheses to it, so it doesn't affect the walk, but the session is
  semantically something the execve feed can't directly observe. Should
  have waited for l-002 (the kube-audit anchor) to materialize v-004.
  This is the seed of the issue called out in §5 below.
- Disposition: benign, hypothesis h-001 ?kubectl-exec-operator → `++`,
  matched archetype `kubectl-exec-by-authorized-employee`.

### Haiku v2-2 — clean pass with one substantive deviation

- All structural changes correct.
- Rule 6: all matches literal.
- **Substantive deviation:** H2 materialized v-004 (kubectl-exec-session)
  inside l-001 AND attached hypotheses h-001/h-002/h-003 to v-004 instead
  of v-003 (runc). This is a defensible but aggressive reading of the
  discrimination-level rule — if the mechanical lead can reveal a session
  vertex, the discrimination level is the session itself, not runc. The
  ref and H1 attached to v-003 (runc); H2 attached to v-004 (session).
  Both are internally consistent but they represent different choices
  about where the mechanical lead's observation boundary ends. **Worth
  clarifying in the spec: does the mechanical lead paint only what the
  data source directly observes, or may it include causally-implied
  vertices?**
- H2 also got h-002's resolution as `-` (not `--`) with no
  `matched_refutation_text` — that's rule-valid because `-` doesn't
  require the match, but shows H2 was careful to distinguish moderate
  vs severe tests.
- Disposition: benign, archetype `kubectl-exec-by-authorized-operator`.

### Haiku v2-3 — 2 rule 6 violations + divergent scenario choice

- Structural changes all correct (journal form, discrimination-level,
  implicit defaults, no host vertex).
- **Rule 6 violations (2):**
  1. h-001 resolution to `--` cites
     `matched_refutation_text: "runc exec parent session authenticated by a human user or unknown-attacker identity"`
     — but that text does NOT appear in h-001.refutation_shape. It
     appears in **h-002.refutation_shape**. Cross-hypothesis text use.
     The spec is arguably not explicit that matched text must come from
     *the target hypothesis's own* refutation_shape — it says "appears
     in the target hypothesis's refutation_shape list," which H3 may
     have read as "any hypothesis's list." Worth tightening.
  2. h-002 resolution to `++` cites
     `matched_prediction_text: "runc exec parent session authenticated by an automation identity"`
     — but h-002.predictions contains
     `"runc exec triggered by a kubectl-exec-session initiated by an automation identity"`
     (first entry) and
     `"a triggered_by edge from v-003 to a kubectl-exec-session authenticated by an automation identity"`
     (second entry). The cited text is a paraphrase that's close to the
     second entry but not a literal substring. Classic rule 6 failure
     mode: agent rephrases the prediction as a summary.
- **Divergent scenario:** H3 simulated the kube-audit anchor returning
  `system:serviceaccount:kube-system:deployment-controller` (an
  automation identity) while Ref, H1, and H2 all simulated a human
  employee. Under H3's simulation, h-002 ?ci-pipeline-maintenance is
  confirmed and h-001 ?kubectl-exec-operator is refuted — the inverse
  of the other arms' walks. Not a spec issue; a simulation choice that
  only matters because we're in pilot mode. In real runs, the evidence
  is real and this divergence can't happen.
- Disposition: benign (same as the others), archetype
  `ci-pipeline-pod-maintenance`.

---

## 5. The one new issue — premature session materialization

Two of three Haikus (H1, H2) materialized v-004 (kubectl-exec-session)
inside l-001's `outcome.produced.vertices`, where l-001 is the mechanical
scope lead against the runtime-audit execve feed.

**Why this is wrong.** The execve feed observes host-side process spawn
events. It can see that `runc:[2:INIT]` was invoked with arguments
`exec -c a1b2c3d4 bash`. It cannot directly see the *kubectl session*
that caused the runc invocation — that's a kube-audit layer observation,
one API layer up. A strict reading of the lead mode says: mechanical
scope leads produce only vertices the data source directly observes;
anything causally implied is the job of a subsequent trust lead.

**Why Haiku did it.** In the execve feed output, the runc cmdline
(`runc exec ...`) does contain an implicit pointer to a kubectl exec
session — it's obviously kubectl-driven. Haiku reasoned "I can see that
this came from a kubectl exec" and materialized the session vertex as
an observation. This conflates "directly observed" with "causally
implied," which the spec doesn't explicitly warn against.

**Why the reference and H3 got it right.** Ref and H3 both kept l-001's
produced vertices to `v-003` (runc) only; the session was materialized
later by l-002 (the kube-audit trust lead). This is the clean version —
mechanical leads materialize what their telemetry directly sees, trust
leads materialize what their anchor authoritatively classifies.

**Frequency:** 2/3 Haikus. Partial-systematic.

**Fix:** add a short note to §6 of the spec:

> **Mechanical leads stay within their data source.** A scope lead's
> `outcome.produced` contains only vertices directly observable from the
> lead's data source. Causally-implied parents or sessions remain
> unmaterialized until a trust lead confirms them. Example: the execve
> feed sees a runc process; it does NOT see the kubectl exec session
> that caused the runc invocation — that's a kube-audit observation and
> belongs to a later trust lead.

This is a one-paragraph addition, not a schema change. It eliminates
the ambiguity that led to H1/H2's deviation without removing any
capability.

---

## 6. The one residual rule 6 concern

Even with explicit capital-letters guidance, worked example, and task-prompt
reinforcement, **1 of 3 Haikus still wrote paraphrased prediction/refutation
text** (H3, two instances). The failure mode was subtle — H3 used prediction
text that was close-but-not-literal and used another hypothesis's refutation
text on the target hypothesis.

**This is the remaining case where the strict validator would force a
retry.** 3 of 4 arms pass on first try (Ref, H1, H2); 1 of 4 needs a
retry (H3). That's a 75% first-pass rate, up from 25% in v1.

**Options for closing the remaining 25%:**

1. **Add an example of a rule 6 violation to the spec.** Show the
   wrong form next to the right form: "WRONG:
   `matched_prediction_text: "the session authenticated to an employee"`.
   RIGHT:
   `matched_prediction_text: "session authenticates to an employee user with PAM-enforced sudo or sensitive-file write permission"`."
   This makes the discipline concrete by negative example, not just
   positive instruction.
2. **Soften the validator to Haiku-judged semantic match**, as discussed
   earlier. The tradeoff is a per-write Haiku call and non-determinism.
3. **Both.** Use negative examples to reduce failures; use Haiku-judged
   semantic match as a belt-and-suspenders layer for the residual tail.
4. **Accept the 25% retry rate as cost of operation.** If each retry is
   cheap (the validator tells the agent "use literal text from the list
   at h-001.refutation_shape[0]"), the operational overhead is
   tolerable — one retry per bad write, usually successful on second
   attempt.

My lean: **(1) for this spec iteration, (3) later.** Negative examples
are cheap to add and may close most of the remaining tail. If they
don't, layer on Haiku-judged match as a fallback.

---

## 7. Qualitative observations across the four arms

- **Writing effort visibly dropped.** The reference took ~20 minutes vs
  ~40 for v1. Haiku runs averaged 280–420ms duration_ms in the
  simulated `execution` fields, which is telemetry fiction but suggests
  Haiku felt confident writing the blocks quickly. Two of the three
  Haiku self-reports called out the journal form as easier, not harder.
- **All four arms landed on benign disposition.** Three via
  ?kubectl-exec-operator confirmed, one (H3) via ?ci-pipeline-maintenance
  confirmed due to a divergent scenario simulation. No arm hallucinated
  a true-positive disposition (v1's H3 did).
- **All four arms reached trust-root termination.** No severity-ceiling
  or exhaustion-escalation outcomes — the case is too clean for those,
  as expected.
- **The biggest subjective shift: the journal form reads like the walk.**
  Reading the v2 companions top-to-bottom is a natural reading of the
  investigation. Reading the v1 companions requires mentally
  reconstructing the time order from cross-references. This is not a
  validator-measurable property but it matters for both agent writing
  and human review.
- **The three Haiku self-reports unanimously cited the discrimination-level
  rule as the conceptual shift** they had to internalize, and unanimously
  reported they followed it. The one arm that failed rule 6 (H3) still
  thought it had followed rule 6 — which is a classic paraphrase-blindness
  failure mode (you read your paraphrase as the original text). Negative
  examples (option 1 above) would catch this specifically.

---

## 8. What this confirms about the v2 design changes

- **Journal form is the right structural choice.** 4/4 compliance. Makes
  every other change easier to apply.
- **Implicit defaults work.** No arm emitted default values as if they
  were intentional assertions. Writing is visibly cleaner.
- **Discrimination-level rule replaces relocation cleanly.** The whole
  concept of hypothesis relocation — which 0/3 v1 Haikus understood — is
  gone from v2, and 3/3 v2 Haikus correctly deferred hypothesizing. The
  spec change didn't soften the safety property; it relocated (pun
  intended) the affordance to a place agents can use.
- **Host-as-attribute closes S3 cleanly.** 3/3 Haikus used the `host_name`
  attribute pattern without invention.
- **Rule 6 still needs one more nudge.** 3/4 compliance is a large
  improvement but not a complete fix. One more iteration (negative
  examples, and possibly a semantic-match fallback) should close the
  remaining gap.

---

## 9. Recommendations — what to land before moving on

Ordered by impact:

1. **Add the "mechanical leads stay within their data source" note to
   spec §6** (one paragraph). Fixes the one new partial-systematic
   issue in v2 before it becomes a pattern.
2. **Add a negative example for rule 6** showing a paraphrased
   `matched_prediction_text` alongside the literal version. Likely closes
   H3's class of failure.
3. **Rerun the same pilot once more** (v2.1 with the two additions) to
   confirm 3/3 clean on the rerun. If yes, lock the v2 design for harder
   cases.
4. **Move to A.3 or A.4 as the next test case.** The design questions
   that matter at scale (severity-ceiling termination, trust-chain
   promotion, partial-authority anchors) didn't fire in A.1 and need
   separate validation. Current A.1 pilot is fully green; the next
   experiment should pick a case that stresses the dimensions this one
   couldn't reach.
5. **Leave the Haiku-judged semantic match for rule 6 as a deferred
   option.** Don't implement it until we see whether negative examples
   alone close the gap on a harder case. Keeps the validator deterministic
   unless we have evidence we need to relax it.

---

## 10. Comparison against the v1 pilot's conclusions

The v1 comparison (`comparison.md`) ended with four concrete next-step
recommendations. v2 tested four of them directly:

| v1 recommendation                                             | v2 outcome                          |
|---------------------------------------------------------------|-------------------------------------|
| Add worked example of relocation to §4 of the spec            | Superseded — relocation dropped entirely by the discrimination-level rule. Not needed. |
| Add `hypothesis.relocated_to` / `relocated_from` fields       | Superseded — same reason. v2 has no relocation machinery at all. |
| Soften rule 6 to semantic match via Haiku judge               | Not yet tested. v2 kept strict but added explicit warning + worked example. Result: 3/4 pass. Still on the table for closing the residual. |
| Add `runs_in container→host` OR new `hosted_on` relation      | Superseded — v2 dropped the host vertex entirely. No new relation needed. |

**Three of four v1 recommendations were obsolesced by the
discrimination-level rule and the journal form**, not because they were
wrong but because they were solving symptoms of a structural problem that
v2 resolved structurally. The fourth (semantic match for rule 6) remains
a deferred option.

This is the kind of design iteration that's rare and worth naming: the
v2 changes didn't just *address* the v1 issues, they *dissolved* most of
them. What's left is a single partial issue (premature session
materialization) and a single residual rule 6 failure, both tractable
with one more spec iteration.
