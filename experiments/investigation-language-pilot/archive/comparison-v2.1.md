# Pilot Rerun Comparison — v2.1 vs v2

Third pass on the same A.1 case. Same three Haikus + Sonnet reference,
v2.1 spec, v2 retrieval-sim (unchanged — v2.1 doesn't touch retrieval
shape). Goal: confirm the seven v2.1 changes land cleanly and decide
whether to lock the design.

Arms: `reference-v2.1.md`, `haiku-v21-1.yaml`, `haiku-v21-2.yaml`,
`haiku-v21-3.yaml`.

---

## 1. Headline

**v2.1 is a clean run. 3/3 Haikus pass all nine validator rules on
first-pass. Aggregate across all Haiku runs went from 25/27 in v2 to
27/27 in v2.1.** The two residual failure modes from v2 (premature
session materialization on scope leads; H3's paraphrased rule 6 match)
are both closed. One new soft issue surfaced — semantic mismatch between
cited refutation text and actual observation in H3's h-001 resolution —
which is not a validator violation but is the subtler form of the rule
6 failure mode.

**Recommendation: lock v2.1 as the working spec and move to a harder
case (A.3 or A.4).**

---

## 2. Structural compliance — the seven v2.1 changes

| Change                                                                                 | Ref | H1 | H2 | H3 | Verdict                                    |
|----------------------------------------------------------------------------------------|-----|----|----|----|---------------------------------------------|
| 1. `intended_hypothesis_set` required on materialize/trust, omitted on scope           | ✓   | ✓  | ✓  | ✓  | **4/4 — clean**                             |
| 2. Drop `execution` block                                                              | ✓   | ✓  | ✓  | ✓  | **4/4 — clean**                             |
| 3. Drop `outcome.status`                                                               | ✓   | ✓  | ✓  | ✓  | **4/4 — clean**                             |
| 4. Drop `source_lead` field                                                            | ✓   | ✓  | ✓  | ✓  | **4/4 — clean**                             |
| 5. Unified `concerns` field (replaces `pitfalls` / `data_quality_note`)                | ✓   | ✓  | ✓  | ✓  | **4/4 — clean**                             |
| 6. "Mechanical leads stay within their data source" rule (§6 + §12 rule 11)           | ✓   | ✓  | ✓  | ✓  | **4/4 — the one v2 issue fully resolved**   |
| 7. Rule 6 negative example in §12                                                     | ✓   | ✓  | ✓  | ✓* | **4/4 strict literal; 1 semantic mismatch** |

`*` H3 passed the literal test on rules 5/6 but one cited refutation
text doesn't actually fit the observed evidence — details in §4.

---

## 3. Validator rule compliance (all nine rules)

| Rule                                                       | Ref | H1   | H2   | H3   |
|------------------------------------------------------------|-----|------|------|------|
| 1. Schema validity                                         | ✓   | ✓    | ✓    | ✓    |
| 2. Classification vocabulary                               | ✓   | ✓    | ✓    | ✓    |
| 3. Relation catalog                                        | ✓   | ✓    | ✓    | ✓    |
| 4. Authority rule (strong weights ← strong authority)      | ✓   | ✓    | ✓    | ✓    |
| 5. Refutation text match (literal)                         | ✓   | ✓    | ✓    | ✓    |
| 6. Prediction text match (literal)                         | ✓   | ✓    | ✓    | ✓    |
| 7. ID references resolve                                   | ✓   | ✓    | ✓    | ✓    |
| 8. Append-only                                             | ✓   | ✓    | ✓    | ✓    |
| 9. Self-containment of lead blocks                         | ✓   | ✓    | ✓    | ✓    |
| 10. Scope leads omit `intended_hypothesis_set`             | ✓   | ✓    | ✓    | ✓    |
| 11. Mechanical leads within their data source              | ✓   | ✓    | ✓    | ✓    |

**v2.1 pass rate:** Ref 11/11, H1 11/11, H2 11/11, H3 11/11.

**Progression across pilots (Haiku arms only, rules 1–9):**

| Pilot | H1   | H2   | H3   | Total |
|-------|------|------|------|-------|
| v1    | 6/9  | 5/9  | 5/9  | 16/27 |
| v2    | 9/9  | 9/9  | 7/9  | 25/27 |
| v2.1  | 9/9  | 9/9  | 9/9  | 27/27 |

27/27 first-pass compliance on Haiku.

---

## 4. Per-Haiku notes

### Haiku v21-1 — clean pass + richer scope

- Structural: all correct. Journal form, no source_lead, no execution,
  no outcome.status, concerns unified, hypothesize empty.
- **Rule 11 (mechanical data source):** produced v-003 (runc) AND v-004
  (containerd-shim) plus two spawned edges (containerd-shim → runc,
  runc → bash). Both processes are host-side and directly visible to
  the execve feed, so this is within the data source. Broader than
  strictly needed but not a violation.
- Rule 6 literal matches: all three verified character-for-character
  against the target hypothesis's own lists.
- Disposition: benign, ?kubectl-exec-operator confirmed, matched
  archetype `sanctioned-operator-interactive-shell`.
- Observation: H1 was the **most detailed** of the three Haikus —
  materialized more of the process chain and gave more reasoning text.
  No downside.

### Haiku v21-2 — minimal clean pass

- Structural: all correct.
- **Rule 11:** produced v-003 (runc) and e-002 (runc → bash) only.
  The minimal correct answer. Scope lead stays exactly within the
  execve feed's observation.
- Rule 6: all literal. H2 used h-002's refutation text for a weight
  `-` resolution (not required) but the text was literal from h-002's
  own list — a belt-and-suspenders pass.
- Disposition: benign, ?kubectl-exec-operator confirmed, archetype
  `kubectl-exec-by-authorized-operator`.

### Haiku v21-3 — literal pass, semantic mismatch in one resolution

- Structural: all correct.
- **Rule 11:** produced v-003 (runc) and e-002 only. Minimal, clean.
- **Rule 5/6 literal:** all passes verified character-for-character.
- **Semantic mismatch in h-001 resolution** (this is the new soft issue):
  - h-001 weight → `-`, `matched_refutation_text: "kube-audit returns no exec authorization record in the ±5s window"`.
  - h-001.refutation_shape contains this string literally ✓.
  - **But** H3's simulated kube-audit outcome *did* return an exec
    authorization record (from `devops-automation-service`). The cited
    refutation text says "no exec record" while the observation is
    "exec record found." These contradict.
  - H3's reasoning field explains what actually happened (the identity
    is automation, shifting plausibility away from the operator
    hypothesis) but the **cited match is the wrong list entry** — H3
    should have cited nothing and let the weight sit at `-` on the
    strength of reasoning alone, or picked a different list entry
    that actually fits.
  - Weight is `-`, not `--`, so the literal match is advisory — the
    validator does not block. **This is not a rule 5 violation.**
  - It is, however, the subtler form of the rule 6 failure mode: the
    agent picks a list entry that's literally present but doesn't
    actually fit the observation. A semantic validator layer (Haiku
    judge) would catch this; the literal validator doesn't.

- **Divergent scenario simulation (same as v2-H3).** H3 imagined the
  anchor returning an automation service account rather than a human
  employee, so their walk concluded with ?ci-pipeline-maintenance →
  `++` and ?kubectl-exec-operator → `-`. Internally consistent,
  anchor-backed, and benign disposition. Not a spec issue.

- Disposition: benign, ?ci-pipeline-maintenance confirmed, archetype
  `kubectl-exec-by-automation`.

---

## 5. The one new failure mode — semantic mismatch at the literal match

v2.1 eliminates literal rule 5/6 failures (3/3 Haikus clean), but H3
surfaced a subtler failure mode: **pick a list entry that's literally
present but doesn't match what was observed.** The literal validator
can't catch this because the text really is in the list. Only a semantic
layer can.

**Why this matters (mildly).** In a real investigation, the validator
would pass H3's resolution, the distiller would project it as a valid
weight transition, and the projection would carry forward the wrong
association between "kube-audit returning an automation identity" and
"h-001 is refuted because no exec record found." Over many runs this
could pollute the `pitfall_index` with misleading entries.

**Why this matters only mildly.** It requires the agent to fail the
reading-comprehension check on its own refutation_shape list. Two of
three Haikus didn't. The failure rate is 1/3 and drops further as the
agent gets more careful. The concrete damage is small because H3 *also*
resolved h-001 to `-` (not `--`), so no strong weight transition is
implicated; the validator's hardest rule (rule 5 for `--`) is not in
play.

**Fix options, ordered:**

1. **Add a positive/negative example pair to §12 showing semantic
   mismatch.** "Your cited refutation text must describe the
   observation you actually made. Citing 'no X record' when the
   observation is 'X record found' is a semantic mismatch even if the
   text is in the list." One paragraph + an example. Cheap. Not
   validator-enforceable, but reduces the incidence.
2. **Optional: Haiku-judged semantic match as a second validator pass.**
   Triggers only on ++/-- resolutions (where the cost of getting it
   wrong is highest). Runs after literal match passes. Returns "text
   matches observation" or "text does not match observation." Non-
   deterministic, adds ~1-2s per write, catches the H3 failure mode.
   **Not needed yet** — at 1/3 rate on a soft issue, literal + doc is
   probably enough. Revisit if it shows up on harder cases.

My lean: **ship (1) as a small spec addition; defer (2) until it's
demonstrated necessary.**

---

## 6. Qualitative observations

- **All three Haiku self-reports unanimously flagged the mechanical-lead
  discipline (rule 11) as the main thing they had to actively watch for.**
  All three navigated it correctly. This is strong evidence the explicit
  rule 11 is the right abstraction — it's sharp enough to steer behavior
  but not so abstract that it fails in practice. H3's self-report was
  the most interesting: they explicitly mentioned *wanting* a
  `suppressed_vertices` field to make the decision to NOT materialize
  v-004/v-005 explicit. That's a real usability observation — the
  discipline is invisible in the output, reviewers can only verify it
  by knowing what the data source can see. Not worth a schema change,
  but worth noting for future UX thinking.
- **The `concerns` unification was unanimously positive.** No Haiku
  asked whether to emit a concern vs an attribute; all three placed
  concerns correctly. The rename landed.
- **The subtractive changes (drop source_lead, execution, status) were
  frictionless.** No Haiku emitted them, no Haiku self-reported
  confusion, no arm looked visibly harder to write.
- **Line counts remained stable from v2 to v2.1.** Haiku arms averaged
  ~235 lines in v2.1 vs ~240 in v2 — the subtractive changes were each
  small, and the cumulative effect is modest on absolute size but
  meaningful on cognitive load.
- **Writing speed: reference was ~15 minutes.** Faster than v2's ~20,
  which was faster than v1's ~40. The trend is the thing: each spec
  iteration has lowered the cost of writing.

---

## 7. What we have at the end of three iterations

Starting from the original investigation-language.md §3, after three
pilot rounds the spec is:

- Structurally reshaped into journal form (v2 change 1)
- Cleaned of redundant metadata (v2.1 changes 2–4)
- Unified on one name for concern-shaped fields (v2.1 change 5)
- Armed with a discrimination-level rule that replaces relocation
  machinery (v2 change 3)
- Armed with a data-source-containment rule for mechanical leads (v2.1
  change 6)
- Armed with literal-match discipline on text matches, plus a negative
  example (v2 change 5 + v2.1 change 7)
- Hosting a vocabulary of ~10 abstract types, ~15 relations, ~30
  classifications, ~5 authority kinds (§9–11)

**Every Haiku run on v2.1 passes 11/11 validator rules on first-pass.**
Every friction point in the v1 reference commentary that mapped to a
Haiku systematic error has been addressed structurally. The remaining
soft issue (semantic mismatch on cited list entries) is low-frequency
and addressable by a doc-only fix.

---

## 8. Recommendation — lock v2.1, move to a harder case

**Lock v2.1 as the working spec.** Either:

- Promote `spec-condensed-v2.1.md` into an update of the canonical
  `investigation-language.md` §3, or
- Keep it as a pilot-directory artifact and use it as the input to
  subsequent experiments. Update the canonical doc when we have
  confidence from more than one case shape.

**Next experiment: a harder case.** A.1 doesn't stress:

- Severity-ceiling termination (A.4 S3 list burst does — partial
  prediction match, partial anchor authority, exhausted in-scope
  severe leads)
- Trust-chain promotion (A.3 sudo-to-root exercises Slack/PAM
  trust-chain)
- Refutation cascades / `refutation_pivots_to` (A.5 prober-bait)
- Revisions and mid-walk attribute updates
- Multi-loop walks with ambiguous mid-walk evidence

**My pick: A.4 (S3 list burst).** It's the cleanest stress on the
severity-ceiling termination category, which is the single spec
mechanism that hasn't fired in any pilot run so far. If v2.1 handles
severity-ceiling cleanly, the design is solid for production. If it
doesn't, we know exactly which dimension needs work.

**Alternative: A.3 (sudo on prod)** if you prefer stressing trust-chain
promotion and multi-loop discrimination. A.5 is the most exotic (bait
catching) and probably premature — it depends on prior runs in the
corpus, which we don't have under the pilot harness.

**Optional small additions before the next run:**

1. Add the "semantic mismatch" example pair to spec §12 (one paragraph).
   Closes the 1/3 H3-class failure mode.
2. Add a one-sentence note to §7 clarifying that `target` on a trust
   lead follows the hypothesis set when `target` and `attached_to_vertex`
   diverge. Resolves the single carry-over pause from v1/v2.

Both are doc-only changes, zero schema churn. Drop them into the
harder-case pilot as part of the setup.

---

## 9. Pilot scorecard

| Metric                                                | v1            | v2            | v2.1          |
|-------------------------------------------------------|---------------|---------------|---------------|
| Haiku aggregate validator compliance                  | 16/27 (59%)   | 25/27 (93%)   | **27/27 (100%)** |
| First-pass clean Haiku arms                           | 0/3           | 2/3           | **3/3**       |
| Systematic errors (all 3 Haikus)                      | 3             | 0             | **0**         |
| Partial-systematic errors (2/3 Haikus)                | 2             | 1             | **0**         |
| New failure modes introduced                          | n/a           | 1             | 1 (soft)      |
| Reference friction points (Sonnet pause count)        | 13            | 5             | **3**         |
| Reference YAML line count                             | ~310          | ~245          | **~215**      |
| Reference write time (approx)                         | ~40 min       | ~20 min       | **~15 min**   |

Three iterations, each visibly better than the last by multiple
metrics. v2.1 is the first iteration where every arm passes every rule
on first pass and the reference writer reports near-zero friction.

**Lock it and move on.**
