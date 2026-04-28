# Invlang validator rule audit

Asks one question of each of the 35 rules in `docs/investigation-language.md` v2.13: **what behavior does it validate, and what specific failure mode does it prevent?** Companion to `dense-investigation-format.md` v0.1. Discussion artifact, not a spec change.

The audit is normative — it answers what each rule is *for*, not how often it currently fires. Empirical fire-rate is a separate question (see end).

## Per-rule audit

**#1 Schema validity.** Validates required fields, enum membership, ID-shape regexes. Prevents downstream parsers operating on malformed records. Type-system foundation.

**#2 Classification vocabulary.** Validates every `classification` is from the seed list or `{type}:{slug}` provisional. Prevents synonymy explosion ("scanner" / "scanner-ip" / "external-scanner") that breaks corpus query and archetype matching.

**#3 Relation catalog.** Validates every `edge.relation` is one of ~25 controlled verbs. Prevents agent-invented edge verbs (Haiku produced `brute_force_burst` and `code_execution` in the write test) and meaning drift across investigations.

**#4 Edge authority cite.** Validates every `++`/`--` resolution cites at least one `siem-event` / `runtime-audit` / `authoritative-source` edge. Prevents strong weight movement on inference alone — the hypothesis-driven model collapses if weights drift without source-of-truth grounding.

**#5 Refutation IDs.** Validates every `--` names the specific refutation pattern (`r{n}`) it matched. Prevents "I refuted it" without committing to *which* prediction failed; forces clean pre-hypothesis refutation shapes.

**#6 Prediction completeness for `++`.** Validates a `++` covers the hypothesis's full prediction set; partial coverage caps at `+`. Prevents overgrading on partial evidence at write time (early gate; #34 is the late gate).

**#7 ID references resolve.** Validates every `v-*, e-*, h-*, l-*` points to a real record. Prevents dangling references — agent hallucinating an edge id (Haiku did this) where downstream queries then operate on phantoms.

**#8 Append-only.** Validates no existing record is mutated. Prevents silent retconning of evidence or weights mid-investigation; preserves audit-trail integrity. Foundational.

**#9 Lead block self-containment.** Validates every vertex/edge/hypothesis from a lead lives inside that lead's `outcome.observations` / `new_hypotheses` / `shelved`. Prevents ambiguous attribution: "which lead actually delivered this evidence?" Required for both audit and corpus queries.

**#10 Mechanical leads stay within data source.** Validates a lead's observations contain only entities the queried system natively names. Prevents cross-system fabrication — a Wazuh-querying lead claiming Splunk-only entities. Today review-enforced; without enforcement, audit trail conflates seen vs assumed.

**#11 Anchor-query provenance completeness.** Validates authz_resolutions and anchor_consultations carry the full provenance tuple. Prevents ungrounded "I checked the registry" claims; forces naming *which* authority, *when*, and *how authoritative*.

**#12 Hierarchical hypothesis IDs.** Validates `h-001-002` requires `h-001` to exist. Prevents orphaned refinements; verifies inheritance topology without external state.

**#13 ceiling_test requires severity-ceiling.** Validates `ceiling_test` iff `termination=severity-ceiling`. Prevents the agent invoking the unusual termination category without naming the specific human/tool gate; severity-ceiling becomes a wave-of-hand escape otherwise.

**#14 Partial authority cap.** Validates a resolution grounded *solely* by partial-authority sources can't push past `+`/`-`. Prevents laundering weak grounding into strong weight; forces the agent to seek full-authority before claiming strong updates.

**#15 component_of sub-vertex IDs.** Validates sub-vertices follow `v-{parent}-{nonce}`. Prevents silent decomposition that breaks parent-child queries. **Today: review-only**, not validator-enforced.

**#16 screen_result scope.** Validates `screen_result` only on `mode:screen` leads and only on the final one. Prevents misuse of the SCREEN fast-path (a regular lead claiming match to skip the loop).

**#17 SCREEN-matched companions omit hypothesize.** Validates `screen_result:match` ⇒ no top-level hypothesize block. Prevents hybrid SCREEN/full-loop companions whose semantics are ambiguous about what was actually run.

**#18 Lead-level predictions structure.** Validates `lp*` entries have `if`/`read_as`/`advance_to` and `advance_to` resolves. Prevents pre-committed branch plans that don't point anywhere; structural for the conditional-branch mechanism.

**#19 Authorization contract edge_ref resolves.** Validates contract `edge_ref` is `proposed` or an existing `e-*`. Prevents contracts attached to undefined edges. (Reference integrity, same family as #7.)

**#20 Authorization back-reference resolves.** Validates `fulfills_contract: h-{id}.ac{n}` points to a real contract. Prevents resolutions that claim to fulfill phantom contracts. (Reference integrity.)

**#21 Authorization-gated disposition.** Validates `disposition:benign` ⇒ every authz contract on confirmed-weight hypotheses resolves `authorized`; `unauthorized` forces unclear/true_positive. Prevents the single most dangerous failure mode: resolved-benign on alerts whose mechanism was never proven permitted. **Most load-bearing safety rule.**

**#22 Attribute-update target shape.** Validates `attribute_updates.target` is exactly one of `v-{id}` or `e-{id}` and resolves. Prevents enrichments pointing at nothing. (Reference integrity.)

**#23 Hypothesis fork distinctness.** Validates siblings don't share `parent_vertex.classification`. Prevents redundant forks — same upstream entity hypothesized twice with different lead requirements. Branch hygiene.

**#24 Hypothesis persistence at CONCLUDE.** Validates every hypothesis whose final weight isn't `--` appears in `surviving_hypotheses`. Prevents silent drops at REPORT — agent declaring benign while quietly forgetting an unresolved hypothesis.

**#25 Same-level sibling rollup.** Validates `matched_prediction_ids` on a resolution for `h-001` come from `h-001`'s own predictions. Prevents cross-citation laundering — claiming sibling `h-002`'s matched prediction as evidence for `h-001`.

**#26 Authorization contract closure at CONCLUDE.** Validates every declared contract has a fulfilling resolution OR a `deferred_authorizations` entry with rationale. Prevents silent omission of unfulfilled contracts; forces explicit "declared but unresolved because X."

**#27 Past-case authority cap and no-sole-grounding.** Validates past-case ⇒ `authority_for_question=partial` (clause a); benign disposition requires at least one `org-authority` grounding (clause b). Prevents an investigation grounded entirely on prior-case citations; precedent supports but never alone carries disposition.

**#28 Past-case chain depth cap.** Validates a past-case citation's cited resolution has `grounding=org-authority` (not past-case again). Prevents `past-case → past-case → past-case → …` chains where no real authority sits at the bottom.

**#29 Impact prediction structure.** Validates `ip*` entries have full structure (dimension, claim, on_match/mismatch/indeterminate, escalation_on); one observable per claim. Prevents vague thresholds ANALYZE can't grade against; forces commit-before-evidence on the impact axis.

**#30 Impact resolution back-reference and grounding.** Validates `impact_resolutions` reference declared `ip*`, dimensions match, grounding ∈ {telemetry-baseline, business-owner-attestation, dlp-policy} (past-case excluded). Prevents ANALYZE retroactively shifting thresholds; blocks past-case grounding on impact (which is per-instance, not per-category).

**#31 Impact closure at CONCLUDE.** Validates every `ip*` has fulfilling `impact_resolutions` OR `deferred_impact_predictions` entry. Prevents silently-dropped impact thresholds. Mirrors #26/#34 for the impact axis.

**#32 Integrity peer discipline.** Validates authz contract on acting-entity hypothesis (session/identity/process) ⇒ peer `?adversary-controlled-*` exists OR `integrity_waived` rationale. Prevents the classic identity-of-use blind spot: confirming a service account is "authorized" without asking whether the service account was the actor on this tick. Without this, impostor-with-stolen-credentials is invisible.

**#33 Attribute-prediction structure.** Validates `ap*` entries have target/attribute/claim; one observable per claim. Prevents stereotype-shaped predictions ("looks like a probe") that don't name an attribute to read; forces implicit stereotypes into checkable observables.

**#34 Prediction closure at CONCLUDE.** Validates every `p*`/`ap*` on a non-refuted, non-shelved hypothesis is cited in some resolution OR deferred with rationale. Prevents predictions declared at PREDICT then walked past — closes the contract ANALYZE owes PREDICT (late gate; #6 is the early gate).

**#35 Sibling prediction divergence.** Validates siblings don't share identical prediction signatures (`(subject, claim)` and `(target, attribute, claim)` tuples). Prevents degenerate forks where ANALYZE has no way to discriminate; forces predictions to be the discriminator they claim to be.

## Failure-mode clusters

Grouping rules by the *kind* of failure they prevent makes the structure visible:

| Cluster | Rules | Failure prevented |
|---|---|---|
| **A. Reference integrity** | 1, 7, 12, 19, 20, 22 | Dangling/hallucinated references; phantom IDs in downstream queries |
| **B. Vocabulary control** | 2, 3 | Synonymy explosion; corpus / archetype matching breakdown |
| **C. Append-only audit** | 8 | Silent retconning of evidence or weights |
| **D. Lead provenance** | 9, 10 | Ambiguous attribution; cross-system fabrication |
| **E. Weight grounding (safety)** | 4, 5, 6, 14 | Vibes-driven weight movement; weak grounding laundering into strong weight |
| **F. Authorization integrity (safety)** | 11, 21, 26, 27, 28 | Silent benign verdicts on unproven activity; precedent-loop laundering |
| **G. Identity-of-use (safety)** | 32 | Impostor-with-stolen-credentials invisibility |
| **H. Sibling / fork hygiene** | 23, 25, 35 | Redundant forks; cross-sibling citation; non-discriminating forks |
| **I. Closure at CONCLUDE** | 24, 26, 31, 34 | Silent drops at REPORT (hypotheses, contracts, impact-preds, predictions) |
| **J. Impact axis structure** | 29, 30, 31 | Ungradeable thresholds; retroactive threshold shift; per-instance fields fed category-grounding |
| **K. SCREEN safety** | 16, 17 | Misuse of fast-path; hybrid bogus companions |
| **L. Pred-shape structure** | 18, 29, 33 | Ungradeable scaffolding (lead-preds, impact-preds, attr-preds) |
| **M. Termination shape** | 13 | Severity-ceiling as wave-of-hand escape |
| **N. Decomposition shape** | 15 | Orphaned sub-vertices (currently soft) |

Several rules appear in multiple clusters because they enforce more than one property — that's fine; the clusters are failure-modes, not partitions.

## Through this lens — what's load-bearing, what's ceremonial

**Load-bearing safety rules (cannot be removed without weakening guarantees):**
- #21 (authz-gated disposition) — the most dangerous failure mode all by itself
- #4 (edge authority cite) — strong weights require source-of-truth
- #14 (partial authority cap) — prevents weak-grounding laundering
- #32 (integrity peer) — closes the impostor blind spot
- #8 (append-only) — preserves audit trail
- #24, #26, #31, #34 (closure rules) — prevent silent drops

**Foundational structure (foundation of the type system, hard to remove):**
- #1, #7 (and their reference-integrity siblings #12, #19, #20, #22)
- #2, #3 (vocabulary)

**Discipline rules (load-bearing for hypothesis dynamics, but more recoverable):**
- #5, #6, #25, #35, #23, #18, #29, #33 — fork hygiene, prediction shape, citation discipline. If these failed, the agent could still produce dispositions; downstream queries and discriminative power would degrade.

**Perimeter rules (corner cases):**
- #13 (severity-ceiling shape), #16, #17 (SCREEN), #27, #28 (past-case)

**Soft / not actually validator-enforced:**
- #10 (mechanical leads) — semantic, hard to mechanize
- #15 (sub-vertex IDs) — explicitly review-only

**Through this lens, the consolidation possibilities from earlier are sharper:**

- **Reference-integrity merge** (#1+#7+#12+#19+#20+#22) reduces six rules to one without weakening any guarantee — they all prevent the same failure mode (dangling refs) on different ID forms.
- **Soft rules** (#10, #15) should either be promoted (write the check) or moved out of the "validator rules" list entirely — having them in the count overstates automation.
- **#27a** (past-case ⇒ partial) is an enum constraint; folds into #11 without losing its guarantee.
- **#6 / #34** are not redundant — different timing on the same closure invariant. Keep both, retitle the relationship.

**Net rule-count reduction available without weakening any failure-mode guarantee: 35 → 28.**

| Action | Rules | Net |
|---|---|---|
| Reference-integrity merge | 1, 7, 12, 19, 20, 22 → one | -5 |
| Soft → review tier | 10, 15 | -2 (or +0 if promoted) |
| #27a → #11 | 27 (single-purpose now) | 0 |

## Behaviors that may be effectively dead

Rules that *prevent failures the current agent prompts already prevent* are dead in the validator's frame — they catch nothing because nothing reaches them. Without per-rule fire-rate logs we can only guess. Top candidates to instrument first:

- **#15** — how often does decomposition happen? If nearly never, the rule guards a near-empty space.
- **#10** — review-enforced today; instrumenting requires writing the check.
- **#16, #17** — depend on SCREEN usage rate; if SCREEN rarely matches, these guard rare paths.
- **#28** — past-case-of-past-case is plausibly never written; rule may be aspirational.
- **#23 vs #35** — likely co-fire; corpus would show whether one ever fires alone.

A rule with zero corpus fires is *not* automatically dead — it might be load-bearing as a guarantee that's never tested because the agent doesn't try. But it's the right starting point for empirical pruning.

## Suggested next step

Instrument `hooks/scripts/invlang_validate.py` to log `{rule_id, run_id, fired, fixture}` to `runs/validator_audit.jsonl`. After N≥50 runs, three buckets emerge:
- **Fires often, prevents real failures** — keep, never touch.
- **Fires rarely / never, guards a real failure mode** — keep but consider whether the guard is structural or aspirational.
- **Fires rarely / never, fails to articulate a clear failure mode in this audit** — candidate for removal.

The rule-count reduction proposed above (35 → 28) doesn't require empirical data — it's safe under any fire rate because none of the merges weaken a failure-mode guarantee. Empirical data would inform a *second* pass of more aggressive cuts.
