# Invlang schema assessment — post-PREDICT/REPORT audit

Audit output for `tasks/invlang-schema-assessment-post-predict-report.md`. Measures the current legitimacy / authorization model against live corpus data, evaluates proposals to restructure it (authz-as-vertex, legitimacy-as-dimension, impact-as-vertex), and recommends next steps.

**Scope note.** The original task framed the core question as hypothesis vs prediction first-class. Separate design-discussion work (captured in conversation, not this doc) surfaced a more specific structural question: does authorization need to graduate from an edge-attribute refinement to a graph primitive, and if so, is business-level legitimacy a second orthogonal axis worth modeling? This audit answers those questions empirically against the v2.8/v2.9 corpus.

## Corpus

14 `investigation.md` files containing `legitimacy_contract` declarations:

- 9 live r5710 runs (2026-04-18 / 2026-04-19 date window)
- 3 live r100001 runs
- 2 pilot / stress-test fixtures

Sample is narrow (mostly r5710, single-week window). Findings are directional; re-measure when rule coverage broadens.

## Q1 — coverage multiplicity

*Does a single authorization contract cover multiple mechanism edges in practice?*

Empirically, no.

| Measure | Count |
|---|---|
| Contracts declared | 17 |
| Resolutions written | 7 |
| Resolutions with `target` matching contract's `edge_ref` | 7 / 7 |
| Multi-edge triples (same `(source, target, relation)`) across all 14 files | 0 |
| Contracts covering >1 edge | 0 |

Every resolved contract in the corpus covers exactly one edge — and in every case, that edge is `e-001` (the prologue edge derived from the triggering alert). Aggregate observations collapse to a single edge via `count` + `window_*` attributes (per the schema's "aggregate observations" convention), so the multi-aggregate-edge pattern sketched in the v2.5 pilot companion doesn't appear in live practice.

**Implication.** The coverage-as-set-relation argument for authz-as-vertex is not supported by the current corpus. An `authorization` vertex would carry one covered edge in every observed case — structurally equivalent to an attribute on that edge but with added indirection. Do not graduate to authz-as-vertex on this evidence.

**Caveat.** The argument could re-emerge if future signatures produce investigations where one policy decision spans multiple distinct edges (e.g., a change-window authorizing several different exec events as one block). Re-run Q1 when the corpus grows beyond r5710/r100001.

## Q2 — authz / legitimacy separability

*Does the investigation need to reason about business impact independently of authorization?*

The corpus reveals a naming problem, not a separability finding.

**Every predicate in every declared contract is a zero-trust ABAC authorization check.** Sample (verbatim):

- "monitorprobe SSH probe is a registered scheduled job OR monitoring daemon on 172.22.0.10"
- "active oncall authorization OR an open change window covers this container or host at 2026-04-18T20:37Z"
- "triple (source, target, user) is listed as an authorized entry in the approved-monitoring-sources registry"
- "a registered deploy run in the deploy-runs registry targets this container image within ±30 min of the event"

Prose scan for business-impact vocabulary across all 14 files (lowercased substring counts):

| Term | Occurrences |
|---|---|
| `business_impact` | 0 |
| `damage` | 0 |
| `business need` | 0 |
| `policy drift` | 0 |
| `shadow` | 0 |
| `devops` | 0 |
| `exfiltrat` | 1 |
| `adversarial_intent` | 0 |
| `intent` | 2 |
| `operational` | 7 |

Zero instances of business-impact or damage reasoning. What v2.8 calls `legitimacy_contract` is, in practice, an authorization contract populated as ABAC. The word "legitimacy" in the field name does not match what agents are putting in it.

**Implication #1 — rename, don't restructure.** The field should be renamed `authorization_contract`. Current semantics are zero-trust authz and the name lies about what the schema models.

**Implication #2 — impact reasoning is absent, not merely unnamed.** Agents never reason about damage / intent / business contribution — not even in prose, not even in concerns fields. Three possible causes:

1. The current signature coverage (failed SSH auth, exec attempts) doesn't exercise the impact-vs-authz separation. All current investigations can collapse to "is this authorized? → if yes, benign; if no, escalate."
2. The schema doesn't ask for impact reasoning, so agents don't produce it.
3. Impact is genuinely derivable from signature + source/target classification, and doesn't need per-investigation graph structure.

Cause 1 is most likely based on coverage. If we onboarded a data-exfiltration signature (rule-type where "authorized" and "business-damaging" can coexist — legitimate admin bulk download vs same operation by compromised account), cause 2 would become load-bearing.

## Q3 — populatability of impact axes

*For the three axes (damage, intent signal, business contribution), what fraction of investigations have evidence sufficient to resolve them?*

Near zero in the current corpus. Damage is implicit in the signature itself (failed auth → none; exec-into-container → integrity-potential); intent signal and business contribution have no evidence stream feeding them. No authority-consultation lead in any corpus file produces impact evidence; no SIEM query in any corpus file targets impact.

**Implication.** Adding impact-as-vertex now would be speculative. It would be an empty graph element in every investigation, populated by LLM-derivation from signature + classification rather than by evidence-gathering leads — which is the failure mode the graph model exists to prevent. Impact belongs in knowledge-base signature profiles (static per mechanism class), not as a per-investigation graph primitive, until we have signatures and evidence streams that make it load-bearing.

## Orphan contracts — a practical problem

Not originally scoped in the task, but the data forced attention: 10 of 17 declared contracts have no resolution in the companion (59% orphan rate). Distribution by final disposition:

| Disposition | Contracts declared | Resolutions written |
|---|---|---|
| `true_positive` | 5 | 1 |
| `inconclusive` | 5 | 2 |
| `benign` | 1 | 1 |
| (none — companion didn't conclude) | 6 | 3 |

Two contract writers (`true_positive` + `inconclusive` dispositions) together declared 10 contracts and resolved only 3. On `true_positive` the 4 unresolved contracts weren't load-bearing — disposition was already forced to escalation — but the structural invariant is still broken: agents declare authorization questions they never close.

Current validator rule #10 (back-reference) + #21 (legitimacy-gated benign) don't catch this: benign is gated on resolution, but escalating dispositions silently accept orphan contracts. The asymmetry encourages sloppy declaration.

**Implication.** Add a CONCLUDE-time check: every declared `authorization_contract` must either have a resolution in the effective set OR be explicitly deferred in a new CONCLUDE field (e.g., `deferred_contracts: [h-001.lc1, h-002.lc1]` with one-sentence rationale each).

## Option comparison

Recap of the four structural options from the original task:

| Option | Evidence support | Engineering cost | Verdict |
|---|---|---|---|
| **Status quo** | 7/7 contracts 1:1, 0 multi-edge triples | none | **RECOMMENDED** for coverage model |
| **Block rename** (`hypothesize:` → `predict:`) | No corpus evidence for or against | medium — corpus re-key + topology retrieval update | deferred; audit post-rename in Q3 2026 |
| **Schema restructure** (predictions top-level) | Discussed in conversation; has cognitive-model appeal but no corpus signal for coverage | high — migrator + validator overhaul | deferred; revisit if PREDICT stress-tests show hypothesis-shape drift |
| **Hybrid dual-write** | n/a | high + ongoing | **REJECT** — violates `feedback_no_unshipped_legacy` |

Two structural changes discussed in conversation (authz-as-vertex, impact-as-vertex) are **rejected** on empirical grounds:

- **Authz-as-vertex.** Coverage multiplicity is not observed. Adding a vertex type to model 1:1 relations is overhead, not primitive.
- **Impact-as-vertex / legitimacy-as-dimension.** Impact reasoning is absent from the corpus. No evidence stream produces it. Adding the primitive now would be a graph element populated by LLM guesswork.

## Recommended changes

In priority order:

1. **Rename `legitimacy_contract` → `authorization_contract`** (and `legitimacy_resolutions` → `authorization_resolutions`). The current name is a misnomer; corpus predicates are 100% ABAC. Rename in schema + validator + prompt + corpus migrator. Low risk, fixes misleading agent-facing vocabulary. Covered by `feedback_fix_misleading_examples_at_root`: prefer structural rename over documentation patching when the name actively misleads.

2. **Add orphan-contract gate at CONCLUDE.** Every declared `authorization_contract` must have a resolution or be listed in `conclude.deferred_authorizations[]` with a rationale. Prevents sloppy declaration and forces explicit closure. New validator rule; straightforward addition.

3. **Add `impact_profile` to signature knowledge-base.** Per-signature static field: `{damage_vector, damage_magnitude, intent_signal_by_source_class, business_contribution_by_source_class}`. Consumed by PREDICT / CONCLUDE prompts to contextualize disposition, not written to the companion graph. Gives us a home for business-impact reasoning without a speculative graph primitive.

4. **Keep block names (`hypothesize:`, `conclude:`).** The aspirational PREDICT/REPORT rename at the phase layer does not propagate to block names at this time. Revisit after one cycle of eval runs under the renamed phases.

## Validator rule audit under PREDICT semantics

| Rule | Load-bearing? | Under PREDICT action |
|---|---|---|
| #1 edge authority | yes | keep |
| #2 refutation IDs | yes | keep |
| #3 prediction completeness | yes | keep |
| #4 append-only | yes | keep |
| #5–6 trust_anchor_result | yes | keep |
| #7 screen_result scope | yes | keep |
| #8 lead-level predictions | untested in corpus; 0 uses observed | keep, re-measure |
| #9–11 legitimacy_contract / resolutions / back-ref | yes (after rename) | keep, rename references |
| #12 target shape | yes | keep |
| #13–15 asks/verdict/kind coherence | yes | keep |
| #16 supersede chain | not exercised in corpus (0 supersedes) | keep, re-measure |
| #17 fork distinctness | may become less useful under single-prediction PREDICT scaffolds — lonesome hypotheses skip the check | keep + re-measure after one eval cycle |
| #20–21 back-ref + legitimacy-gated benign | yes; but orphan loophole on escalation paths | **amend** — extend gate to all dispositions via deferred-list mechanism |
| (new) #N authorization closure at CONCLUDE | — | **add** — every declared contract resolved or deferred |

**Not adding:** token-match rules on adversarial-flavored classifications (out-of-scope per task context; bottomless pit).

## Downstream unblocks under recommended path

- **Renaming** unblocks corpus queries by axis: `authorization_contract` is unambiguously an authz thing, so "how often does authz gate disposition?" becomes a clean query. Today the field name bleeds into impact discussions and muddles intent.
- **Orphan-contract gate** unblocks honest investigations — agents can no longer declare a contract as flavor text on a hypothesis they then abandon. This should raise the signal on rule-#10 back-reference violations and expose authority-consultation gaps.
- **`impact_profile` in signature knowledge-base** unblocks real PREDICT-time prompt context: the prompt can condition on "this mechanism class has intent-signal high, damage low" to shape hypothesis seeds, without requiring the agent to re-derive this per run.

## Notes

- Memory `feedback_no_unshipped_legacy`: hybrid dual-write option is rejected on this principle. Pre-MVP; rewrite the shape, don't carry shims.
- Memory `feedback_fix_misleading_examples_at_root`: the `legitimacy_contract` rename is this principle applied — misleading field name corrected structurally, not via documentation warnings.
- Sample size is small (14 companions, narrow rule coverage). Re-run Q1 + Q2 after either (a) signature breadth doubles or (b) a signature lands where authz and impact clearly separate (e.g., data-exfiltration-style rules).
