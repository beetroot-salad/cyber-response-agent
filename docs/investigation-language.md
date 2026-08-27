# Investigation Language

**Status:** Spec v2.23. Implemented.
**Query tool:** `soc-agent/scripts/invlang/` — see `cli.py --help`
**On-disk surface:** `​```invlang` fenced blocks. `​```yaml` fences in `investigation.md` are rejected by the validator, and so is a write that introduces a block header OUTSIDE any fence — rows written there are not parsed, so they reach no rule and no corpus query. A trailing unterminated `​```invlang` is exempt: that is a write cut off mid-block, which the next append closes. Block-tag grammar (`:V` / `:E` / `:H` / `:L` / `:R` / `:T` / `:G`), row shapes, and the surface-to-canonical-dict projection live in `docs/dense-investigation-format.md`. The canonical companion dict — what the validator and the corpus queries operate on — is what every block projects to via `soc-agent/scripts/handlers/_dense_parser.py`.

**v2.23 delta:** doc-only, and no rule is added or struck — **the active count stays at 26** (#932).

- **Rule #5 gains a scope note: refutation spans two phases.** The refutation *shape* is authored at PLAN (`:H h-NNN.refuts`) and its `refutes` cell validated there against the declaring hypothesis's predictions (`_check_refutation_scope`); refutation *matching* is graded at ANALYZE, and that is what rule #5 states. Nothing changes about what either half refuses. The note exists because a finding about refutation was being attributed to ANALYZE by default, sending shape defects to the wrong prompt — which is how an experiment's top-ranked PLAN failure mode came to be a measurement of a schema field that did not yet exist.
- **The surface rule gains its quiet half.** `_check_surface` refused a ```yaml fence and nothing else, so a block written under NO fence — the shape a run produces when it closes its ORIENT fence, writes prose, then continues with `## PLAN` and its `:H` rows — landed clean and parsed to nothing. Every hypothesis-side rule stood down on an empty companion, and the append-only fence COUNT check saw no decrease because the write added no pair rather than removing one. Now refused, scoped to the headers THIS write introduces so a document already carrying unfenced rows is not wedged, and exempting a trailing unterminated fence, which is a write cut off mid-block rather than an orphaned one. Measured before arming: over the 27 documents in the tree carrying invlang, exactly one investigation fires — the run that prompted it — and no shipped golden, worked example or SKILL fence does.
- **A proposed PLAN-side atomicity gate on `refuts` rows was measured and refused**, and does not become rule #37. It has no gap entry here because it was never a rule; the measurement and the argument are in `docs/decisions/defender-invlang-enforcement-ramp.md` §Why a refutation-atomicity gate is not a rung. Short form: a refutation scoped `refutes: p1,p2` overturns `p1 ∧ p2`, so `¬p1 ∨ ¬p2` is the correct rendering and a lexical AND/OR test reads the correct rendering as the defect — it fires on 48% of the refutation rows in the tree, `defender/SKILL.md`'s own teaching block and a shipped e2e golden among them. Same disposition, same reason, as #32 and #36.

**v2.22 delta:** the two APPEND-ONLY WEDGES are closed (#933 follow-up). **The active count is unchanged at 26** — rules #6 and #17 both keep their numbers; #17 loses one of its three clauses and #6 changes which documents it speaks about, neither adds or strikes a rule.

- **The invariant both broke.** A validator over an append-only document may refuse a row only for something knowable when that row is written. Both rules refused a document that had validated CLEAN, turned into an error by a LATER legal append, naming a committed row no write can reach back into — and in both cases the repair the message offered was one the author could not take.
- **Rule #6** compared a growing cited set against a growing DECLARED set. `:H h-NNN.preds` arrives by append, so declaring one more prediction on a hypothesis already carrying a committed `++` turned that row into a `++` that no longer covered its own hypothesis. The offered repair — grade `+` — did nothing, because the rule keyed on the first `++` any row ever wrote. It now asks whether the hypothesis STANDS at `++` (`_confirmed_and_standing`), so appending `h-NNN ++ → +` withdraws the coverage claim and clears the refusal. **Standing is COUNTED off each row's own `before`/`after` pair, never folded over an order the projection does not carry.** A row entering `++` scores +1, one leaving it −1, a `++ → ++` restatement neither; on a chain whose rows join up the net is positive exactly when the last move left the hypothesis at `++`. Counting is what makes the reading order-free *and* keeps it honest in both directions — `_walkers.final_weights` resolves last-move-wins by LEAD-DECLARATION order rather than append order, so on a multi-lead document a `++` on a later-declared lead beat a withdrawal on an earlier one; and a bare "was it ever withdrawn" set fixes that while breaking the other way, standing the rule down for good on a hypothesis that appends `+ → ++` and grades itself `++` again. Both cells are read closed on the weight-cell vocabulary, so `++ → null` and `++ → ∅` withdraw like any other exit while a misspelled `++ → confirmd` moves nothing and takes nothing back. What follows a withdrawal is #34's business at CONCLUDE. Rule #34's exclusion moves to the same predicate in the same change: split across two spellings, a confirmed-then-downgraded hypothesis would fall in the gap and its uncited predictions would be asked about by neither rule.
- **Rule #17's intermediate-lead clause is struck** as unenforceable by shape, the same disposition v2.19 gave #32. Whether a screen lead is the sequence's last depends on leads not yet written. The implementation had already carved `match` out of the arm for exactly this reason; the carve-out was the whole rule.

**v2.21 delta:** seven more documented-but-unarmed rules implemented (#933) — #13, #18, #26, #29, #30, #31, #34. **The active count does not change and stays at 26**: nothing is added and nothing is struck, seven numbers stop being aspirational. Each now carries an **Implemented as `<function>`** line, continuing the v2.20 backfill; 14 of the 26 active rules now have one (the five from v2.20, these seven, plus #7 and #21), and the 12 that do not are the backfill still owed.

- **Two parser holes had to close first, and closing them is the load-bearing half of this change.** Every `:T conclude.*` sub-block except `conclude.surviving` was recognized, consumed and dropped by a bare `return True`, and `:L l-NNN.lead_preds` / `.impact_preds` were documented and unprojected (#820). So rules #18, #26, #29, #30, #31 and #34 had nothing to read. The three `:T conclude.deferred_*` tables now project to `Conclude.deferred_{authorizations,impact_predictions,predictions}[]` and the two `:L` blocks to `findings[].{predictions,impact_predictions}[]`. **The deferral tables landed in the same change as the rules that demand them** — arming "every declared X must resolve" over an unprojected escape hatch would refuse documents whose author had already written the answer.
- **`ceiling_test` is a repeated flat row, not a sub-table.** `docs/dense-investigation-format.md` specified `:T conclude.ceiling_test [kind|subject]`; the shipped surface (`skills/invlang/SKILL.md`, eleven checked-in lessons, `schema.Conclude.ceiling_test: list[str]`, the judge prompt, and every `:T conclude` block on disk) writes one flat `ceiling_test  "<gap>"` row per unreachable check. The flat row is real; the format doc is reconciled to it, and a block written under the retired sub-table spelling is still accepted and ignored rather than refused.
- **Rule #13 ships at half its stated width, and the half that ships fails silent.** Only "required when `termination.category: severity-ceiling`" is enforced. The "forbidden otherwise" half is not, and should not be: it was written against the pilot spec's `ceiling_test: {kind, subject}` — THE out-of-band step that would resolve a ceiling — while the shipped field is the list of checks a run could not make, which eleven lessons instruct writing whenever a source was out of reach. And the trigger is unbacked: `termination.category` is free text with no vocabulary, so a typo disables the rule in silence. The vocabulary was NOT closed here — the spec's four values are contradicted by both shipped e2e goldens (`data-ceiling`, `adversarial-confirmed`) and by three test corpora (`exhaustion`, `adversarial-confirmed`, `natural`). See the note on the rule.
- **Rule #18's route-compliance clause is not implemented, and honouring "warning" is why.** The spec asks for a warning when the following lead's `name` matches no `advance_to`. In this codebase a warn diagnostic with no `Locus` is dropped by `runtime/tools._addressable` and does nothing at all, while one WITH a locus FLAGS that row and blocks every subsequent write until `fix_row` rewrites it. Both candidate rows must not be rewritten: the follower's `:L findings` row is a committed lead declaration the warn family has never been able to reach, and letting a run edit its own `lead_preds` pre-registration to match where it ended up destroys the only thing pre-registration is for. Upgrading it to an error would not honour the spec. Recorded as a gap inside an otherwise-implemented rule.
- **Rule #31's two conclude VOCABULARIES are taught and not armed.** `skills/invlang/SKILL.md` has never stated `impact_verdict ∈ {none, within, exceeds, indeterminate}` nor `impact_severity ∈ {null, low, moderate, high}`; both live only here, and refusing on a vocabulary the runtime prompt never gave the model is the failure rule #32 was struck for two revisions ago. `impact_verdict` carries the measurement: it fires on both shipped e2e goldens (`none-detected`, `attempted-lateral-movement`), and those are not authored fixtures whose cell can be corrected — they are recorded runs replayed through this very gate from `tool_trace.jsonl`, so arming it refuses the recorded write and takes seven e2e tests with it. `impact_severity` measures zero fires and is left unenforced with it; the two are one decision. Both are registered in `vocab.SLOTS`, which IS the teaching step. #31's closure arm and its structural `impact_severity`-required-iff-`impact_verdict` clause ARE armed, and neither depends on a membership test.
- **#26, #31 and #34 are one rule over three namespaces** — *every declared X is resolved, or deferred with a reason* — and share one implementation of the closure walk (`_unclosed_commitments`), with each rule keeping its own declared set, its own definition of resolved, and its own prose. #31's text already said it "mirrors rule #26's orphan gate".
- Severity: all seven land at **error**. Measured over every distinct ```invlang `investigation.md` in the tree, `defender/tests/_golden_invlang/`, `defender/examples/`, and every ```invlang fence in `defender/SKILL.md` and `defender/skills/invlang/SKILL.md` (32 validation units, re-measured against the post-#934 corpus): #13, #18, #29, #30 and #31 fire on nothing; #26 fired once on `examples/example-c-cumulative-escalation.md`, which was genuinely non-compliant and is fixed here; #34 fires on one distinct document — the experiment fixture rule #6 already fires on, checked in twice byte-identically — which is genuine and left as it is. #34 also fired once on `examples/example-c`, where #934's rewrite had packed two citation heads into one `:T resolutions` row and the grammar reads only the first; the second head is now its own row and the example is clean. No shipped golden fires on any of the seven, and `defender/tests/test_shipped_invlang_documents.py` is the standing guard on that.

**v2.20 delta:** five documented-but-unarmed rules implemented (#933) — #6, #17, #23, #24, #33. Rule count unchanged at 26: nothing is added or struck, five numbers stop being aspirational. Each of the five now carries an **Implemented as `<function>`** line naming the function in `defender/skills/invlang/validate.py`, joining rule #21 — the absence of any rule → function link anywhere in this section is what let five rules sit unenforced across three spec revisions with nobody able to tell. Rules without such a line are not thereby implemented; the backfill is #933 follow-up work.
- Rule #24 is trimmed a second time. Two of arm (b)'s three sub-arms are excised as unbacked (`termination` is free text and an unchecked scalar; `matched_archetype` is read by zero production code and resolves against no catalog), and the surviving arm is scoped to closes that WRITE a `:T conclude.surviving` table — see the note on the rule.
- Severity: #6, #17, #23, #24 and #33 all land at **error**. Measured over the same 32 units, re-measured against the post-#934 corpus: #17, #23, #33 and #24-as-implemented fire on nothing; #6 fires on one distinct document (checked in twice byte-identically as `experiments/judge-glm52-vs-kimik3/fixtures/case-00{1,2}`), an experiment fixture capturing model output, genuine — a `++` on a hypothesis whose own third prediction the run's leads had contradicted. No shipped golden and no worked example fires.
- Rule #33's uniqueness clause needs no implementation and gets none — see the note on the rule. *(#35 was the other clause of that shape, and v2.19 above took it further: a rule that needs no implementation because another rule already refuses strictly more of it is not a rule, and #35 is struck.)*

**v2.19 delta:** one rule struck and one gap finally written down — 27 → 26 active. Arithmetic: 36 numbers − 10 gaps = 26; the gap list grows from nine to ten with #32. #35 is the tenth number but not a tenth strike: v2.17 merged it into #23 and counted it as a gap in the header, while leaving its entry standing as a rule. This is where the entry catches up with the count. Doc-only, and doc-only in the strict sense: neither rule was ever implemented anywhere in this repository. `defender/skills/invlang/validate.py` has no `_check_integrity_peer_discipline` and no `_check_sibling_prediction_divergence`; both names survive only in `experiments/relax-invoker-identity-peer/`, against a `soc-agent` tree this repository does not contain.
- **Rule #32 (integrity peer discipline) becomes the tenth gap.** Four independent reasons, argued in full at the rule's entry: it is universally non-complied-with (of the 10 content-distinct hypotheses in the corpus carrying an `authorization_contract`, 6 satisfy #32's trigger, all 6 fail it, 0 discharge it — two of the six are shipped goldens, one is a shipped worked example, and one is the runtime SKILL's own canonical "Right" answer); its discharge test is a `name.startswith("?adversary-controlled-")` prefix match on model-authored free text, the same lexical-token experiment #36 already ran and v2.16 already reverted; arming it would mint six `?adversary-controlled-X` rows written to clear the gate rather than to test integrity, the manufactured-compliance failure #934 measured one rule over; and it reinstates the "maintain adversarial hypothesis until `--`" bookkeeping rule that `docs/decisions/adversarial-as-attribute-not-hypothesis.md` item 6 dropped and that rule #21 says it replaced. **The coverage gap it leaves is real** — authorized-bulk-read-from-a-compromised-account clears authz, clears impact, and never tests the integrity premise. The recorded answer to that gap is not a structural gate but §Hypothesis → *Behavioral-consistency prediction*, and the gap entry says so.
- **Rule #35 (sibling prediction divergence) was made the eighth gap at v2.17** and is rewritten as one here — subsumed by rule #23 as reconciled and implemented in #934 as `_check_fork_distinctness`. #35's signature is `predictions[]` `(subject, claim)` plus `attribute_predictions[]` `(target, attribute, claim)`; #23 keeps the attribute-prediction tuple whole and drops `subject` from the prediction one, so every pair #35 refuses #23 refuses too, plus the pair that wrote one sentence under two subject labels. Strictly stronger, same sibling group, same empty-signature skip. v2.17's header already counted #35 as a gap; this is where the entry catches up and stops calling it a rule.
- **Rule #23 now owns the empty-signature skip.** It was stated as "per rule #35's convention" while #35 was the rule that had it. With #35 struck the convention has nowhere to be borrowed from, so #23 states it.
- **`integrity_waived?` is now read by nothing.** The column is in the `:H` grammar, the parser projects it (`defender/skills/invlang/parser.py`), `HypothesisRecord` types it (`schema.py`), and every worked example emits it — and with #32 struck no validator rule consumes it. It is NOT removed here: removing a projected column is a grammar change with a parser, a schema, and roughly thirty test fixtures behind it, and the field still has a use as an authoring note. Recorded as an unread column pending a decision.
- Gaps are now #10, #12, #15, #16, #19, #20, #22, #32, #35, #36 — ten of the 36 numbers, leaving 26 active.
- **Not re-armed, and #32 not re-armed under a different discharge test.** Struck, not rewritten. Reasons 3 and 4 argue against the rule's *shape*, not against its spelling; a structural gate on integrity is the thing being rejected, so replacing the prefix match with a better one is not the follow-up.

**v2.18 delta:** retired-vocabulary trim — 28 → 27 active rules. Doc-only; no validator behaviour change, because there was no behaviour to change. Rule #36 and the escalation clauses of #21/#24 were specified against a disposition vocabulary the system never had: `true_positive`, `unclear`, and a `status: escalated` routing target. The live run-disposition enum is `DISPOSITION_VALUES = ("benign", "false-positive", "inconclusive", "malicious")` (`defender/_vocab.py`), and `true_positive` has never appeared anywhere under `defender/` in the repository's history — this was not a rename that drifted out of sync, the spec invented a vocabulary and the code never adopted it.
- Rule #36 (affirmative `true_positive` disposition) becomes the ninth gap. Its entire substance is a constraint on routing a value the enum cannot express, and nothing enforces it: `true_positive` has zero occurrences in `defender/skills/invlang/validate.py`, and the `hooks/scripts/invlang_checks_authorization.py:_check_affirmative_true_positive` the v2.14/v2.16 deltas cite does not exist. Numbering preserved with a redirect note, per the v2.15 convention.
- Rule #21 keeps its **benign** half, which is implemented — `_check_benign_authz` in `defender/skills/invlang/validate.py`. Its **escalation** half (the `status: escalated` forcing and the disposition ∈ {`unclear`, `true_positive`} floors) is excised, here and in its §Authorization prose restatement. Rule #24's trailing `status: escalated` clause is excised for the same reason; the persistence rule itself is untouched.
- §Two-axis CONCLUDE restated in the live enum (`true_positive` → `malicious`, `unclear` → `inconclusive`), which is a spelling correction, not a semantic one — `defender/_vocab.py` documents `malicious` as the confirmed-threat landing and `inconclusive` as the nothing-established landing.
- Gaps are now #10, #12, #15, #16, #19, #20, #22, #35, #36 — nine of the 36 numbers, leaving 27 active. (#35 is v2.17's, not this delta's.)
- **Not re-armed under the live spelling.** Struck, not translated. #36's substance survives translation and #21's escalation half largely does (see the notes at each), but re-arming a rule under a new vocabulary is a separate decision; these are gaps until someone makes it.

**v2.17 delta:** rule #23 (hypothesis fork distinctness) re-keyed from
`proposed_edge.parent_vertex.classification` onto the predicted observable, and
rule #35 (sibling prediction divergence) merged into it — the two stated one check
once the axis moved. `??` added to §Types escapes and rule #2 as the open-slot
marker on a `parent_class` nothing closes. §Three shapes of adversariness and
§Hypothesis reworded so the adversarial peer is distinguished by its predictions
rather than by its classification. Active-rule count 29 → 28. Rationale and the
prompt-side change: #934; validator implementation
`defender/skills/invlang/validate.py:_check_fork_distinctness`.
- The header count moved to eight gaps here, but #35's ENTRY was left standing as a
  rule with a "merged into #23" note, so the list still read 36 numbers against
  seven gap entries — 29, not 28. v2.19 rewrites the entry and closes that.

**v2.16 delta:** *(Superseded by v2.18 above: rule #36 is struck as retired vocabulary. The implementation path cited below does not exist in this repository. Left as written for the record.)* rule #36 simplified — `disposition: true_positive` now requires only `++` on a surviving hypothesis (weight-only). The v2.14 adversarial-classification token check is removed; the lexical token list desynced from playbook-canonical fork names (e.g. `?credentials-used-outside-registered-actor`) and produced false rejections of legitimately-graded `true_positive` routings. The affirmative-evidence signal is captured by the `++` requirement; the "wrong-named survivor" failure mode is caught by Tier-2 judges and rule #21. Validator implementation: `hooks/scripts/invlang_checks_authorization.py:_check_affirmative_true_positive`. Parser-side X5 (`scripts/handlers/_output_parser.py:_validate_cross_block_invariants`) similarly weight-only.

**v2.15 delta:** Validator rule consolidation — 36 → 29 active rules *(29 was current until v2.17 above, which merges #35 into #23; v2.18 then strikes #36 and v2.19 #32, and the count is now 26)*. Doc-only refactor; no validator behavior change. Drives:
- Reference-resolution merge: rules #12, #19, #20, and the resolution clause of #22 fold into rule #7. Single "all references resolve in scope" rule covers `v-*`, `e-*`, `h-*`, `l-*`, hierarchical `h-{parent}-{nonce}`, contract `edge_ref`, `fulfills_contract`, and `attribute_updates.target`.
- SCREEN structural integrity merge: former #16 (screen_result scope) absorbs into #17.
- Schema-validity scope expansion: rule #1 absorbs former #15 (sub-vertex `v-{parent}-{nonce}` shape) and the exclusivity clause of former #22 (target shape).
- Past-case ⇒ partial enum constraint moves from former #27a to rule #11; #27 retains the no-sole-grounding rule for benign.
- Demotion: former #10 (mechanical leads stay within data source) is now a review-only discipline guideline — semantic, not validator-enforced. Retained in §Conventions.
- Numbering preserved with redirect notes at the seven gaps (#10, #12, #15, #16, #19, #20, #22) so existing code, prompt, and test references to those rule numbers remain greppable. Rule #36 (v2.14) is unaffected by the consolidation and counts toward the 29 active rules. *(Superseded: #35 became the eighth gap at v2.17, #36 the ninth at v2.18 and #32 the tenth at v2.20, leaving ten gaps and 26 active rules. The 36 → 29 arithmetic below describes v2.15 as it landed and is left as written.)*
- Per-rule audit: see `docs/invlang-rule-audit.md` (added 2026-04 alongside `docs/dense-investigation-format.md`).

**v2.14 delta:** *(Superseded by v2.18 above: rule #36 is struck as retired vocabulary. The implementation path cited below does not exist in this repository. Left as written for the record.)* rule #36 — affirmative `true_positive` disposition. Closes the absence-of-benign-confirmation cascade (4 production runs documented in `docs/decisions/analyze-true-positive-routing.md`) by structurally rejecting `disposition: true_positive` writes whose `surviving_hypotheses[]` carries no hypothesis that is both adversarially-classified AND graded `++`. Validator implementation: `hooks/scripts/invlang_checks_authorization.py:_check_affirmative_true_positive`. Empirically motivated: trap-set evaluation showed prompt-only guidance lets ~50% of false-true-positive cases through; the structural gate raises catch rate to ~100%.

**v2.13 delta:** Tier-0 contract-completeness rules between PREDICT and ANALYZE.
- Rule #34 (prediction closure at CONCLUDE) — at REPORT, every declared `p*` / `ap*` on a non-refuted hypothesis must be cited in some resolution's `matched_prediction_ids[]` with a non-null `after`, OR appear in `conclude.deferred_predictions[]` with rationale. Generalises rule #6 (which only fired on `++`) into a coverage gate at REPORT regardless of weight. New conclude surface: `deferred_predictions[]` (parallel to `deferred_authorizations[]` and `deferred_impact_predictions[]`).
- Rule #35 (sibling prediction divergence) — *(Superseded: #35 was merged into rule #23 at v2.17 and rewritten as a gap entry at v2.19, and the rule #32 it generalises is struck at v2.19 too. Left as written for the record.)* within a sibling group (shared `parent_hypothesis_id` + `attached_to_vertex`), no two siblings may declare identical prediction signatures (combining `(subject, claim)` from `predictions[]` and `(target, attribute, claim)` from `attribute_predictions[]`, case-normalised). Generalises rule #32 (integrity-peer-specific, contract-gated) to all sibling forks regardless of contract presence.
- Companion to spec rule #33 (attribute-prediction structure) — already in schema.md; documented here for completeness.

**v2.12 delta:** top-level block rename `gather:` → `findings:`. Same merge semantics (same-id append; ANALYZE merges outcome.resolutions + verdicts onto the GATHER-populated entry), clearer name for cross-phase state. Handler-authored: subagents emit plain-YAML envelopes; `scripts/handlers/gather.py` + `scripts/handlers/analyze.py` synthesize `findings[]` and merge via the existing validator. Raw SIEM/anchor payloads moved off the companion to `runs/<run-id>/raw_details/loop-<N>/<lead-id>.yaml`; analyze-handler preloads them per-loop.

**v2.11 delta:** three orthogonal resolution axes named explicitly.
- **Impact** promoted from a signature-knowledge hand-wave to a lead-level first-class record. `impact_predictions[]` on leads declare threshold predicates before evidence lands; ANALYZE grades observations against them and emits `impact_resolutions[]` on lead outcomes; `conclude.impact_verdict` and `conclude.impact_severity` are a second axis alongside `disposition`. The authorized-but-malifying class (authorized bulk read at 3σ above baseline; authorized admin delete of 10 000 rows) resolves here — not on authz. Signature-tier `impact_profile.md` deferred pending corpus measurements; per-signature impact knowledge lives in playbook prose until threshold drift is observed.
- **Integrity** promoted from a paragraph under §Authorization to its own §Integrity section. Mechanism-hypothesis placement reaffirmed (`?adversary-controlled-*` peers with predictions on discriminating observables); integrity is evidential, not anchored, and not a contract. Discipline: `authorization_contract` on a hypothesis whose predicted edge has an acting-entity source (`session`, `identity`, `process`) expects a peer integrity hypothesis unless `integrity_waived: <rationale>` is present — closes the authorized-bulk-read-from-compromised-account shortcut. Forthcoming validator rule; guidance applies today. *(Superseded by v2.20: the forthcoming validator rule — #32 — never arrived and is now struck; the mandate half of this discipline is struck with it, here and in its §Integrity prose restatement. The representational half — an integrity concern is a peer mechanism hypothesis with predictions on discriminating observables, not a contract — is unaffected and still current.)*
- **Hypothesis cardinality 0-N** made explicit. §Lean hypotheses renamed §Hypothesis cardinality and leanness, with a table mapping cardinality to intent (0 = enriching, 1 = mechanism pinned, 2-3 = observable-diverging peers, >3 = refine under a hierarchical parent). Mirrors PREDICT Shapes D/E/I/A/M in `soc-agent/agents/predict.md`.
- **Terminology cleanup.** `vertex.trust_root: true` attribute dropped — unvalidated and unqueried; the signal already lives on `outcome.trust_root_reached: v-{id}` (ref-checked) and `conclude.termination.category: trust-root`. "Anchor" reserved for external authority surfaces (`anchor_id`, `anchor_kind`, `anchor_consultations[]`); the "anchor:" gloss on `attached_to_vertex` removed — the field name self-explains.

**v2.10 delta:** motivated by `experiments/invlang-post-predict-assessment.md`.
- Rename `legitimacy_contract` → `authorization_contract` and `legitimacy_resolutions` → `authorization_resolutions`. The v2.8 name was a misnomer — 100% of corpus predicates are zero-trust ABAC authorization checks, not business-impact legitimacy reasoning. Business-impact legitimacy is parked at the signature knowledge-base layer (`impact_profile`), not the graph.
- `authorization_resolutions[]` becomes self-describing: each resolution carries `anchor_id`, `grounding_kind`, `authority_for_question`, `effective_window`, and `conditioning_context: []`. Authz provenance and temporality live on the resolution they justify.
- Anchor consultations that inform hypothesis weight but do not fulfill a contract (baselines, registry lookups, reference queries) keep a structured home at the lead outcome level: `anchor_consultations[]` — the v2.10 successor to v2.9's `trust_anchor_result`, narrowed to non-authz consultations and renamed because it records a consultation event, not a singular result. Keeps baseline/expectation evidence first-class instead of demoting it to prose.
- `authorization_resolutions[].grounding_kind ∈ {org-authority, past-case}` — baselines cannot ground an authz verdict. `anchor_consultations[].grounding_kind ∈ {org-authority, telemetry-baseline}` — past-case citations are authz-only. `past-case` uses a structured citation (`cites_past_case.run_id`, `cites_past_case.contract_ref`). Constraints: force-caps `authority_for_question` to `partial`; cannot be sole grounding for benign disposition; a past-case cannot cite another past-case as its grounding (depth cap).
- `conclude` gains `deferred_authorizations[]` — every declared `authorization_contract` must resolve OR appear here with rationale (validator rule #26). Closes the orphan-contract loophole where escalation paths silently accept unresolved contracts.
- Validator rules #19–#21 renamed `legitimacy_*` → `authorization_*`; rules #26–#28 added (orphan gate, past-case authority cap, past-case depth cap).

**v2.9 delta:** validator rules #24 (hypothesis persistence at CONCLUDE) and #25 (same-level sibling rollup for `matched_prediction_ids`). Closes two bias gaps identified during the ANALYZE-phase state-machine cutover: silent hypothesis drop across loops, and cross-sibling prediction-ID citation. See `.claude/skills/migrate-state-machine/SKILL.md` for the design context.

**v2.8 delta:** authorization as first-class edge attribute (`edge.authorization_resolutions`) driven by hypothesis-declared contracts (`hypothesis.authorization_contract`); `attribute_updates` extended to edge targets; validator rules #19–#22; supersedes the former "maintain adversarial hypothesis until `--`" bookkeeping rule. (Originally shipped with `legitimacy_*` names — renamed in v2.10; see above.)

A structured schema for recording security investigations as graph
traversals. Designed for SOC-level alert triage: the agent works
backward from an observed alert until it reaches trust-authoritative
sources or exhausts available tools.

---

## Goals

**Elegant.** Small number of primitives; everything else derivable.
No field exists solely to carry information already present in the
graph structure.

**Readable.** A companion is a document. An analyst reading it should
be able to follow the investigation's reasoning without parsing schema
headers.

**Writable.** An LLM writing a companion should rarely need to look up
a rule. The schema nudges correct behavior through structure; edge
cases are rare.

**Searchable.** Companions support corpus queries that measure
investigation effectiveness: which hypothesis patterns recur, which
leads are most discriminating, where investigations stall and why.

---

## Philosophy

### The investigation graph

An investigation maintains two layers at all times.

**Confirmed graph** — vertices and edges backed by observation
authority (SIEM events, runtime audit, authoritative sources). Grows
monotonically; nothing is ever mutated.

**Proposed frontier** — candidate graph extensions, one per active
hypothesis. Each hypothesis proposes that a specific upstream vertex
exists, connected to the confirmed graph by one edge. Leads test
whether proposed elements actually exist, moving them from proposed
to confirmed (or refuting them).

The investigation progresses by running leads that collapse the
frontier. It halts when the frontier is empty (all hypotheses
resolved) or the confirmed graph reaches a vertex where no accessible
upstream exists — a **trust root**.

This maps to graph search: the confirmed graph is the explored set;
the proposed frontier is the candidate set; each lead is an edge
measurement. The difference from static graph search is that the
graph is being constructed as it goes — each lead can both test
existing proposals and introduce new vertices that open the next
layer of questions.

### Backward traversal

Investigations look backward: observation → cause → cause-of-cause
→ until a trust root. The driving question at each step is *why does
this edge/vertex exist?* The confirmed answer becomes the new anchor
for the next question.

**Depth is forced by evidence.** Do not propose a deep causal chain
at loop 1. Form the immediate discrimination question; deepen only
when a lead confirms the current anchor and opens the next layer.

### Unknowns and focus questions

An investigation always has more open questions than the next loop can
reasonably test. Treat these as unknowns: immediate mechanism,
immediate actor, upstream actor, authorization, actor integrity,
impact, scope, observability gaps, and any case-specific dimension
that a prior phase surfaced.

Unknowns are not hypotheses. An unknown names what is not solved; a
hypothesis is one candidate answer with predictions and refutations.
PREDICT should pick the one current focus question that is reducible by
the next lead, preferring mechanism-shaped questions close to the alert
over upstream or authorization questions unless the alert authority has
already pinned the mechanism.

In the current dense format this is a prompt discipline, not a stored
schema surface. The focus question is expressed through existing
fields: Shape E lead-level readings, Shape A/M stories and predictions,
and routing rationale. A future schema may make focus questions
explicit, but omitted unknowns are not structurally solved today.

### Scale of reasoning

Model at the granularity the investigation reasons at, not finer.
A process vertex is opaque until the investigation needs to
distinguish sub-entities within it — because different sub-entities
would lead to different hypotheses, different leads, different
conclusions. Before that point, the entity is atomic and its
internal structure is transparent to the investigation.

When a lead reveals heterogeneous internal structure that changes
the investigation's trajectory, decompose into sub-vertices linked
by `component_of`. The parent vertex and its existing edges remain
valid; coarse observations are still true. Fine-grained edges
specialize them — they do not replace them.

**Cartography principle.** A world map renders an island opaque; a
city map shows streets; a floor plan shows rooms. The right
resolution depends on the question being asked. Pre-decomposing adds
entities the investigation hasn't needed to reason about — graph
clutter without discrimination value.

### Hypothesis cardinality and leanness

The loop authors **0 to N** hypotheses per PREDICT pass (realistically
N ≤ 3). Cardinality is not a structural requirement — it's a
discrimination commitment. Author a hypothesis when naming it makes a
bias explicit or partitions lead selection; don't author one when the
next move is pure enrichment.

| N | When | What the hypothesis does |
|---|---|---|
| 0 | Alert under-specified; the next lead enriches before a fork is possible | — |
| 1 | Mechanism pinned by alert fields; only authz, integrity, or impact open | Makes the open axis explicit; drives lead choice |
| 2–3 | Mechanisms diverge on already-observable fields | Makes the discriminator explicit; partitions leads |
| > 3 | Usually a refinement that belongs under a hierarchical parent | Emit children as `h-{parent}-{ordinal}`; retire the parent by resolving it |

Cardinality is structural in the companion: the `hypothesize:` block
is present iff ≥ 1 new hypotheses are authored this loop. Omission
means "continue the existing frontier." See PREDICT Shapes D/E/I/A/M
(`soc-agent/agents/predict.md`) for the authoring decision procedure.

A hypothesis, when authored, captures the **immediate next
discrimination question**, not a deep causal narrative. A lean
hypothesis has 1–2 predictions: the minimum that distinguishes it
from competing hypotheses.

Pre-committing to a deep narrative fragments the hypothesis space
across cases that should match the same retrieval pattern, creates
prediction IDs for facts not yet in evidence, and makes weight
accumulation harder. Refine into more specific children only when
evidence forces the distinction.

### Authorization as edge attribute

Authorization — is this edge *permitted by policy*? — is a property
of the (`source_vertex`, `edge`, `target_vertex`, `authority`)
quadruple at time T. The same `read` edge from a session to a storage
object is authorized when the session's identity carries the required
role and unauthorized when it does not. The mechanism is identical;
only the verdict differs. Authorization therefore lives **on the
edge**, not as a parallel hypothesis.

A hypothesis whose disposition depends on authorization declares an
`authorization_contract` naming the edge(s) whose verdict is
load-bearing and the authority that resolves them. When the resolving
lead fires, the edge gains an `authorization_resolutions` entry with
the verdict and a back-reference to the contract. Append-only is
preserved by backward traversal: the hypothesis is written once and
never mutated; the materialized edge points backward via
`fulfills_contract`.

**Authorization ≠ business-impact legitimacy.** The field was called
`legitimacy_contract` through v2.9 and renamed in v2.10 because the
name was a misnomer — agents consistently populated it with zero-trust
ABAC predicates ("is this triple listed in the approved-sources
registry?"), never with business-impact reasoning ("does this event
help or damage business needs, and by how much?"). Business-impact
legitimacy is a real but separate axis — direct damage (CIA effects),
intent signal (does this event indicate adversarial intent), and
business contribution (does this serve a sanctioned goal). Those axes
are knowledge-base concerns tied to mechanism class, not per-instance
graph elements — they live in `knowledge/signatures/{id}/impact_profile.md`,
consumed by PREDICT/CONCLUDE prompts to contextualize disposition.

**Three shapes of adversariness.** Not every adversarial question is
an authorization question:

- **Mechanism-level** — enumerate an `adversary-controlled` story
  alongside the benign one when they predict observationally distinct
  world-states. Normal mechanism enumeration; no contract needed. It
  is the PREDICTIONS that must diverge, not the classifications
  (rule #23) — the two peers may share a `parent_class`, open or not.
- **Attribute-level (policy authorization)** — same mechanism, same
  observables, but an authority would answer "allowed" differently
  depending on the source identity. This is the authorization
  contract case. Common.
- **Future-edge** — the adversarial signal is a separate downstream
  edge (a failed-auth alert followed by an unexpected success). That
  is a topology question; write it as its own hypothesis attached to
  the hypothetical future edge.

**Contracts answer policy, not integrity or impact.** A contract asks
"is this edge allowed by the relevant authority?" It does not ask
"was this edge actually executed by the claimed actor?" (integrity —
see §Integrity as mechanism enumeration) or "does this edge's effect
matter enough to escalate?" (impact — see §Impact as lead-level
prediction). The three axes are orthogonal and resolve through
different machinery.

### Integrity as mechanism enumeration

Integrity — *is the acting entity what it claims to be?* — is a
separate axis from authorization. Session hijack, token theft, MFA
bypass, process hollowing, tool masquerade are integrity questions:
if the impostor is presenting valid credentials, the IAM anchor will
answer "authorized" about the claimed identity. That verdict is
correct under the authz question's scope; it does not address whether
the session is actually the claimed session.

Integrity is **evidential, not anchored.** No single authority
answers "is this session compromised?" — the answer is composed from
behavioral observables: application-layer correlation, query-shape
template match, impossible travel, device-fingerprint mismatch,
anomalous timing against baseline, presence or absence of a
correlating upstream request.

**Representation: mechanism-hypothesis peers, not contracts.** An
integrity concern produces a peer hypothesis
(`?adversary-controlled-<entity>`) alongside the routine-mechanism
hypothesis, with predictions on the discriminating observables. The
two peers share the same authz contract (both evaluate to
`authorized` against IAM) but differ on the predictions that test the
premise. Discrimination happens at ANALYZE via normal weight-update
machinery — not through a contract verdict. Contract shape doesn't
fit integrity: the question is evidential rather than categorical, no
single anchor owns the answer, and the question is the same across
peer hypotheses (not mechanism-conditional the way authz is).

**Acting-entity discipline — the mandate is struck (v2.19); the gap
is real.** This paragraph read: when an `authorization_contract` is
declared on a hypothesis whose predicted edge has an acting-entity
source (`session`, `identity`, `process`), a peer integrity
mechanism is expected unless the hypothesis carries an explicit
`integrity_waived: <rationale>` note. That is validator rule #32,
which v2.19 strikes — see its gap entry for the four reasons, of
which the load-bearing one is that a mandated peer is a minted peer,
not an integrity question someone asked.

The failure mode it named is still open and still worth naming:
authz clears, impact clears, and the integrity premise was never
tested — the authorized-bulk-read from a compromised service
account. What is struck is the answer, not the question. The
recorded answer is the **behavioral-consistency prediction** in
§Hypothesis: opt-in, gated on baseline availability, scope, and
weight-sensitivity, capped at `moderate` severity, running through
the prediction machinery that already exists rather than through a
structural gate. `docs/decisions/adversarial-as-attribute-not-hypothesis.md`
reached that answer before #32 was written; #32 was the structural
gate that decision had already declined.

Integrity bottoms out at the authentication edge: below the
session → identity authz layer, further integrity questions require
out-of-band evidence the investigation typically cannot access (TPM
attestation, endpoint EDR, identity-provider forensics). Reaching
that boundary is a `termination.category: severity-ceiling`
condition, not a trust-root.

### Impact as lead-level prediction

Impact — *does this edge's effect matter enough to escalate?* — is a
third axis, orthogonal to authorization and integrity. An
authorized, uncompromised action can still be escalation-worthy if
its consequence exceeds a threshold (authorized backup service
uploads 180 GB when baseline is 60 GB; authorized admin deletes
10 000 rows from a production table). Conversely, an unauthorized
attempt that achieves no effect stays low-impact. Disposition on the
authz/integrity axis does not determine impact on the consequence
axis.

Impact is assessed at **ANALYZE**, graded against **pre-registered
predicates** authored at **PREDICT** (lead-level). The
commit-before-evidence property that makes hypothesis predictions
reliable transfers to impact verdicts: the threshold is written into
the record before the lead runs, so ANALYZE cannot retroactively
shift the bar after seeing the observation.

**Lead-level `:L l-{id}.impact_preds`.** A PREDICT-scaffolded lead that measures impact-relevant observables carries one or more `ip*` rows. Column shape and enums: see `soc-agent/knowledge/invlang/schema.md` §Lead → Impact predictions.

One observable per `claim` (rule #29): split compound AND/OR predicates into multiple `ip*` rows so partial evidence can pivot each side independently.

**Outcome-level `:R impact`.** ANALYZE emits one row per fulfilled `ip*`. Column shape `[resolved_by|cites_leads?|pred_ref|dim|observed|verdict|matched_pred|grounding|anchor_id|anchor_kind|authority|as_of|effective_window?|conditioning?|reasoning]` and per-cell enums: see schema.md §Resolutions → `:R impact`. Past-case is not admissible as `grounding` — impact reasoning is per-instance, not category-of-event.

Rule #14 (partial authority caps weight) applies — a baseline that
covers magnitude but not intent is `partial` and cannot alone force
high-severity escalation.

**Closure at CONCLUDE.** Every `impact_predictions[]` entry whose
resolving lead ran must either have a fulfilling
`impact_resolutions[]` entry OR appear in
`conclude.deferred_impact_predictions[]` with rationale. Mirrors
rule #26's orphan gate for authorization contracts.

**Two-axis CONCLUDE.** The `:T conclude` block carries both axes — `disposition` (authz/mechanism) and `impact_verdict` (impact: `none` \| `within` \| `exceeds` \| `indeterminate`), with `impact_severity` set when `impact_verdict ∈ {exceeds, indeterminate}`. The disposition axis is the live enum `DISPOSITION_VALUES` in `defender/_vocab.py`: `benign` \| `false-positive` \| `inconclusive` \| `malicious`. They combine orthogonally:
- `(benign, within)` — routine activity, no escalation.
- `(benign, exceeds)` — **authorized but malifying.** Mechanism
  confirmed benign; consequence exceeds threshold. Requires analyst
  review on impact even though the mechanism cleared.
- `(malicious, within)` — confirmed threat whose consequence
  stayed bounded (failed probe, denied access attempt).
- `(malicious, exceeds)` — confirmed threat with realized
  consequence. Highest-severity class.
- `(inconclusive, *)` — mechanism indeterminate; impact verdict still
  recorded for handoff.

`false-positive` is the fourth live disposition and is deliberately
absent from this grid: it describes the DETECTOR misfiring rather than
the alerted entity, so it makes no claim on the impact axis that this
grid could pair it with. It is reached only through
`_check_false_positive_gating` (`defender/skills/invlang/validate.py`).
*(v2.18: this grid read `true_positive` / `unclear` until the
retired-vocabulary trim; those spellings were never in the enum.)*

Escalation policy in the plugin configuration may drive on either
axis independently.

**Signature-tier deferred.** A per-signature `impact_profile.md`
declaring static class-level impact predicates (a 2σ threshold for
`rule-dlp-4421` regardless of instance) would strengthen the
commit-before-evidence property further but is not required in
v2.11. Lead-level authoring is the minimal honest starting point;
per-signature knowledge lives in playbook prose until corpus
measurements show PREDICT threshold drift. Promotion to a
signature-tier record is additive — `impact_predictions[].inherited_from: sig-iq1` back-reference — and does
not restructure the lead-level shape.

### Temporality of authorization

Authorization is time-bound. An authz verdict holds *as of* a specific
moment, conditional on state that was true at that moment — an oncall
rotation, an open change window, an approved travel ticket, a registry
entry. The schema records three temporal fields on every
`authorization_resolutions[]` entry:

- **`as_of`** — the timestamp the answer is authoritative *about*.
  Required.
- **`effective_window`** — optional `{start, end}` for authz grants
  with explicit time bounds (change windows, oncall shifts, travel
  approvals). When present, validates that the observed event falls
  inside.
- **`conditioning_context: []`** — optional prose list of then-true
  conditions that the verdict rests on. Examples: "operator on-shift
  per oncall rotation active 2026-04-14T00:00–2026-04-15T00:00",
  "CHG-2041 open and applicable", "user-travel-approved
  2026-04-14→2026-04-21".

Conditioning context matters forensically even after conditions
change. An authz verdict that was correct *as of* its time does not
retroactively become wrong when the underlying conditions lapse. But
analysts reading the companion months later need to see *why* the
verdict held — the conditioning list makes this auditable. The same
fields carry retrospective impact reads: if an exfil attempt was
blocked by DLP rule R33 and that rule was later removed, the
`conditioning_context` records R33 as the reason observed impact was
"failed" — without claiming the impact would still be zero today.

### Past cases as authorization source

A past investigation's conclusion that a specific triple was
authorized may serve as a **weak temporal authz source**
(`authorization_resolutions[].grounding_kind: past-case`). Constraints
are structural:

- `authority_for_question` is force-capped to `partial` regardless of
  how confidently the past case resolved — rule #14 then caps weight
  effect at `+`/`-`.
- A past-case consultation cannot be the sole grounding for
  `disposition: benign` on any contract. If every fulfilling
  resolution on a benign-eligible contract has
  `grounding_kind: past-case`, escalation is forced (rule #27).
- A past-case consultation cannot cite another past-case consultation
  as its own grounding — `cites_past_case` points to the exact prior
  contract, and that cited resolution must have
  `grounding_kind: org-authority`. Prevents bootstrap drift where past
  cases recursively authorize themselves (rule #28).

Past-case-as-authz is distinct from archetype matching at CONCLUDE.
Archetype matching is disposition-shaped ("this looks like outcome
cluster Y"); past-case-as-authz is authz-shaped ("this triple was
deemed authorized in SEC-2024-001"). The same past companion can
inform both, via different schema paths. Do not conflate.

### Leads as graph operations

A lead is an operation on the investigation graph. Two kinds:

- **Topology-extending** — materializes new vertices and edges
  (confirmed graph grows). When it discriminates between competing
  hypotheses, `tests` names them.
- **Attribute-refining** — enriches existing confirmed vertices
  without adding new topology (`attribute_updates`). No hypothesis
  target; the lead answers "what more do we know about this entity?"

Many leads are both: a trust anchor lookup may enrich an existing
vertex *and* materialize new entities in the same outcome. The
distinction is not categorical — there is no `mode` field. A lead
that produces only `attribute_updates` is implicitly attribute-
refining; one that produces `observations` is topology-extending.
Whether it discriminates between hypotheses is expressed by
`tests`, not by a type label.

### Append-only

Once written, no record is mutated. Sub-vertices are appended when
decomposition is forced; the parent stays. Placeholder vertices are
linked to their real counterpart via `identified_as` when
attribution is recovered; the placeholder stays. The graph
accumulates; it does not revise.

---

## Schema

The on-disk surface is `​```invlang` blocks. The **canonical companion dict** the validator and corpus queries operate on is what every block projects to via `soc-agent/scripts/handlers/_dense_parser.py`. This section captures the schema's design intent and invariants; the **field-level grammar** (block tags, column shapes, sub-cell packing, cell enums) lives in two places that should be read together:

- `soc-agent/knowledge/invlang/schema.md` — agent runtime reference (loaded into the investigate prompt). Every section below has a corresponding §section in schema.md.
- `docs/dense-investigation-format.md` — surface design doc with full block-tag grammar and the schema-mapping table.

### Top-level structure

```
:V prologue.vertices    — CONTEXTUALIZE: vertices derived from the alert
:E prologue.edges       — CONTEXTUALIZE: edges derived from the alert
:H hypothesize.hypotheses — PREDICT: initial proposed frontier (omit for SCREEN-matched cases)
:L findings             — GATHER + ANALYZE: one row per lead; same id merges across phases
  (per-lead sub-blocks: :V/:E/:R/:T scoped by l-{id})
:T conclude (+ sub-tables) — REPORT termination, disposition, deferreds
```

**`hypothesize` is optional.** For SCREEN-matched investigations, no
hypothesis formation step runs — the screen leads encode pattern
evaluation directly, and `outcome.screen_result: match` records the
verdict. Omit the `hypothesize` block in these cases.

For full-loop investigations, `hypothesize` is written once (after
CONTEXTUALIZE, before the first GATHER lead). Subsequent-loop hypothesis
evolution is captured inside leads via `new_hypotheses` (additions); a
hypothesis is retracted by being resolved to `--`, `:T shelved` having
been retired in #933. There is no second top-level `hypothesize` block.

### Vertex

Field grammar: `:V <block> [id|type|class|ident|attrs?|placeholder?|concerns?|citations?]` — see `soc-agent/knowledge/invlang/schema.md` §Vertex for cell-level semantics and enums. Used by `:V prologue.vertices` (CONTEXTUALIZE) and `:V l-{id}.observations.vertices` (GATHER).

**Sub-vertex IDs.** When a vertex is decomposed inward via
`component_of`, sub-vertices use `v-{parent}-{nonce}` IDs (e.g.,
`v-001-01`, `v-001-02`). This encodes containment in the ID itself,
enabling prefix queries without edge traversal.

**Trust-root signaling lives on lead outcomes and CONCLUDE, not
vertices.** When a lead reaches a vertex with no accessible upstream,
it records the vertex id in `outcome.trust_root_reached: v-{id}`; the
terminating companion sets `conclude.termination.category:
trust-root`. The investigation does not write a `trust_root: true`
flag onto the vertex itself — the signal is about the frontier
collapsing, not about the vertex having an intrinsic property.

**Placeholder vertices.** When a lifecycle edge requires two
endpoints but one is unobservable, write a placeholder vertex with
`placeholder: true`. If a later lead identifies the real entity,
append a new vertex and link via `identified_as`. Never mutate the
placeholder.

### Edge

Field grammar: `:E <block> [id|rel|src|tgt|when|auth_kind:source|attrs?|status?|trust_chain?|concerns?]` — see `soc-agent/knowledge/invlang/schema.md` §Edge for cell-level semantics and enums. Authorization verdicts live in `:R authz` rows, not on the `:E` row itself (see §Authorization below). Used by `:E prologue.edges` and `:E l-{id}.observations.edges`.

**Authority is observational, not authorization.** It describes how
reliably the source recorded the observation. `siem-event`,
`runtime-audit`, and `authoritative-source` support `++`/`--`
weight. `client-asserted` and `inferred-structural` cap at `+`/`-`.

A `client-asserted` edge on a verified trust chain gets effective
`authoritative-source` authority; record the chain in `trust_chain`.

**Authorization verdicts are plural per edge.** Each `:R authz` row resolves one contract's verdict — see `soc-agent/knowledge/invlang/schema.md` §`:R authz` for the full row grammar (column shape `[edge|verdict|anchor_kind|anchor_id|grounding|authority|as_of|effective_window?|fulfills|resolved_by|cites_past_case?|conditioning?|concerns?]` plus per-cell enums and the past-case constraints).

Plural because real edges often face parallel policy layers — IAM ×
data-classification × time-of-day — each resolved independently by a
different anchor, any one of which can deny. Do not collapse layered
policies into a single entry; each contract gets its own resolution.

**When `authorization_resolutions` appears.** Only on edges that
fulfill a declared contract. Edges not referenced by any contract
omit the field entirely. Do not write speculative verdicts — that is
verdict-on-everything clutter.

**Append-only on existing edges.** If a contract resolves against an
already-confirmed edge (not the proposed edge of its hypothesis), the
resolving lead writes the verdict via `attribute_updates` targeting
the edge — not by mutating the original edge record.

**Per-question authority** (whether a source covers all aspects of
the question being asked) is a property of the specific resolution,
not the edge itself. It lives in
`authorization_resolutions[].authority_for_question`.

### Hypothesis

Field grammar: `:H <block> [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status|concerns?]` — see `soc-agent/knowledge/invlang/schema.md` §Hypothesis for cell semantics, sub-cell packing (`p<n>:<subject>:"<claim>"`, `ap<n>:<target>:<attribute>:"<claim>"`, `r<n>[<refs>]:"<claim>"`, `ac<n>:<edge_ref>:<anchor_kind>:"<predicate>":<on_unauth>/<on_indet>`). Used by `:H hypothesize.hypotheses` (top-level) and `:H l-{id}.new_hypotheses` (born inside a lead). *(v2.19: this sentence also pointed at "the integrity-waiver rule" — rule #32, now struck. `integrity_waived?` stays in the grammar and stays projected, but no validator rule reads it; see the v2.19 delta.)*

**One-hop discipline.** `proposed_edge.parent_vertex` is the
immediate upstream cause — exactly one hop from `attached_to_vertex`.
Do not propose a distant ancestor.

**Refinement via hierarchical IDs.** When evidence forces a lean
hypothesis into more specific sub-cases, allocate child IDs as
`h-{parent}-{ordinal}` (e.g., `h-001` → `h-001-001`, `h-001-002`).
Write children as full hypothesis records in the lead's
`new_hypotheses`. Retire the parent by RESOLVING it — a `:T resolutions`
row moving it to `--` when the children refute it, or a
`:T conclude.surviving` row (and a `:T conclude.deferred_preds` row per
unsettled `p*`) when the run is still carrying it. `:T shelved`, which
used to do this in the same block, is retired (#933) and the parser
refuses it by name. Children inherit no weight from the parent; their
histories are independent.

**Lean means 1–2 predictions.** A single prediction captures the
core discriminating claim. Add a second only when two independent
facts each partially confirm the hypothesis and neither alone
suffices. Three or more predictions usually signals either a
non-lean hypothesis or a refinement that should be deferred.

**Authorization contracts** are declared on the hypothesis when disposition hinges on an authorization lookup (§Authorization). Each contract is one `ac<n>` sub-cell on the `:H` row's `authz?` cell — packed `ac<n>:<edge_ref>:<anchor_kind>:"<predicate>":<on_unauth>/<on_indet>` (see schema.md §Hypothesis for the sub-cell grammar). `edge_ref` is `proposed` (the hypothesis's own proposed edge) or `e-{id}` (an existing confirmed edge).

The predicate is natural language. Any AND/OR combination is
permitted — no structured DSL. The agent evaluates the predicate
against anchor data when the resolving lead fires. Declare contracts
only when the mechanism is consistent with both benign and adversarial
readings depending on authorization; when the adversarial reading IS
the mechanism (e.g., `?adversary-controlled-process`), skip the
contract — the `?name` and its predictions already carry the claim.
(The CLASSIFICATION does not: rule #23 forbids resting a fork on it,
so the adversarial peer is distinguished by what it predicts.)

**Behavioral-consistency prediction (optional).** A contract resolved
`authorized` establishes policy compliance, not integrity. The
hypothesis MAY carry one baseline-consistency prediction — positive
("expect corroborating activity X") or negative ("expect NOT to see
>Nσ volume deviation / access outside baseline file set / concurrent
geo-distant sessions"). Gates: baseline queryable, scoped to the
alert's entities, weight-sensitive. Severity caps at `moderate`.
Unavailable baseline → `indeterminate` in `concerns`; do not
confabulate.

### Lead

A lead has one header row in `:L findings` plus zero or more lead-scoped sub-blocks (all sub-block names namespaced by the lead id). Field grammar lives in `soc-agent/knowledge/invlang/schema.md` §Lead — covering the header row columns (`[id|loop|name|target|mode?|tests|system|template|query|window|trust_root?|fail_reason?|screen_result?|selection_rationale?]`) and every sub-block:

| Sub-block | Carries |
|---|---|
| `:V l-{id}.observations.vertices` | new vertices entering the confirmed graph |
| `:E l-{id}.observations.edges` | new edges entering the confirmed graph |
| `:L l-{id}.lead_preds` | conditional branch plans (`lp*`) for non-branching but interpretation-vulnerable leads |
| `:L l-{id}.impact_preds` | pre-registered threshold predicates (`ip*`) graded by ANALYZE into `:R impact` rows |
| `:L l-{id}.substitutions` | query substitutions (`key|value` pairs) |
| `:H l-{id}.new_hypotheses` | hypotheses born inside the lead |
| `:T shelved` | RETIRED (#933). No investigation on record ever wrote one, while it stayed a discharge arm on rules #23, #24 and #34 and two fields on the shipped document — a retirement route the validator honoured and the injected SKILL.md never taught. The parser refuses the block by name and projects nothing; a hypothesis leaves the live frontier by being RESOLVED — `--` when the run refuted it, a `:T conclude.surviving` row NAMING it when the run is still carrying it. Omitting it from a written surviving table is not a retirement; rule #24 refuses that. |
| `:R authz` | authorization-contract verdicts on confirmed edges (see §Authorization) |
| `:R consultations` | non-authz anchor queries (baselines, registry lookups) |
| `:R impact` | impact-prediction verdicts (see §Impact) |
| `:R attr_updates` | vertex/edge enrichment without new topology |
| `:T resolutions` | proof-trace lines — one per hypothesis weight transition |

**`selection_rationale` is optional.** Use it to capture the inter-lead
strategic reasoning — why this lead was chosen next given what was
already known. Omit for the first lead of an investigation (choice is
obvious) and for SCREEN leads (subagent-directed). Include when the
choice required weighting competing options: "source-classification
first because IP attribution determines which hypotheses are live
before committing to discriminating queries."

**`mode: screen`** marks leads dispatched by the SCREEN subagent (loop
0). These leads share SCREEN's fast-path purpose — pattern match or
fall through — and are always in `loop: 0`. `outcome.screen_result`
records whether the overall SCREEN matched (`match`) or fell through
(`no_match`). The sequence's answer is its final lead's, so a reader
takes the last `screen_result` in the loop in `:L findings` DOCUMENT
order; an earlier lead may carry its own `no_match` and the validator
does not refuse it. It cannot: whether a screen is the sequence's last
is a fact about leads not yet written. A programmatic reader must go
back to the surface for that order — `companion["findings"]` is the
projector's lead buckets in FIRST-MENTION order, so a `:T resolutions`
head naming a lead ahead of its `:L findings` row reorders the list.

`match` is the exception, and it is not softened by the reading above:
the surviving arm of rule #17 refuses ANY lead carrying `match` beside
a `hypothesize` block, last in its sequence or not. So a sequence whose
earlier screen matched and whose later screen fell through cannot then
hypothesize — the run has to treat the `match` as the answer. **This is
the one append-only wedge v2.22 leaves open**: the arm names a
committed `:L findings` cell, and where the `:H` block is committed
first neither repair it offers is a write the document can make.

**`tests` is optional.** Present when the lead is discriminating
between specific competing hypotheses. Absent when the lead is
purely informational (classification lookup, attribute enrichment,
establishing scope). A lead with no `tests` still produces
`resolutions` when its outcome happens to bear on active hypotheses
— the connection is recorded in the resolution, not pre-declared.

**`predictions` is optional — pre-commitment for interpretation-
vulnerable leads.** A lead can be non-branching (same step-1
regardless of which story is true) yet still have outcome fields
whose reading is interpretive — volume anomaly shape, process-name
plausibility, reputation-weight thresholds. For those leads,
pre-register how the outcome will be read as conditional branch
plans: `if <outcome pattern> → read_as <interpretation> →
advance_to <next step>`. The triple is auditable: the actually-run
next lead should match one of the `advance_to` values. If the
observed pattern doesn't fit any `if` branch, that is itself a
signal — HYPOTHESIZE to extend the fork space, don't silently
rationalize.

Lead-level predictions are **not** a substitute for hypothesis-level
predictions. The two are orthogonal commitments:

| Form | Commits to | When to use |
|---|---|---|
| Hypothesis + predictions | Named world models; predictions test them | Multiple plausible explanations, analytically distinct, divergent step-1 leads |
| Lead + predictions | Decision rules on a shared next-step lead | Same step-1 lead regardless; the *reading* determines step-2 |

Interpretation-vulnerability is per-field, not per-lead. A single
lead can mix mechanical fields (UID, count) with interpretive ones
(process-name plausibility, threshold judgment). Pre-register on
the specific fields that carry the judgment.

**`attribute_updates` vs `observations`.** Use `attribute_updates`
when the lead enriches an already-confirmed vertex or edge without
new topology (e.g., a classification lookup adds `classification:
monitoring-host` to an existing endpoint vertex; an authorization
resolution adds an `authorization_resolutions` entry to an existing edge).
Use `observations` when new vertices or edges enter the confirmed
graph. Both may appear in the same outcome. Each `attribute_updates`
entry targets exactly one of `target: v-{id}` or `target: e-{id}`.

**Anchor consultation vs authorization resolution.** Two records
carry anchor-query provenance; which one applies is determined by
whether the query fulfills a declared `authorization_contract`:

| Record | Where | When |
|---|---|---|
| `authorization_resolutions[]` | on the resolved edge | query produces a verdict (`authorized | unauthorized | indeterminate`) that fulfills a contract declared on some hypothesis |
| `anchor_consultations[]` | on the lead outcome | query returns evidence that informs hypothesis weight but does not fulfill a contract (baseline lookups, registry membership checks, reference queries) |

The split maps to a real semantic difference. Authorization resolutions
gate disposition (rule #21). Anchor consultations ground evidence
weight via the lead's `resolutions[]`, the same way any other observation
does. Temporal validity, authority-for-question scope, and
conditioning context are structurally shared — the same fields mean
the same thing in both records — but the verdict/contract-fulfillment
machinery is authz-only.

`as_of` is the timestamp the answer is **authoritative about** — not
the query time unless they coincide. Applies identically to both
records:
- Event anchors (did X happen at time T?) → the event timestamp
- Current-state anchors (is property X true now?) → the query time
  or snapshot timestamp
- Slowly-changing references (was status X as of last sync?) → the
  last-modified time, not the query time

`effective_window` is set when the anchor's answer has explicit time
bounds (change windows, oncall shifts, approved-travel dates for
authz; baseline-snapshot windows for expectation). When present on an
authz resolution, the validator checks that the observed event's
timestamp falls inside `[start, end]`; a mismatch demotes the verdict
to `indeterminate` regardless of the anchor's stated result.

`conditioning_context` is a prose list of then-true conditions the
verdict rests on. Authorization: `["operator on-shift per oncall
rotation active 2026-04-14T00:00–2026-04-15T00:00", "CHG-2041 open
and applicable"]`. Retrospective impact reads (recorded in the same
field on consultations or resolutions, depending on which is in
scope): `["DLP rule R33 in force, scope includes
s3://prod-data/*"]`. The list is an audit trail for later analysts
who need to understand *why* the verdict held before conditions
lapsed.

`authority_for_question: partial` means the consulted source covers
only some aspects of the question. A resolution *or* a consultation
with `authority_for_question: partial` cannot push a hypothesis past
`+` or `-` regardless of its verdict or result (validator rule 14).

`grounding_kind` distinguishes provenance from policy surface:
`anchor_kind` says *what* authority surface was queried (`iam-policy`,
`oncall-schedule`, `image-baseline`); `grounding_kind` says *what
sort of source* produced the answer.
- `authorization_resolutions[].grounding_kind ∈ {org-authority, past-case}`
- `anchor_consultations[].grounding_kind ∈ {org-authority, telemetry-baseline}`

Baselines cannot ground an authz verdict (they answer expectation,
not authorization); past-cases cannot appear as expectation evidence
(their semantic is authz-shaped). The enum constraints enforce this
structurally so rules #13/#14 from v2.9 (baselines-don't-authorize
discipline) don't have to be restated.

`grounding_kind: past-case` is a weak-temporal authz source citing a
prior companion's conclusion. Force-caps `authority_for_question` to
`partial` (rule #27), cannot be sole grounding for benign disposition
(rule #27), cannot chain on another past-case consultation (rule #28).
`cites_past_case.run_id` names the source companion; `contract_ref`
names the exact contract in that companion being relied upon.

**`failure_reason` enum.** `adapter-error` | `attribution-opaque` |
`partial-coverage` | `permission-denied` | `timeout` | `other`

**Severity of test.**

| Severity | Meaning | Max weight effect |
|---|---|---|
| `severe` | Outcome directly confirms or contradicts a core prediction | up to `++` / `--` |
| `moderate` | Constrains plausibility without direct contradiction | one step |
| `weak` | Circumstantial consistency | caps at `+` / `-` |

### Conclude

REPORT writes a flat `:T conclude` key/value block plus its sub-tables (`:T conclude.surviving`, `:T conclude.deferred_authz`, `:T conclude.deferred_impact`, `:T conclude.deferred_preds`). Those four are the whole sub-table set, and any other `:T conclude.<sub>` name is a parse warning — a misspelled deferral table is refused on write rather than dropped, since dropping it makes rule #26/#31/#34 refuse a commitment the author DID account for. The ONE exception is the retired `:T conclude.ceiling_test [kind|subject]` spelling, which `_RETIRED_CEILING_TEST_BLOCK` accepts and ignores in silence. `ceiling_test` is not a sub-table: it is a repeated flat row in `:T conclude` itself, one per unreachable check (see rule #13, and `docs/dense-investigation-format.md` §`:T`, reconciled in #933) — so a run that writes the retired sub-table has its receipt dropped with no diagnostic, and rule #13 then refuses the close for a `ceiling_test` the author can see in their own output. Naming the translation in that drop is #933 follow-up. Field grammar — every key, every sub-table column shape, every enum, and the missing-vs-empty convention — lives in `soc-agent/knowledge/invlang/schema.md` §Conclude; the shipped authoring surface is `defender/skills/invlang/SKILL.md` §`:T conclude`.

**`deferred_authorizations`.** Lists authorization contracts that were
declared but not resolved by any lead. Each entry names the contract
in its `contract_ref` column (`h-{id}.ac{n}`) and a rationale — typical rationales are
"escalation-forced by unauthorized sibling contract, no benefit in
resolving this one", "authority anchor unavailable (see concerns on
h-003)", "superseded by mechanism refutation at lead l-007". Rule #26
rejects a `conclude:` block that leaves any declared contract
unresolved and absent from this list. Empty list is valid when every
declared contract has a fulfilling resolution.

**`surviving_hypotheses`.** When a `conclude:` block is written, every
declared hypothesis whose final effective weight is not `--` must appear in
this list (validator rule 24). Empty list is valid — it means every
hypothesis reached `--`. For `disposition: benign` the list is typically
empty; for escalation shapes it names the hypotheses that kept the
investigation from closing and should be included in the analyst handoff.

**`impact_verdict` and `impact_severity`.** The impact axis is
orthogonal to `disposition`. `impact_verdict: none` means the
investigation declared no impact predicates (low-impact signature,
alert class inherently bounded). `within` / `exceeds` / `indeterminate`
are the roll-up over fulfilled `impact_resolutions[]` — `exceeds` if
any fulfilling resolution's verdict is `exceeds`, `indeterminate` if
any is `indeterminate` and none `exceeds`, `within` when all cleared.
`impact_severity` is null unless `impact_verdict ∈ {exceeds,
indeterminate}`; severity reflects the maximum across fulfilling
resolutions, capped by `authority_for_question: partial` per rule #14.
`(benign, exceeds)` is the authorized-but-malifying class — requires
analyst review on consequence even though the mechanism cleared.

Neither field's vocabulary is validator-enforced, and both are
registered as `enum conclude.impact_verdict` /
`enum conclude.impact_severity` so `skills/invlang/SKILL.md` can teach
them before that changes — see rule #31 and
`docs/decisions/defender-invlang-enforcement-ramp.md`. What IS enforced
is the pairing: `impact_severity` present exactly when `impact_verdict`
∈ {`exceeds`, `indeterminate`}.

**`deferred_impact_predictions`.** Impact-axis analog of
`deferred_authorizations`. Lists `impact_predictions[]` entries that
were declared but not resolved by any lead (tool unavailable, baseline
scope-mismatch, escalation forced before the measurement landed).
Rejected by the impact closure rule (#31, `_check_impact_closure`)
when absent but a declared prediction has no fulfilling resolution.
A rationale is required on every entry: the row records WHY the
measurement could not be made, and a blank cell discharges the
prediction while saying nothing.

**Termination categories.** The four below are the intended vocabulary
and are NOT enforced — `termination.category` is a projected free-text
scalar with no `vocab` entry, and the tree already carries
`data-ceiling`, `adversarial-confirmed`, `exhaustion` and `natural`
across shipped goldens and test corpora. Rule #13 turns on the exact
string `severity-ceiling`, so a value outside this list disables that
rule silently; closing the vocabulary is filed in
`docs/decisions/defender-invlang-enforcement-ramp.md` rather than done.
- `trust-root` — confirmed graph reached a vertex with no accessible
  upstream. Frontier collapsed.
- `adversarial-refuted` — every adversarial hypothesis was explicitly
  refuted by confirmed evidence.
- `severity-ceiling` — live hypotheses remain but their critical
  edges cannot be tested with available tools. `ceiling_test`
  records the out-of-band step that would resolve it.
- `exhaustion-escalation` — loop budget exhausted.

**Authorization-gated disposition.** `disposition: benign` requires
that every `authorization_contract` on every confirmed-weight
hypothesis (weight `++` or `+`, status `confirmed` or `active`) has at
least one fulfilling `authorization_resolutions` entry with `verdict:
authorized` on a contracted edge. Any contract that is unfulfilled
(and not in `deferred_authorizations`, per rule #26), or whose
fulfillment carries `verdict: indeterminate`, blocks `benign`.
Past-case-sourced resolutions
(`grounding_kind: past-case`) cannot be the sole grounding for
`authorized` on a benign-eligible contract (rule #27). This replaces
the former
"maintain adversarial hypothesis until `--`" bookkeeping rule; teeth
are structural via validator rules #21 and #26–#28.

*(v2.18: this paragraph also stated what an unfulfilled or
`unauthorized` contract forces disposition TO — `status: escalated`
with disposition ∈ {`unclear`, `true_positive`}. Excised with rule
#21's escalation half: none of those three tokens is in
`DISPOSITION_VALUES` (`defender/_vocab.py`), and nothing enforced
them. What survives is the negative constraint, which is what
`_check_benign_authz` actually implements: an undischarged contract
blocks `benign`. Where it lands instead is unconstrained by this
spec.)*

---

## Conventions

### Lifecycle vs action observations

SIEM observations come in two shapes.

**Lifecycle** — a persistent entity that now exists: a process
running on a host, a session that was established, a file that was
written. The entity outlives the event and the investigation will
refer to it as a noun. Model it as a vertex; model the event with an
edge verb (`spawned`, `wrote`, `authenticated_as`, `runs_in`, …).

**Action** — an audit-log record of an invocation: who called what
with which arguments. Model as a `command` vertex carrying the
action's attributes, with `targeted → <thing acted on>` and (when
applicable) `executed_in → session`. Covers cloud API calls, failed
auth attempts, list/enumerate operations, configuration changes.

**Discriminator.** Is the observation's natural noun an invocation?
→ action (`command` vertex). Is it an entity whose later state the
investigation reasons about? → lifecycle (typed vertex + edge verb).

**CRUD is uniformly action-shaped.** `iam:CreateUser`,
`s3:DeleteObject`, `s3:GetObject` all model as `command` vertices.
Promote the target to its own vertex only if later reasoning
references it as a noun.

### Aggregate observations

When an observation describes N occurrences of something (17
ListObjectsV2 calls over a 172-second window), the aggregate belongs
on a single edge with `count` + `window_*` attributes. Do not
materialize one vertex per occurrence. The SIEM's native unit is the
alert; model at that unit.

### Mechanical leads stay within their data source

A scope lead's `outcome.observations` contains only vertices the
data source directly observes. If the raw event stream would not
contain a record naming a vertex by its native identity, do not
materialize it. Causal implication does not count as native naming.

---

## Types

| Type | Replaces | Notes |
|---|---|---|
| `endpoint` | host, device, remote-endpoint, ip | Compute unit with an OS. IP-only sources use `endpoint` with `attributes.knowledge: partial`. Vendor specifics in `attributes.kind`. |
| `process` | — | Running execution unit on an endpoint. |
| `thread` | — | Sub-entity of process; use with `component_of` and hierarchical ID. |
| `memory-region` | — | Sub-entity of process; use with `component_of` and hierarchical ID. |
| `module` | — | Loaded library/DLL; use with `component_of` and hierarchical ID. |
| `container` | — | Runtime container. |
| `session` | — | Authenticated interactive or API session. |
| `identity` | user | Any authenticatable entity. `attributes.kind ∈ {user, group, role, service-account, application}`. |
| `storage` | — | Object/file/blob/secret store. `attributes.kind ∈ {object-store, block, file, secrets, nfs}`. |
| `database` | — | Structured data system with query interface. |
| `network-device` | — | Firewall, switch, router, load balancer, WAF. |
| `file` | — | A specific file artifact. |
| `command` | — | An audited invocation (action-shaped observation). |
| `socket` | — | Network socket (transport-layer). |

Use `unclassified-{type}` when classification is unknown.
Use `ambiguous-{a}-or-{b}` when two classifications are genuinely
indistinguishable.
Use `??` (or `{a, b, c}` for a candidate set) when the slot is an OPEN
QUESTION a lead is expected to close — the difference from the two
above is openness, not ignorance: only `??` / `{a, b, c}` read as
unresolved, so only they block `disposition: benign` and only they
surface as frontier slots. `??` is the canonical spelling on a
`proposed_edge.parent_vertex.classification`, which nothing closes
(rule #23).

---

## Relations

| Relation | Source → Target | Notes |
|---|---|---|
| `spawned` | process → process | |
| `executed` | process → file | |
| `loaded_by` | process → file | For modules / libraries. |
| `opened` | process → socket | |
| `connected_to` | socket → endpoint | Transport-layer only. |
| `read` / `wrote` | process → file | |
| `runs_in` | process → container | |
| `runs_on` | process \| container \| database \| session → endpoint | Compute-substrate containment. |
| `authenticated_as` | session → identity | |
| `initiated_by` | session → identity \| endpoint | |
| `triggered_by` | process \| session → process \| session | |
| `escalated_privilege` | session → session | Self-edge. |
| `executed_in` | command → session | |
| `targeted` | command → endpoint \| storage \| database \| identity \| file \| container \| network-device | Action-target for command vertices. Do not use for lifecycle events. |
| `member_of` | identity → identity | User → group, role → role-bundle. |
| `identified_as` | placeholder → real-vertex | Post-hoc attribution. Never mutate the placeholder. |
| `component_of` | vertex → vertex | Part-of for inward decomposition. Sub-entity → containing entity. Vertex type discriminates semantics. |
| `listed` | session \| process → storage \| database | Enumeration/list operation. |
| `modified` | session \| process → storage \| database \| identity \| file | Configuration or state change. |
| `attempted_auth` | endpoint \| process \| session → endpoint | Observed authentication attempt (may be failed). |
| `classified_as` | vertex → classification-value | |

`listed`, `modified`, `attempted_auth` are provisional — in active
use across the pilot corpus but not yet stabilised from wider case
coverage.

---

## Validator rules

The validator enforces **26 active rules** (rules 1–36 with ten gaps: 36 numbers − 10 gaps = 26). Ten historical rule numbers (#10, #12, #15, #16, #19, #20, #22, #32, #35, #36) are gaps — their content was merged into a sibling rule, demoted to review-only discipline, subsumed by a stronger rule (#35 → #23, v2.17), or struck outright (#36 as retired vocabulary, v2.18; #32 as a mandate that would manufacture its own compliance, v2.20). Numbering is preserved for grep-stability of existing code, prompt, and test references; merged rules carry a redirect to their new home, and each struck rule carries a note on why. Rules #21 and #24 remain active but were trimmed in v2.18 — see the excision notes on each.

1. **Schema validity.** Required fields present, enums valid, IDs
   well-formed (including hierarchical patterns for hypotheses,
   sub-vertices `v-{parent}-{nonce}`, and the `target: v-{id}` /
   `target: e-{id}` exclusivity on `attribute_updates`).
   *(Absorbs former #15 sub-vertex ID shape and the shape clause of
   former #22 attribute-update target.)*

2. **Classification vocabulary.** Every `classification` is from the
   seed vocabulary (§Types classification lists) or a
   `{type}:{slug}` provisional — or one of the two open markers `??`
   and `{a, b, c}`, which name a slot the run has not settled rather
   than a classification (§Types, escapes).

3. **Relation catalog.** Every `edge.relation` appears in §Relations.

4. **Edge authority rule.** `++` or `--` resolutions cite at least
   one `siem-event`, `runtime-audit`, or `authoritative-source` edge
   in `supporting_edges`.

5. **Refutation ID match.** Every `--` resolution's
   `matched_refutation_ids` is non-empty and references IDs that
   exist in the target hypothesis.

   **Refutation spans two phases, and this rule owns one of them.**
   The refutation *shape* — "what observation would kill this
   hypothesis" — is authored at PLAN as an `:H h-NNN.refuts` row, and
   its `refutes` cell is validated there against the declaring
   hypothesis's own predictions (`_check_refutation_scope`). Refutation
   *matching* — a `--` citing the `r*` that came in — is graded at
   ANALYZE, and that is the half stated above. A finding about
   refutation attributes to PLAN or ANALYZE by which half it is about;
   "refutation is an ANALYZE concern" is the natural misreading, and it
   sends shape defects to the wrong prompt.

6. **Prediction completeness for `++`.** `matched_prediction_ids`
   across all resolutions on a hypothesis must equal the full
   prediction set. Partial coverage caps at `+`. Early gate at
   write time on a hypothesis STANDING at `++`; rule #34 is the late
   closure gate at CONCLUDE on every weight.

   Implemented as `_check_prediction_completeness`
   (`defender/skills/invlang/validate.py`). **"Full prediction set"
   is the union of `predictions[]` (`p*`) and
   `attribute_predictions[]` (`ap*`)** — the set
   `_declared_prediction_ids` builds and the set rule #34 enumerates.
   Rules #33 and #34 both make an `ap*` citable in
   `matched_prediction_ids`, so a `p*`-only reading would let an
   author take an observable out of this gate by declaring it under
   `.attr_preds`, which is a formatting choice. The union is taken
   across every resolution on the hypothesis that MOVED it — not only
   the `++` row, and not a `null → null` row, which recorded that the
   lead looked rather than that the prediction settled. The CITED side
   therefore only grows, and a write that clears this gate on that side
   clears it for good. The DECLARED side grows too, which is why the
   trigger is `validate._confirmed_and_standing` and not "some row once
   wrote `++`" — see the v2.22 delta at the top of this document. That
   predicate COUNTS each row's `before`/`after` pair: a row that enters
   `++` scores +1, one that leaves it −1, and a `++ → ++` restatement
   neither. On a chain whose rows join up, entries and exits alternate,
   so a positive count means the last move left the hypothesis at `++`
   — the same answer a last-move-wins fold gives, reached without an
   order the projection does not carry. `_walkers.final_weights` is the
   wrong fold for this question twice over: it orders by lead
   declaration rather than append, and it reads `after` raw where the
   count reads both cells closed on the weight-cell vocabulary, so
   `++ → confirmd` moves nothing and takes nothing back.
   "Moved" is membership in the four weight buckets, not "anything that
   is not `null` / `∅`": the `after` cell
   is an unvalidated token, so an open test would make a misspelled
   weight discharge every prediction it cites while skipping this gate
   and rule #4. The walk is factored out as
   `validate._settled_predictions` for rule #34's closure gate to read,
   so the two cannot disagree about which citations count.

7. **Reference resolution.** Every `v-*`, `e-*`, `h-*`, `l-*`
   reference in any field points to a record that exists in the
   companion. Hierarchical hypothesis IDs `h-{parent}-{nonce}`
   require the parent hypothesis to be declared. Authorization
   contract `edge_ref` is the literal `proposed` or an existing
   `e-*` id. Authorization resolution `fulfills_contract` of shape
   `h-{id}.ac{n}` points to a hypothesis whose `authorization_contract`
   declares that `ac{n}`. Attribute-update `target` of shape
   `v-{id}` or `e-{id}` points to a declared record. Refutation-shape
   `refutes_predictions` cites `p*` / `ap*` ids the SAME hypothesis
   declares — a refutation overturns its own hypothesis's predictions,
   and a `--` citing it inherits that scope.
   *(Absorbs former #12 hierarchical hypothesis IDs, #19 contract
   edge_ref, #20 fulfills_contract back-ref, and the resolution
   clause of former #22 attribute-update target.)*

   Implemented as `_check_lead_refs`, `_check_hypothesis_refs`,
   `_check_prediction_refs`, `_check_refutation_scope` and
   `_check_attr_update_targets` (`defender/skills/invlang/validate.py`).

8. **Append-only.** No existing record is mutated.

9. **Lead block self-containment.** Every vertex, edge, or hypothesis
   produced by a lead lives inside that lead's `outcome.observations`
   or `new_hypotheses`.

10. **(Demoted to review-only.)** *Mechanical leads stay within their
    data source* — a lead's `outcome.observations` contains only
    entities the queried system directly observes by native identity.
    Semantic discipline that requires per-system knowledge to
    enforce mechanically; not currently validator-checked. Retained
    in §Conventions as authoring guidance.

11. **Anchor-query provenance completeness and enums.** Every
    `authorization_resolutions[]` entry requires `verdict`,
    `anchor_kind`, `anchor_id`, `grounding_kind`,
    `authority_for_question`, `as_of`, `resolved_by_lead`, and
    `fulfills_contract`. When `grounding_kind: past-case`,
    `cites_past_case.run_id` and `cites_past_case.contract_ref` are
    required, AND `authority_for_question` must be `partial` (rule
    #14 then caps weight effect at `+`/`-`). Every
    `anchor_consultations[]` entry requires `anchor_id`,
    `anchor_kind`, `grounding_kind`, `result`, `as_of`, and
    `authority_for_question`. Enum constraints per §Anchor
    consultation: authz resolutions exclude `telemetry-baseline`
    from `grounding_kind`; consultations exclude `past-case`.
    *(Absorbs the past-case ⇒ partial enum clause from former #27a;
    #27 retains only the no-sole-grounding rule.)*

12. **(Merged into rule #7.)** Hierarchical hypothesis ID
    consistency — see rule #7.

13. **`ceiling_test` requires severity-ceiling.** Required when
    `termination.category: severity-ceiling`; forbidden otherwise.

    Implemented as `_check_ceiling_test_scope`
    (`defender/skills/invlang/validate.py`) — **the required half only.**
    A close carrying `termination.category: severity-ceiling` and no
    `ceiling_test` row is refused; `ceiling_test` under any other
    category is not.

    **"Forbidden otherwise" is deliberately not enforced, because the
    field it forbids is not the field this rule was written about.** The
    pilot spec's `ceiling_test` was `{kind, subject}` — *the* out-of-band
    step that would resolve the ceiling — from which "only under a
    ceiling" follows. The shipped field is the list of checks the run
    could not make, one flat row per gap, and eleven checked-in lessons
    instruct writing it whenever a source was out of reach ("name them by
    host and source type in `ceiling_test`"). Forbidding it elsewhere
    would refuse a run for obeying a lesson, which
    `learning/core/persist.py` turns into a discarded run.
    `golden-v2sshd` names two such gaps and terminates on
    `data-ceiling`.

    **The trigger is unbacked and the rule fails silent because of it.**
    `termination.category` is a projected free-text scalar with no
    vocabulary anywhere, so `severity_ceiling` or `severity-celing`
    disables this check with nothing said. That direction is the safe
    one — a typo costs a miss, never a wrongful refusal — but it is a
    real limit. Closing the vocabulary would fix it and was not done in
    #933: the four values §Conclude names (`trust-root`,
    `adversarial-refuted`, `severity-ceiling`, `exhaustion-escalation`)
    are contradicted on disk by `data-ceiling` and
    `adversarial-confirmed` in the two shipped e2e goldens and by
    `exhaustion` / `adversarial-confirmed` / `natural` across three test
    corpora, so closing it is a spec-owner decision with its own
    measurement. Filed in
    `docs/decisions/defender-invlang-enforcement-ramp.md`.

    The `ceiling_rationale` clause that
    `docs/dense-investigation-format.md` attaches to this rule is not
    enforced either; that document is reconciled to say so.

14. **`partial` authority caps weight.** A hypothesis resolution
    grounded *solely* by `authorization_resolutions[]`,
    `anchor_consultations[]`, or `impact_resolutions[]` entries with
    `authority_for_question: partial` cannot push weight past `+`
    or `-` regardless of verdict or result. A resolution citing at
    least one `full`-authority entry alongside partial entries is
    *not* capped — the cap fires only when every cited grounding
    entry is partial.

15. **(Merged into rule #1.)** `component_of` sub-vertex
    ID `v-{parent}-{nonce}` shape — see rule #1 (IDs well-formed).

16. **(Merged into rule #17.)** `screen_result` requires `mode:
    screen` — see rule #17 (SCREEN structural integrity).

17. **SCREEN structural integrity.** `outcome.screen_result` is only
    valid on leads where `mode: screen` is set. When any lead carries
    `outcome.screen_result: match`, the top-level `hypothesize` block
    must be absent — a SCREEN-matched companion does not enumerate
    hypotheses. *(v2.22: the "only the final lead in a SCREEN sequence
    carries `screen_result`" clause is STRUCK as unenforceable by
    shape — see below.)*
    *(Absorbs former #16 — SCREEN scope and SCREEN-match
    omit-hypothesize collapse into one structural rule.)*

    Implemented as `_check_screen_structure`
    (`defender/skills/invlang/validate.py`), reading
    `findings[].screen_result` — where the `:L findings` column
    projects. The `outcome.` prefix above is pre-dense envelope
    spelling the projector has never used. `mode` and `screen_result`
    are compared case-insensitively and the `none` / `n/a` empty-cell
    marker is not read as a verdict.

    **The intermediate-lead clause is struck (v2.22), not unimplemented.**
    It was armed and then removed, because it cannot be obeyed. Whether
    a screen lead is the sequence's last depends on leads not yet
    written, so the author cannot know it when writing the row; and by
    the time a second screen makes the first intermediate, the first is
    a committed `:L findings` cell that append-only puts beyond reach.
    The refusal named that earlier lead and offered "only its final lead
    carries the result", which is an instruction to have written a
    different row. The implementation had already carved `match` out for
    this exact reason; the carve-out was the whole rule. What is lost is
    that an early `no_match` still reads as the sequence's answer to a
    careless reader — a reader-side concern the `loop` column and
    `:L findings` DOCUMENT order answer, which is not the order
    `companion["findings"]` projects in (see §`mode: screen` above).

18. **Lead-level predictions structure.** When `lead.predictions` is
    present, each entry has `id` (matching `^lp\d+$`, unique within
    the lead), `if`, `read_as`, `advance_to`. `advance_to` is either
    a lead name appearing elsewhere in the companion, or one of
    `CONCLUDE` / `HYPOTHESIZE`. If the lead is followed by another
    lead in the same companion, the follower's `name` should match
    at least one `advance_to` value — otherwise a route-compliance
    warning is emitted.

    Implemented as `_check_lead_prediction_structure`
    (`defender/skills/invlang/validate.py`), reading
    `findings[].predictions[]` — where `:L l-NNN.lead_preds` projects
    since #933; before that the block was recognized and its rows
    discarded, so this rule had nothing to read. `advance_to` resolves
    against every declared lead `name` including the declaring lead's
    own: "elsewhere in the companion" is a topology claim the format
    does not carry, and refusing a self-route buys no safety.
    UNIQUENESS is not checked, for the reason recorded on rule #33 —
    `_warn_repeated_ids` makes a within-block repeat a parse error and
    `_extend_by_id` keeps the first record per id across blocks, so a
    duplicate never reaches the projected list.

    **The route-compliance clause is NOT implemented, and honouring
    "warning" is the reason.** In this codebase warn severity is not an
    advisory: a warn diagnostic with no `Locus` is dropped by
    `runtime/tools._addressable` and does nothing at all, while one WITH
    a locus flags that row and blocks every subsequent write until
    `fix_row` rewrites it. Neither candidate row may be rewritten. The
    follower's `:L findings` row is a committed lead declaration —
    `_tool_fix_row` records that the warn family "walks
    `:R attr_updates` blocks and nothing else", and widening it to lead
    declarations is a separate decision. The `lead_preds` row is worse:
    letting a run edit its own pre-registration to match where it ended
    up destroys the only thing pre-registration is for. Raising it to an
    error would not honour the spec either. A gap inside an otherwise
    implemented rule; see the enforcement ramp.

19. **(Merged into rule #7.)** Authorization contract `edge_ref`
    resolves — see rule #7 (reference resolution).

20. **(Merged into rule #7.)** Authorization back-reference resolves
    — see rule #7 (reference resolution).

21. **Authorization-gated disposition.** A `conclude.disposition:
    benign` requires every `authorization_contract` across all
    confirmed-weight hypotheses (weight `++` or `+`, status
    `confirmed` or `active`) to have at least one fulfilling
    `authorization_resolutions` entry with `verdict: authorized`.
    Unfulfilled contracts (and not listed in `deferred_authorizations`
    per rule #26), or fulfillments with `verdict: indeterminate`, or
    any `verdict: unauthorized`, therefore block `benign`. Replaces
    the former "maintain adversarial hypothesis until `--`"
    bookkeeping rule.

    Implemented as `_check_benign_authz`
    (`defender/skills/invlang/validate.py`).

    **v2.18 — escalation half excised.** The rule also read: those
    shapes "force `status: escalated` and disposition ∈ {`unclear`}",
    and an `unauthorized` verdict forces `status: escalated` with
    disposition ∈ {`unclear`, `true_positive`}. Neither `unclear` nor
    `true_positive` is in `DISPOSITION_VALUES`
    (`defender/_vocab.py`), no `status: escalated` routing target
    exists, and `escalated` has zero occurrences in the validator. The
    benign half above is the enforced half and is unchanged. Only the
    positive floor — *which* non-benign value an undischarged contract
    must land on — was retired vocabulary, and it is gone.

22. **(Merged into rules #1 and #7.)** Attribute-update target shape
    — exclusivity check (exactly one of `v-{id}` / `e-{id}`) lives
    in rule #1 (schema validity); reference resolution lives in
    rule #7.

23. **Hypothesis fork distinctness.** Within a sibling group —
    hypotheses sharing `(parent_hypothesis_id, attached_to_vertex)` —
    no pair that has declared predictions may declare the same ones.
    A difference is what a lead splits them on; a pair predicting the
    same observables proposes the same causal upstream under two ids
    and can be discriminated by nothing. (Absorbs former #35 sibling
    prediction divergence, which stated this check on the
    classification-agnostic axis #934 settled on.)
    `proposed_edge.parent_vertex.classification` is NOT the axis: a
    shared one is legal, and an open one (`??` in any slot) is the
    canonical spelling for a fork whose parent the alert has not
    placed, so a check keyed on classification would refuse the shape
    §Sibling-fork uniqueness asks for (#934). Enforced by
    `validate._check_fork_distinctness` at the textual floor — LIVE
    siblings whose declared claims are identical after case/whitespace
    normalization. The compared set is the union of `predictions[]`
    `claim` and `attribute_predictions[]` `(target, attribute, claim)`;
    `predictions[].subject` is NOT in it, since the same claim filed
    under `proposed_parent` and under `proposed_edge` still splits
    nothing. A hypothesis that has declared no predictions yet is
    exempt (the `:H` row and its `.preds` block are separate appends),
    and refuting one of two colliding rows is the append-only repair.
    Whether two differently-worded claims say the same thing is not
    detectable and stays the author's discipline.

    Implemented as `_check_fork_distinctness`
    (`defender/skills/invlang/validate.py`). The sibling group key is
    the parent read off the id shape `h-{parent}-{nonce}` paired with
    `attached_to` — there is no `parent_hypothesis_id` column to key
    on.

    **The two prediction blocks contribute differently shaped keys,
    because their `claim` cells are different kinds of thing.** A
    `.preds` claim is a sentence carrying its own subject ("failures
    arrive in bursts"), so `subject` is out of the key: one sentence
    filed under two subject labels is still one observable. An
    `.attr_preds` claim is a VALUE — `unsigned`, `none`, `partial` —
    which names nothing without the `target` and `attribute` saying
    what it is a value OF, so those are in. Keying attribute
    predictions on the bare value would fuse
    `proposed_parent.signing=unsigned` with
    `attached_vertex.publisher=unsigned` and refuse a pair one lead
    splits by measuring two different things.

    **Empty-signature hypotheses are skipped.** A hypothesis declaring
    no prediction at all has no fork axis to compare, so it collides
    with nothing and is passed over; the leanness and refutation-link
    rules own that shape. This was stated as rule #35's convention
    until #934 merged #35 into this rule; it is this rule's convention
    now.

24. **Hypothesis persistence — no orphaned hypotheses at CONCLUDE.**
    When a `conclude:` block is present, every hypothesis declared in
    `hypothesize.hypotheses[]` or any prior `lead.outcome.new_hypotheses[]`
    must either (a) have its final effective weight be `--` across the
    resolutions chain, OR (b) be named in
    `conclude.surviving_hypotheses[]`.
    *(A third arm — retirement by a `:T shelved` row — was removed in
    #933 along with the block. It let a run stop carrying a hypothesis
    without refuting it, which is a real shape; but no investigation on
    record ever used it, and the block was never taught in the injected
    SKILL.md, so the arm was reachable only by a run that guessed its
    grammar while the rule stayed armed for everyone. A run that is no
    longer carrying a hypothesis resolves it. The removed note read:
    listing a set-aside hypothesis as surviving asserts the run is
    still carrying it, and `--` asserts a refutation that never
    happened.)*
    *(v2.18: arm (b)'s surviving sub-arm read "…driving `status:
    escalated`". The qualifier is dropped — no such status exists.
    v2.20: the other two sub-arms are excised, and the rule is scoped
    to closes that write the table — both notes below.)*
    A hypothesis declared and then silently ignored — never refuted,
    never carried into CONCLUDE — fails this rule. Closes the "silent
    hypothesis drop across loops" bias: grading blindness on one
    mechanism cannot be papered over by forgetting the hypothesis
    existed. The ANALYZE subagent is the proximate enforcer (it
    decides when weights are terminal); this rule is the structural
    backstop at the CONCLUDE write boundary.

    Implemented as `_check_hypothesis_persistence`
    (`defender/skills/invlang/validate.py`).

    **v2.20 — two of arm (b)'s three sub-arms excised.** The arm read
    "cited in the conclude block (as the termination target, as the
    matched archetype's mechanism, or as a surviving-but-indeterminate
    hypothesis)". Neither of the first two is a projected hypothesis
    reference and neither was ever checkable.
    `termination.rationale` is free text and `termination.category` an
    unchecked scalar, so nothing in the termination pair names an
    `h-*`. `matched_archetype` is declared at
    `defender/skills/invlang/schema.py` (`Conclude`), written only in
    test fixtures and worked examples, read by **zero** production
    code, and resolved against an archetype catalog that does not
    exist anywhere in the repository — so "the matched archetype's
    mechanism" is a reference into nothing. An escape hatch that
    cannot be checked is one every document holds open; what remains
    is the one arm the parser actually projects.

    **v2.20 — scoped to closes that write the table.**
    `conclude.surviving_hypotheses` is omittable by construction:
    `parser._project_surviving_block` projects it *checkable, not
    authoritative*, and benign gating computes survival from the
    resolution record precisely so a run may leave it out. So an
    ABSENT table is read as the document deferring to that record,
    under which every non-refuted hypothesis is surviving and nothing
    was dropped — the rule stands down. A table that is PRESENT (rows,
    or the `none` empty-array marker) is read as the author's own
    enumeration, and a live hypothesis missing from it fails.
    Measured before choosing: reading an absent table as an empty one
    would newly refuse **seven of the eight** ```invlang documents in
    the tree — both shipped goldens
    (`defender/fixtures-e2e/golden-sshpivot-ab3`,
    `golden-v2sshd`), `defender/examples/example-c-cumulative-escalation.md`,
    and four experiment fixtures — because none of them writes the
    table at all. Making it mandatory is a decision about what ANALYZE
    must WRITE, not about what a document says, and it is not made
    here.

25. **Same-level sibling rollup — prediction IDs are hypothesis-scoped.**
    On any `gather[i].resolutions[j]` entry for target hypothesis `H`,
    every id in `matched_prediction_ids[]` must appear in `H`'s own
    declared `predictions[]`. Rule 5 already enforces the equivalent
    for `matched_refutation_ids[]` on `--` resolutions; rule 25
    extends coverage to `matched_prediction_ids[]` on every weight
    and closes the same-level sibling-rollup loophole (upgrading `H`
    on the strength of a sibling's confirmed prediction). Rule 6's
    per-hypothesis coverage aggregation would silently ignore a
    mis-cited ID; rule 25 rejects it loudly so the grade is forced
    to rest on this hypothesis's own evidence.

26. **Authorization contract closure at CONCLUDE.** When a `conclude:`
    block is written, every declared `authorization_contract[]` entry
    across `hypothesize.hypotheses[]` and any
    `lead.outcome.new_hypotheses[]` must either (a) have at least one
    fulfilling entry in the
    effective set of `authorization_resolutions[]`, OR (b) appear in
    `conclude.deferred_authorizations[]` with a non-empty rationale.
    A contract that is declared and silently abandoned — never
    resolved, never deferred — fails this rule. Closes the orphan-
    contract loophole observed in the pre-v2.10 corpus where 59% of
    declared contracts had no resolution; rule #21 gated benign but
    escalation paths silently accepted orphans.

    Implemented as `_check_authz_contract_closure`
    (`defender/skills/invlang/validate.py`), reading
    `conclude.deferred_authorizations[]` — where
    `:T conclude.deferred_authz` projects since #933; before that the
    block was recognized and its rows discarded, and arming arm (a)
    without arm (b) would have refused documents with no legal repair.
    Runs under every disposition and covers contracts on REFUTED
    hypotheses too: refutation is offered here as a deferral RATIONALE
    ("superseded by mechanism refutation at lead l-007"), not as an
    automatic discharge, because that is a claim about the case a reader
    should be able to see the run make.

    DEFERS to `_check_benign_authz` on any contract the run's own
    disposition gate is already refusing, matched on that gate's output
    rather than on the disposition keyword. Reporting both would name
    one missing `:R authz` row twice, and this rule's arm (b) would be a
    trap there — deferring clears this rule and leaves `benign` blocked.
    The two are otherwise independent: deferring with a reason satisfies
    this rule and never satisfies rule #21, because benign needs the
    question ANSWERED, not accounted for.

    Shares its closure walk with rules #31 and #34
    (`_unclosed_commitments`): the three are one sentence over three
    namespaces. A deferral row written with the qualified
    `h-{id}.ac{n}` discharges only that contract; one written bare
    (`ac1`) discharges every hypothesis's `ac1`, matching the
    document-wide reading `_check_benign_authz` gives a bare
    `fulfills_contract`.

27. **Past-case no-sole-grounding for benign.** On any
    `authorization_contract` that is load-bearing for
    `disposition: benign` (i.e., the hypothesis is confirmed-weight at
    CONCLUDE), at least one fulfilling `authorization_resolutions`
    entry must have `grounding_kind: org-authority` — if every
    fulfilling resolution has `grounding_kind: past-case`, the
    contract is treated as unresolved for rule #21 and escalation is
    forced. *(Former clause (a) — past-case ⇒ partial — moved to
    rule #11 as an enum constraint.)*

28. **Past-case chain depth cap.** An `authorization_resolutions[]`
    entry with `grounding_kind: past-case` references a source
    companion via `cites_past_case.run_id` and an exact prior contract
    via `cites_past_case.contract_ref`. The referenced companion's own
    fulfilling resolution for that contract must have
    `grounding_kind: org-authority` — a past-case companion cannot
    itself cite another past-case as its grounding. Prevents bootstrap
    drift where similar alerts recursively authorize themselves
    without any real policy consultation in the chain.

29. **Impact prediction structure.** Every `impact_predictions[]`
    entry on a lead has `id` matching `^ip\d+$` and unique within the
    lead, plus required fields `dimension` (one of `confidentiality`,
    `integrity`, `availability`, `scope`), `claim`, `on_match`,
    `on_mismatch`, `on_indeterminate`, `escalation_on`. `claim` names
    one observable per entry — compound `AND` / `OR` / semicolon
    predicates must be split across entries. The full cross-lead
    identity of the prediction is `l-{lead_id}.ip{n}`.

    Implemented as `_check_impact_prediction_structure`
    (`defender/skills/invlang/validate.py`), reading
    `findings[].impact_predictions[]` — where `:L l-NNN.impact_preds`
    projects since #933. `dimension` is closed against
    `vocab.IMPACT_DIMENSION`; the remaining five cells are checked for
    being non-blank, because `_impact_pred_row` requires only `id` and
    a predicate missing one of its outcomes cannot be graded on that
    outcome. Uniqueness is owned upstream, exactly as on rule #33. The
    **one-observable-per-entry clause is semantic and deliberately not
    enforced**, for the reason recorded on rule #33: it is a judgment
    about what a sentence asserts, and a lexical test would refuse
    "session bytes and connection count stay within baseline" written
    about one measurement.

30. **Impact resolution back-refs and grounding.** Every
    `impact_resolutions[]` entry on a lead outcome has `prediction_ref`
    resolving to a declared `impact_predictions[]` id somewhere in the
    companion (bare `ip{n}` resolves within the emitting lead; fully
    qualified `l-{id}.ip{n}` resolves across leads). `dimension` must
    match the referenced prediction's `dimension`. `verdict ∈ {within,
    exceeds, indeterminate}`. `grounding_kind ∈ {telemetry-baseline,
    business-owner-attestation, dlp-policy}` — `past-case` is forbidden
    on impact resolutions (impact is per-instance reasoning, not
    category-of-event). Required fields: `prediction_ref`, `dimension`,
    `verdict`, `grounding_kind`, `authority_for_question`, `as_of`,
    `reasoning`.

    Implemented as `_check_impact_resolution_refs`
    (`defender/skills/invlang/validate.py`). The impact analog of
    `_check_prediction_refs` and armed for the same reason: nothing
    joined a `:R impact` row back to the predicate it claims to grade,
    so a typo, a forward reference and another lead's `ip1` all landed
    identically. A bare `ip{n}` is scoped to the lead the row was filed
    under — its `resolved_by` — which is the only lead that could have
    measured it. `past-case` is refused by name rather than left to the
    enum's silence, because the omission is a judgment and not an
    oversight.

    NOT checked: whether `observed` supports `verdict`. That is free
    text and reading it against `claim` is the judgment ANALYZE exists
    to make; this rule checks that the row is ANSWERABLE, not that the
    answer is right.

31. **Impact closure at CONCLUDE.** When a `conclude:` block is
    written, every declared `impact_predictions[]` id across all
    leads must either (a) have at least one fulfilling
    `impact_resolutions[]` entry, OR (b) appear in
    `conclude.deferred_impact_predictions[]` with a non-empty
    rationale. Mirrors rule #26's orphan gate for authorization
    contracts. `conclude.impact_verdict ∈ {none, within, exceeds,
    indeterminate}`; `conclude.impact_severity ∈ {null, low, moderate,
    high}` and is required when `impact_verdict ∈ {exceeds,
    indeterminate}` and forbidden otherwise. Rule #14 (partial
    authority cap) applies to impact resolutions as well.

    Implemented as `_check_impact_closure`
    (`defender/skills/invlang/validate.py`), reading
    `conclude.deferred_impact_predictions[]` — where
    `:T conclude.deferred_impact` projects since #933. The orphan arm
    shares its closure walk with rules #26 and #34
    (`_unclosed_commitments`), which is what "mirrors rule #26's orphan
    gate" now means literally. `impact_severity`'s required-iff PAIRING
    with `impact_verdict` is enforced — structural, and it holds
    whatever the two cells say — and `null` is read as an ABSENT
    severity, since that is the word the format uses for one.

    **Neither conclude scalar's VOCABULARY is enforced.**
    `skills/invlang/SKILL.md` has never stated `impact_verdict ∈ {none,
    within, exceeds, indeterminate}` nor `impact_severity ∈ {null, low,
    moderate, high}`; both live only in this document. Refusing on a
    vocabulary the runtime prompt never gave the model is the failure
    rule #32 was struck for. The measurement makes the point for
    `impact_verdict`: it fires on both shipped e2e goldens —
    `golden-v2sshd` writes `none-detected` and `golden-sshpivot-ab3`
    writes `attempted-lateral-movement`, where the spec's roll-up over
    zero `:R impact` rows is `none` in both cases — and those two are
    not authored fixtures whose cell can be corrected but recorded runs
    replayed through this same gate from `tool_trace.jsonl`, so arming
    it refuses the recorded write and takes seven e2e tests with it.
    `impact_severity` measures zero fires and is left unenforced
    alongside it: the two are one decision, and a vocabulary is either
    taught or it is not.

    Both are registered in `vocab.SLOTS`
    (`enum conclude.impact_verdict`, `enum conclude.impact_severity`),
    which IS the teaching step; #933 ships that and not the arming. The
    conditional-presence clause needs neither: an unrecognized verdict
    is not in `{exceeds, indeterminate}`, so a severity beside it is
    forbidden and a missing one is not demanded — the right reading of
    a roll-up the enum does not name.

    NOT checked: whether the roll-up is arithmetically right. That needs
    `:R impact` rows, and no document in the tree carries any.

    Rule #14's partial-authority cap is unimplemented for impact
    resolutions as it is everywhere else; #14 carries no
    **Implemented as** line.

32. **(Struck — a mandate that would manufacture its own compliance.)**
    Integrity peer discipline. Specified (v2.11 as prose, numbered as a
    rule from v2.13) as: when a hypothesis carries an
    `authorization_contract` AND its
    `proposed_edge.parent_vertex.type` is an acting-entity type
    (`session`, `identity`, `process`), either (a) a sibling
    hypothesis sharing `(parent_hypothesis_id, attached_to_vertex)`
    whose `name` starts with `?adversary-controlled-` must exist, OR
    (b) the contract-carrying hypothesis must carry
    `integrity_waived: <non-empty rationale>`. Non-acting-entity
    parent vertex types (endpoint, file, storage, database, …) are
    exempt. Its purpose was to close the
    authorized-bulk-read-from-compromised-account shortcut — authz
    clears, impact clears, but the integrity premise was never tested
    — with integrity resolving through normal weight machinery on the
    peer rather than through a separate contract.

    Never implemented. There is no `_check_integrity_peer_discipline`
    in `defender/skills/invlang/validate.py`; the name appears in this
    repository only in `experiments/relax-invoker-identity-peer/`,
    against a `soc-agent` tree that is not here.

    Struck in v2.19. Its discharge test is a
    `name.startswith("?adversary-controlled-")` prefix match on
    model-authored free text: 6 of the 10 contract-bearing hypotheses
    in the corpus trigger it, all 6 fail it, **0 discharge it**, and
    arming it would mint the peers rather than find them. That
    measurement, the four arguments it rests on, and the coverage gap
    it leaves open — whose recorded answer is the
    behavioral-consistency prediction in
    `docs/decisions/adversarial-as-attribute-not-hypothesis.md`, not a
    structural gate — are in
    `docs/decisions/defender-invlang-enforcement-ramp.md` §Struck from
    the spec. The `integrity_waived?` column stays in the `:H` grammar
    and is now read by nothing.

33. **Attribute-prediction structure.** Each `attribute_predictions[]`
    entry on a hypothesis has `id` matching `^ap\d+$` (unique within the
    hypothesis), `target` ∈ {`proposed_parent`, `attached_vertex`,
    `proposed_edge`}, `attribute` (non-empty string — the field name
    being predicted), and `claim` (non-empty string, one observable per
    entry — compound `AND` / `OR` predicates split into separate
    entries). `refutation_shape[].refutes_predictions` may cite `ap*`
    ids alongside `p*` ids on the same hypothesis.
    `matched_prediction_ids[]` on a resolution may likewise cite both
    `p*` and `ap*` ids from the target hypothesis.

    Implemented as `_check_attribute_prediction_structure`
    (`defender/skills/invlang/validate.py`) for the `^ap\d+$` id
    shape, the `target` enum and the non-empty `claim`. The other two
    clauses need no code there and get none. `attribute` non-empty is
    already a parse error — `_hyp_sub_attr_pred_row` `_require`s it,
    and `_require` tests truthiness. **Uniqueness within the
    hypothesis** is enforced one level up in two places:
    `_warn_repeated_ids` makes a repeat inside one `.attr_preds` block
    a parse error, and `_extend_by_id` keys accumulation by id so a
    repeat ACROSS blocks never reaches the projected record — and must
    not be refused there, because re-emitting a sub-block with one row
    added is the documented append shape. A uniqueness check in
    `validate.py` would be unreachable code that read as live. The
    "one observable per entry, split compound `AND`/`OR`" clause is
    semantic and deliberately not enforced, exactly as on rule #29.

34. **Prediction closure at CONCLUDE.** When a `conclude:` block is
    written, every declared `predictions[].id` (`p*`) and
    `attribute_predictions[].id` (`ap*`) on a hypothesis whose final
    status is not `refuted` (i.e. `active` or
    `confirmed`) must be either (a) cited in some resolution's
    `matched_prediction_ids[]` with a non-null `after`, OR (b) listed
    in `conclude.deferred_predictions[]` with a non-empty `rationale`.
    Each `deferred_predictions[]` entry has
    `prediction_ref: h-{id}.{p|ap}{n}` and `rationale: "<why>"`. The
    projected record keeps the column name its own table writes —
    `prediction_ref` here and on `:T conclude.deferred_impact`,
    `contract_ref` on `:T conclude.deferred_authz` — rather than folding
    the three onto one key: the column name is what this document calls
    the field, and one closure walk over three namespaces is a reason
    for ONE reader (`_deferral_index` takes either), not for one column
    name. See `schema.DeferralRecord`.
    Late closure gate; rule #6 is the early gate at write time on a
    hypothesis standing at `++`. The exclusion the implementation
    applies here — a hypothesis #6 already owns is not asked for a
    deferral — reads the same `validate._confirmed_and_standing`, so the
    two cannot both stand down on one hypothesis (v2.22). Closes the contract analyze owes predict:
    predict pre-commits a prediction set; analyze must address every
    entry by REPORT or the loop owes a justification.

    Implemented as `_check_prediction_closure`
    (`defender/skills/invlang/validate.py`), reading
    `conclude.deferred_predictions[]` — where
    `:T conclude.deferred_preds` projects since #933. Shares its closure
    walk with rules #26 and #31 (`_unclosed_commitments`).

    "Final status" is read off the RESOLUTION RECORD, not off the `:H`
    `status` column, and that is the same translation
    `_check_hypothesis_persistence` applies to rule #24: `status` is
    fixed at declaration time and append-only forbids updating it, so it
    can never carry a FINAL status. Refuted is final weight `--`, and
    since #933 retired `:T shelved` it is the whole of what "final
    status" means here. Scoped to the declaring hypothesis,
    never document-wide — a sibling's `p1` discharges nothing, which is
    the cross-citation rule #25 refuses one level down.

    Corpus: fires on two experiment fixtures,
    `experiments/judge-glm52-vs-kimik3/fixtures/case-00{1,2}` — the same
    two documents and the same `h-001.p3` that rule #6 already fires on,
    where the run's own `l-002` showed no successful auth and `p3`
    predicted one. Both genuine, neither a shipped golden or a worked
    example, both left as they are. It also fires on five minimal
    fixtures in `defender/tests/test_invlang_rules_933*.py` written for
    rules #23/#24 — documents that declare predictions, write a
    `:T conclude`, and never cite or defer them. Those fixtures are
    non-compliant under this rule and need one
    `:T conclude.deferred_preds` block each; the rule is not what is
    wrong there.

35. **(Struck — subsumed by rule #23.)** Sibling prediction
    divergence. Specified (v2.13) as: within a sibling group —
    hypotheses sharing `(parent_hypothesis_id, attached_to_vertex)` —
    no two siblings may declare identical prediction signatures, a
    signature being the union of `predictions[]` `(subject, claim)`
    and `attribute_predictions[]` `(target, attribute, claim)` tuples
    (case-normalised), with empty-signature hypotheses skipped.
    Identical signatures mean both hypotheses propose the same
    observable expectations and ANALYZE has no discriminator to grade
    them differently — the fork is paraphrase, not mechanism. That
    substance is entirely preserved; it now lives in rule #23.

    Why #23 refuses strictly more — its signature is #35's with
    `predictions[].subject` dropped, which only widens what collides —
    is recorded in `docs/decisions/defender-invlang-enforcement-ramp.md`
    §Struck from the spec.

36. **(Retired — vocabulary the system does not have.)** Affirmative
    `true_positive` disposition. Specified (v2.14, simplified v2.16) as
    a constraint on `conclude.disposition: true_positive` — requiring at
    least one `conclude.surviving_hypotheses[]` entry whose final weight
    is `++`, so the routing rested on affirmative grading evidence
    rather than on absence-of-benign-confirmation.

    Struck in v2.18 because `true_positive` is not a disposition this
    system can express. The live enum is
    `DISPOSITION_VALUES = ("benign", "false-positive", "inconclusive",
    "malicious")` in `defender/_vocab.py`; `true_positive` has never
    appeared anywhere under `defender/` in the repository's history, so
    this was never a rename that drifted out of sync. Nothing enforced
    the rule — `true_positive` has zero occurrences in
    `defender/skills/invlang/validate.py`, and the
    `hooks/scripts/invlang_checks_authorization.py:_check_affirmative_true_positive`
    that the v2.14 and v2.16 deltas cite as its implementation does not
    exist in this repository.

    **The substance survives translation; the translation was not
    made.** Read against the live enum the rule becomes: `disposition:
    malicious` requires a `++`-graded survivor, and the honest landing
    where none exists is `inconclusive`. That is a coherent rule and
    `defender/_vocab.py` supports the mapping directly — `malicious` is
    the confirmed-threat landing, `inconclusive` the nothing-established
    one. Re-arming it under the live spelling is a separate decision
    that has not been made, so it is recorded here as a gap rather than
    silently rewritten into an active rule. The empirical motivation is
    preserved in `docs/decisions/analyze-true-positive-routing.md` (4
    production runs) for whoever takes that decision up.

    Numbering preserved for grep-stability, per the v2.15 convention.
