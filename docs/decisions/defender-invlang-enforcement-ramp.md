---
title: Defender invlang validator — deferred rules blocked on spec self-contradictions
status: todo
groups: defender, invlang, reliability
---

**Shipped.** `defender/hooks/invlang_validate.py` enforces the current
invlang spec on `investigation.md` writes, **blocking** (exit 2) on any
violation — and **failing closed** (exit 2) on an internal validator
error rather than letting the write through. Scope is anchored to
`DEFENDER_RUN_DIR` so only the run's own companion is gated. Rules (in
`defender/skills/invlang/validate.py`):

0. surface — line endings are normalized (a CRLF file can't slip past
   the fence regex into an empty-companion no-op pass), and a
   `​```yaml`/`​```yml` fence is rejected (the on-disk surface is
   `​```invlang`).
1. parse-clean — any parser `ParseWarning` blocks.
2. append-only — `​```invlang` block count must not shrink **and** no
   committed vertex/edge (by id) may be mutated in place or removed.
3. edge-authority — `++`/`--` resolutions must cite a
   siem-event/runtime-audit/authoritative-source edge.
4. closed-vocab — vertex `type`, edge `rel`, authz `anchor_kind`, edge
   `auth_kind` ∈ `vocab`, and `:R attr_updates` keys ∈ {`class`,
   `attrs.<name>`} (a bare key is silently dropped by the resolver).
5. benign-gating — `disposition: benign` requires (a) no unresolved
   `??` slot **or `{a,b}` candidate-set** on any vertex and (b) every
   authz contract on a **live** (final weight ≠ `--`) hypothesis
   resolved `authorized`. Survival is computed from the resolution
   record, **not** the omittable `:T conclude.surviving` table, and a
   later `authorized` row can't mask an earlier `unauthorized` for the
   same contract.
6. prediction-refs — a resolution's `matched_prediction_ids` /
   `matched_refutation_ids` must resolve to ids the moved hypothesis
   itself declares in `:H h-NNN.preds` / `.attr_preds` / `.refuts`. The
   parser derives those lists from head tokens and never joined them
   back to the declaring block, so a typo, a forward reference and a
   *sibling's* `p1` all parsed clean (#798).
6a. hypothesis-refs — every `h-*` a document names must be declared, at
   `:H hypothesize.hypotheses` or at a lead's `:H l-NNN.new_hypotheses`
   (#818, #821). The projector opens no bucket for an unknown `h-*`, so a
   phantom moved to `++` in silence and `_walkers.final_weights`
   reported it live. It could not be enforced until `:H` blocks
   accumulated (#817) — before that a legitimate mid-run fork's earlier
   hypotheses were dropped and this error fired on a correct document.
   One error per row (the citation half of rule 6 stands down for that
   row), and it defers to rule 1 when a parse warning came off a
   hypothesis *declaration* block: those warnings delete ids the
   document still refers to, so the parse error already names the
   cause. `examples/example-b-parallel-iam-cmdb.md` is the shipped
   instance — its `:H` rows use `attached_to=e-001`, which `:H` forbids,
   and four resolutions then point at the hypotheses those row errors
   dropped. *Fix the example and the deference stops mattering there.*

   That deference is keyed to the dropped IDS, not to the document
   (`parser.deferred_hypothesis_ids`). Answering only "did any
   declaration get dropped?" meant one malformed `:H` row anywhere
   silenced the rule for the whole file, so an unrelated typo three
   leads away went unreported behind a warning that had nothing to do
   with it. The id is recoverable in both failure modes — a whole-block
   rejection carries `ParseWarning.dropped_ids`, a row-level failure
   carries its row, whose first cell IS the id. `None` (a dropped row
   too mangled to name an id) still stands the rule down wholesale,
   because there is then no way to tell a reference that block would
   have satisfied from a genuine phantom. A warning naming NO id — a
   header rejected on a block that held no rows — deleted nothing and so
   defers for nothing; reading "named nothing" as "unmappable" put the
   whole file back behind a warning that dropped no declaration at all.
   `dropped_ids` is the authoritative channel and is read off whatever
   block carries it, because the singular typo `:H l-NNN.new_hypothesis`
   deletes declarations too and does not match the DECLARING names.

   Rule 6b defers the same way by construction: a row whose `h-*` was
   dropped is skipped (its commitments cannot be scoped), and so is a row
   with nothing to scope against at all.

   #818 closed only the `:T resolutions` row. FOUR sites reference an
   `h-*` and `_check_hypothesis_refs` now owns all four (#821): the
   resolution, `:L findings`'s `tests` column, `:T shelved`, and
   `:T conclude.surviving`. Two of the three added are the ones a run
   reaches FIRST — a lead can claim to test a hypothesis nobody declared,
   and a `:T shelved` row can retire one that never existed — so a typo
   used to surface a step late, pointing at the resolution rather than at
   the PLAN row that introduced it. The fourth is the one a run reaches
   LAST, and the parser was accepting it and discarding its rows
   (`if name.startswith("conclude."): return True`), so the closing claim
   about what is still standing could name a phantom and nothing looked.
   It is now projected to `conclude.surviving_hypotheses[]` — *checkable,
   not authoritative*: rule 5 still computes survival from the resolution
   record, because this table is self-reported and omittable.

   `tests` alone is scoped to `h-*`-SHAPED ids, because `tests` alone is
   mixed: it is the commitments the lead was run for and the shipped
   golden proves that is three id kinds (`golden-sshpivot-ab3` tests `ac1`
   on l-002, `p2` on l-003), so reading the column as hypotheses-only
   denies a correct document. `:T shelved`'s column is `hyp_id` — every
   value in it IS a hypothesis reference, so no shape gate applies there;
   one would exempt exactly the typo the rule exists to catch (`h_888`
   shelves nothing and would pass in silence). The shape itself covers the
   hierarchical child form `h-{parent}-{ordinal}`, which is what a lean
   hypothesis refines into and what the lead's `new_hypotheses` declares
   with the parent shelved in the same block.

   The validator is a gate in front of a walker that minted the same
   phantom, and #821 closed that too: `_walkers.final_weights` seeded an
   entry from the resolution row, so its key set — which is what
   `live_hypothesis_ids` reports — could carry an id no `:H` row declares.
   The gate only runs on the write; `skills/invlang/queries.py` and
   `learning/pipeline/judge/compare.py` read the walker on documents that
   never passed through it. Both already looked weights up BY a declared
   id, so narrowing the key set to `all_hypotheses` changed neither, and
   `_check_benign_authz`'s `live` loop already skipped ids `all_hypotheses`
   does not carry.
6b. tested-commitment refs — a `p*`/`ap*`/`r*`/`ac*` in `:L findings`'s
   `tests` column must be declared by a hypothesis that same row says it
   is testing (#821). The other half of the mixed column: rule 6a
   resolves its `h-*` and nothing resolved the rest, so
   `tests=h-001,p9,ac9` named two commitments that do not exist and
   validated clean — rule 6's hole, one namespace over, at the site that
   writes it first. Scoped to the row's own hypotheses rather than the
   document, or it would accept a sibling's `p2`, which is exactly the
   cross-citation rule 6 refuses one level down; a row naming no
   hypothesis falls back to every declared one. `ac*` is checkable
   nowhere else — no resolution head cites a contract. An id in no
   recognized namespace is left alone; the one that reaches here is
   `lp*`. *(#933 projected `:L l-NNN.lead_preds`, so "it resolves
   against nothing" has stopped being the reason. The exemption stands
   on a better one: an `lp*` is scoped to a LEAD and this column is
   scoped to a HYPOTHESIS, so no hypothesis's declarations could resolve
   it, and rule 16 below owns that namespace where it lives.)*
7. strong-move citation — a `++`/`--` must name at least one of them.
   The other half of rule 3's provenance tuple: which pre-committed
   claim the cited observation settled.
8. prediction completeness — a `++` must name **all** of them (#933,
   spec rule #6). Rule 7 stops at "cites something": a hypothesis
   declaring five predictions reached *confirmed* on whichever one the
   lead found convenient, and the other four were never heard from
   again. The union is over every resolution on the hypothesis, not
   just the `++` row, so it only grows — a document that clears this
   clears it for good, which is what makes it safe on an append-only
   file. **`ap*` counts**: `_declared_prediction_ids` is the one
   definition of the declared set, and spec rule #34 (the CONCLUDE-time
   closure gate this is the write-time half of) enumerates `p*` and
   `ap*` alike, so a `p*`-only reading would exempt an observable from
   the gate for being declared under `.attr_preds`. Corpus: fires on
   two experiment fixtures, both genuine — in
   `experiments/judge-glm52-vs-kimik3/fixtures/case-00{1,2}` the run's
   own `l-002` showed no successful auth and `p3` predicted one, and it
   graded `++` anyway. Neither is a shipped golden or a worked example;
   they are snapshots of model output and are left as they are.
9. SCREEN structural integrity (#933, spec rule #17) — a
   `screen_result` on a lead with no `mode: screen` (a verdict about a
   screen that never ran), on an intermediate screen lead (a partial
   answer in the slot readers take for the final one), or a
   `screen_result: match` beside a `:H hypothesize.hypotheses` block (a
   run claiming both that the fast path closed it and that it
   investigated). Read off `findings[].screen_result`; the spec's
   `outcome.` prefix is pre-dense spelling the projector never used.
   Corpus: zero fires — SCREEN is barely exercised on disk, which is
   why this could be armed at error severity without measurement risk.
10. sibling-fork distinctness (#933, spec rule #23; the deferral closed
   below). Two hypotheses in the same `(parent, attached_to)` group
   whose claim sets are identical after whitespace/case normalization.
   The group key is derived from the ID SHAPE `h-{parent}-{nonce}` —
   there is no `parent_hypothesis_id` column. **Not keyed on
   `parent_class`**, and `test_invlang_sibling_fork_934.py` is the guard
   that keeps it that way: siblings legitimately share `??/??/??` since
   #934. Detection floor is textual and stays there — paraphrase is
   authoring discipline, and a check that tried to read two sentences
   as one prediction would refuse correct documents. This **subsumes
   spec rule #35** (sibling prediction divergence), which is not
   implemented separately and does not need to be: this rule's
   signature is #35's with ONE column dropped, `predictions[].subject`,
   so every pair #35 refuses this refuses too. Corpus: zero fires.
   *(Spec v2.20 finished this: #35 is struck as subsumed, and the
   empty-signature skip — stated here and in the code as "#35's
   convention" — now belongs to #23.)*

   **One rule, two implementations, one survivor.** #934 and #933 wrote
   this check independently and landed within a day of each other:
   `_check_fork_distinctness` (#934) and
   `_check_sibling_fork_distinctness` (#933). Both were wired into
   `diagnose`, so for the length of one merge every fork violation was
   reported twice. #933's is the one that ships, with three things
   carried across from #934's before deleting it, each of which #934 had
   right and #933 did not:
   * **Sentence punctuation is normalized away** (`_normalized_claim`
     strips a trailing `.`/quote as well as folding case and inner
     whitespace). A full stop is the cheapest edit that defeats a
     textual floor.
   * **LIVE only.** `:H` rows are immutable, so a collision already on
     disk is unrepairable under a declared-set reading — every later
     write would be denied for a row nobody may touch. Refuting one of
     the two is the in-grammar repair and has to stay reachable.
   * **Attribute predictions key on `(target, attribute, claim)`, not
     on the claim alone.** A `.preds` claim is a sentence carrying its
     own subject, so `subject` is out of the key; an `.attr_preds`
     claim is a bare VALUE (`unsigned`, `none`) that names nothing
     without what it is a value of. Keying it on the value alone fused
     `proposed_parent.signing=unsigned` with
     `attached_vertex.publisher=unsigned` and refused a legal fork.
   #933's blank-claim skip went the other way and was kept: a blank
   `.attr_preds` claim contributes nothing to the signature, where
   #934's would have manufactured a spurious fork report on top of the
   two rule 12 errors the blank cells already earn.
11. hypothesis persistence at CONCLUDE (#933, spec rule #24) — a close
   that WRITES a `:T conclude.surviving` table and leaves a
   non-refuted hypothesis out of it. Scoped to a written table, and
   that scope is the measured half of the decision: the table is
   omittable by construction (rule 5 above computes survival from the
   resolution record precisely because it is), so an absent table is
   read as deferring to that record, under which nothing was dropped.
   Reading an absent table as an empty one would refuse **seven of the
   eight** ```invlang documents in the tree — both e2e goldens,
   `examples/example-c-cumulative-escalation.md`, and four experiment
   fixtures — none of which writes the table at all. Making it
   mandatory is a decision about what ANALYZE must write and is not
   made here. A table present as the `none` empty-array marker still
   counts as written: it claims nothing survived, and a live hypothesis
   contradicts that. Two of spec #24's discharge arms were excised as
   part of arming it — `termination.{category,rationale}` is an
   unchecked scalar beside free text, and `matched_archetype` is a
   `schema.Conclude` field read by zero production code against an
   archetype catalog that does not exist. Corpus: zero fires.
12. attribute-prediction structure (#933, spec rule #33) — `^ap\d+$` id
   shape, `target ∈ {proposed_parent, attached_vertex, proposed_edge}`,
   non-empty `claim`. The parser `_require`s id/target/attribute to be
   PRESENT and never looks at what they say, so `a1|the parent|colour|`
   parsed clean and landed a prediction no citation site could resolve.
   Two of spec #33's clauses are deliberately absent from the check:
   **uniqueness** is already owned upstream (`_warn_repeated_ids` makes
   a within-block repeat a parse error; `_extend_by_id` keys
   accumulation by id, so a cross-block repeat never reaches the record
   — and must not be refused, since re-emitting a sub-block with one
   row added is the documented append shape), and the
   **one-observable-per-entry** clause is semantic, left to the author
   exactly as on rule #29. Corpus: zero fires — no shipped document
   uses `.attr_preds` at all. It fired twice on ONE test fixture,
   `test_invlang_sibling_fork_934.py`'s `_ATTR_FORK`, which wrote a
   vertex id in the `target` cell; that shipped with #934 because #33
   had no implementation yet, and the cell is now `attached_vertex` —
   the same prediction about the same object, said in the grammar. The
   only other `v-*` target left in the tree is
   `test_invlang_parser_characterization.py`'s, which is deliberate:
   it characterizes the parser passing the cell through unread, which
   is exactly why this rule has to exist.

13. **The two projector holes, closed first (#933, #820).** Rules 14–18
   below could not be written until the parser stopped discarding their
   data, so this entry is the precondition and not a rule. Two holes:
   every `:T conclude.*` sub-block except `conclude.surviving` was
   recognized, consumed and dropped by a bare `return True`, and
   `:L l-NNN.lead_preds` / `.impact_preds` were documented and
   unprojected. Now projected: `Conclude.deferred_{authorizations,
   impact_predictions,predictions}[]` (from `:T conclude.deferred_{authz,
   impact,preds}`, normalized to one `{ref, rationale}` record shape
   because the three tables spell the reference column two ways) and
   `findings[].{predictions,impact_predictions}[]`.
   **The deferral tables landed in the same change as the rules that
   demand them** — arming "every declared X resolves" over an unprojected
   escape hatch refuses documents whose author already wrote the answer.

   `:L l-NNN.substitutions` stays recognized-and-dropped, deliberately:
   `query_details.substitutions` has no reader, so projecting it invents
   a field to hold rows nothing asks for, and warning on it would refuse
   a block the format permits. It is the last `:L` hole.

   **`ceiling_test` reconciled: the flat row is real, the sub-table is
   not.** `docs/dense-investigation-format.md` specified
   `:T conclude.ceiling_test [kind|subject]`, inherited from the pilot
   spec's YAML where `ceiling_test: {kind, subject}` named *the*
   out-of-band step that would resolve a severity ceiling. The shipped
   field is a REPEATED FLAT ROW naming one unreachable check each —
   `skills/invlang/SKILL.md` §`:T conclude` teaches it, eleven checked-in
   lessons under `defender/lessons/` instruct it,
   `schema.Conclude.ceiling_test: list[str]` carries it, and
   `render_synthesis` puts it in front of the judge
   (`test_ceiling_test_reaches_the_judge_prompt` records 49 run files
   that were writing the rows before anything read them). The `kind`
   enum appears in no vocabulary and no document.
   The format doc is corrected; a block written under the retired
   sub-table spelling is still accepted and ignored
   (`_RETIRED_CEILING_TEST_BLOCK`) rather than refused, because the
   content goes in the flat row either way and denying the write would
   cost a run for following a stale format note.

   **Projection behaviour, measured separately from the rule fires.**
   Over every ```invlang-bearing document in the tree (20 files, 75
   validation units — 10 whole companions plus every fence of every
   multi-illustration document): **zero new parse warnings, zero changed
   parse warnings.** No document writes any newly projected block, any
   newly allowlisted block, or an unknown `:T conclude.<sub>` /
   `:<TAG> l-NNN.<sub>` name. `_check_append_only` is untouched (it
   compares `:V`/`:E` records and fence counts, neither of which these
   blocks are). `deferred_hypothesis_ids` is untouched: the new warnings
   carry no `dropped_ids` and their block labels do not match
   `HYP_DECLARATION_BLOCK_RE`, so they cannot stand the
   undeclared-hypothesis rule down. The `:H` arm of the "unknown lead
   sub-block" warning keeps its `h-*`-filtered `dropped_ids` verbatim.
   `test_real_corpus_companion_is_byte_identical` still passes on both
   goldens — neither writes any affected block.

   **Two new refusal paths, both zero-fire today.** An unknown
   `:T conclude.<sub>` and an unknown `:<TAG> l-NNN.<sub>` are now parse
   warnings where they were silent. The conclude one matters most:
   `:T conclude.deferred_authorizations` (the FIELD name, which the spec
   also uses) would otherwise drop the whole deferral table and rule 15
   would then refuse a contract the author DID account for — an error
   pointing away from its cause. The asymmetry with
   `_project_conclude_scalars`, which stays silent on an unrecognized
   flat KEY, is deliberate and stated at both sites: a flat key can be
   lesson-instructed content, a block name is grammar.
14. **#13 ceiling_test scope (spec rule #13) — half the rule, and the
   half that fails silent.** `_check_ceiling_test_scope`. Only "required
   when `termination.category: severity-ceiling`" is armed. Corpus: zero
   fires (nothing in the tree writes that category).

   "Forbidden otherwise" is **not** armed and should not be. It was
   written against the pilot spec's single `{kind, subject}` ceiling
   step; the shipped field is the list of checks a run could not make,
   and eleven lessons instruct writing it whenever a source was out of
   reach. Forbidding it elsewhere refuses a run for obeying a lesson —
   the one failure `learning/core/persist.py` turns into a discarded run.
   `golden-v2sshd` names two such gaps under `data-ceiling`.

   **The trigger is unbacked and the vocabulary was NOT closed.**
   `termination.category` is free text with no `vocab` entry, so
   `severity_ceiling` disables this rule in silence. That direction is
   the safe one — a typo costs a miss, never a wrongful refusal — but it
   is real. Closing the four-value spec enum was measured and declined:
   both shipped e2e goldens are outside it (`data-ceiling`,
   `adversarial-confirmed`), and so are three test corpora (`exhaustion`,
   `adversarial-confirmed`, `natural`). Closing it would refuse the
   goldens, whose `investigation.md` is REPLAYED through this gate from
   `tool_trace.jsonl` — so it is not a fixture edit but a trace rewrite.
   **Open: close `termination.category`.** Order is teach in
   `skills/invlang/SKILL.md`, re-record the goldens, then arm.
15. **#26 authz contract closure (spec rule #26).**
   `_check_authz_contract_closure`. Every declared `ac*` is fulfilled by
   a `:R authz` row or deferred in `:T conclude.deferred_authz` with a
   non-empty rationale, under every disposition and including contracts
   on refuted hypotheses — refutation is offered as a deferral RATIONALE,
   not an automatic discharge. Closes the orphan-contract hole rule 5
   left open on every escalation path (59% of declared contracts had no
   resolution in the pre-v2.10 corpus).

   Corpus: **one fire**, on `examples/example-c-cumulative-escalation.md`,
   which declares `h-001.ac1` and abandons it. The example was wrong, not
   the rule: it is shipped teaching material, the deferral rationale the
   spec itself lists ("superseded by mechanism refutation at lead l-007")
   is exactly this case, and the fix is one additive row. Fixed here, so
   the worked example now demonstrates the mechanism. It remains
   clean outright: the vocabulary drift it also carried (`endpoint`,
   `package`, `queried_dns`, `org-policy` — 12 errors, an unrelated
   backlog) was fixed by #934's rewrite of the same file, and
   `test_shipped_invlang_documents.py` now holds it there.

   DEFERS to `_check_benign_authz` on any contract the active disposition
   gate is already refusing, matched on that gate's OUTPUT rather than on
   the disposition keyword — so a price added to `_DISPOSITION_GATES`
   that also refuses contracts is deferred to without an edit. Reporting
   both would name one missing row twice, and this rule's deferral arm is
   a trap beside the benign gate: deferring clears this rule and leaves
   benign blocked. (That deference is also what keeps
   `test_invlang_hypothesis_accumulation`'s one-error assertion true.)
16. **#18 lead-prediction structure (spec rule #18).**
   `_check_lead_prediction_structure`. `lp<n>` id shape, non-empty `if` /
   `read_as` / `advance_to`, and `advance_to` resolving to a declared
   lead NAME or to `CONCLUDE` / `HYPOTHESIZE`. Corpus: zero fires — no
   document writes `lead_preds` at all, so this is unmeasured rather than
   measured-clean, and the surface is fully opt-in. Uniqueness is owned
   upstream exactly as on rule 12.

   `advance_to` resolves against every declared lead NAME including the
   declaring lead's own. `:L findings` document order is the only
   ordering the dense surface carries, so the spec's "elsewhere in the
   companion" can only mean "not this row" — which would refuse a
   self-route and nothing else. Left alone: two loops may declare
   same-named leads under different ids and no cell says which one a
   name means, so the test can be wrong where accepting the self-route
   costs nothing.

   **The route-compliance clause is NOT implemented, and honouring
   "warning" is why — the READING is settled, the CHANNEL is not.**
   "Followed by another lead" is the next `:L findings` row in document
   order, the same ordering rule 9 already uses for "the final lead in a
   SCREEN sequence". What blocks it is that warn severity here is not an
   advisory: locus-less warn diagnostics are dropped by
   `runtime/tools._addressable` and do nothing, and a warn WITH a locus
   flags that row and blocks every later write until `fix_row` rewrites
   it. Neither candidate row may be rewritten — the follower's
   `:L findings` row is a committed lead declaration the warn family has
   never reached (`_tool_fix_row`: "the warn family walks
   `:R attr_updates` blocks and nothing else"), and letting a run edit
   its own `lead_preds` pre-registration to match where it ended up
   destroys the only thing pre-registration is for. Raising it to error
   would not honour the spec. **Open: a warn channel that can point at a
   row without making it rewritable**, or a decision to widen `fix_row`'s
   scope deliberately.

   `docs/dense-investigation-format.md`'s worked example wrote
   `advance_to PREDICT`; that is the PHASE name for the block
   `:H hypothesize.hypotheses` lives in, not a third sentinel. Rule #18
   names two, so the example was corrected rather than the enum widened.
17. **#29 impact-prediction structure + #30 impact-resolution refs.**
   `_check_impact_prediction_structure`, `_check_impact_resolution_refs`.
   Rule #30's required-field list is exactly the seven the spec writes
   (`pred_ref`, `dim`, `verdict`, `grounding`, `authority`, `as_of`,
   `reasoning`) — NOT extended into `anchor_id` / `anchor_kind`, which is
   rule #11's territory — and reported as one error per ROW rather than
   one per column, since an under-filled row is one defect.
   `ip<n>` shape, closed `dimension`, five non-empty outcome cells; and
   on the grading side, `pred_ref` resolving (bare within the emitting
   lead, qualified across leads), `dimension` MATCHING the predicate's,
   closed `verdict` and `grounding_kind` with `past-case` refused by
   name, and the seven required cells. Corpus: **zero fires for both** —
   no document in the tree writes an `:R impact` row or an
   `impact_preds` block, so the whole impact axis is unexercised. Both
   are therefore unmeasured rather than measured-clean; what makes them
   safe to arm is that they engage only on blocks a run has to opt into.
   The axis is now taught end-to-end in `skills/invlang/SKILL.md`
   §`:R impact` — teaching only half of it would let a run register a
   predicate it has no documented way to grade, which rule 18 then
   refuses.
18. **#31 impact closure + #34 prediction closure.**
   `_check_impact_closure`, `_check_prediction_closure`. With rule 15
   these are **one sentence over three namespaces** — *every declared X
   is resolved, or deferred with a reason* — and they share one
   implementation of the closure walk (`_unclosed_commitments`), with
   each keeping its own declared set, its own definition of resolved, and
   its own prose. #31's spec text already said it "mirrors rule #26's
   orphan gate"; now it does so literally.

   BOTH reference spellings are accepted, and refusing either would be a
   restriction nobody taught. A deferral written with the qualified
   reference (`h-001.ac1`) discharges only that commitment; one written
   bare (`ac1`) discharges every owner's — the same document-wide
   reading rule 5 gives a bare `fulfills_contract`. Generous on purpose
   and stated at the helper: over-refusing a deferral leaves an author
   with no legal repair, while over-accepting one costs an orphan a
   differently-spelled row would have excused anyway.

   **#31.** Closure arm plus `impact_severity`'s required-iff PAIRING
   with `impact_verdict` — structural, and it holds whatever the two
   cells say. Corpus: zero fires.

   **Neither conclude scalar's VOCABULARY is armed.** The SKILL has
   never stated `impact_verdict ∈ {none, within, exceeds,
   indeterminate}` nor `impact_severity ∈ {null, low, moderate, high}`;
   both live only in `docs/investigation-language.md`. Refusing on a
   vocabulary the runtime prompt never gave the model is the failure
   spec rule #32 was struck for, one issue ago. `impact_verdict` has the
   measurement behind it: it fires on BOTH shipped e2e goldens
   (`none-detected`, `attempted-lateral-movement`), and arming it took
   seven e2e tests red in the trial — those two are not authored
   fixtures but recorded runs replayed through this gate from
   `tool_trace.jsonl`, so "fixing" them rewrites a trace of what a model
   wrote. `impact_severity` measures zero fires and is left unenforced
   with it, because the two are one decision. Both ARE registered in
   `vocab.SLOTS`, which is the teaching step and the thing that has to
   land first. **Open: arm both** after the teaching has been in front
   of a corpus generation.

   **#34.** Every `p*`/`ap*` on a hypothesis that is neither `--` nor
   shelved is cited by a resolution with a non-null `after`, or deferred.
   "Final status" is read off the resolution record, not off the `:H`
   `status` column — append-only fixes that cell at declaration time, so
   it can never carry a FINAL status; same translation rule 11 applies to
   spec #24. Corpus: **two fires**, both on
   `experiments/judge-glm52-vs-kimik3/fixtures/case-00{1,2}` — the same
   two documents and the same `h-001.p3` rule 8 already fires on, both
   genuine, neither a shipped golden or a worked example, both left as
   they are.

   `examples/example-c` fired three times before its `:T resolutions`
   block was corrected, and the last of those is a defect #934's rewrite
   introduced: it moved `h-003` with TWO citation heads packed into one
   row (`[l-001 p1 ... :: prose; l-003 p2 ... :: prose]`). The grammar
   reads one head per row, so `l-003 p2` was swallowed into the first
   head's annotation string and `h-003.p2` was never settled. The
   in-grammar spelling is a second row at the same weight — `h-003
   + → +` — which is what both shipped goldens already do
   (`golden-sshpivot-ab3` writes `h-002 ++ → ++` for its second lead).
   Fixed here; the rule found it, which is the whole point of arming a
   closure gate over prompt surface.

   The five minimal fixtures in `defender/tests/test_invlang_rules_933.py`
   and the one in `..._adversarial.py` that this rule caught — written
   for rules #23/#24, predating the deferral table — carry a
   `:T conclude.deferred_preds` block each and are green. To back the
   rule out, deleting the `_check_prediction_closure` line from
   `diagnose` defers #34 and nothing else depends on it.

Pre-MVP, historical runs on earlier invlang variants are expected to fail
— intentional. Two guards were named here for the claim that the runtime
SKILL never teaches invlang the gate blocks, and NEITHER existed in this
repo: `test_skill_worked_examples_all_pass` and
`test_skill_example_a_accumulates_clean`. In their absence
`examples/example-b` shipped anchoring both hypotheses on an edge id (7
parse warnings, the whole `:H` block dropped) and `example-c` shipped two
vocabulary renames behind the enum. `defender/tests/test_shipped_invlang
_documents.py` is the guard those names promised — every shipped document
parse-clean and gate-clean, plus Example A validated as the gate sees it,
fences applied in order (#934). The stale Example A (`type=endpoint`,
`file:binary`, prose-cited resolutions, a bare `provenance` attr key) was
fixed to current grammar as part of the original work.

19. **Refutation scope (#933, spec rule #7's family).** A
    `:H h-NNN.refuts` row's `refutes` column cites `p*` / `ap*` ids the
    declaring hypothesis actually declares. `_check_refutation_scope`.

    The third site naming a prediction, and the one nothing resolved.
    Rule 6 walks the ids a MOVE matched and rule 5's half walks the `r*`
    a `--` cited; neither asks what the refutation itself claims to
    overturn, so `r1|p9,ap9|"…"` on a hypothesis declaring neither
    validated clean. Not only bookkeeping: a hypothesis reaches
    `refuted` through a `--`, and rule 18's prediction closure exempts a
    refuted hypothesis — so a phantom-scoped refutation discharged every
    prediction on it without settling any. The exemption is right; the
    hole was upstream.

    Scoped to the declaring hypothesis for the reason rule 6 is: a
    sibling's `p2` is not this hypothesis's evidence in either
    direction. Silent on a hypothesis declaring no predictions — the
    lean shape spec rule #23 exempts, not a defect this owns.

    Measured before arming: 17 documents carry a `.refuts` block, 31
    hypotheses declare refutation shapes, 47 refutation rows, **0
    unresolved ids**. Error severity costs nothing on the current
    corpus.

**Open: two current-spec rules were deferred because the spec
contradicted its own worked examples.** Don't enforce one until its spec
is reconciled, or it'll false-positive on valid current writes. One is
still open; the second shipped in #933 and is struck below:

- **Per-type class-slot grammar.** `skills/invlang/SKILL.md` §Classification
  grammar defines slash-tuples per type with slot enums in `vocab.py`, but
  its §Open-questions worked example uses `class=monitoring-agent/…` while
  `COMPUTE_ROLE` only has `monitoring` (no `monitoring-agent`). A strict
  per-slot check would reject the spec's own example. *Fix:* reconcile the
  role enum vs the examples (add `monitoring-agent`, or correct the
  examples to `monitoring`), settle the `??` / `{a,b,c}` / `unclassified-*`
  / `ambiguous-*-or-*` escape grammar, then implement + enforce.
- ~~**Sibling-fork uniqueness.**~~ **Closed.** The spec contradiction
  (§Sibling-fork uniqueness demanded a topological difference on
  `parent_type`/`parent_class`/`attached_to`/`rel` while the
  §Discovery-hypotheses worked example forked `h-001`/`h-002` identical
  on all four axes, on the predictions alone) was decided in #934 —
  prediction divergence IS the distinctness, and slots the alert has not
  settled stay `??` in `parent_class` rather than being minted into a
  fork axis — and implemented in #933 as rule 10 above. The constraint
  that came with the decision holds in the shipped check: it is keyed on
  the claim set, never on `parent_class`, and
  `test_invlang_sibling_fork_934.py` fails if that changes. Semantic
  distinctness is not detectable and stays the author's discipline.

  What that drops, deliberately: #933's reproduction — two siblings both
  on a CONCRETE `unclassified-process`, from a real 2026-08-13 run — now
  passes as long as their claims differ, which is the right answer under
  the new axis but is NOT what #933's ask 2 described ("the rule needs an
  open-slot exemption before it can ship", i.e. `??` exempt and concrete
  duplicates still refused). Nothing covers concrete duplicate
  classifications any more, and nothing should: a shared concrete parent
  class with divergent predictions is a legal fork.

Both were spec-owner decisions, not validator bugs. The class-slot one
stays file-and-hold here until the canonical SKILL is internally
consistent; it is now the only one left open.

**Open, from #933 (rules 13–18 above).** Three, restated here so they are
findable without reading the rule entries:

- **Close `termination.category`.** A free-text scalar with no
  vocabulary, and rule 14 turns on the exact string `severity-ceiling`,
  so a typo disables it in silence. Order: teach the enum in
  `skills/invlang/SKILL.md`, re-record the goldens (`data-ceiling`,
  `adversarial-confirmed`), then arm.
- **Arm `conclude.impact_verdict` and `conclude.impact_severity`.** Same
  order, same reason: `impact_verdict`'s enum fires on both shipped e2e
  goldens today, neither field has ever been stated in the SKILL, and a
  vocabulary is either taught or it is not. Both are registered in
  `vocab.SLOTS` by #933 — that is the teaching; the arming is not.
- **A warn channel that can point at a row without making it
  rewritable.** Rule 16's route-compliance clause needs one and there is
  none: a locus-less warn is dropped by `runtime/tools._addressable`,
  and a warn with a locus lets `fix_row` rewrite that row. Either that
  channel, or a deliberate decision to widen `fix_row`'s scope past
  `:R attr_updates`.

The authoring surface moved with the rules, which is the other half of
arming a closure gate: `skills/invlang/SKILL.md` gained the
`:L l-NNN.lead_preds` shape, a `:R impact` section carrying the whole
impact axis (register at PLAN, grade at ANALYZE), and a
§`:T conclude` table naming the three deferral tables with the
"send them in the SAME `append_block`" note — the whole document is
validated on every write, so a `:T conclude` that lands without them is
refused before they can follow. `defender/examples/example-c-cumulative-escalation.md`
was corrected for the same reason: a shipped worked example that
violates a newly-armed rule teaches the violation.
