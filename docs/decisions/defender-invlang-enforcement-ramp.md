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
   recognized namespace is left alone: `:L l-NNN.lead_preds` is
   documented and unprojected (#820), so its `lp*` resolves against
   nothing and reporting it would deny a legal document.
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
   *(Spec v2.19 finished this: #35 is struck as subsumed, and the
   empty-signature skip — stated here and in the code as "#35's
   convention" — now belongs to #23.)*

   **One rule, two implementations, one survivor.** #934 and #933 wrote
   this check independently and within a day of each other. #934's
   `_check_fork_distinctness` shipped first and is the one that stays,
   under its own name: #933's was an identically-shaped rewrite built on
   a base #934 had already superseded, so keeping both would have
   reported every fork violation twice and keeping #933's would have
   renamed a shipped symbol for nothing. Everything the two agreed on —
   the live-only scope, the `(target, attribute, claim)` key on
   attribute predictions, the `subject` cell left out of the `.preds`
   key, sentence punctuation folded away — was already #934's and is
   untouched. Two things came across from #933's before it was deleted,
   and only two:
   * **Shelved counts as retired.** `live_hypothesis_ids` filters on
     final weight `--` alone and knows nothing about `:T shelved`, so
     without this term rule 10 and rule 11 disagreed about what the run
     is still carrying — and rule 10 is the one that WEDGES on the
     disagreement, because both repairs it offers rewrite an immutable
     `:H` row and the only exit left is a `--` the run never earned.
   * **The trailing full stop comes off the END only.** `str.strip`
     takes a character SET, so `strip(" .\"'")` also ate a LEADING
     decimal point — fusing `.5σ above baseline` with `5σ above
     baseline` and refusing a pair that forks on a tenfold threshold.
     Quotes still come off both ends; the format wraps a whole cell.
   #933's blank-claim skip came across with them: a blank `.attr_preds`
   claim contributes nothing to the signature, where counting it would
   manufacture a spurious fork report on top of the two rule 12 errors
   the blank cells already earn.
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

13. **Refutation scope (#933, spec rule #7's family).** A
    `:H h-NNN.refuts` row's `refutes` column cites `p*` / `ap*` ids the
    declaring hypothesis actually declares. `_check_refutation_scope`.

    The third site naming a prediction, and the one nothing resolved.
    Rule 6 walks the ids a MOVE matched and rule 5's half walks the `r*`
    a `--` cited; neither asks what the refutation itself claims to
    overturn, so `r1|p9,ap9|"…"` on a hypothesis declaring neither
    validated clean. Not only bookkeeping: a hypothesis reaches
    `refuted` through a `--`, and the prediction-closure rule (spec #34,
    not ramped yet) exempts a refuted hypothesis — so a phantom-scoped
    refutation discharged every prediction on it without settling any.
    The exemption is right; the hole was upstream.

    Scoped to the declaring hypothesis for the reason rule 6 is: a
    sibling's `p2` is not this hypothesis's evidence in either
    direction. Silent on a hypothesis declaring no predictions — the
    lean shape spec rule #23 exempts, not a defect this owns.

    Measured before arming: 17 documents carry a `.refuts` block, 31
    hypotheses declare refutation shapes, 47 refutation rows, **0
    unresolved ids**. Error severity costs nothing on the current
    corpus.

**Struck from the spec, and so never ramped (#933).** Five clauses left
`docs/investigation-language.md` without ever having had an
implementation here, so none of them is a rung this list skipped — they
are rungs that turned out not to exist. Recorded because a reader
counting rule numbers against this list will otherwise go looking for
them:

- **Spec rule #36** (affirmative `true_positive` disposition) — struck
  at spec v2.18 as retired vocabulary. `true_positive` is not in
  `DISPOSITION_VALUES` (`defender/_vocab.py`) and has never appeared
  under `defender/` in this repository's history; the
  `hooks/scripts/invlang_checks_authorization.py` path the v2.14/v2.16
  deltas cite does not exist.
- **Spec rule #21's escalation half** and **rule #24's trailing
  `status: escalated` clause** — struck at v2.18 with it, for the same
  reason. #21's benign half is rule 5 above and is untouched.
- **Spec rule #32** (integrity peer discipline) — struck at v2.19. Its
  discharge test is a `name.startswith("?adversary-controlled-")`
  prefix match on model-authored free text: 6 of the 10 contract-bearing
  hypotheses in the corpus trigger it, all 6 fail it, 0 discharge it, and
  arming it would mint the peers rather than find them. The coverage gap
  is real and its recorded answer is the behavioral-consistency
  prediction in `docs/decisions/adversarial-as-attribute-not-hypothesis.md`,
  not a structural gate.
- **Spec rule #35** (sibling prediction divergence) — struck at v2.19 as
  subsumed by #23, which refuses strictly more
  (`validate._check_fork_distinctness`).

None is a candidate for a later rung. Re-arming any of them is a fresh
spec decision, not a scheduling one.

### Why #32 was struck — the evidence

Moved here from rule #32's gap entry, which had grown to 170 lines inside a
reference list whose longest ACTIVE rule is 25. The verdict stays in the spec;
the working belongs in the ledger.

**1. Measured non-compliance — 6 fire, 0 discharge.** Over every
non-archival ```invlang document in the tree (both e2e goldens,
both `defender/examples/`, the worked examples in
`defender/SKILL.md` and `defender/skills/invlang/SKILL.md`, and
the experiment fixtures), 10 content-distinct hypotheses carry an
`authorization_contract` — 11 if the byte-identical
`judge-glm52-vs-kimik3` case-002 mirror is counted separately —
and of those, **6 satisfy #32's trigger and 0 discharge it.** No
`?adversary-controlled-` peer sits in the sibling group of any
contract carrier on that surface (the sole exception in the whole
tree is a hand-authored design-doc illustration — see reason 2),
and `integrity_waived` has never been set to anything on any row,
in any document, in the repository's history. The six failures are
not stragglers:

| document | hypothesis | parent type | sibling written instead |
|---|---|---|---|
| `defender/fixtures-e2e/golden-sshpivot-ab3` | `h-001` | `session` | `?adversarial-cross-tier-pivot` |
| `defender/fixtures-e2e/golden-v2sshd` | `h-002` | `process` | `?scanner-or-noise-probe` |
| `defender/examples/example-b-parallel-iam-cmdb.md` | `h-001` | `process` | `?adversary-on-monitoring-source` |
| `defender/skills/invlang/SKILL.md` §Sibling-fork uniqueness, the **"Right"** block | `h-001` | `identity` | *(none — one hypothesis, two contracts, which is what the section teaches)* |
| `experiments/actor-basin-276/…/falco-net-tool-live` | `h-001` | `process` | *(none)* |
| `experiments/actor-basin-276/…/sshd-gabe-live` | `h-001` | `identity` | *(none)* |

Two are shipped goldens. One is a shipped worked example. One is
the canonical **correct** answer in the runtime authoring skill —
§Sibling-fork uniqueness's "Right" block is a single
`identity`-parented hypothesis carrying two authz contracts, and
#32 refuses it. A rule that refuses the document teaching the
right shape is not measuring the corpus; the corpus is measuring
the rule.

**2. The discharge test is lexical.**
`name.startswith("?adversary-controlled-")` is a prefix match on
model-authored free text, and this repository has run that
experiment already. Rule #36's v2.14 shipped an
adversarial-classification token list; it desynced from
playbook-canonical fork names (`?credentials-used-outside-registered-actor`
is the example the v2.16 delta records) and produced false
rejections of correctly-graded routings, and v2.16 deleted it.
Row 3 of the table above is that failure recurring before the rule
was even armed: `?adversary-on-monitoring-source` is an integrity
peer, written deliberately, doing exactly what the discipline
asks — and it fails the prefix. Meanwhile the corpus's actual
`?adversary-controlled-` names sit where #32 does not fire:
`?adversary-controlled-write` in `defender/SKILL.md` and
`?adversary-controlled-writer` in the pre-dense pilot fixtures are
both on hypothesis pairs carrying no contract at all.

**The prefix and the trigger co-occur exactly once in the tree, and
it is not a run.** `docs/dense-investigation-format.md`'s
stress-1 worked example pairs `?monitoring-probe` (an `identity`
parent carrying `ac1`) with `?adversary-controlled-source-session`,
and it discharges #32 cleanly. That document is a hand-authored
design proposal — *"Status: design experiment, v0.1 … Not
implemented"*, pinned to spec v2.13 — written alongside the
§Integrity discipline to illustrate it, in a ```markdown fence
rather than the ```invlang surface the corpus count above scans.
The single document that satisfies the rule is the rule's own
illustration. Nothing a model produced, and nothing that ships,
has ever satisfied it.

**3. It would produce manufactured compliance, not integrity
reasoning.** This is the load-bearing reason. #934 documented what
this system does when the spec mandates a structural property the
model cannot naturally satisfy: it mints the shape. All four
tuple-class sibling pairs in the corpus differed in **all three**
class slots — invented wholesale to clear the old topological
§Sibling-fork uniqueness — and one of them then lost weight on a
three-conjunct refutation of which exactly one conjunct was
observed, because the manufactured axis was not the axis anyone
was reasoning about. Arming #32 predicts the same outcome one rule
over: six `?adversary-controlled-X` rows written to clear the
gate, each needing predictions that also clear rule #23's
distinctness check, i.e. predictions reverse-engineered from two
validators rather than from a question about the actor. That is
the failure #934 fixed, shipped again immediately after fixing it.

*Corroborating, with a caveat.* The one time a rule under this
number ran anywhere,
`experiments/relax-invoker-identity-peer/results/final.md`
measured it and recommended shipping it **disabled** — item 1 of a
seven-part composite intervention against a lock-on-benign failure
mode, alongside disabling #35. Read that record before re-arming
#32. The caveat: it disabled a `soc-agent`
`_check_integrity_peer_discipline` whose described behaviour
("necessary because the agent will write peer forks the rule would
otherwise reject") is the *converse* of what #32's spec text
mandates, so what was measured may not be the rule written here.
That divergence is itself evidence — the number has meant two
different things in two places, which is what happens to a rule
nobody can point at an implementation of.

**4. It contradicts a settled decision.**
`docs/decisions/adversarial-as-attribute-not-hypothesis.md`
(`status: done`) item 6: *"Drop the 'maintain adversarial
hypothesis until `--`' rule … Teeth move from
hypothesis-bookkeeping to evidence-based structural enforcement."*
Rule #21's own text says it *"Replaces the former 'maintain
adversarial hypothesis until `--`' bookkeeping rule."* #32 is that
bookkeeping rule reinstated three numbers later, and reinstated
specifically on the hypotheses carrying the contract #21 gates on
— so the decision's replacement and the thing it replaced would
have fired on the same rows. The same decision doc had also
already answered the narrower question directly: *"Legitimacy
contracts for session-hijack / forgery? — No… Integrity/forgery
questions are mechanism-level."* Mechanism-level, not gate-level.

**The gap is real, and this entry is not pretending otherwise.**
Striking #32 leaves the authorized-bulk-read-from-a-compromised-account
case uncovered: the IAM anchor answers "authorized" about the
claimed identity, that answer is correct under the authz
question's scope, impact may clear on volume, and nothing has
asked whether the session was the claimed session.
`adversarial-as-attribute-not-hypothesis.md` names this in as many
words — *"A legitimacy contract resolved `authorized` establishes
policy compliance, not integrity. The compromised-credential case
(policy says yes, pattern says off) needs a third check."*

**Its answer was not a structural gate, and that is the point.**
The same section answers it with the **opt-in
behavioral-consistency prediction**: one baseline-consistency
prediction on the existing `predictions` / `refutation_shape`
machinery, gated on three conditions (baseline is queryable for
this identity; the prediction is scoped to the alert's entities
and window, not a hunt; the outcome is weight-sensitive), capped
at `moderate` severity because identity patterns drift and
"looks consistent" is cheap by coincidence, and with an
unavailable baseline written into `concerns` rather than
confabulated. It is restated in this spec at §Hypothesis →
*Behavioral-consistency prediction (optional)*. **Read that before
re-deriving #32.** A structural gate on this question was
considered and declined on the record; #32 was the gate, arriving
later without the decision being revisited.

**Left standing, unread: the `integrity_waived?` column.** It is
in the `:H` grammar, `defender/skills/invlang/parser.py` projects
it, `schema.py` types it on `HypothesisRecord`, and every worked
example emits the empty cell — and with #32 struck, no validator
rule consumes it. Deliberately not removed here: dropping a
projected column touches the parser, the schema, and roughly
thirty test fixtures, and the field remains usable as an authoring
note. Whether it stays is a separate decision nobody has taken.

Numbering preserved for grep-stability, per the v2.15 convention.

### Why #23 subsumes #35

Moved here from rule #35's gap entry, for the same reason.

**Rule #23 refuses strictly more.**
`_check_fork_distinctness`
(`defender/skills/invlang/validate.py`, shipped in #934) keys on
the same sibling group — the parent hypothesis read off the
`h-{parent}-{nonce}` id shape, paired with `attached_to`, there
being no `parent_hypothesis_id` column to key on — skips the same
empty signatures, and compares the normalized signature across
both `predictions[]` and `attribute_predictions[]`. That signature
is #35's with ONE column dropped: `predictions[].subject`. The
attribute-prediction tuple is kept whole, because an `.attr_preds`
claim is a bare value and `target` / `attribute` are what say
which measurement it is a value of. Dropping `subject` only widens
what is refused — any pair colliding on the fuller tuple collides
without it — so **every pair #35 refuses, #23 refuses too**, plus
the pair #35 would let through, the one that wrote a single
sentence under two different subject labels. One sentence twice is
one observable twice however it is attributed, and the claim is
what a lead comes back on.

Merged into #23 at v2.17 (#934) and rewritten as a gap entry at
v2.19, rather than kept as a weaker parallel statement of an
implemented rule. v2.17 counted it as a gap in the header while
leaving this entry standing as a rule, which is what made the
header say 28 over a list that still totalled 29. Two rule numbers
over one check also invite the reading that some pair fails #35
and passes #23; none can. The two stopped being distinct when
#934 rewrote #23 off
`parent_class` and onto the predicted observable — before that,
#23 keyed on `proposed_edge.parent_vertex.classification` and #35
on prediction text, and "complements #23" was true. This entry
previously said #35 "complements rule #23 (which blocks shared
`parent_vertex.classification`)"; that describes the pre-#934 rule
and had already stopped being true. #32, which #35's text called
the integrity-peer-specific rule it generalised, is struck at its
own entry above for unrelated reasons.

Numbering preserved for grep-stability, per the v2.15 convention.

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
