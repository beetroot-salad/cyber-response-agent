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

   #818 closed only the `:T resolutions` row. Three sites reference an
   `h-*` and `_check_hypothesis_refs` now owns all three (#821): the
   resolution, `:L findings`'s `tests` column, and `:T shelved`. The two
   added are the ones a run reaches FIRST — a lead can claim to test a
   hypothesis nobody declared, and a `:T shelved` row can retire one that
   never existed — so a typo used to surface a step late, pointing at the
   resolution rather than at the PLAN row that introduced it.

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
7. strong-move citation — a `++`/`--` must name at least one of them.
   The other half of rule 3's provenance tuple: which pre-committed
   claim the cited observation settled.

Pre-MVP, historical runs on earlier invlang variants are expected to fail
— intentional. `test_skill_worked_examples_all_pass` (per-fence grammar)
plus `test_skill_example_a_accumulates_clean` (the flagship example
validated as the hook sees it — fences applied in order with append-only
re-checked) guard that the runtime SKILL never teaches invlang the hook
blocks. The stale Example A (`type=endpoint`, `file:binary`, prose-cited
resolutions, a bare `provenance` attr key) was fixed to current grammar
as part of this work.

**Open: two more current-spec rules are deferred because the spec
contradicts its own worked examples.** Don't enforce them until the spec
is reconciled, or they'll false-positive on valid current writes:

- **Per-type class-slot grammar.** `skills/invlang/SKILL.md` §Classification
  grammar defines slash-tuples per type with slot enums in `vocab.py`, but
  its §Open-questions worked example uses `class=monitoring-agent/…` while
  `COMPUTE_ROLE` only has `monitoring` (no `monitoring-agent`). A strict
  per-slot check would reject the spec's own example. *Fix:* reconcile the
  role enum vs the examples (add `monitoring-agent`, or correct the
  examples to `monitoring`), settle the `??` / `{a,b,c}` / `unclassified-*`
  / `ambiguous-*-or-*` escape grammar, then implement + enforce.
- **Sibling-fork topological uniqueness.** §Sibling-fork uniqueness says
  sibling hypotheses must differ on a topological axis
  (`parent_type`/`parent_class`/`attached_to`/`rel`), but the
  §Discovery-hypotheses worked example forks `h-001`/`h-002` that are
  identical on all four axes (both `v-001|runs_on|process|unclassified-process`),
  differing only on `?name` + predictions — which that same section
  explicitly endorses when `parent_class` is unknown. *Fix:* decide
  whether name+prediction divergence counts as distinctness (and how to
  detect it), update the spec, then enforce.

Both are spec-owner decisions, not validator bugs. File-and-hold here
until the canonical SKILL is internally consistent.
