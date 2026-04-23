---
title: Invlang schema assessment after PREDICT/REPORT rename settles
status: done
groups: invlang, schema, predict, report
---

**Result:** Audit doc at `docs/experiments/invlang-post-predict-assessment.md`. Key findings:

- Coverage multiplicity (Q1): not load-bearing. 7/7 resolved contracts cover exactly 1 edge; 0 multi-edge triples across 14 corpus files. Rejects authz-as-vertex proposal empirically.
- Authz/legitimacy naming (Q2): 100% of contract predicates are zero-trust ABAC. Zero mention of damage, intent, or business contribution. Field name is a misnomer.
- Populatability (Q3): impact axes have no evidence stream in the current corpus; impact-as-vertex would be speculative.
- Orphan contract problem: 10/17 declared contracts never resolve — rule #21 gates benign but escalation paths accept orphans silently.

**Recommended (in priority order):**
1. Rename `legitimacy_contract` → `authorization_contract` (+ resolutions). The schema field was a misnomer — 100% of corpus predicates are zero-trust ABAC.
2. Add temporality fields to `trust_anchor_result`: `effective_window` (optional; authz time bounds — change windows, oncall shifts, travel approvals) and `conditioning_context: []` (prose list of then-conditions — "operator on-shift", "CHG-1234 active", "DLP rule R33 in force"). Applies to both authz decisions (why this was authorized *at that time*) and retrospective impact reads (what controls produced the observed outcome *at that time*).
3. Add `kind: past-case` to `trust_anchor_result.kind` enum, as a weak-temporal authz source. Constraints: force-cap `authority_for_question` to `partial`; cannot be sole grounding for benign disposition; a past-case consultation cannot cite another past-case as its grounding (depth cap to prevent bootstrap drift). Archetype matching (disposition-shaped precedent) stays separate from past-case-as-authz (authz-shaped precedent).
4. Add CONCLUDE-time orphan-contract gate: every declared contract resolved or in `deferred_authorizations[]`. Corpus shows 10/17 contracts orphaned today (59%); rule #21 gates benign but escalation paths accept orphans silently.
5. Add `impact_profile` to signature knowledge-base (static, not per-investigation graph). Impact belongs with mechanism class (signature context), not with per-run graph work.
6. Keep block names (`hypothesize:`, `conclude:`) — revisit after one eval cycle under the phase rename.

**Consolidation note.** First-pass v2.10 edit folded `trust_anchor_result` entirely into `authorization_resolutions[]`, which overshot: expectation-kind queries (baselines, registry lookups that inform hypothesis weight but don't fulfill a contract) lost their structured home, and `grounding_kind: telemetry-baseline` on an authz resolution became a category error. Corrected to a hybrid: authz verdicts live on `authorization_resolutions[]` (edge), non-authz anchor queries live on `anchor_consultations[]` (lead outcome, renamed from `trust_anchor_result` — the record is a consultation event, not a singular result). Enums enforce the split: authz-resolutions exclude `telemetry-baseline`, consultations exclude `past-case`. Rule #14 (partial-authority weight cap) covers both records.

**Rejected:** authz-as-vertex, impact-as-vertex, hybrid dual-write. See audit doc for reasoning.

**Sample caveat:** 14 companions, mostly r5710 over one week. Re-run Q1/Q2 when signature breadth doubles or a data-exfiltration-style signature lands where authz and impact clearly separate.

**Spec delta codified.** v2.10 in `docs/investigation-language.md` reflects recommendations 1–4; knowledge/invlang/schema.md + validator + prompts are the separate implementation pass.

---

## Context — why this exists

The PREDICT/REPORT rename (`predict-phase-rename`, `report-phase-rename`, `predict-report-docs-update`) deliberately preserves the invlang YAML block names `hypothesize:` and `conclude:` for corpus backward-compat. That's the right move in the short term — the corpus has 39+ companions, topology retrieval is keyed off those block names, and renaming the schema alongside the phase would compound risk.

**But the rename exposes a schema question worth auditing once the new phase semantics have run in production for a cycle**: should the block names match the phase deliverables, should the block contents change shape under the reframe, or is backward-compat the winning tradeoff forever?

Specifically:
- `hypotheses:` as a block name fits the old cognitive-stance framing. Under PREDICT semantics the deliverable is predictions + refutation_shapes + legitimacy_contracts + lead-hint, optionally gathered under one or more mechanism stories. The block could be renamed `scaffold:` / `predict:` or restructured so the mechanism-stories list is one sub-field among several.
- The `hypotheses[].name` field packs mechanism classification + legitimacy verdict when agents slip into the FM4 pattern. A schema that names the two axes separately (`mechanism_class:` + `legitimacy_state:` where applicable) would make the corpus queryable on each axis independently and would surface the anti-pattern statically rather than at prompt level.
- `no-fork` mode currently emits no block at all. Under PREDICT, a single-hypothesis scaffold is common; the block shape needs to express "one hypothesis + legitimacy_contract + discriminating lead" first-class.
- The `conclude:` block's archetype fields (`matched_archetype`, `matched_ticket_id`) were designed with archetype-as-mid-loop pressure in mind. Post-rename, archetypes resolve at REPORT time against a confirmed picture — the block could adopt a tighter shape (confirmed verdict, archetype route, precedent citation) that reflects this.

This task is the structured audit of those questions, not the implementation.

## In scope

**Measure the current pain**:
- How many live-corpus companions ride each existing invlang field? Is the pain in every field or a few high-weight ones?
- How often does topology retrieval tier 0 miss specifically because the block schema doesn't let the fingerprint resolve cleanly (e.g. `name:` field packs classification + legitimacy, so a same-mechanism different-legitimacy past case looks like a different hypothesis to the matcher)?
- How often do validator rules 23 / 27 / 29 / 30 fire in practice? If rule 23 (fork distinctness) essentially never fires because agents produce syntactically-distinct classifications even when semantically equivalent, the validator is doing less than its prompt cost implies.

**Enumerate schema options** — produce a short doc comparing:
- **Status quo** — keep block names; only phase names and prompt framing change. Cheapest; corpus zero-regression; accepts some semantic-name mismatch as overhead.
- **Block rename** — `hypothesize:` → `scaffold:` (or `predict:`); `conclude:` → `report:`. Breaks corpus queries + topology retrieval until migrator re-keys. Aligns names; modest engineering.
- **Schema restructure** — split `hypotheses[]` into `mechanism_stories[]` + `legitimacy_contracts[]` + `predictions[]` at top level; rename to match. Deeper shift; corpus needs migration path; enables cleaner retrieval semantics (mechanism-axis vs legitimacy-axis queries). Higher engineering, longer payoff horizon.
- **Hybrid** — keep block names for compat, add new top-level fields (`mechanism_stories:`, `scaffold:`) that new runs populate alongside the legacy hypothesize-nested form. Dual-write during transition; single-read once corpus fully migrates. Most backward-compatible; most transient surface area.

**Validator rule audit**:
- Rules 23, 26, 27, 28, 29, 30 — which ones are currently load-bearing under PREDICT semantics? Rule 27 (evaluation-prefix forbidden) still relevant; rule 29 (prediction subject scope) still relevant. Rule 23 (fork distinctness) may become less useful if single-hypothesis scaffold is the common case — lonesome hypothesis blocks skip the check entirely. Rule 28 (≤2 predictions) may need relaxing for genuinely-multi-prediction scaffolds.
- Decide whether to add rules that support the PREDICT reframe (e.g. `legitimacy_contract` resolution consistency: every declared contract must be resolved or explicitly deferred by the time REPORT fires).
- Explicitly decided **not** to add token-match rules on adversarial-flavored classifications — that's a bottomless pit (see `predict-phase-rename` context).

**Produce a recommendation** — pick one of the schema options above, with cost estimate and migration path. Do not implement in this task; produce the decision doc for the next planning pass.

## Out of scope

- Any implementation. This task ships a written recommendation + measurements, nothing else.
- Anything touching past corpus files. The corpus stays read-only for the audit.
- Changes to `scripts/invlang/queries.py` retrieval functions. Those are correct under the current schema; restructuring decisions await the recommendation.

## Acceptance criteria

1. Short doc (`docs/experiments/invlang-post-predict-assessment.md` or similar) exists containing:
   - Corpus-measurement section with concrete numbers.
   - Option comparison with engineering-cost + query-impact + prompt-alignment axes.
   - One recommended option with rationale.
   - Migration path for the recommended option (or explicit "status quo is the recommendation").
2. Validator-rule audit section (same doc) classifying each rule as "keep / relax / drop / add" under PREDICT semantics.
3. One or two "if we do this, it unblocks X" notes — downstream tasks that become cheaper under the chosen schema.

## Dependencies

**Blocked by** `predict-phase-rename`, `report-phase-rename`, and ideally `predict-report-docs-update` — audit is most useful once the rename has run through at least one real end-to-end eval cycle and the corpus has a few companions authored under the new phase semantics (even if still with the old block names).

## Notes

- The point of keeping this as backlog-not-todo is that the rename might turn out to be sufficient. If PREDICT + REPORT with unchanged invlang produce the desired scaffold shape in live runs, the block-name mismatch becomes aesthetic rather than load-bearing, and status-quo wins. The audit is the right way to find out — don't pre-commit to restructuring.
- Memory `feedback_no_unshipped_legacy` says don't design dual interfaces for pre-MVP code. The hybrid option (dual-write) inherits that risk — flag explicitly in the recommendation if proposed.
- Memory `feedback_fix_misleading_examples_at_root` says prefer structural fixes to warning blocks. If the audit finds that schema names actively mislead agents (e.g. agents over-index on the word "hypotheses" when authoring the block), structural rename has a strong case over documentation-only patches.
