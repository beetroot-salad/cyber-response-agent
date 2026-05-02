---
title: Replace archetypes with precedent calibration + cached-org-authority
status: backlog
groups: invlang, archetypes, authorization
---

Implements `docs/design-v3-authority-cache.md` (third pass). Replaces the hand-curated archetype catalog with two mechanical patterns over the corpus:

- **Pattern 1 — Precedent calibration**: walker over invlang companions matching `(signature_id, sorted (anchor_kind, predicate) set)` → reports disposition distribution → feeds `confidence` (does not gate disposition).
- **Pattern 2 — Cached org-authority**: new `grounding_kind: cached-org-authority` enum value, reusing `cites_past_case`. Soundness gated mechanically by contract-shape match + `effective_window` envelope of `current_edge.as_of` + org-authority origin (no chaining).

The design rests on the v2.10+ schema invariants already in force (rules #21 / #26 / #27 / #28). It does not weaken rule #27 — past-case still cannot be sole grounding for benign. The new grounding kind is exempt because soundness is mechanical, not weak-temporal.

## Why this is persistent

Implementation deferred to a fresh session (per the design status). The migration touches the spec, validator hooks, two subagents, every operations file, and removes a large surface (`archetypes/` directories, `archetype-match` subagent, fixtures). It will not land in a single session.

## Pre-flight

Before editing anything, re-read in `docs/investigation-language.md`:
- §Temporality of authorization
- §authorization_resolutions schema (the plural list block)
- Rule #21 (every contract resolves authorized for benign)
- Rule #26 (orphan gate / `deferred_authorizations[]`)
- Rule #27 (past-case no-sole-grounding for benign)
- Rule #28 (past-case depth cap — no chaining)

The design assumes these are already-implemented invariants. Confirm before any spec edits.

## Migration plan (mirrors design doc §Migration order)

- [ ] **1. Pre-flight re-read** — confirm spec invariants above are unchanged since the design was written (2026-05-02).
- [ ] **2. Spec edit (v2.16)** — `docs/investigation-language.md`:
    - New `precedent` block in `conclude` with `status / matching_count / matching_case_ids / matching_dispositions`.
    - Extend `grounding_kind` enum on `authorization_resolutions[]` with `cached-org-authority`.
    - Add validator rules #29–#32 (cache shape match, window envelope, origin+depth cap, `full`-authority retention).
    - Add precedent → confidence rules (novel ⇒ ≤medium, mixed ⇒ low).
    - Cross-reference the new grounding kind from §Temporality and §past-case sections.
- [ ] **3. Walker implementation** — `soc-agent/scripts/invlang/queries.py`:
    - `precedent_match(signature_id, contract_shape_set)` → matching set + disposition distribution.
    - `cached_org_authority_lookup(anchor_kind, anchor_id, predicate, subject, object, conditioning_context, current_edge_as_of)` → most-recent enveloping resolution or none. Entity matching honors prologue aliases.
    - Unit tests: empty corpus, single-match, multi-match-consistent, multi-match-mixed, window-out-of-envelope, depth-cap rejection (citing past-case or cached-org-authority), entity-alias resolution.
- [ ] **4. Validator implementation** — `soc-agent/hooks/scripts/invlang_checks_authorization.py`: rules #29–#32 + precedent rules. Unit tests under `soc-agent/tests/test_invlang_validate.py`.
- [ ] **5. Operations-file extension** — every `soc-agent/knowledge/environment/operations/*.md` gains `declared_predicates` with `cacheable` and `window_source` where applicable. Most existing predicates are `cacheable: false` — that is correct. Only mark `cacheable: true` when the authority response carries an explicit window field.
- [ ] **6. REPORT subagent** — `soc-agent/agents/report.md`: invoke the precedent walker; write the `precedent` block. Update report judge to enforce precedent → confidence.
- [ ] **7. GATHER subagent** — `soc-agent/agents/gather.md`: invoke `cached_org_authority_lookup` for cacheable predicates before dispatching the live-consultation lead.
- [ ] **8. Cutover** (see design §Disposition-policy change) — flip the report judge to drop the two-leg gate; rely on rules #21 / #26 / #27 already in force. Remove `matched_archetype` from report frontmatter; replace with `precedent` field.
- [ ] **9. Removal** — delete:
    - `soc-agent/knowledge/signatures/*/archetypes/` directories (every signature)
    - `soc-agent/agents/archetype-match.md`
    - `soc-agent/tests/test_archetype_*.py` and archetype fixtures
    - `soc-agent/knowledge/signatures/_template/archetypes/` skeleton
    - any `matched_archetype` / `matched_ticket_id` / `required_anchors` references in code, tests, and docs
- [ ] **10. Documentation** — archive `docs/design-v3-hypothesis-archetype-rewrite.md` to `docs/archive/`. Update `CLAUDE.md` (Hook Architecture section, Project Structure tree, Adding a New Signature workflow). Update `soc-agent/skills/handbook/content/`.

## Decisions locked in the design (do not re-litigate without revisiting the doc)

- **Disposition not in Pattern 1 match tuple.** The walker reports the distribution; including disposition in the tuple makes `mixed` definitionally empty.
- **Cache validity is window-envelope, not `expiry > now()`.** Authorization is *as-of* the edge's event time. The check is `prior.effective_window.start ≤ current_edge.as_of ≤ end`. Time-independent at validation.
- **Lookup key is full contract shape.** `(anchor_kind, anchor_id, predicate, subject, object, sorted(conditioning_context))`. The earlier `(authority, claim, entity)` key was too weak — ignored resource side, layered policies, and conditioning_context.
- **`cached-org-authority` is a new enum value, not a relaxation of past-case.** Rule #27 stays in force untouched.
- **Confidence cap on `mixed`, no disposition override.** Past disagreement surfaces for review via the auto-close gate; it does not overrule current evidence.

## Risks tracked in the design (revisit during implementation)

- Strictness tuning for the precedent walker (start strict; loosen if `novel`-rate >50%).
- Bootstrap behavior — first N investigations of every signature are `novel`. Operator-facing docs should call this out.
- Cache scope creep — author skill should validate `window_source` references a real authority response field. Validator rule #30 (window envelope) is the structural backstop.
- Entity normalization for cache lookup — must honor prologue aliases.
- Cache poisoning escape hatch (`revoked_runs.txt`) — defer until observed.

## References

- Design: `docs/design-v3-authority-cache.md` (third pass, 2026-05-02)
- Spec being extended: `docs/investigation-language.md` (v2.10 schema, current at v2.16)
- Existing past-case mechanism (compare against): see §Temporality of authorization in spec
- Codex review that drove the third-pass redraft: see git log for commit on `docs/design-v3-authority-cache.md`
