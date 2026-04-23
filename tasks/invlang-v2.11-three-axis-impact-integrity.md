---
title: Invlang v2.11 — three-axis framing (integrity + impact) + terminology cleanup
status: done
groups: invlang, schema, spec
---

**Result:** `docs/investigation-language.md` updated to spec v2.11. All seven acceptance criteria met in one pass (v2.11 delta header; §Hypothesis cardinality and leanness; §Integrity as mechanism enumeration; §Impact as lead-level prediction; `vertex.trust_root` field + paragraph removed; `attached_to_vertex` "anchor:" gloss removed; no validator/schema touches — those belong to the implementation pass). Unblocks the follow-up implementation pass for v2.10 + v2.11 (schema.md, validator, queries, subagent prompts, corpus migrator) listed in the Follow-up tasks section below.

---

## What

Next spec revision after v2.10. Makes the three orthogonal resolution axes explicit in the spec and closes the impact-reasoning gap that v2.10 hand-waved into `knowledge/signatures/{id}/impact_profile.md`.

Scope is **spec-only** (`docs/investigation-language.md`). Schema snippet, validator, queries, subagent prompts, and corpus migrator are the separate implementation pass that inherits both v2.10 and v2.11 deltas at once.

## Insights from the design conversation

### Three-axis framing

An alert's disposition depends on three orthogonal questions:

| Axis | Question | Shape | Anchor | Where it lives |
|---|---|---|---|---|
| **Authorization** | Is this edge permitted by policy? | categorical (authorized / unauthorized / indeterminate) | single source of truth (IAM, data-classification, deploy-runs) | `authorization_contract` on hypothesis → `authorization_resolutions[]` on edge |
| **Integrity** | Is the acting entity what it claims to be? | evidential (composed from observables) | no single anchor | mechanism-hypothesis peers (`?adversary-controlled-*`) with predictions on discriminating observables |
| **Impact** | Does this edge's effect matter enough to escalate? | quantitative, N-dimensional (CIA + scope) | baselines + policy (telemetry, DLP, business-owner) | `impact_predictions[]` on leads → `impact_resolutions[]` on outcomes → `impact_verdict` on conclude |

The axes are orthogonal. `(disposition: benign, impact_verdict: exceeds)` is the authorized-but-malifying class (authorized bulk upload above baseline; service-account read at 3σ above mean). `(disposition: true_positive, impact_verdict: within)` is the confirmed-but-contained class (failed credential probe, denied access attempt). Authz clearing does not clear impact, and vice versa.

### Why integrity is mechanism-hypothesis, not a contract

Authz has contracts because the question is categorical with a single source of truth. Integrity fails all three of those properties:

- Evidential (no clean verdict — composed from correlation, shape, timing, geo)
- No single anchor (behavioral observation across multiple signals)
- Same question across peer hypotheses (session `s1` integrity is the same question whether you're asking `?routine-app-read` or `?adversary-controlled-session`)

The contract shape doesn't fit. Peer mechanism hypothesis with observable predictions does — it's what v2.10 already implicitly prescribed in the "Contracts answer policy, not integrity" paragraph. v2.11 promotes that to a proper §Integrity section.

### Why impact is lead-level, not hypothesis-level

Impact's question is usually alert-level, not mechanism-level. In the DLP volume case, `?scheduled-bulk-backup` and `?adversary-exfil` ask the same impact question ("is 180 GB malifying?"). Hypothesis-level contracts would duplicate the same predicate across peers. Lead-level predictions fit cleanly — the lead that measures the impact dimension carries the predicate.

Impact is graded at ANALYZE via the same commit-before-evidence machinery as hypothesis predictions: PREDICT authors `impact_predictions[]` with the threshold; GATHER runs the lead; ANALYZE matches observation against the pre-committed predicate; rule #14 (partial-authority cap) and rule #26-analog (closure at CONCLUDE) generalize.

### Why lead-level only (no signature tier yet)

Two tiers were considered:
- **Tier 1** signature-level (`impact_profile.md`) — static, class-level predicates authored outside the investigation
- **Tier 3** lead-level — PREDICT-authored, per-instance

Tier 1 is stronger commit-before-evidence (threshold authored outside any specific run), at the cost of staleness risk and authoring burden. Decision: start with lead-level only. Per-signature knowledge lives in playbook prose (existing surface, consumed by PREDICT the way other playbook knowledge is). Promote to tier 1 **only if corpus measurements show threshold drift** — same empirical methodology as v2.10's authz rename. Promotion is additive (`inherited_from: sig-iq1` back-reference) and non-disruptive.

Measurements that would trigger promotion:
- Threshold variance across same-signature cases without case-specific justification
- Coverage gaps (alerts that should have tested impact, but PREDICT omitted the predicate)
- Resolution rate — analog of the "10/17 never resolve" audit on authz

### Integrity discipline — peer hypothesis expected

When `authorization_contract` is declared on a hypothesis whose predicted edge has an acting-entity source (`session`, `identity`, `process`), a peer integrity mechanism hypothesis is expected unless an explicit `integrity_waived: <rationale>` is present. Closes the failure mode: authz clears, impact clears, integrity premise never tested (authorized bulk read from compromised service account). Guidance applies today; a validator rule is a forthcoming candidate.

### Terminology cleanup

- **`vertex.trust_root: true` is dead code.** Unvalidated, unqueried. The signal is already carried by `outcome.trust_root_reached: v-{id}` (ref-checked) and `conclude.termination.category: trust-root`. Drop the vertex attribute.
- **"Anchor" reserved for external authority surfaces** (`anchor_id`, `anchor_kind`, `anchor_consultations[]`). `attached_to_vertex`'s existing inline "anchor: …" comment is overload and reads as though the graft point is an authority; drop the gloss.

### Hypothesis cardinality 0-N

§Lean hypotheses currently reads as "hypotheses are mandatory, just lean." Outdated since PR 119 landed structural cardinality (`hypothesize:` block present iff ≥1 new hypotheses). Promote the shape table (0 = enrichment, 1 = mechanism pinned, 2-3 = observable-diverging peers, >3 = refine hierarchically) into the spec so other consumers (handbook, playbook template, signature READMEs) can reference the decision procedure by name. Matches predict.md Shape D/E/I/A/M.

## Spec changes landed in this task

In `docs/investigation-language.md`:

1. v2.11 delta header
2. §Lean hypotheses → §Hypothesis cardinality and leanness, with the 0-N table
3. Promote "Contracts answer policy, not integrity" paragraph into §Integrity as mechanism enumeration
4. Add §Impact as lead-level prediction
5. Drop `vertex.trust_root` field and paragraph
6. Drop "anchor:" gloss on `attached_to_vertex`
7. Add two-axis CONCLUDE shape (`impact_verdict`, `impact_severity`)
8. Closure note for impact (mirrors rule #26)

Not in this task:
- Schema.md rewrite, validator rules, query CLI updates, subagent prompts, corpus migrator — covered by the **implementation pass** task that inherits both v2.10 and v2.11 deltas together.
- Signature-tier `impact_profile.md` — deferred pending corpus measurements.
- Mechanical validator rule for the integrity-peer discipline — candidate for the implementation pass.

## Acceptance criteria

1. Spec v2.11 delta header added; status line updated.
2. §Hypothesis cardinality and leanness replaces §Lean hypotheses with a cardinality table and cross-reference to predict.md Shapes.
3. §Integrity section exists as a peer to §Authorization, naming integrity as evidential/mechanism-hypothesis placement and the acting-entity discipline.
4. §Impact section exists with lead-level `impact_predictions[]`, outcome-level `impact_resolutions[]`, and a two-axis CONCLUDE shape (`impact_verdict`, `impact_severity`).
5. `vertex.trust_root` removed from the vertex schema block and its paragraph dropped.
6. "anchor:" overload in the `attached_to_vertex` comment removed.
7. No field/rule renames beyond the above — the implementation pass owns the schema.md + validator touch.

## Follow-up tasks

- **Implementation pass for v2.10 + v2.11** — `knowledge/invlang/schema.md` rewrite, validator rules (rename + add #26-28 for v2.10 + #29+ for v2.11 impact closure / integrity-peer discipline), query CLI (new impact queries, `anchor_consultations` + `authorization_resolutions` split), subagent prompts (predict.md, analyze.md, report.md, screen.md — drop `legitimacy_*` / add impact + integrity), corpus migrator for existing companions. Sequence: schema.md + migrator + validator flip together; prompts can lag with dual-parse.
- **Corpus measurement pass once impact has ≥10 cases**: threshold variance within signature, coverage gaps, resolution rate. Outputs the promote-to-signature-tier decision.
- **Integrity-peer validator rule trial.** Measure first (cases that declared authz on acting-entity edges without an adversarial peer and reached benign) — promote to a mechanical rule if the failure mode is observed.
