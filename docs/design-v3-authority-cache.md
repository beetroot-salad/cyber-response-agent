# Precedent Calibration + Time-Bounded Cache (replaces archetypes)

## Status

Design draft. Implementation deferred to a fresh session.

Supersedes the archetype-catalog mechanism described in `design-v3-hypothesis-archetype-rewrite.md` and extends `design-v3-authority-consultation.md`. Once implemented, archetype machinery is removed wholesale.

This draft is the second pass. The first pass proposed a general-purpose authority cache; that design failed soundness analysis for weak-temporality claims (the freshness check turned out to be the same query as the original authority consultation, and passive corpus self-invalidation was unsound because it depends on detection coverage). The two-pattern shape below survives that critique.

## Motivation

Archetypes were a hand-curated approximation of the past-investigation corpus: each archetype directory bundled a story shape, required anchors, and precedent ticket snapshots that an investigation could match against to ground a benign disposition. Two structural problems:

1. **Frozen and curated.** Archetypes had to be authored ahead of time, kept in sync with reality, and removed when stale. The corpus of past `investigation.md` companions already contains everything an archetype encodes, with the advantage of being live.
2. **Two-leg resolution conflated two different things.** "Required anchors confirmed" is a *grounding* claim about the current investigation. "Matched ticket id" is a *precedent* claim about prior investigations. Treating them as interchangeable substitutes obscures what each is actually doing.

The new design separates them, and provides a different machinery for each:

- **Pattern 1 — Precedent calibration**: a mechanical structural check that asks "has this investigation shape been resolved this way before?" Feeds investigation confidence, not the disposition itself. Universal — applies to every investigation.
- **Pattern 2 — Time-bounded cache**: a narrow cache for claims where the authority itself committed the answer to a time window (tokens, change-window approvals, JIT bindings). Validity check is `expiry > now()`, no authority round-trip needed.

What was rejected in the second pass:

- **General-purpose authority cache for non-time-bounded claims**. The freshness check is asymptotically the same query as the original authority consultation — no latency win. For weak-temporality claims (group membership, role assignment), there is no narrow signal cheaper than the full re-query.
- **Passive corpus self-invalidation**. "A future investigation will observe the contradiction and invalidate the cache" is unsound because contradicting state changes only get observed if detection coverage exists for them. Group-membership changes that don't fire alerts would never invalidate stale cache.
- **Subscription / CDC mode**. Operationally heavy; silent failure modes (consumer down, missed events) defeat the soundness it was supposed to provide. Defer indefinitely.

## Empirical basis

Three Haiku-driven experiments validated the *retrieval* mechanism that both patterns rely on. Pattern 1 uses a mechanical walker (no LLM), but the same retrieval shape would back any future LLM-assisted variant of pattern 1; pattern 2's lookup is structural exact-match.

| Experiment | Setup | Result |
|---|---|---|
| Lookup feasibility | n=10, 5 fixtures, 5 query categories | precision=1.00, recall=1.00 |
| Adversarial lookup | n=100, 9 categories (alias, near-miss, expired, partial, authority-mismatch, orthogonal) | precision=1.00, recall=0.90 (FNs were correct safety calls on expired authorizations) |
| Cross-instance consistency | 8 scenarios × 5 independent Haiku writeups; single + multi-writeup lookup; adversarial cross-check | single 0.90, multi 1.00, adversarial 0 FP |

Findings folded into the design:

- Multi-writeup retrieval is the realistic operating point and was 1.00 on the consistency test. The corpus naturally accumulates multiple past resolutions per shape; a precedent lookup only needs *one* match.
- Consistency failures came from query-side under-specification, not authoring drift. The lookup contract therefore requires the caller to pass structured fields (signature_id, authority+claim tuples, disposition), not free-form prose.
- No need for a closed claim vocabulary or normalization phase.

## Pattern 1: Precedent calibration (universal)

### What it does

At REPORT time, walk the corpus for past investigations whose shape matches the current one. Surface a mechanical signal: `novel | stable | mixed`. The signal feeds investigation confidence; it does not gate the disposition.

### Shape match (mechanical)

The match tuple per investigation:

```
(signature_id, sorted_unique[(authority, claim) for c in resolved_contracts], disposition)
```

A current investigation's tuple is compared against every past investigation's tuple. The walker returns the count of past investigations sharing the tuple, plus whether they all reached the same disposition.

This is a pure Python walker over invlang companions. No LLM. Reuses the existing corpus query infrastructure under `soc-agent/scripts/invlang/`.

### Outputs

- **`novel`** — fewer than N past investigations match the tuple, and any that do match share the same disposition. (N is tunable; start at 3.) This subsumes the zero-match case and the 1-to-(N-1) same-disposition case: in both, there is not yet enough precedent to call the shape established.
- **`stable`** — ≥N past investigations, all with the same disposition.
- **`mixed`** — at least 2 past investigations matching the tuple but with differing dispositions. Any escalation in matching shape forces `mixed`.

### Strictness tuning

Start strict (full tuple match). If observed `novel`-rate is high (>50%), loosen by relaxing the authority-set match to ≥M-of-N rather than exact. Tunable, not a design commitment. Calibration happens after the first month of corpus accumulation.

### Where the signal lands

The `precedent` signal feeds `confidence` calibration. No new disposition gate. Two effects:

1. **Confidence cap.** `confidence: high` is permitted only when `precedent: stable`. `precedent: novel` caps at `confidence: medium`. `precedent: mixed` caps at `confidence: low`. The disposition itself is not overridden by precedent — past disagreement is a reason to surface for human review (handled by the auto-close gate below), not a reason to overrule the disposition the current evidence supports.
2. **Auto-close gate.** The existing close-ticket action gate already keys off confidence. So `medium`-confidence benigns surface for human review even though they resolve benign structurally; only `high`-confidence benigns auto-close. No new action-gate machinery.

This avoids deadlock on novel scenarios (they still resolve benign, just don't auto-close on first occurrence) while letting well-trodden paths auto-resolve.

### Invlang spec changes for pattern 1

A new field in `conclude`:

```yaml
conclude:
  termination: { ... }
  disposition: benign | true_positive | unclear
  confidence: high | medium | low
  precedent:
    status: novel | stable | mixed
    matching_count: <int>
    matching_case_ids: [...]   # up to 5, for traceability
```

Validator rules:
- `precedent.status` must be present in `conclude`.
- If `precedent.status == novel`, `confidence` must not be `high`.
- If `precedent.status == mixed`, `confidence` must be `low`. (Disposition is not constrained — the auto-close gate, keyed off `confidence: low`, surfaces the case for human review regardless of disposition.)
- The walker's output is computed mechanically and written by the REPORT subagent; the validator re-checks it deterministically.

## Pattern 2: Time-bounded cache (narrow)

### What it does

For claims where the authority itself committed the answer to a time window, cache the resolution with its expiry. Subsequent investigations with a structural-match query against the cache get the cached verdict if `expiry > now()`. On expiry: fall back to live authority consultation (same as today).

### Scope

Only applies to claims with explicit start + expiry encoded by the authority. Examples:

- OAuth/SAML tokens (`exp` claim).
- Approved-change windows on tickets (`scheduled_start`, `scheduled_end`).
- Sprint / migration approvals (`valid_until: 2025-Q2-end`).
- Out-of-office / business-trip context (`from`, `to`).
- Temporary group elevations (PIM/JIT bindings).

Claims without authority-committed time bounds are not cacheable. Most claims fall into this category — every consultation is live. That is intentional and reflects what the soundness analysis showed.

### Operations-file declaration

Each `environment/operations/{anchor}.md` gains a per-claim declaration:

```yaml
authority: change-management-system
declared_claims:
  - id: actor_listed_on_active_ticket
    time_bounded: true
    expiry_source: ticket.scheduled_end
  - id: ticket_window_active
    time_bounded: true
    expiry_source: ticket.scheduled_end
  - id: ticket_scope_includes_resource
    time_bounded: false
```

`declared_claims` is documentation for authoring + lookup hinting; not enforced as a closed enum (the consistency experiment showed normalization is unnecessary). `time_bounded: true` plus `expiry_source` is what marks a claim as cacheable.

### Invlang spec changes for pattern 2

A new optional field on `legitimacy_resolution`:

```yaml
legitimacy_resolutions:
  - contract_id: <id>
    verdict: authorized
    cached_from: SEC-2025-0412
    cached_expiry: "2025-12-31T23:59:00Z"
    citations: [<edge_id>]
```

Validator rules:
- `cached_from` may be set only when the contract's `(authority, claim)` resolves a `time_bounded: true` claim per the authority's operations file. Resolutions on non-time-bounded claims with `cached_from` set are a structural failure.
- `cached_expiry` is required when `cached_from` is set.
- At validation time (PreToolUse on report write), if `cached_expiry <= now()`, the resolution is a structural failure (cache should have been treated as miss earlier). This is belt-and-suspenders against agent error.
- Mechanical post-verification: walk the named `case_id`'s companion, confirm a `legitimacy_resolution` exists with matching `(authority, claim, entity)` and original `cached_expiry`. Mismatch = structural failure.
- `cached_from` resolutions still require ≥1 authoritative edge citation (the original cache write's authoritative edge, transitively cited via the `case_id`). The current investigation does not need to re-cite a current-run authoritative edge for the time-bounded case — this is the difference vs. the rejected first draft, and it is sound because the authority itself committed to the time window.

### Lookup flow

Inside GATHER, for any contract whose claim is `time_bounded: true`:

1. Structural query against the corpus for past `legitimacy_resolution`s matching `(authority, claim, entity)` with non-expired `cached_expiry` and verdict `authorized`.
2. If hit: ANALYZE writes the cached resolution.
3. If miss: fall back to the live consultation lead defined in the playbook (existing flow).

Pure mechanical lookup. No Haiku, no subagent. The lookup is cheap enough to inline as a helper in the gather subagent rather than dispatching a separate one.

## Disposition-policy change: from two-leg gate to authorization-only

Removing archetypes is not just a cleanup — it changes how `disposition: benign` is grounded. This deserves to be called out separately from the migration steps, because the soundness argument is the load-bearing piece.

**Before.** `status: resolved` with `disposition: benign` required two legs:
1. `matched_archetype` naming an archetype directory under the signature, AND
2. Grounding — every `required_anchors` entry confirmed, OR `matched_ticket_id` citing a precedent snapshot inside that archetype directory.

The two legs were doing two different jobs (current-investigation grounding vs. past-investigation precedent), conflated under one gate. Archetype curation also had to keep up with reality.

**After.** `disposition: benign` is gated solely on every `legitimacy_contract` on a live-weight hypothesis resolving `authorized`. No archetype match, no `required_anchors`.

**Why authorization-only is sufficient grounding.** A `legitimacy_contract` already encodes the discriminating question for the benign branch (e.g., "is this actor on an active change ticket covering this resource?"), and its resolution must cite an authoritative edge (`authoritative-source` / `runtime-audit` / `siem-event`) per the existing edge-authority rule. The work that `required_anchors` was doing — forcing the agent to confirm specific facts before calling benign — is now done by the contract resolutions themselves, with the validator enforcing that all contracts resolve `authorized` (rule #21). The precedent question — "has this shape resolved benign before?" — moves to pattern 1 and lands on `confidence`, not on the disposition gate.

**Net effect on safety posture.** Strictly looser on archetype-match (no longer required at all), strictly equivalent or tighter on grounding (every contract must resolve, not just the archetype's required anchors). Auto-close behavior is governed by `confidence` rather than archetype presence: novel-shape benigns resolve benign but surface for review until the corpus accumulates precedent.

## What dies

| Removed | Replaced by |
|---|---|
| `archetypes/{name}/` directories under each signature | The corpus + pattern-1 precedent walker |
| `matched_archetype` in `report.md` frontmatter | `precedent` block in `conclude` |
| `archetype-match` subagent | (none) — pattern 1 is mechanical, pattern 2 is inlined |
| Two-leg resolution gate | Single gate: every legitimacy_contract resolved authorized |
| `required_anchors` (per-archetype) | Already redundant with `legitimacy_contract`s; removed |
| First-draft general-purpose authority cache | Rejected on soundness grounds |
| First-draft `invalidation_signals` schema | Replaced by `time_bounded` + `expiry_source` for the narrow case |
| First-draft subscription / CDC mode | Operationally unsound; deferred indefinitely |

## What is added

| Added | Role |
|---|---|
| Mechanical precedent walker | Compute `(signature_id, authority+claim tuple set, disposition)` matches across corpus |
| `precedent: {status, matching_count, matching_case_ids}` in `conclude` | Surface signal; feeds `confidence` |
| Validator rules tying `precedent.status` to permitted `confidence` and `disposition` | Soundness gate via existing fields |
| `time_bounded: true` + `expiry_source` on operations-file `declared_claims` | Mark which claims are cacheable |
| `cached_from` + `cached_expiry` on `legitimacy_resolution` (optional, scoped to time-bounded claims) | Time-bounded cache hit |
| Mechanical post-verification walker for `cached_from` | Confirm tuple match + non-expiry |

## Migration order (for fresh session)

1. **Spec edit (v2.16)**: fold the changes into `docs/investigation-language.md`. New `precedent` block in `conclude`. New optional `cached_from` + `cached_expiry` on `legitimacy_resolution`. New validator rules for both.
2. **Walker implementation**:
   - `soc-agent/scripts/invlang/queries.py` — add `precedent_match(signature_id, contract_tuple_set, disposition)` returning the matching set.
   - `soc-agent/scripts/invlang/queries.py` — add `time_bounded_cache_lookup(authority, claim, entity)` returning the most recent non-expired matching resolution.
   - Unit tests covering empty corpus, single-match, multi-match-consistent, multi-match-mixed.
3. **Validator implementation**: extend `hooks/scripts/invlang_validate.py` with the new rules. Unit tests.
4. **Operations-file extension**: update existing `environment/operations/*.md` with `declared_claims`, `time_bounded`, `expiry_source` where applicable. Most existing claims will be `time_bounded: false` — that is correct.
5. **REPORT subagent**: update `soc-agent/agents/report.md` to invoke the precedent walker and write the `precedent` block. Update the report judge to enforce the precedent → confidence relationship.
6. **GATHER subagent**: update `soc-agent/agents/gather.md` to invoke `time_bounded_cache_lookup` for time-bounded claims before dispatching the live-consultation lead.
7. **Cutover** (see §Disposition-policy change above for the rationale): flip the report judge to drop the two-leg gate; require only that all legitimacy_contracts resolve authorized. Remove `matched_archetype` from report frontmatter; replace with `precedent` field.
8. **Removal**: delete `archetypes/` directories across all signatures, `archetype-match.md`, archetype fixtures and tests, the `_template/archetypes/` skeleton.
9. **Documentation**: archive `design-v3-hypothesis-archetype-rewrite.md` to `docs/archive/`. Update `CLAUDE.md` references. Update handbook.

## Risks and open questions

- **Strictness tuning for the precedent walker.** Start strict; loosen if `novel`-rate is consistently high after corpus accumulation. Calibration is empirical, not designed up front.
- **Bootstrap behavior.** First N investigations of any signature will all be `precedent: novel`, capping confidence at `medium` and surfacing for human review. That is correct behavior — humans validate the early instances. Worth being explicit about in operator-facing docs so this doesn't read as a regression.
- **Mixed precedent semantics.** Capping `mixed` at `confidence: low` (and routing through the auto-close gate for human review) is conservative; a majority-rules variant that lets the dominant disposition reach `medium` is more permissive. Start conservative; revisit if it surfaces too many false escalations.
- **Time-bounded cache scope creep.** The temptation will be to mark non-time-bounded claims as `time_bounded: true` to "get cache benefits." Resist. The author skill should validate that `expiry_source` references a real field on the authority's response.
- **Authority entity normalization.** Pattern-2 lookup is structural — `(authority, claim, entity)` tuple match. Entity surface form variation (`alice` vs `alice@corp`) could miss legitimate cache hits. Mitigation: the lookup walker should accept any prologue alias for an entity (the prologue records identity links). Implementation detail for step 2.
- **Pattern 1 "shape match" overfitting to current signature playbooks.** As playbooks evolve and add/remove leads, the (authority, claim) tuple for matching alerts will drift. Past investigations with the older tuple won't match. Mitigation: tune strictness, or add a corpus migration step when playbooks change materially. Defer to first occurrence.
