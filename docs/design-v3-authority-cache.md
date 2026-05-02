# Precedent Calibration + Time-Bounded Cache (replaces archetypes)

## Status

Design draft. Implementation deferred to a fresh session.

Supersedes the archetype-catalog mechanism described in `design-v3-hypothesis-archetype-rewrite.md` and extends `design-v3-authority-consultation.md`. Once implemented, archetype machinery is removed wholesale.

This is the third pass. The first proposed a general-purpose authority cache; rejected on soundness for weak-temporality claims. The second pass introduced two patterns but was written against the retired `legitimacy_*` schema and got the temporality model and lookup key wrong (Codex review, 2026-05-02). This pass is rewritten against the v2.10+ authorization schema (`authorization_contract` / `authorization_resolutions`, with `anchor_kind`, `anchor_id`, `grounding_kind`, `effective_window`, `conditioning_context`, `cites_past_case`).

## Motivation

Archetypes were a hand-curated approximation of the past-investigation corpus: each archetype directory bundled a story shape, required anchors, and precedent ticket snapshots that an investigation could match against to ground a benign disposition. Two structural problems:

1. **Frozen and curated.** Archetypes had to be authored ahead of time, kept in sync with reality, and removed when stale. The corpus of past `investigation.md` companions already contains everything an archetype encodes, with the advantage of being live.
2. **Two-leg resolution conflated two different things.** "Required anchors confirmed" is a *grounding* claim about the current investigation. "Matched ticket id" is a *precedent* claim about prior investigations. Treating them as interchangeable substitutes obscures what each is actually doing.

The new design separates them, and provides a different machinery for each:

- **Pattern 1 — Precedent calibration**: a mechanical structural check that asks "has this investigation shape recurred?" Surfaces a disposition distribution; feeds investigation `confidence`; does not gate the disposition itself. Universal — applies to every investigation.
- **Pattern 2 — Cached org-authority**: a narrow cache for resolutions whose original `org-authority` consultation produced an `effective_window` from the authority itself, where the current investigation's edge falls inside that window. The check is "does the prior commitment still cover this edge?", not "is the prior verdict still live now?"

What was rejected:

- **General-purpose authority cache for non-time-bounded claims**. The freshness check is asymptotically the same query as the original authority consultation — no latency win. For weak-temporality claims (group membership, role assignment), there is no narrow signal cheaper than the full re-query.
- **Passive corpus self-invalidation**. "A future investigation will observe the contradiction and invalidate the cache" is unsound because contradicting state changes only get observed if detection coverage exists for them. Group-membership changes that don't fire alerts would never invalidate stale cache.
- **Subscription / CDC mode**. Operationally heavy; silent failure modes (consumer down, missed events) defeat the soundness it was supposed to provide. Defer indefinitely.
- **`expiry > now()` as the cache validity check.** Conflates "is the prior verdict still live" with "did the prior commitment cover this event." Authorization in invlang is *as-of* the edge's event time, not the report-write time. The corrected check is `prior.effective_window.start ≤ current_edge.as_of ≤ prior.effective_window.end`, evaluated mechanically against the cited prior resolution. No time dependence at validation, no "expired mid-investigation" failure mode.

## Empirical basis

Three Haiku-driven experiments validated the *retrieval* mechanism. Both patterns in this draft use mechanical walkers (no LLM at runtime), but the experiments establish that the structural-match approach is feasible against real companion writeups.

| Experiment | Setup | Result |
|---|---|---|
| Lookup feasibility | n=10, 5 fixtures, 5 query categories | precision=1.00, recall=1.00 |
| Adversarial lookup | n=100, 9 categories (alias, near-miss, expired, partial, authority-mismatch, orthogonal) | precision=1.00, recall=0.90 (FNs were correct safety calls on expired authorizations) |
| Cross-instance consistency | 8 scenarios × 5 independent Haiku writeups; single + multi-writeup lookup; adversarial cross-check | single 0.90, multi 1.00, adversarial 0 FP |

What the experiments validate vs. what they don't:

- **Validated**: structural retrieval against companion writeups is reliable when the caller passes structured fields (anchor_kind, predicate, entities), not free-form prose.
- **Not validated** (design choice, not empirical): the mapping from `precedent.status` to permitted `confidence` levels in Pattern 1, and the soundness conditions for cache reuse in Pattern 2. Both are arguments from the schema, evaluated below.

## Pattern 1: Precedent calibration (universal)

### What it does

At REPORT time, walk the corpus for past investigations whose *shape* matches the current one. The walker reports the disposition distribution across matches. The shape match deliberately excludes disposition — that's what we're trying to characterize. The signal feeds `confidence`; it does not gate disposition.

### Shape match (mechanical)

The match tuple per investigation:

```
(signature_id, sorted_unique[(anchor_kind, predicate) for ac in conclude.authorization_contracts])
```

Drawn from the contracts that resolved (or were deferred) at CONCLUDE — these characterize the discriminating questions the investigation actually asked. `predicate` is the contract's predicate text (e.g., `actor_listed_on_active_ticket`); `anchor_kind` is the authority surface (e.g., `change-management-system`). Disposition is *not* in the tuple — the walker reports the disposition distribution across the matches.

A current investigation's tuple is compared against every past investigation's tuple. The walker returns matching case_ids and the disposition each reached. Pure Python over invlang companions; no LLM. Reuses corpus query infrastructure under `soc-agent/scripts/invlang/`.

### Outputs

Let `M` = matches; `N` = stable threshold (start at 3, tunable).

- **`novel`** — `|M| < N`, all dispositions in `M` agree (including the empty case).
- **`stable`** — `|M| ≥ N`, all dispositions in `M` agree.
- **`mixed`** — `|M| ≥ 2` and dispositions in `M` differ. Any disagreement among matches forces `mixed` regardless of count.

`mixed` is now reachable because the match tuple no longer pre-filters by disposition.

### Strictness tuning

Start strict (full tuple match). If observed `novel`-rate is high (>50%), loosen by relaxing the `(anchor_kind, predicate)` set match to ≥M-of-N rather than exact. Tunable, not a design commitment. Calibration happens after the first month of corpus accumulation.

### Where the signal lands

The `precedent` signal feeds `confidence` calibration. No new disposition gate. Two effects:

1. **Confidence cap.** `confidence: high` is permitted only when `precedent: stable`. `precedent: novel` caps at `confidence: medium`. `precedent: mixed` caps at `confidence: low`. The disposition itself is not overridden by precedent — past disagreement is a reason to surface for human review (handled by the auto-close gate below), not a reason to overrule the disposition the current evidence supports.
2. **Auto-close gate.** The existing close-ticket action gate already keys off confidence. So `medium`-confidence benigns surface for human review even though they resolve benign structurally; only `high`-confidence benigns auto-close. No new action-gate machinery.

This avoids deadlock on novel scenarios (they still resolve benign, just don't auto-close on first occurrence) while letting well-trodden paths auto-resolve.

### Invlang spec changes for Pattern 1

A new field in `conclude`:

```yaml
conclude:
  termination: { ... }
  disposition: benign | true_positive | unclear
  confidence: high | medium | low
  precedent:
    status: novel | stable | mixed
    matching_count: <int>
    matching_case_ids: [...]            # up to 5, for traceability
    matching_dispositions: { benign: <int>, true_positive: <int>, unclear: <int> }
```

Validator rules (additions):
- `precedent.status` must be present in `conclude`.
- If `precedent.status == novel`, `confidence` must not be `high`.
- If `precedent.status == mixed`, `confidence` must be `low`. (Disposition is not constrained — the auto-close gate, keyed off `confidence: low`, surfaces the case for human review.)
- `precedent.status` must be consistent with `matching_count` and `matching_dispositions` (mechanical re-check; the walker is deterministic and the validator runs the same walker).

## Pattern 2: Cached org-authority (narrow)

### What it does

For an `authorization_contract` whose prior `org-authority` resolution committed an `effective_window` and whose current edge falls inside that window, reuse the prior resolution without a fresh authority round-trip. The cache is *not* "this verdict is still true now" — it is "this authority's prior commitment still covers this event."

This is structurally different from `grounding_kind: past-case` (which already exists in the spec): past-case is weak-temporal, capped at `partial`, cannot be sole grounding for benign. Cached org-authority is window-bounded, retains `full` authority, and *can* be sole grounding for benign — because the soundness conditions are mechanically verified, not heuristic.

### Soundness conditions (all three required)

1. **Original is `org-authority`.** The cited prior resolution must have `grounding_kind: org-authority`. No chaining on `past-case` and no chaining on another `cached-org-authority` (depth cap, mirrors rule #28).
2. **Window envelope.** The prior resolution must carry `effective_window: { start, end }`, and `start ≤ current_edge.as_of ≤ end`.
3. **Contract-shape exact match.** `(anchor_kind, anchor_id, predicate, subject_entity, object_entity, sorted(conditioning_context))` between the prior contract+resolution and the current contract+edge. Entity matching honors prologue aliases (the prologue records identity links).

If any condition fails, the cache is a miss and the live consultation lead runs as today.

`(anchor_kind, anchor_id, predicate, subject, object, conditioning_context)` is the right key because that is the shape the original verdict actually justified. `(authority, claim, entity)` (the prior draft's key) was too weak: it ignored the resource side, ignored layered policies, and ignored the conditioning_context that scopes `actor_listed_on_active_ticket` to a specific ticket.

### New `grounding_kind`: `cached-org-authority`

Pattern 2 introduces a third value alongside `org-authority` and `past-case`:

```yaml
authorization_resolutions:
  - verdict: authorized
    anchor_kind: change-management-system
    anchor_id: ChangeMgmt-prod
    grounding_kind: cached-org-authority
    authority_for_question: full          # retained — soundness conditions ensure no information loss
    anchor_query: "actor on active ticket covering host?"
    as_of: <iso>                          # the current edge's event time
    effective_window:                     # copied from the cited prior resolution
      start: <iso>
      end: <iso>
    conditioning_context: [...]           # exact match required vs. cited prior resolution
    cites_past_case:                      # required, same shape as past-case
      run_id: <run-id>
      contract_ref: h-{id}.ac{n}
    resolved_by_lead: l-{id}              # the inlined cache-lookup lead
    fulfills_contract: h-{id}.ac{n}
```

`cites_past_case` is reused unchanged — the schema already supports the citation shape. The new value extends the existing enum.

### Validator rules for Pattern 2

Additions to the validator:

- **#29 (cached-org-authority shape match).** A resolution with `grounding_kind: cached-org-authority` must mechanically match the cited prior resolution on `(anchor_kind, anchor_id, predicate, subject, object, sorted(conditioning_context))` (entity-alias-aware). Mismatch = structural failure.
- **#30 (cached-org-authority window envelope).** The current resolution's `as_of` must satisfy `prior.effective_window.start ≤ as_of ≤ prior.effective_window.end`. Out-of-window = structural failure (cache should have been a miss).
- **#31 (cached-org-authority origin and depth).** The cited prior resolution must have `grounding_kind: org-authority`. Citing a `past-case` or another `cached-org-authority` resolution is a structural failure (mirrors #28).
- **#32 (cached-org-authority retains `full`).** `authority_for_question` must remain `full` (because soundness conditions guarantee no information loss). Setting `partial` is a structural failure — if the agent has a reason to weaken authority, it should not be using the cache.

Rule #27 is **not** weakened. `cached-org-authority` is a new third grounding kind, not a relaxation of past-case. Rule #27's "past-case cannot be sole grounding for benign" still holds. Rule #21 (every contract resolves `authorized` for benign) admits cached-org-authority resolutions as authorized — correctly, because they are window-enveloped org-authority commitments, not weak-temporal precedent.

### Operations-file declaration

Each `environment/operations/{anchor}.md` gains a per-predicate declaration:

```yaml
anchor_kind: change-management-system
declared_predicates:
  - id: actor_listed_on_active_ticket
    cacheable: true
    window_source: ticket.scheduled_{start,end}
  - id: ticket_window_active
    cacheable: true
    window_source: ticket.scheduled_{start,end}
  - id: ticket_scope_includes_resource
    cacheable: false
```

`declared_predicates` is documentation for authoring + lookup hinting; not enforced as a closed enum. `cacheable: true` plus `window_source` marks a predicate as eligible for Pattern 2; it tells the agent (a) when to attempt a cache lookup and (b) which authority response field carries the window. Predicates without authority-committed windows are not cacheable. Most predicates fall here — every consultation is live. That is intentional and reflects what the soundness analysis showed.

### Lookup flow

Inside GATHER, for any contract whose predicate is `cacheable: true`:

1. Structural query against the corpus for prior `authorization_resolutions` with `grounding_kind: org-authority`, matching contract shape (#29), and `effective_window` enveloping the current edge's `as_of` (#30). Most-recent wins on ties.
2. **Hit**: ANALYZE writes the cached resolution with `grounding_kind: cached-org-authority` and the soundness fields above.
3. **Miss**: fall back to the live consultation lead defined in the playbook (existing flow). A miss can mean: no shape match, no window envelope, prior resolution wasn't `org-authority`, or no prior resolution at all.

Pure mechanical lookup. No Haiku, no subagent. Cheap enough to inline as a helper in the gather subagent rather than dispatching a separate one.

### Why this is more than redundant with past-case

The spec already lets a current investigation cite a prior case via `grounding_kind: past-case`. Why not just use that?

Because past-case is *weak-temporal*: the prior verdict is taken as evidence that the answer was true at the prior `as_of`, with no claim that it remains true now. That's why rule #27 forbids past-case from being sole grounding for benign — you need a current `org-authority` consultation to confirm the answer still holds.

Cached org-authority is *window-bounded*: the original `org-authority` itself committed to a time window (the change ticket says "active 14:00–18:00"; the JIT binding says "valid until 16:30"; the OAuth token says `exp: <iso>`). Inside that window, the answer is *defined* to hold by the authority that issued it. There is no weak-temporal gap to close. Soundness rests on the authority's own commitment, mechanically verified, not on the agent's inference.

If the original consultation didn't produce a window — most consultations don't — the resolution stays `org-authority` with no cache eligibility, and future investigations re-consult live or use `past-case` (with its constraints).

## Disposition-policy change: from two-leg gate to authorization-only

Removing archetypes is not just a cleanup — it changes how `disposition: benign` is grounded. This deserves to be called out separately from the migration steps, because the soundness argument is the load-bearing piece.

**Before.** `status: resolved` with `disposition: benign` required two legs:
1. `matched_archetype` naming an archetype directory under the signature, AND
2. Grounding — every `required_anchors` entry confirmed, OR `matched_ticket_id` citing a precedent snapshot inside that archetype directory.

The two legs were doing two different jobs (current-investigation grounding vs. past-investigation precedent), conflated under one gate. Archetype curation also had to keep up with reality.

**After.** `disposition: benign` is gated solely on every `authorization_contract` on a confirmed-weight hypothesis resolving `authorized` (rule #21), with rule #27 (no sole past-case grounding) and rule #26 (orphan gate) already in force. Pattern 2's `cached-org-authority` resolutions count as authorized for rule #21 because the soundness conditions are mechanical.

**Why authorization-only is sufficient grounding.** An `authorization_contract` already encodes the discriminating question for the benign branch (e.g., "is this actor on an active change ticket covering this resource?"), and its resolution must cite an authoritative edge per the existing edge-authority rule. The work that `required_anchors` was doing — forcing the agent to confirm specific facts before calling benign — is now done by the contract resolutions themselves, with the validator enforcing that all contracts resolve `authorized`. The precedent question — "has this shape resolved benign before?" — moves to Pattern 1 and lands on `confidence`, not on the disposition gate.

**Net effect on safety posture.** Strictly looser on archetype-match (no longer required at all), strictly equivalent or tighter on grounding (every contract must resolve, not just the archetype's required anchors). Auto-close behavior is governed by `confidence` rather than archetype presence: novel-shape benigns resolve benign but surface for review until the corpus accumulates precedent.

## What dies

| Removed | Replaced by |
|---|---|
| `archetypes/{name}/` directories under each signature | The corpus + Pattern 1 precedent walker |
| `matched_archetype` in `report.md` frontmatter | `precedent` block in `conclude` |
| `archetype-match` subagent | (none) — Pattern 1 is mechanical, Pattern 2 is inlined |
| Two-leg resolution gate | Single gate: rule #21 (all contracts resolve `authorized`) + #26 + #27 |
| `required_anchors` (per-archetype) | Already redundant with `authorization_contract`s; removed |
| First-draft general-purpose authority cache | Rejected on soundness grounds |
| Second-draft `cached_from` / `cached_expiry` schema | Replaced by `grounding_kind: cached-org-authority` reusing `cites_past_case` |
| Second-draft `expiry > now()` validity check | Replaced by `effective_window` envelope of `current_edge.as_of` |
| Second-draft `(authority, claim, entity)` lookup key | Replaced by full contract-shape match `(anchor_kind, anchor_id, predicate, subject, object, conditioning_context)` |

## What is added

| Added | Role |
|---|---|
| Mechanical precedent walker | Compute `(signature_id, sorted (anchor_kind, predicate) set)` matches across corpus and report disposition distribution |
| `precedent: {status, matching_count, matching_case_ids, matching_dispositions}` in `conclude` | Surface signal; feeds `confidence` |
| Validator rules tying `precedent.status` to permitted `confidence` | Soundness gate via existing `confidence` field |
| `grounding_kind: cached-org-authority` enum value | Third grounding kind alongside `org-authority` and `past-case` |
| Validator rules #29–#32 | Cache shape match, window envelope, origin+depth cap, `full`-authority retention |
| `cacheable: true` + `window_source` on operations-file `declared_predicates` | Mark which predicates are eligible for Pattern 2 |
| Mechanical cache-lookup walker | Find prior `org-authority` resolutions with envelope window for current edge |

## Migration order (for fresh session)

1. **Re-read**: §Temporality of authorization, §authorization_resolutions schema, rules #21 / #26 / #27 / #28 in `docs/investigation-language.md`. The design rests on these being already-implemented invariants — confirm before editing.
2. **Spec edit (v2.16)**: fold the changes into `docs/investigation-language.md`. New `precedent` block in `conclude`. Extend `grounding_kind` enum with `cached-org-authority`. Add validator rules #29–#32. Update §Temporality and §past-case sections to cross-reference the new grounding kind.
3. **Walker implementation**:
   - `soc-agent/scripts/invlang/queries.py` — add `precedent_match(signature_id, contract_shape_set)` returning the matching set + disposition distribution.
   - `soc-agent/scripts/invlang/queries.py` — add `cached_org_authority_lookup(anchor_kind, anchor_id, predicate, subject, object, conditioning_context, current_edge_as_of)` returning the most-recent enveloping resolution or none.
   - Unit tests covering empty corpus, single-match, multi-match-consistent, multi-match-mixed, window-out-of-envelope, depth-cap (citing past-case or cached-org-authority should reject), entity-alias resolution.
4. **Validator implementation**: extend `hooks/scripts/invlang_checks_authorization.py` with rules #29–#32 and the new `precedent` rules. Unit tests.
5. **Operations-file extension**: update existing `environment/operations/*.md` with `declared_predicates`, `cacheable`, `window_source` where applicable. Most existing predicates will be `cacheable: false` — that is correct.
6. **REPORT subagent**: update `soc-agent/agents/report.md` to invoke the precedent walker and write the `precedent` block. Update the report judge to enforce the precedent → confidence relationship.
7. **GATHER subagent**: update `soc-agent/agents/gather.md` to invoke `cached_org_authority_lookup` for cacheable predicates before dispatching the live-consultation lead.
8. **Cutover** (see §Disposition-policy change above for the rationale): flip the report judge to drop the two-leg gate; rely on rules #21 / #26 / #27 already in force. Remove `matched_archetype` from report frontmatter; replace with `precedent` field.
9. **Removal**: delete `archetypes/` directories across all signatures, `archetype-match.md`, archetype fixtures and tests, the `_template/archetypes/` skeleton.
10. **Documentation**: archive `design-v3-hypothesis-archetype-rewrite.md` to `docs/archive/`. Update `CLAUDE.md` references. Update handbook.

## Risks and open questions

- **Strictness tuning for the precedent walker.** Start strict; loosen if `novel`-rate is consistently high after corpus accumulation. Calibration is empirical, not designed up front.
- **Bootstrap behavior.** First N investigations of any signature will all be `precedent: novel`, capping confidence at `medium` and surfacing for human review. That is correct behavior — humans validate the early instances. Worth being explicit about in operator-facing docs so this doesn't read as a regression.
- **Mixed precedent semantics.** Capping `mixed` at `confidence: low` is conservative; a majority-rules variant that lets the dominant disposition reach `medium` is more permissive. Start conservative; revisit if it surfaces too many false escalations.
- **Cache scope creep.** The temptation will be to mark non-windowed predicates as `cacheable: true` to "get cache benefits." Resist. The author skill should validate that `window_source` references a real field on the authority's response, and the validator's window-envelope check (#30) catches misuse at write time.
- **Entity normalization for the cache.** Lookup is structural — contract-shape match. Entity surface form variation (`alice` vs `alice@corp`) could miss legitimate cache hits. Mitigation: the lookup walker accepts any prologue alias for an entity (the prologue records identity links). Implementation detail for step 3.
- **Pattern 1 shape-match overfitting to current playbooks.** As playbooks evolve and add/remove contracts, the `(anchor_kind, predicate)` set will drift. Past investigations with the older set won't match. Mitigation: tune strictness, or add a corpus migration step when playbooks change materially. Defer to first occurrence.
- **Cache poisoning / manual invalidation.** A wrong prior `org-authority` resolution with a long `effective_window` would propagate to cache hits until the window expires. Two mitigations are available without re-introducing CDC: (a) the validator already requires the prior resolution be `org-authority` with citation to an authoritative edge, so the prior had to clear rule #21; (b) an operator escape hatch — a `revoked_runs.txt` file the cache walker honors — can be added if needed. Defer until observed.
- **Window granularity vs. clock skew.** `effective_window` boundaries are inclusive. Edge `as_of` matching the boundary exactly is a hit. Sub-second clock skew between authority and current edge is not addressed; if it surfaces, add a configurable tolerance. Defer.
