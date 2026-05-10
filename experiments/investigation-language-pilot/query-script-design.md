# Query Script — Design Spec (terse)

The query script reads completed v2.3 investigation companions and answers retrieval questions the agent has during a live walk. Its job is **what the agent can ask**, not how past cases are stored.

## Goal

Given an in-progress investigation, return relevant past-case signal fast enough to shape the next decision: seed hypotheses, calibrate anchor trust, avoid known dead leads, pick termination category.

**Latency targets**

- Structured query returns in < 1 s.
- Prose substring returns in < 3 s.
- Corpus scale: up to ~180k companions (~10 GB raw YAML). Hardware is not the limit at this scale — see `query-script-architecture.md` if it exists.

## Non-goals

- Not a semantic search engine.
- Not an analytics platform — summary stats are a side effect, not the product.
- Not a feedback loop — post-resolution outcomes live elsewhere.
- Not a writer tool — read-only over completed companions.

## What you can ask — seven query classes

Every retrieval wish surfaced in the A.4, rule-5710, and m365 walks maps to one of seven classes. Each class has a fixed filter shape; the agent (or a haiku wrapper) picks the class and fills the filter.

### 1. Coarse case lookup

**Question shape:** "Find cases where [structured conclusion fields match X]."

**Filters:** `disposition`, `termination.category`, `confidence`, `matched_archetype`, `ceiling_test.kind`, plus a time window on the alert envelope.

**Returns:** case list ordered by recency, each with a one-line summary and the matched filter values.

**Example:** severity-ceiling cases with disposition=unclear that needed out-of-band-human-contact.

### 2. Anchor calibration

**Question shape:** "For anchor X, how have past writers classified its authority on similar questions, and how did those cases resolve?"

**Filters:** `trust_anchor_result.{anchor_id, result, authority_for_question, as_of}` + optional question-shape hint (the hypothesis name or prediction text the anchor was tested against).

**Returns:** distribution of `(result × authority_for_question) → disposition`, plus example cases per cell, plus an `as_of` staleness histogram for calibration.

**Example:** `vpn-mfa` with `authority_for_question: full` — disposition distribution over the last 90 days.

### 3. Refinement chain shape

**Question shape:** "For alert class X (or hypothesis pattern Y), how did past walks fork the hypothesis space?"

**Filters:** alert rule name (joined from envelope), root-level hypothesis name pattern.

**Derives from:** hierarchical hypothesis IDs (`h-001 → h-001-001 → h-001-001-001`). Chain structure is parsed from IDs, no derived_from field needed.

**Returns:** tree shapes per case — `{root_name, [children_at_loop_1], final_weight_per_leaf, triggering_lead_kind}`.

**Example:** `?interactive-human-action` refinement shapes, grouped by alert source.

### 4. Dead-lead lookup

**Question shape:** "Has this lead system been attribution-opaque or partial-coverage for this vertex shape before?"

**Filters:** `lead.query_details.system`, `outcome.failure_reason`, target vertex `type` + `classification`.

**Returns:** case list with vertex-shape annotations + failure-reason enum bucket counts.

**Example:** `iam-session-origination-chain` on `session:service-session` — historical failure modes.

### 5. Lead-sequence pattern

**Question shape:** "What lead sequences resolved cases similar to the current one?"

**Filters:** partial prefix of the current walk's own lead sequence, matched archetype, disposition.

**Derives from:** traversal of `gather[]` in order, serialized as a compact trace string (e.g., `trust(job-scheduler:refuted)→scope(endpoint)→trust(vpn-mfa:confirmed)→…`).

**Returns:** matching trace strings + disposition + final hypothesis weights.

**Example:** all cases whose walk started with `trust(job-scheduler:refuted)→scope(endpoint)` and ended at trust-root.

### 6. Name wildcard

**Question shape:** "Find hypotheses whose name matches pattern X with final weight Y."

**Filters:** hypothesis `name` (glob / substring), `weight` enum, `status`, optional `disposition` join.

**Returns:** tuples of `(case_id, hypothesis_id, name, final_weight, disposition)`.

**Example:** `?*self*|?*legitimate*|?*user-configured*` with weight ∈ {+, ++} and disposition=benign — the "benign self-setup confirmation patterns" retrieval from the m365 survey.

### 7. Prose substring

**Question shape:** "Find cases whose free-text fields contain phrase X."

**Filters:** substring / regex over flattened prose fields — `concerns[]`, `resolutions[].reasoning`, `ceiling_rationale`, `summary`.

**Returns:** case list + highlighted match snippets.

**Example:** `"partial-authority"` in resolution reasoning — finds cases where writers invoked the partial-authority cap.

## Input shape

The script exposes one callable per query class plus a top-level router. Each takes a typed filter object and returns the same output envelope.

**No natural-language input at the primitive layer.** Natural language is the haiku wrapper's job (see §Wrapper). The primitive layer is typed and deterministic.

## Output shape

Every query returns:

- `hits` — list of `{case_id, snippet, score}` where the snippet is whatever structural fragment the class surfaces (a conclude block, a single resolution, a refinement tree, …).
- `aggregates` — class-specific summary (distribution counts, trace-string histogram, staleness histogram, …).
- `query_trace` — the normalized filter that was actually executed. For debugging and for the haiku wrapper to diff against its intent.

JSON, machine-consumable. A separate pretty-printer renders for human spot-checks.

## Haiku wrapper (layer on top, optional, not MVP)

A thin layer translating natural-language retrieval wishes into 3-5 primitive calls:

1. Takes a natural-language wish and the current alert + partial walk as context.
2. Reads the **attribute-key vocabulary** (periodic sweep: every `attributes.*` key ever used, per vertex type) and the **hypothesis-name vocabulary** (every `?*` name ever used).
3. Picks a query class and issues a primitive call.
4. If hits are thin, issues another primitive call with a different wildcard / key variant.
5. Returns the union to the caller, with notes on which variants worked.

The attribute-key and name vocabularies are the mechanism by which "free-form" fields become queryable: haiku enumerates likely keys instead of the schema constraining them.

**Not MVP.** Build the primitive first, exercise it by hand, add the wrapper once the primitive's query-class shapes are stable.

## What's out of scope (and why)

- **Semantic embeddings.** The wildcard-plus-haiku-enumeration loop serves the retrieval wishes the survey surfaced. Embeddings become relevant only if real corpus queries show that wildcards miss recall that matters. Not yet observed, not yet worth the infrastructure.
- **Cross-corpus federation.** One corpus at a time.
- **Writer-side validation.** Different tool.
- **Post-resolution outcomes.** Not in the companion. A separate feedback file, if it ever exists, is out of scope for this script.

## Evolution rule

Every query class earned its place by appearing as a retrieval wish in one of the walks. **Don't add a class without a case that motivates it.** If a new wish lands and fits an existing class, widen the filter. If it genuinely needs a new class, write it up here first, then build it.
