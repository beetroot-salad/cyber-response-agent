---
title: Improving invlang query script capabilities
status: doing
groups: invlang, knowledge
---

## Axes

### 1. Retrieval improvements to existing classes

**Ranking and top-N output.** All classes should support `--top N` output with a configurable sort metric. Currently Class 8 sorts by effectiveness; others return unsorted hits. Add `--top N` as a global flag and ensure every class has a natural default sort (e.g., Class 1 by confidence, Class 5 by lead_count, Class 6 by final_weight severity).

**Child hypothesis enumeration.** `--enumerate hypotheses` currently returns a flat set of distinct hypothesis names. Extend to support `--enum-tree` which returns the parent-child hierarchy derived from the `h-001-002` ID structure (already computable via `_parse_hypothesis_chain` in Class 3). Useful for understanding hypothesis refinement patterns across the corpus.

**Discrimination score as extension to Class 8.** Add a `--discriminate-between PATTERN1 PATTERN2` flag to Class 8. Computes `mean(signed_delta_H1 - signed_delta_H2)` for each lead across cases where both hypothesis patterns are present. A lead that consistently moves H1 positively and H2 negatively scores high. Complements the existing `effectiveness` score (total movement) with a directional split. Extension, not replacement.

### 2. New query classes

**Weight-reversal mining (pitfall extraction).** Find resolutions where hypothesis weight moved from positive to negative within an investigation (`before ∈ {null, +, ++}` and `after ∈ {-, --}`). The reasoning fields in those resolutions are "pitfall text" — patterns that looked like evidence but weren't. Enables pitfall pre-registration at HYPOTHESIZE time grounded in corpus data rather than first-principles reasoning.

**Lead pair synergy.** For composite dispatches (leads grouped by same loop + entity), compare `sum(individual_weight_deltas)` to `combined_weight_delta`. Pairs where combined >> sum are synergistic — the conjunction is what discriminates, not either lead alone. Bidirectional: check whether (A then B) and (B then A) cases both show the synergy. Returns ranked synergistic pairs with hypothesis context.

**Post-failure recovery map.** Class 4 extension: for each failed lead (`failure_reason` present), extract the next lead in the sequence (from the trace string in Class 5), compute its weight delta. Returns `{failed_lead, system} → {typical_next_lead, effectiveness_of_next}`. Guides recovery when a data source is broken.

**Independent data source metric.** For each case, count distinct systems in `query_details.system` across leads. Distribution grouped by severity + disposition. Replaces loop count as a convergence metric: "for this class of alert at this severity, how many independent data sources are typically needed?" More epistemologically meaningful than loop depth.

### 3. Ad hoc / natural language fallback

The `query-past-investigations` lead (tracked in `past-runs-lead.md`) should be a subagent. Its interface: the main agent passes a natural-language question + any structured parameters. The subagent attempts Class 1-8 first. When no class fits, it generates polars code against the corpus.

**Critical constraint:** generated code must be returned alongside results, not just the result. Silent wrong answers are the failure mode of LLM-generated polars code. "Here is the code I ran, here is what it returned" lets the main agent verify before trusting the output.

This absorbs the "Haiku wrapper for natural language queries" direction from the original task spec.
