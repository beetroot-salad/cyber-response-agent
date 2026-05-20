---
title: Defender advisory invlang retrieval wiring
status: doing
groups: defender, invlang, knowledge, retrieval
---

## Progress (2026-05-20)

Compatibility step #2 from the original §Compatibility Work is **done**:
a tolerant defender-side loader ships under
`defender/scripts/invlang/{parser,corpus}.py`. Standalone (no
soc-agent imports). Loads 41/41 cases under `/tmp/defender-runs/`,
up from 23/41 with the strict soc-agent loader.

Schema gaps catalogued and absorbed:

1. **Unescaped `|` inside `attrs` cells** (8 cases) — Falco fields
   `flags=EXE_WRITABLE|EXE_LOWER_LAYER` written verbatim. Resolved by
   `_collapse_extra_cells_into_attrs`: rows whose final column is
   `attrs` rejoin any over-cells with `|`.
2. **Extra empty cell in `:H` hypothesize rows** (5 cases, 15 cells
   where the spec declares 14) — the defender writer occasionally
   inserts an extra `||` between refuts and authz. Resolved by
   `_normalize_hypothesis_cells`: leading 7 + trailing 3 cells stay
   positional; the middle 4 columns (preds, attr_preds, refuts,
   authz) are *content-routed* by sub-cell marker (`p<n>:`, `ap<n>:`,
   `r<n>...`, `ac<n>:`), so misalignment cannot shift content
   between columns.
3. **`:T resolutions` rows missing `⟂`** (2 cases) — inline-anchor
   resolutions without cited supporting edges. Resolved by tolerant
   parsing in `_parse_resolution_line`: when `⟂` is absent the
   bracketed body lands as `reasoning`, supporting_edges is `[]`.
4. **Signature ID source** — `defender/scripts/invlang/corpus.py`
   reads `rule.id` from the sibling `alert.json` and exposes it as
   `Companion.signature_id` (`wazuh-rule-<N>`). Path-based `ruleNNN`
   extraction did not match defender path conventions.
5. **`created_at` source** — corpus loader stamps the companion with
   the run directory's mtime since defender investigation.md does
   not carry `<!-- created: -->`. Sufficient for recency filtering
   at ≥day granularity.

Coverage (41 cases):

- prologue + findings + conclude all present for every case.
- Hypotheses: 168 predictions, 95 refutation rows, 27 authorization
  contracts.
- Findings: 55 leads have at least one resolution.
- Disposition mix: 14 malicious, 13 benign, 9 inconclusive, 5 escalate.

Tests: `defender/tests/test_invlang_parser.py` (9 unit tests covering
each drift pattern + an end-to-end synthetic corpus).

Remaining work toward the original task scope:

- Class 1/5/6/8/13/14/15-style query helpers on top of the loader
  (advisory retrieval surface). The loader produces canonical
  companion dicts so query code can be ported straight from soc-agent
  with minor field-name adaptations.
- The A/B test plan in §Empirical Test Plan (baseline vs deterministic
  retrieval vs subagent retrieval).


## Summary

Wire the existing invlang query package into defender as an advisory retrieval surface.

The retrieval result should help the investigator choose better hypotheses and leads, but it must not be treated as current-case evidence. Past investigations can suggest "cases like this usually needed lead X" or "this hypothesis pattern often resolved this way", but only current run observations can support, refute, authorize, or conclude the alert.

This replaces the older `past-runs-lead.md` direction of exposing past investigations as a normal lead. A normal lead would enter the same lead sequence as evidence-gathering leads and risks contaminating the actor/oracle learning loop. Advisory recall should stay outside `lead_sequence.yaml` unless a separate memory namespace and projection exclusion are explicitly added.

## Existing Implementation

The core query implementation already exists under `soc-agent/scripts/invlang/`.

Relevant files:

- `soc-agent/scripts/invlang/cli.py` - CLI surface and query class dispatch.
- `soc-agent/scripts/invlang/corpus.py` - loads `**/investigation.md`, parses invlang fences, builds companion objects.
- `soc-agent/scripts/invlang/queries_effectiveness.py` - lead effectiveness, topology/prologue-conditioned retrieval, lead discrimination.
- `soc-agent/scripts/invlang/queries_recall.py` - lead exemplars and authz calibration recall.
- `soc-agent/scripts/invlang/queries_cache.py` - loop-N lead distribution cache.
- `soc-agent/scripts/invlang/run.sh` - wrapper used by soc-agent prompts for venv/path setup.
- `soc-agent/scripts/handlers/_dense_parser.py` - parser shared by validator/corpus loader.

The query script already matches the advisory retrieval need in broad shape:

- Class 1: coarse case lookup.
- Class 5: lead sequence patterns for similar resolved cases.
- Class 6: hypothesis wildcard lookup and prior final weights.
- Class 8: lead effectiveness and discrimination.
- Class 13: lead exemplars for analyze-time recall.
- Class 14: authorization calibration recall.
- Class 15: loop lead distribution for exact signature/prologue/cache-key matching.

The original design also expected a lightweight natural-language wrapper that translates retrieval requests into primitive query calls, rather than making the main investigation agent hand-author every query.

## Current Alignment With Defender

Defender's dense-language skill uses the same core invlang tags:

- `:V` and `:E` for observed vertices and edges.
- `:H` for hypotheses.
- `:L` for findings/lead declarations.
- `:R` for analysis observations and attribute updates.
- `:T` for resolutions and final conclusions.

The soc-agent dense parser maps those same tags into the canonical companion structure, so the structure is broadly compatible.

A dry run against `defender/learning/runs` showed the package is usable but not cleanly wired yet:

- 6 defender `investigation.md` files were present.
- 3 loaded successfully into the corpus.
- Class 1, 5, 6, and 13 produced useful output from the loaded cases.
- Class 8 returned rows but could not compute useful effectiveness scores because of a schema-key mismatch.
- Class 14 returned no useful authz calibration because defender runs currently declare authz questions more often than they emit structured `:R authz` rows.
- Class 15 is implemented, but the CLI help notes that real current-prologue call sites should call the function directly rather than relying on a placeholder CLI invocation.

## Compatibility Work

Before wiring this into defender, fix the narrow compatibility issues that make retrieval brittle.

1. Dependency and invocation boundary

   Decide whether defender imports the soc-agent query package directly, invokes `soc-agent/scripts/invlang/run.sh`, or gets a small local wrapper. The dry run required the soc-agent venv and `PYTHONPATH=/workspace/soc-agent`.

   Preferred first implementation: add a small defender-side adapter that calls the existing package with an explicit corpus root and hides environment setup from prompts.

2. Corpus root selection

   The adapter must make the corpus explicit. Candidate roots:

   - `defender/learning/runs` for learning-loop cases.
   - A production run directory for real investigation memory.
   - A curated fixture corpus for evaluation.

   Do not silently search the whole repo. The corpus should be an explicit config/env var.

3. Parser hygiene for existing defender runs

   Some defender invlang rows are malformed for the current parser:

   - Unescaped `|` inside attribute values.
   - Older `:H` rows with an extra cell delimiter.
   - Missing or inconsistent created/run metadata.

   Decide whether to repair old runs, tolerate/skip them with loud telemetry, or add a migration script. For production wiring, retrieval should report parse counts and skipped files.

4. Lead schema alias

   The parser emits lead hypothesis links as `tests_hypotheses`, while `queries_effectiveness.py` reads `lead.get("tests")`. Add an alias in the parser output or update the query code to accept both. Without this, Class 8 cannot score defender leads correctly.

5. Signature and time metadata

   `corpus.py` currently recovers signature IDs from path patterns like `ruleNNN`, producing IDs such as `wazuh-rule-5710`. Defender run paths do not reliably follow that shape. Add a defender-compatible signature source, preferably from run metadata/frontmatter with a path fallback.

   Add or normalize `created_at` so recency filters in `queries_cache.py` can work predictably.

6. Authz recall data

   If Class 14 is part of the desired surface, defender must emit structured `:R authz` rows when resolving authorization contracts. Prose or generic `:R attr_updates` are not enough for the existing query.

## Proposed Wiring

Add advisory retrieval at two possible points, with PLAN/PREDICT first.

### PLAN/PREDICT Advisory Recall

After ORIENT has produced the current prologue, call a targeted retrieval helper before finalizing the lead plan.

Input:

- Current alert summary.
- Current invlang prologue, including vertices, edges, classifications, and signature/rule ID.
- Optional active hypotheses, if already declared.
- Retrieval intent, such as "suggest prior leads for this topology" or "find prior cases matching this hypothesis pattern".
- Top-K limit.

Output:

- Top matching cases or lead patterns.
- Scores/counts/support.
- Case IDs and source paths.
- Suggested leads or hypothesis names.
- Short caveat that this is advisory precedent, not current evidence.

The main defender agent then decides which real evidence-gathering leads to author. The retrieval call itself should not become a `:L findings` row.

### ANALYZE Advisory Recall

Optionally call recall during ANALYZE for classes 13 and 14:

- Class 13: exemplars for a lead pattern.
- Class 14: historical authz contract calibration.

This must follow the soc-agent analyzer rule: recall is advisory only and cannot upgrade evidence, confidence, or authorization. It can explain likely pitfalls or suggest drilling into current evidence.

## Subagent vs Main Agent

Start with a targeted retrieval helper/subagent rather than handing raw query-script control to the main agent.

Reasoning:

- The query package already has multiple classes with different filters and failure modes.
- A narrow helper can choose the right primitive calls and return a compact, normalized advisory block.
- The main agent should stay focused on current-case investigation and should not over-read prior dispositions as evidence.
- The existing query-script design already anticipated a lightweight wrapper over primitive classes.

The first implementation can be deterministic rather than model-based if that is simpler:

- Fixed recipes for common intents.
- No generated Polars unless the primitive classes fail and the task explicitly allows ad hoc queries.
- Always return the command/function used and structured results.

If using a Haiku/subagent wrapper, require the same contract: return the exact primitive calls made, the top-K results, skipped/empty result reasons, and the advisory caveat.

## Empirical Test Plan

Compare at least three variants:

1. Baseline defender with lessons only.
2. Defender with deterministic advisory retrieval injected after ORIENT.
3. Defender with targeted retrieval subagent injected after ORIENT.

Optional fourth variant:

4. ANALYZE-only recall for lead exemplars/authz calibration.

Use a small fixture set where past-case memory should plausibly help:

- Monitoring-vs-bruteforce SSH/login cases.
- Rule 5710-style invalid user patterns.
- Container/process execution cases.
- Cases with failed or misleading first leads.

Measure:

- Lead coverage: did retrieval suggest a missing high-value lead?
- Disposition correctness against held-out ground truth.
- Escalation quality: fewer false benigns and fewer unnecessary inconclusive reports.
- Time/cost/latency.
- Query misuse rate: wrong class, empty corpus, malformed filters, over-broad matches.
- Anchoring risk: did prior disposition cause current evidence to be overweighted?
- Parse health: loaded count, skipped count, skip reasons.

Run the same cases with final past-case dispositions visible and hidden if anchoring becomes a concern.

## Implementation Steps

1. Add a defender advisory retrieval adapter.

   Suggested shape:

   - `defender/scripts/advisory_invlang_retrieval.py`
   - Accepts current prologue/current run context and retrieval intent.
   - Sets the corpus root explicitly.
   - Calls the existing invlang query functions or wrapper.
   - Returns compact JSON suitable for prompt injection.
   - Includes parse telemetry and source case IDs.

2. Fix schema compatibility.

   - Accept both `tests` and `tests_hypotheses` in lead effectiveness queries, or emit both from the parser.
   - Add defender-compatible signature ID extraction.
   - Normalize `created_at` for defender runs.
   - Decide how to handle malformed older rows.

3. Add prompt/wiring integration.

   - Inject PLAN/PREDICT advisory recall after ORIENT and before lead selection.
   - Mark the block clearly as advisory memory.
   - Exclude retrieval calls from `lead_sequence.yaml` and actor-facing lead projection.
   - Add ANALYZE recall only after PLAN/PREDICT is stable.

4. Add telemetry.

   - Corpus root.
   - Files scanned.
   - Files loaded.
   - Files skipped and parse reasons.
   - Query classes invoked.
   - Top-K results returned.
   - Empty/miss reasons.

5. Add tests.

   - Unit test parser/query compatibility on defender-style invlang fixtures.
   - Unit test Class 8 scoring with `tests_hypotheses`.
   - Unit test adapter output shape for empty, partial, and successful corpus hits.
   - Integration test that advisory retrieval does not appear in `lead_sequence.yaml`.
   - Evaluation harness for baseline vs deterministic retrieval vs subagent retrieval.

## Acceptance Criteria

- Defender can run advisory invlang retrieval over an explicit corpus root without manual venv/PYTHONPATH setup in prompts.
- Retrieval returns top-K scored/count-based advisory results with case IDs and source paths.
- Parse telemetry is visible and includes skipped-file reasons.
- Class 8 lead effectiveness works on defender-style parsed leads.
- PLAN/PREDICT can consume advisory retrieval without recording it as a normal evidence lead.
- Actor/oracle learning-loop projection remains unchanged unless an explicit memory namespace is added.
- ANALYZE recall, if enabled, is labeled advisory and cannot be used as supporting evidence for current-case `:T resolutions`.
- Empirical comparison is run before making the retrieval path default-on.

## Open Questions

- Should final past-case dispositions be shown to the main agent, or hidden to reduce anchoring?
- Which corpus should be default for local defender development?
- Should malformed historical invlang be migrated, skipped, or loaded with best-effort warnings?
- Should the first helper be deterministic recipes, a Haiku/subagent wrapper, or both behind an experiment flag?
- What minimum support threshold is required before a prior lead distribution can influence PLAN/PREDICT?
- Should lessons run before retrieval, retrieval before lessons, or should retrieval only fill gaps when no lesson matches?
- Should advisory retrieval be persisted in `investigation.md` as a non-lead memory block for auditability?
