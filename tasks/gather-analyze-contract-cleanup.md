---
title: Findings model — agents emit envelopes, handlers author invlang
status: done
groups: gather, analyze, invlang, cost
---

**Landed (2026-04-24).** All scope items complete.

- Invlang v2.12 schema rename `gather:` → `findings:` across validator, walkers, corpus, schema.md, handlers (screen/report), skill prompts, handbook, docs, test fixtures.
- Envelope parsers in `scripts/handlers/_output_parser.py`: `parse_gather_envelope` + `parse_analyze_envelope` + dataclasses (`GatherEnvelope`, `AnalyzeEnvelope`), following `parse_predict_output`'s three-bucket pattern.
- Gather handler (`scripts/handlers/gather.py`) rewritten around the envelope: `_parse_envelope_response`, `_reconstruct_*_from_checkpoint` return envelopes, `_dispatch_single` detects `status: error` + recoverable `escalate_trigger` for composite fallback, `_write_raw_details` writes per-lead raw payloads to `runs/<run-id>/raw_details/loop-<N>/<lead-id>.yaml`, payload carries backwards-compat fields (`mode`, `status`, `lead_name`, `characterization`, `cross_lead_notes`) plus new `leads` + `raw_details_paths` for analyze consumption.
- Analyze handler (`scripts/handlers/analyze.py`) rewritten: preloads `<raw_details>` block from run-dir files alongside `<alert>` + `<investigation>`, parses envelope via `parse_analyze_envelope`, renders a prose `## ANALYZE (loop N)` section from envelope resolutions + anomalies + data_wishes + routing. Routing back-fill for `unresolved_prescribed_set` preserved.
- Subagent prompts rewritten: gather.md, gather-composite.md, analyze.md all emit the unified envelope (`gather:` / `analyze:` top-level) with explicit forbiddance of analyze-authored fields in gather and handler-composed findings block in analyze.
- CLAUDE.md + docs/investigation-language.md bumped to v2.12 + 33 rules.

Full suite: **1292 passed, 26 deselected**.

## Handler-side invlang synthesis (landed)

Analyze handler (`scripts/handlers/analyze.py:_synthesize_findings_block`) now composes the complete `findings[]` invlang YAML block at the end of each ANALYZE cycle. Design:

- **Single-writer model (no merge).** ANALYZE writes the full per-lead entry once, combining gather's envelope (stashed in `ctx.outputs[Phase.GATHER]["leads"]`) with its own interpretation envelope. Avoids the same-id merge extension to `_merge_blocks` that the original task proposed.
- **Target-vertex derivation.** `_first_prologue_vertex_id` reads the companion's prologue and picks `v-001` as the default target for all leads this loop. Matches the non-SCREEN reality that leads investigate the alert's subject vertex.
- **Field translation.** Analyze envelope shapes (`trust_anchor_result`, `legitimacy_resolutions`, `impact_resolutions`, `resolutions`) get translated onto their schema-canonical locations:
  - `trust_anchor_result` → `outcome.anchor_consultations[]`
  - `legitimacy_resolutions` → `outcome.attribute_updates[].updates.authorization_resolutions[]` (edge-targeted)
  - `impact_resolutions` → `outcome.impact_resolutions[]`
  - `resolutions` (hypothesis grades) → top-level lead `resolutions[]`
- **Silent skip on SCREEN-matched path.** When `ctx.outputs[Phase.GATHER]` is absent (SCREEN match short-circuit, forced-exhaustion), synthesis returns empty string and the handler falls back to prose-only append.

Two new tests (`TestFindingsSynthesis` in `tests/test_handlers_analyze.py`) verify both paths: synthesis-with-gather and silent-skip-without-gather. Final suite: **1294 passed, 26 deselected**.


**Blocker.** The current `gather[]` block mashes GATHER's work (observations, attribute_updates, raw query results) with ANALYZE's work (resolutions with hypothesis grades, trust_anchor_result with authority verdicts, legitimacy_resolutions, impact_resolutions). Three problems compound:

1. **Name vs content mismatch.** `gather:` names an act; the block holds state that multiple phases contribute to. Every phase pretends the act-name also means the state-name.

2. **Cognitive conflation across agents.** Gather's job is "go look"; analyze's is "decide what it means." Today they share an output slot, and both subagents have to know invlang well enough to emit schema-valid YAML.

3. **Raw evidence bloats the companion.** Gather surfaces raw SIEM responses and anchor record excerpts inline. These persist in investigation.md forever even though they are consumed by analyze once and never referenced again. Loop-N wall-time amplification (testrun meta-finding #22) is partly driven by this accumulation.

## Reframe

Rename the block from `gather:` to `findings:` — the block represents the **state of prediction-vs-reality comparison**, not the act of gathering. Multiple phases contribute to that state; each owns a disjoint field set.

And move invlang authoring from subagents to handlers. Subagents emit **structured envelopes** (plain YAML with a narrow, phase-specific shape). Handlers translate envelopes into invlang merges on the companion. Consequences:

- Subagent prompts get markedly simpler — no "emit YAML that happens to be invlang-valid."
- Agents can be retargeted (Haiku vs Sonnet, prompt rewrites) without risking validator regressions.
- Authorship is answered by which handler ran, not by field-level provenance inside a single block.
- `raw_details` stop being an agent concern; handlers route them straight to disk.

## Contracts

### Gather envelope (agent → handler)

Plain YAML, not invlang. Single-lead or multi-lead (composite dispatches N>1; same shape):

```yaml
leads:
  - id: l-00N
    name: <lead-slug>
    status: ok | data_missing | error | dropped_attempt
    query: {system, template, query, time_window, substitutions}
    observations:
      vertices: []
      edges: []
    attribute_updates: [...]
    consultations: [...]          # {anchor_id, anchor_kind, anchor_query, as_of, effective_window}
                                  # NO verdict, NO result — those are analyze's
    raw:
      siem_response: |
        <verbatim query result>
      consultations:
        - anchor_id: approved-monitoring-sources
          raw_response: |
            <verbatim rows>
```

Gather emits *no* resolutions, trust_anchor_result, legitimacy_resolutions, or impact_resolutions. The prompt forbids them explicitly.

### Analyze envelope (agent → handler)

```yaml
resolutions:
  - lead_ref: l-00N
    entries: [...]                 # hypothesis grades with matched_prediction_ids
trust_anchor_result:
  - lead_ref: l-00N
    asks: [...]
    verdict: ...
    reasoning: ...
legitimacy_resolutions:
  - lead_ref: l-00N
    entries: [...]                 # contract fulfillments
impact_resolutions:
  - lead_ref: l-00N
    entries: [...]                 # predicate grading
routing:
  decision: halt | continue
  termination_category: ...        # if halt
  disposition_recommendation: ...  # if halt
```

Analyze refers to leads by `lead_ref: l-00N`, doesn't re-emit gather's fields.

### Handler-synthesized invlang companion block

```yaml
findings:
  loop: <int>
  leads:
    - id: l-00N
      loop: <int>
      name: <lead-slug>
      status: ...
      query_details: {...}
      outcome:
        observations: {...}              # gather-handler
        attribute_updates: [...]         # gather-handler
        consultations: [...]             # gather-handler
        resolutions: [...]               # analyze-handler
        trust_anchor_result: {...}       # analyze-handler
        legitimacy_resolutions: [...]    # analyze-handler
        impact_resolutions: [...]        # analyze-handler
      predictions: [...]                 # gather-handler, pass-through from predict
      new_hypotheses: []                 # handler, if any
```

Gather-handler writes `findings[].outcome.<gather-fields>` on the gather phase; analyze-handler writes `findings[].outcome.<analyze-fields>` on the analyze phase, keyed by lead id. Invlang's `_merge_blocks` already handles same-id merge — no schema change for that. The top-level block renames `gather:` → `findings:`, which **is** a schema change (invlang v2.12).

### Raw details on disk

Gather-handler writes raw payloads to `runs/<run-id>/raw_details/loop-<N>/<lead-id>.yaml`. Analyze-handler preloads them into `<raw_details>` alongside `<investigation>` + `<alert>` for the analyze subagent. Never reaches the companion; queryable post-hoc from the run dir.

## Why bundle the envelope + handler-authoring moves

The half-step (rename to `findings:` and split the output contract, but agents still author invlang) keeps all the cognitive load on the subagent prompts. The rename pays off only when agents emit something strictly simpler than invlang. Splitting the rollout also means two rounds of subagent-prompt rewrites across gather, gather-composite, and analyze — churn on the same files. Bundle.

## Invlang v2.12 schema evolution

- Top-level block rename: `gather:` → `findings:`.
- Update `_merge_blocks` registry under the new name.
- Rule updates: anywhere `gather[]` is referenced by rule text, update to `findings[]`. No semantic rule changes — the same merge semantics and closure rules apply (rules #21, #26, #31 still fire at CONCLUDE; rule #25 grading discipline unchanged).
- Single-shot migration. No dual-name tolerance window — MVP, no production companions to migrate.

## Scope

1. **Invlang v2.12 schema** — rename `gather:` → `findings:` in `soc-agent/knowledge/invlang/schema.md`; update rule texts referencing `gather[]`; update `soc-agent/hooks/scripts/invlang_validate.py` and `invlang_walkers.py`; bump corpus schema version.

2. **Envelope parser** (`soc-agent/scripts/handlers/_output_parser.py`) — add `parse_gather_envelope(stdout) → GatherEnvelope(leads[], raw_by_lead, telemetry)` and `parse_analyze_envelope(stdout) → AnalyzeEnvelope(resolutions, trust_anchor_result, legitimacy_resolutions, impact_resolutions, routing, telemetry)`. Both are plain YAML, not invlang-shaped.

3. **Gather handler** (`scripts/handlers/gather.py`)
   - Parse envelope; synthesize `findings:` invlang block from envelope fields; append via existing invlang merge.
   - Write raw payloads to `runs/<run-id>/raw_details/loop-<N>/<lead-id>.yaml`.
   - Stash raw-details path list in `ctx.outputs[Phase.GATHER]` for analyze preload.
   - Single-gather and composite converge on the same envelope shape (composite just has N>1 leads).

4. **Analyze handler** (`scripts/handlers/analyze.py`)
   - Preload injects `<raw_details>` block from run-dir files alongside `<investigation>` + `<alert>`.
   - Parse analyze envelope; synthesize per-lead invlang fragments under `findings[].outcome.*`; merge via existing invlang same-id merge.
   - Routing trailer consumed as before.

5. **Agent prompts**
   - `agents/gather.md` — emit the gather envelope (plain YAML, documented shape). Drop all invlang vocabulary from the prompt. Explicitly forbid authoring resolutions / verdicts. Keep Level 1 finish-discipline + status discriminator.
   - `agents/gather-composite.md` — parallel changes; multi-lead envelope, same shape.
   - `agents/analyze.md` — read `<raw_details>` from preload. Emit the analyze envelope. Drop invlang-shape knowledge from the prompt.

6. **Tests**
   - Parser: envelope shapes (single-lead, multi-lead, ad-hoc, status variants; analyze envelope with each optional field subset).
   - Gather handler: envelope → `findings[]` invlang; raw payloads written to run dir; path list populated for analyze.
   - Analyze handler: raw_details preload from disk; envelope → `findings[].outcome.<analyze-fields>` merge onto existing entries by lead_ref.
   - Invlang validator: v2.12 rename; `findings[]` merge across phases; no regressions on closure rules.

7. **Live eval gate**
   - One 5710 bait mid-burst full-loop run. Verify companion stays leaner across loops than the current baseline; verify raw_details is present on disk and analyze grades correctly off it; verify gather envelope contains no analyze-authored fields; verify validator accepts the v2.12 companion.

## Out of scope (follow-ups)

- Hypothesis shelve-and-compact on `--`-graded hypotheses to bound loop-N hypothesis-YAML growth — orthogonal, attacks a different dimension of loop-N amplification.
- Per-field provenance on `findings[].outcome.*` (e.g., `<field>_author: gather|analyze`) — not needed while handler-authoring is the single source of truth for authorship.
- A validator rule "gather-phase handlers may only write gather-owned fields" — enforceable via unit test on the handler rather than a companion-schema rule.

## Why this, now

- Wall-time: gather's preload shrinks (no investigation.md), analyze's preload adds bounded raw_details (not cumulative). Subagent-prompt token counts drop because invlang vocabulary leaves the prompts.
- Cognitive clarity: gather is "mechanical executor emitting observation YAML" (Haiku-friendly); analyze is "interpreter emitting verdict YAML"; handlers are the sole invlang authors.
- Universal phase-output pattern: every subagent's output = `{state_envelope, ephemeral_for_next, telemetry}` with a uniform parser shape in `_output_parser.py` and a uniform handler→invlang synthesis step.

## Coordination

Single atomic change — invlang v2.12 schema + all three handlers + all three subagent prompts must land together because the envelope contract, handler synthesis, and block rename are coupled.
