---
title: ANALYZE context redesign — grading units decomposition, prediction-anchored observations, focused manifest
status: todo
groups: analyze, prompt, schema, context-engineering
---

**Goal.** Restructure ANALYZE's input context so the unit of work is a *grading unit* (one prediction / refutation / contract / branch reading), not a free-form envelope over the whole loop. Merge the gather observations into the analysis frontier as prediction-anchored slices, decompose them into per-unit on-disk files the model Reads at grading time, scaffold the model's thinking with a per-unit template, and trim the available-context manifest to what ANALYZE actually uses.

The biggest lever is **merging gather into the frontier, keeping observations tied to predictions** — and pushing each prediction-observation pair to its own file so the agent has the freshest possible context at the moment it grades that unit.

## Why

ANALYZE today receives:

- `<alert-{salt}>` summary
- `<analysis_frontier>` (active hypotheses + predictions + prior outcomes + pointers)
- `<available_context>` (manifest of read-on-demand artifacts: alert.json, investigation.md, signature/lead/environment knowledge)
- `<current_gather>` (this loop's `gather.leads[]` minus raw payloads)
- `<prior_recall>` (cross-loop adjacency)
- `<raw_details>` (opt-in via `SOC_AGENT_ANALYZE_INCLUDE_RAW_DETAILS=1`)

Three structural problems:

1. **Predictions and observations live in separate blocks.** ANALYZE has to read PREDICT's predictions out of the frontier, then locate the matching evidence in `<current_gather>`, then mentally join them per hypothesis. The join is deterministic — `subject` / `target` / `comparison.dimension` / `anchor_kind` / `predicate` — and belongs in handler-side Python, not in the model's working memory.
2. **Settled resolutions are inferred from weights, not tagged.** Prior `++/--` grades are settled for their lead scope; the discipline says do not relitigate, but there is no structural cue. The model has to reconstruct settledness from active-hypothesis weights.
3. **Available-context is identical to PREDICT's manifest.** ANALYZE almost never reads `playbook.md` / `context.md` / `field-quirks.md` / `TAGS.md` / `leads_root` / `environment_root` — those are planner surfaces. Keeping them in the manifest steers the model toward unhelpful reads and burns cache_write per dispatch.

The pattern we want is "iterate grading units, Read each unit's slice, emit a graded row" — not "synthesize one envelope over a loop's worth of unstructured evidence." The current shape forces synthesis when grading is what's needed.

## Core Model

### Grading unit as the unit of work

A grading unit is one of:

- a `p*` prediction
- an `ap*` attribute prediction
- an `r*` refutation shape
- an `ac*` authorization contract
- an `lp*` Shape E branch reading

Each unit has a fixed source shape: a claim, an optional comparison (selector + dimension), a subject/target on the proposed edge or vertex, the hypothesis or lead branch it lives under, and after this loop, a status (`pending` / `settled` / `indeterminate`). Settled units carry a grade + grading-loop + lead.

Each unit also has a fixed **output family**. The output family is what prevents the authoring surface from mixing unrelated verdict types:

| output_family | unit kinds | allowed verdicts | handler projection |
|---|---|---|---|
| `hypothesis_grade` | `p*`, `ap*`, `r*` | `++`, `+`, `-`, `--`, `indeterminate` | current `:T resolutions` / `resolutions_by_lead` shape, keyed to the owning hypothesis and matched predicate id |
| `authorization_verdict` | `ac*` | `authorized`, `unauthorized`, `indeterminate` | current `:R authz` / `legitimacy_by_lead` shape, keyed to `h-*.ac*` |
| `consultation_result` | anchor consultations that do not close an `ac*` | `confirmed`, `refuted`, `partial`, `no-data` | current `:R consultations` / `trust_anchor_by_lead` shape |
| `impact_verdict` | impact predictions, if surfaced later | `within`, `exceeds`, `indeterminate` | current `:R impact` / `impact_by_lead` shape |
| `branch_reading` | `lp*` Shape E branch readings | `matched`, `not_matched`, `indeterminate` | branch/routing metadata for the next PREDICT step; only emitted once Shape E readings are persisted into the gather entry |

`indeterminate` on a `hypothesis_grade` unit is a model-authored no-grade result: it does **not** project to a `:T resolutions` row because current invlang weights have no indeterminate state. The handler records the rationale as an anomaly/data-wish/no-change note and leaves the predicate pending for the next loop.

### Prediction-anchored frontier

Replace `<current_gather>` and the prediction half of `<analysis_frontier>` with one `<grading_units>` dense block:

```
:G grading_units [unit_id|owner|predicate_id|unit_kind|output_family|claim|baseline_ref|observation_ref|status]
g1|h-001|p1|prediction|hypothesis_grade|"<claim>"|baselines/h-001.p1.md|observations/h-001.p1.md|pending
g2|h-001|ac1|authorization_contract|authorization_verdict|"<predicate>"|-|observations/h-001.ac1.md|pending
g3|h-002|r1|refutation|hypothesis_grade|"<refutation>"|baselines/h-002.r1.md|observations/h-002.r1.md|pending
g4|h-001|p1|prediction|hypothesis_grade|<settled-claim>|-|-|settled          # carried; skip
```

Inline cost in the prompt drops to one row per grading unit. The model does not see gather output inline — it Reads each unit's observation file when it grades that unit. Freshness comes from the Read landing right before the grade. The row is a routing/index surface only; the handler keeps the full `unit_id -> canonical source object` mapping in Python so output rows can be projected back into the existing ANALYZE envelope without guessing.

### Handler join source of truth

`_grading_units.py` builds units from the **full parsed current PREDICT companion state** plus the current loop's GATHER payload, not from the already-compact `<analysis_frontier>` prompt block.

That distinction is load-bearing. `format_analyze_frontier_block()` is a model-facing summary and is allowed to omit detail for cache cost. The join is not allowed to lose detail. It must read the canonical hypothesis objects from the parsed companion (`predictions`, `attribute_predictions`, `refutation_shape`, `authorization_contract`, `attached_to_vertex`, `proposed_edge`, story links, and any target/attribute fields), then join those objects to `ctx.outputs[Phase.GATHER]` and raw detail paths. Only after the join succeeds does the handler emit the compact `<grading_units>` rows and per-unit files.

Practical flow:

```
investigation.md current PREDICT fence + ctx.outputs[Phase.GATHER] + raw_details paths
  -> _grading_units.py full-state join
  -> unit index (handler-only) + observations/*.md + baselines/*.md
  -> compact :G grading_units rows in the prompt
  -> model :G unit_resolutions rows
  -> handler projection into AnalyzeEnvelope / invlang findings
```

### Per-unit files (handler-emitted)

Per-loop directory layout under the run:

```
runs/<run>/grading/loop-<N>/
  observations/h-001.p1.md      # gather slice bearing on p1
  baselines/h-001.p1.md         # baseline slice (deviation kinds only)
  observations/h-001.ac1.md     # anchor consult result for the contract
  observations/h-002.r1.md
  prior_grades/h-001.md         # carried settled grades on h-001
```

The handler does the join once, in Python, using:

- prediction `subject` / `target` and `comparison.dimension` to slice gather's per-lead `findings[]`
- contract `anchor_kind` / `predicate` to slice anchor consultations
- `lp*` `if` selector and `comparison` to slice Shape E branch results
- claim field references (matched against the alert + gather schemas) to pull raw-payload fields the structured digest dropped

This is the claim-driven raw-payload preload: the right raw fields ride with the unit that needs them, instead of being gated by `SOC_AGENT_ANALYZE_INCLUDE_RAW_DETAILS=1`.

### Per-unit grading template

Each `observations/*.md` is structured so the model fills a fixed bottom block:

```markdown
# Grading h-001.p1
claim: "<claim>"
kind: geometry
comparison.selector: <selector>
comparison.dimension: inter-event-gap-distribution

## Foreground (this loop)
<sliced rows / values from gather, copied verbatim from raw or digest>

## Baseline
<sliced rows / values; "structurally zero" when applicable>

## Settled grades on this hypothesis
- loop 1: + (lead: authentication-history) — <one-line carry>

## Grade this unit
output_family: hypothesis_grade
verdict: ++ | + | - | -- | indeterminate
citing: [<evidence-edge ids>]
rationale: <one sentence>
```

Authoring surface = the bottom block per unit. ANALYZE's stdout becomes a sequence of `:G` resolution rows (one per ungraded unit) plus the routing trailer:

```
:G unit_resolutions [unit_id|output_family|verdict|citing|rationale]
g1|hypothesis_grade|++|"e-001"|"foreground inter-event gap distribution within historical-self baseline"
g2|authorization_verdict|authorized|"e-002"|"anchor confirms registered principal initiated"
g3|hypothesis_grade|--|"e-001"|"refutation observable present"
```

The parser validates that every `unit_id` exists, `output_family` matches the handler-owned unit index, and `verdict` belongs to that family's allowed set. The handler then projects the typed unit result into the current `AnalyzeEnvelope` buckets (`resolutions_by_lead`, `legitimacy_by_lead`, `trust_anchor_by_lead`, `impact_by_lead`) and composes the prose `## ANALYZE (loop N)` section from those rows + the unit files. The model never authors prose; it grades typed units.

### Settled resolutions as a structural field

`frontier.settled_resolutions[]` carries `{unit_id, owner, predicate_id, output_family, verdict, grading_loop, lead}` for terminal unit outcomes. For `hypothesis_grade`, only decisive `++` / `--` outcomes are settled; partial `+` / `-` outcomes remain pending and are exposed through `prior_grades/` so the model can re-grade them against new evidence. Corresponding `:G` rows are pre-stamped `status=settled`; the model skips them. The "do not relitigate prior grades" discipline becomes a field, not a prose rule.

### Trimmed `<available_context>`

ANALYZE's manifest drops PREDICT-shaped pointers entirely:

```
<available_context>
  alert: runs/<run>/alert.json
    Read when a unit's claim references a field not in <alert-{salt}>.
  prior_predict: investigation.md lines A-B
    Read when a unit's prediction needs the original story sentence.
  grading_units: runs/<run>/grading/loop-<N>/
    Read each unit's observation file before grading it.
</available_context>
```

Three pointers, all decision-shaped. Removed: `playbook.md`, `context.md`, signature `field-quirks.md`, system `field-quirks.md`, `TAGS.md`, `leads_root`, `environment_root`. Those are planner surfaces; ANALYZE is the comparator.

### Read-instrumentation

Without empirical data on what ANALYZE actually reads, manifest trimming is a guess. Add per-dispatch `runs/<run>/analyze_reads.jsonl` capturing `{unit_in_focus, path, byte_range, time_to_next_token}` from the subagent's tool log. After a batch (≥50 runs), the data tells us which manifest entries earn their keep and which to cut further.

This is also the empirical answer to "how does ANALYZE think" — read sequences correlate with grading order. If the model consistently re-reads `prior_predict` mid-grade, that's a signal to inline more story context per unit; if it never reads `alert.json`, the schema summary is sufficient and the pointer can go.

## Stage Plan

### Stage 1 — handler-side join + per-unit file emission

1. **`scripts/handlers/analyze.py`** — extend `_assemble_prompt` to emit `<grading_units>` and write per-unit files under `runs/<run>/grading/loop-<N>/`. Keep the existing `<current_gather>` / `<analysis_frontier>` blocks for now so ANALYZE keeps working through the cutover.
2. **`scripts/handlers/_grading_units.py`** (new) — module owning the prediction↔observation join. It parses the full current PREDICT companion state from `investigation.md` and joins it to the loop's gather output; it does not consume the compact `<analysis_frontier>` block as input. One function per unit kind (`p*`, `ap*`, `r*`, `ac*`, `lp*`) returns a `GradingUnit` object containing the compact row fields, `output_family`, allowed verdicts, canonical source object, observation markdown, optional baseline markdown, and optional raw-payload slice.
3. **Tests** — `tests/test_grading_units_join.py` against fixtures: deviation-kind prediction with baseline, attribute prediction target/attribute carry, contract with anchor consult, Shape E `lp*` with selector, settled-grade carry. Each fixture verifies the file path layout, output family, allowed verdict set, handler projection target, and slice contents.
4. **Investigation manifest** — extend `format_run_manifest` (or fork it for analyze) so the manifest surfaces `grading_units: runs/<run>/grading/loop-<N>/` once the directory exists.

### Stage 2 — settled-resolution structural tagging

5. **`scripts/handlers/investigation_views.py`** — extend `format_analyze_frontier_block` to compute `settled_resolutions[]` from the accumulated companion (walk hypothesize/findings, project last decisive `++/--` per `(hypothesis_id, predicate_id)` for `hypothesis_grade`, and terminal contract verdicts per `(hypothesis_id, ac_id)` for `authorization_verdict`). Partial `+/-` grades are prior context, not settled rows.
6. **Per-unit emission** — settled units get `status=settled` and no observation file (or a `prior_grades/h-{id}.md` summary file referenced from the unit row). Model skips them.
7. **Independent of stage 1** — can land in either order.

### Stage 3 — read instrumentation

8. **`scripts/handlers/_subagent.py`** (or a sibling) — emit per-dispatch `analyze_reads.jsonl` from the subagent's tool log, keyed by the grading unit in focus when the Read fired.
9. **Batch run** — execute ≥50 runs across the existing fixture set and the playground. Aggregate to a read-frequency table per manifest entry.
10. **Decision** — trim the manifest based on observed read frequency. Targets for removal listed above; the data may surprise us.

### Stage 4 — authoring surface migration

11. **`agents/analyze.md`** — rewrite the output contract: stdout is `:G unit_resolutions` rows + routing trailer. The prompt must teach the family-specific verdict sets; `authorized` is only legal for `authorization_verdict`, and `++`/`--` are only legal for `hypothesis_grade`. Drop the prose `## ANALYZE (loop N)` envelope from the model's job; the handler composes it from `:G` rows + per-unit files.
12. **`scripts/handlers/_output_parser.py`** — accept the typed `:G unit_resolutions` shape, validate `(unit_id, output_family, verdict)` against the handler-owned unit index, and project rows into the existing `AnalyzeEnvelope` buckets. Emit a remediation note when the model emits prose envelopes or mismatched verdict families (one cutover loop, then reject).
13. **`scripts/handlers/_analyze_dense.py`** — handler-side composition of the persisted `## ANALYZE (loop N)` markdown section from typed `:G` rows + grading-unit observations.
14. **Trim manifest** — at this stage drop the listed PREDICT-shaped pointers; previous stages were strictly additive.
15. **Drop `<current_gather>`** — once `<grading_units>` carries the load-bearing slice, the inline structured-gather block is redundant. Keep the gather output on disk under `runs/<run>/`; it still feeds the join.

### Stage 5 — claim-driven raw-payload preload

16. **`_grading_units.py`** — walk each prediction's claim text against the alert + gather schemas; pull raw-payload fields the structured digest dropped into the unit's observation file.
17. **Drop `SOC_AGENT_ANALYZE_INCLUDE_RAW_DETAILS`** — the env-var blanket goes away once the targeted preload is in. Tests verify that the fields predictions actually reference are preloaded into their unit's file.

## Acceptance — outcome deltas, not process checks

Three measurable shifts:

1. **Prediction-observation join is deterministic.** Pick a fixture where today's ANALYZE prose narrates "comparing p1's claim against the gather of `authentication-history` we see X." After stage 1, the unit file `observations/h-001.p1.md` contains the slice X verbatim, with no model effort spent on locating it. Measurable by: presence of the slice in the unit file, and absence of "the relevant lead is …" prose in the model's output.
2. **Settled grades are not relitigated.** Pick a fixture with a multi-loop run where loop 1 graded `p1` `++`. After stage 2, loop 2's `:G grading_units` row for that predicate is `status=settled` and the model emits no resolution for it. Measurable by: zero `:G unit_resolutions` rows naming a settled unit_id.
3. **Manifest trim does not cause regressions.** After stage 3 + 4, the trimmed manifest is in production for ≥20 runs with no degradation in grading quality (judge metric, or eyeballed against the pre-trim runs on the same fixtures). Measurable by: judge-A/B parity on a held-out set, plus no Read attempts to removed paths in `analyze_reads.jsonl`.

Without all three, the redesign can show "the new shape is producible" but not "the new context investigates better."

## Open Design Questions

1. **Granularity of unit files.** One file per predicate is the proposal. Alternative: one file per hypothesis, with sections per predicate. Bias: per-predicate. Smaller files = fresher context per grade; the model Reads exactly what it grades. Worth measuring read-size distributions in stage 3 before locking.
2. **Composite predictions.** `p*` claims are split to one observable each by validator rule #26, so per-predicate granularity is well-defined. Composite contracts (`ac*` whose `predicate` references multiple anchors) may need decomposition; defer until a fixture forces the question.
3. **Cross-loop carry.** Settled-resolution carry is straightforward. What about `+`/`-` partial grades that are *not* yet settled? Bias: keep them as `pending` units with a `prior_grades/` reference; the model re-grades against the new loop's evidence. Same shape, different status.
4. **Frontier-only vs. file-only observation surface.** Should the unit row carry a one-line digest of the observation, or only a path? Bias: path-only. The row is for routing; the file is the surface to grade against. Inline digests would re-create the join-in-prompt problem at smaller scale.
5. **Backward compatibility during cutover.** Stages 1–3 are additive (new files + new structural fields, existing blocks intact). Stage 4 is the cut. Bias: hard cut, no migration shim — same discipline as `predict-gather-contract-realignment.md`. ANALYZE's output contract changes in one PR.
6. **Interaction with the PREDICT/GATHER realignment.** The realignment changes the gather output shape (`missing_lead_spec`, per-leg system selection, `query_source` taxonomy). The grading-unit join consumes whatever gather emits — no direct coupling — but the join code should land *after* the realignment so it joins against the final gather shape, not the current one. Cross-reference at landing time.

## What Not To Do In This Iteration

- Do not change ANALYZE's *routing* logic (continue / halt). The realignment is structural — what the model sees and emits — not what it decides.
- Do not pre-grade in Python. The handler does the join; the model still does the comparison. Pre-grading collapses ANALYZE into a deterministic pass and loses the comparator's judgment on edge cases (partial baselines, anomalous foreground shapes, indeterminate anchors).
- Do not bundle with the contract-realignment task. The realignment changes the inputs ANALYZE consumes (gather shape); this task changes how those inputs are surfaced. They share a fixture set but are otherwise orthogonal.
- Do not skip the read-instrumentation stage. Manifest trimming without data is a guess; the data-driven trim is the whole point.
