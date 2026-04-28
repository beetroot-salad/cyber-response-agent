# Handlers Refactor Map

**Scope:** `soc-agent/scripts/handlers/` (~9.5K lines, 14 files) + `scripts/orchestrate.py` + `scripts/run_orchestrator.py`.

**Purpose of this document:** orientation artifact for the multi-PR refactor of the orchestrator. The refactor optimizes for *future edit ease* and *immediate code comprehension*, not for runtime behavior change. Work proceeds one vertical per PR.

**How to use this doc:** read §1–2 to learn the surface; consult §3–5 when proposing a new vertical; follow §6 ordering unless you have a reason not to; update §7 as questions get answered.

---

## 1. One-line role per file

- **`scripts/orchestrate.py`** — pure state machine: validates phase transitions, persists `state.json`, enforces `MAX_LOOPS`, exports run env, calls registered phase handlers in a loop until REPORT.
- **`scripts/run_orchestrator.py`** — CLI entrypoint: parses argv, builds `run_dir` + `meta.json` + sanitised `alert.json`, constructs `Context`, calls `orchestrate.run` with `default_handlers()`.
- **`handlers/__init__.py`** — exports `default_handlers()` mapping each `Phase` to its module's `handle` function.
- **`handlers/_subagent.py`** — shared `claude -p` dispatcher: loads `agents/{name}.md` frontmatter, injects SIEM adapter for env-gated agents, mints session id, writes session→run mapping, persists per-call audit log + raw stdout under run dir.
- **`handlers/_context_loader.py`** — deterministic preloaders + XML-tagged formatters for alert / investigation.md / playbook / archetypes / leads (with per-mode trimming of `investigation.md`).
- **`handlers/_output_parser.py`** — pure YAML envelope parsers for `predict:`, `gather:`, `analyze:` outputs into dataclasses with split invlang-delta / routing / telemetry buckets.
- **`handlers/_markdown.py`** — small markdown-it wrapper: parse, iterate ` ```yaml ` fences, walk tables under headings.
- **`handlers/_raw_manifest.py`** — manages the hooks-written tool-output manifest: cursor-based consume, session-partitioned consume, lead correlation, attach paths to envelope.
- **`handlers/contextualize.py`** — CONTEXTUALIZE: parses playbook metadata, runs preflight, dispatches `ticket-context` + `contextualize-prologue` in parallel, composes section, validates + writes, routes to SCREEN or PREDICT.
- **`handlers/screen.py`** — SCREEN: loads playbook Screen table, dispatches single `screen` subagent with prologue inlined, runs structural verification on match, routes match→REPORT or fallthrough→PREDICT.
- **`handlers/predict.py`** — PREDICT: assembles prompt with priors + env-memory + alert + trimmed investigation + playbook + lead catalog; tries loop-1 fast-path cache; dispatches `predict`; parses envelope; retries with remediation notes on validator errors; checkpoint recovery.
- **`handlers/predict_fastpath.py`** — pure cache-key + lookup module: builds key from prologue + key-attribute family, scores leads against historic corpus, returns `FastpathHit` or miss.
- **`handlers/gather.py`** — GATHER: derives scope, picks single/composite/parallel-singleton dispatch, handles checkpoint recovery + escalate-to-composite fallback, runs scope + baseline contract checks, writes raw_details files, composes prose section, routes.
- **`handlers/analyze.py`** — ANALYZE: assembles prompt, dispatches subagent, parses envelope, synthesizes per-lead invlang `findings:` block (verdicts → schema shapes), validates + appends.
- **`handlers/report.py`** — REPORT: 4-tier composer (SCREEN-mechanical-grounded / SCREEN-mechanical-partial / ANALYZE-mechanical-with-narrative / full-subagent fallback); resolves archetype, derives termination, applies benign-action shortcircuit, writes `report.md` + Tier-1 validate + rollback, spawns post-mortem leads job.
- **`handlers/env_memory.py`** — environment-memory retrieval: parses `## Atoms` YAML blocks under `knowledge/environment/`, derives mechanic anchors from hypothesis triples, scores by anchor-overlap, formats prompt block.

---

## 2. Concerns inside each large file

### `gather.py` (1709)
1. Dispatch routing (single / composite / parallel-singleton selection) — `handle()` 1593–1685, eligibility flags 1602–1615.
2. Scope derivation (vendor, window, entity_bindings, reporting_agent from alert + lead frontmatter) — 151–308.
3. Prompt assembly (single + composite shapes) — 312–460.
4. Envelope parsing wrappers + slim-schema hydration (`query_details`, `health_probe`) — 464–595.
5. Checkpoint recovery + escalate-to-composite fallback — 599–873.
6. Parallel-singleton orchestration (futures, session ids, per-session manifest correlation, fallback subset re-dispatch, lead-id renumbering) — 877–1035.
7. Post-execution contract enforcement (composite-scope, baseline-required, contract-violation fold-in) — 1043–1196.
8. Raw-details disk persistence — 1199–1263.
9. Payload synthesis + markdown composition + investigation.md append + invlang `findings:` lead-pick block — 1267–1483.
10. PREDICT-payload re-validation (`_PredictPayload`) — 1491–1590.

### `report.py` (1798)
1. Routing-source selection + archetype-match dispatch + result annotation — 123–355.
2. SCREEN-match mechanical composer (Level 1 vs Level 2, anchor leg vs precedent leg, rollback on Tier-1 failure) — 363–543.
3. Trust-anchor / authorization-resolution extraction from invlang findings (two surfaces) — 560–657.
4. Findings extraction from investigation.md (YAML-fence preference, prose-form GATHER fallback) — 884–984.
5. Trace + Hypothesis-Outcomes + Key-Evidence markdown synthesis — 1017–1235.
6. Narrative subagent dispatch + tag parsing — 1242–1323.
7. ANALYZE-routed mechanical composer (status decision via authz rule #21, narrative dispatch, report.md assembly, Tier-1 + rollback) — 1326–1614.
8. Benign-action shortcircuit (shell-wrapper normalisation + match against playbook `## Benign action classes`) — 1617–1739.
9. Termination-category derivation + rationale composer + summary truncator — 1063–1175, 1742–1798.
10. Post-mortem detached spawn (in `handle()`) — 272–287.

### `predict.py` (1045)
1. Subagent invocation wrapper + loop-n compute — 124–150.
2. Prompt assembly stitching priors + env-memory + alert + investigation + signature + lead catalog — 153–199.
3. Past-investigation priors retrieval (loop-1 prologue-keyed vs loop-N frontier-keyed; tier fallback) — 203–540.
4. Prologue + last-hypothesize fence walker — 432–453.
5. Markdown formatter for priors block (strong-prior recommendation gate vs sparse fallback) — 322–540.
6. Validator-retry loop + remediation-notes plumbing — 568–771, 977–1013.
7. Empty-stdout checkpoint recovery synthesis — 727–771.
8. Loop-1 fast-path: discriminating-classification gate, cache-key build, corpus lookup, fast-path marker write, JSONL telemetry — 800–974.
9. Final routing payload assembly (selected_lead, composite_secondary, lead_hints, scope_override, branch_plan_predictions) — 1023–1045.

### `_output_parser.py` (852)
1. Predict envelope: extraction, header, hypotheses, branch_plan, routing, scope_override, lead_hints, shape-consistency matrix — 79–400.
2. Gather envelope: extraction, lead-status enum, raw-payload split, cross_lead_notes — 403–591.
3. Analyze envelope: extraction, per-lead bucket grouping, routing-trailer halt-vs-continue validation, anomalies/data_wishes — 594–852.
4. Three duplicate `_extract_*_envelope_doc` functions — 84–121, 452–484, 634–662.
5. Three independent error classes (`PredictOutputError`, `GatherOutputError`, `AnalyzeOutputError`) — 66, 448, 630.

### `_context_loader.py` (678)
1. Run-dir loaders (alert, investigation.md, salt) — 34–64.
2. Knowledge-tree loaders (archetype shapes, signature texts, lead catalog) — 72–194.
3. XML-tag prompt formatters — 201–678.
4. Investigation.md section parser + per-mode trimmers (predict / analyze / report-narrative / gather-section / yaml-only / analyze-grade summary) — 215–486.
5. Playbook archetype-section stripper — 517–533.
6. Two near-duplicate frontmatter regexes (`_FRONTMATTER_RE` redefined + lead summary parser avoiding yaml import) — 587, 596–608.

### `analyze.py` (731)
1. Prompt assembly + raw-details inlining toggle — 115–183.
2. Routing payload projection (halt vs continue back-compat) + `unresolved_prescribed_set` backfill from gather — 191–254.
3. Prose `## ANALYZE` section composition (Assessment, Authority verdicts, Self-report) — 261–331.
4. Invlang findings synthesis: name→id translation, default supporting_edges, trust-anchor / legitimacy / impact verdict mapping onto schema — 335–642.
5. Investigation.md validation + append helper — 650–673.
6. Two prologue-walking regexes — duplicates patterns in `gather.py` and `predict.py`.

---

## 3. Cross-file duplication / shared seams

- **Investigation.md append + validate:** four near-identical implementations — `contextualize.py:445–473`, `screen.py:300–318`, `analyze.py:650–673`, `gather.py:1369–1396`. Each lazy-imports `validate_companion`, reads current, concats with separator, validates, writes. `predict.py:589–593` and `report.py:768–772` skip the validator and just append. **Most obvious extraction.**
- **Output parsing of subagent stdout:** `_output_parser.py` covers predict/gather/analyze with three duplicated envelope-doc extractors. `contextualize.py`, `screen.py`, `report.py` bypass it entirely and call `_subagent.extract_terminal_yaml` directly — there is no `parse_screen_output` / `parse_report_output` / `parse_ticket_context_output`.
- **Subagent invocation boilerplate:** `_subagent.invoke_subagent` is the shared dispatcher and is well-used. But every handler defines a thin module-level `_invoke_*` wrapper purely so tests can monkeypatch (`screen.py:67–73`, `predict.py:124–130`, `analyze.py:101–107`, `gather.py:124–143`, `contextualize.py:67–74`, `report.py:99–117`). **Six near-identical 5-line shims that the test suite depends on** — see §7 test stub topography below.
- **Context-loading bypass:** `contextualize.py` reads playbook.md directly via its own `parse_markdown` + `_SECTION_RE` walker (123–201). `screen.py:81–107` does the same for the Screen table. `report.py:884–984` re-walks investigation.md fences instead of using `_parse_investigation_sections`. The loader is bypassed wherever a handler needs structured fields, not just text blocks.
- **Investigation.md fence walking:** four independent regexes match the same ` ```yaml ... ``` ` shape (gather, analyze, predict, env_memory). `_markdown.iter_yaml_fences` exists but only contextualize/screen/report use it.
- **Run-dir / session resolution:** `_subagent._resolve_run_context` (135–146) reads env vars exported by `orchestrate.run`. Same env vars also read by `hooks/scripts/run_context.py`. Hidden cross-process contract worth documenting.
- **Loop-N computation:** `predict.py:_compute_loop_n` (138–150) and `analyze.py:_compute_loop_n` (115–122) — see §7, **not** a bug but the asymmetry must survive consolidation.
- **Frontmatter parsing:** `contextualize.py` uses `frontmatter.loads` (114), `gather.py` uses `frontmatter.loads` (273, 1092), `report.py` uses `parse_yaml_frontmatter` from hooks (553). Three different paths for the same job.
- **`sys.path` mutation to reach hooks/:** every handler that calls `validate_companion` mutates `sys.path` independently — six separate sites.

---

## 4. Dead or near-dead code

- **`contextualize.py:481–489`** — `_route` accepts `dedup_id` but downstream is unused; module docstring says the dedup fast-path is retired.
- **`predict.py:555–560`** — comment block listing removed helpers — leftover from envelope-unification.
- **`_output_parser.py:80`** — `_LEGACY_SHAPE_MAP = {"D": "E", "I": "A"}` — explicitly tagged "tolerance for stray subagent emission". Dead the moment subagents stop emitting D/I.
- **`predict_fastpath.py:90–94`** — `frontier_signature` slot with `TODO(loop-N)`; lookup returns `frontier_not_supported` miss when set. Loop-N is never wired in production.
- **`gather.py:1607–1615`** — `parallel_eligible` gate. **Per direction this should become production default; see §7.** Until flipped, the entire `_dispatch_parallel_singletons` path is dormant outside opt-in.
- **`analyze.py:84–93`** — `INCLUDE_RAW_DETAILS` env var, default off; `_load_raw_details` (125) only runs when set.
- **`report.py:922–944` / `1238–1267`** — lazy-init module globals for compiled regexes; defensive leftover, simplifiable.

---

## 5. Dependency surprises

- `report.py:283` lazily imports `scripts.postmortem.leads.run` — postmortem imports `scripts.handlers.gather._derive_vendor`, so a top-level import would cycle.
- `report.py:1707` lazy-imports `scripts.handlers.contextualize.load_playbook_metadata`. Same in `predict.py:412, 897`.
- `predict.py:218` lazy-imports `scripts.handlers.env_memory` from inside `_safe_env_memory_section` — handler→handler import.
- Every handler that calls validator mutates `sys.path` to import `hooks/scripts/invlang_validate` or `hooks/scripts/frontmatter`.
- `_subagent.py:34–41` mutates `sys.path` to import `hooks.scripts.run_context`.
- `predict.py:268–272, 458–462, 895` — multiple lazy imports of `invlang.*` (the package at `/workspace/soc-agent/invlang/`, not under `scripts/`).
- `_subagent.py:50–53` — `ENV_GATED_SUBAGENTS` mirrors `hooks/scripts/inject_env_context.py` (per comment); two-place definition, no shared source.
- `gather.py` ↔ `_raw_manifest` ↔ `hooks/scripts/tag_tool_results.py` is a three-actor implicit contract.

---

## 6. Vertical ordering recommendation

Churn (last 6mo, commits): gather 12, analyze 11, subagent 8, predict 8, context_loader 7, contextualize 7, screen 6, run_orchestrator 5, report 5, orchestrate 5, output_parser 4, raw_manifest 2, env_memory 1, markdown 1, predict_fastpath 1.

1. **`_subagent.py`** — small (397), heavy churn (8), every handler depends on it, no upstream deps. Clarify env-context coupling, factor the per-handler `_invoke_*` shims into a single test-friendly seam. Done first because every other vertical's tests stub through this.
2. **Investigation.md write/append seam** — pure mechanical refactor; six call sites collapse to one. Unblocks cleaner ANALYZE / GATHER work.
3. **`_output_parser.py`** — three near-identical envelope extractors. Low churn, but all of predict/gather/analyze read from it. Collapsing first means three handler verticals can be read against one extraction story.
4. **`_context_loader.py`** — high cohesion, moderate churn (7). Investigation.md per-mode trimmers (215–486) are a coherent sub-module that could split into `investigation_views.py`.
5. **`contextualize.py`** — small (533), self-contained except for playbook-metadata loader (cross-vertical seam). Extract metadata loader to `_context_loader.py` or new `_playbook.py`. After that, contextualize is just dispatch + compose.
6. **`screen.py`** — already small (402) and isolated. Touch only after contextualize has surrendered playbook-metadata loading; structural verifier becomes a clean ~200-line module.
7. **`predict.py`** — large (1045), high churn. Two big sub-concerns (priors + fast-path) are already partially extracted; priors block (203–540, ~340 lines) is the next obvious extraction (`predict_priors.py`). Retry/checkpoint plumbing is a separate concern.
8. **`gather.py`** — largest (1709), highest churn. Five clean sub-modules hiding inside: scope derivation, prompt assembly, dispatch (3 modes + recovery + fallback), contract checks, raw-details persistence. **Seam not obvious** between dispatch and contract checks — the parallel-singletons path mutates envelopes mid-flight (942–1035) interleaving manifest enrichment, fallback re-dispatch, and lead renumbering. Map this further before extraction.
9. **`analyze.py`** — `_synthesize_findings_block` (472–642) is the most complex piece; verdict-mapping logic for trust_anchor / legitimacy / impact is opaque (defaults, name→id translation, supporting_edges defaulting). **Seam not obvious** — these mappings encode invlang-schema conventions that aren't documented anywhere else. Consider preserving as one module but separating the prompt+dispatch layer (~150 lines) from the synthesis layer.
10. **`report.py`** — large (1798), low churn (5) — surprisingly stable for its size. Mechanical composers (SCREEN-mechanical and ANALYZE-mechanical) are two mostly-parallel ~300-line stories that could split. Benign-action shortcircuit is independent. Termination-category derivation is independent. Narrative-subagent path is independent. Four clean extractions.
11. **`env_memory.py`** — ~1 commit / 6mo, called only from predict via try-except wrapper. Lowest priority unless touching predict.

---

## 7. Open questions — resolved

### 7a. `SOC_AGENT_PARALLEL_GATHER` — should be production default

**Decision (2026-04-28):** flip the gate to opt-out, not opt-in. The parallel-singleton dispatch path (`gather.py:877–1035`) is production-grade and should be on by default.

**Implication for the refactor:** treat `_dispatch_parallel_singletons` as a hot path. Any gather refactor must preserve session-id correlation behavior. Tests in `test_handlers_gather.py` set `SOC_AGENT_PARALLEL_GATHER=1` explicitly (eight call sites at 499, 558, 587, 621, 663, 732, 773); after the flip those `setenv` calls become no-ops and one test (line 535's `delenv` for negative case) needs inversion to assert opt-out. Implementation goes in a follow-up PR distinct from this map.

### 7b. `_compute_loop_n` divergence — not a bug, asymmetric by design

Predict (`predict.py:138–150`):
```python
prior = sum(1 for p in ctx.history if p == Phase.PREDICT.value)
if ctx.current_phase == Phase.PREDICT and prior > 0:
    prior -= 1
return prior + 1
```

Analyze (`analyze.py:115–122`):
```python
return sum(1 for p in ctx.history if p == Phase.PREDICT.value) or 1
```

**Why both are correct:** `orchestrate.run` appends the *current* phase to `ctx.history` *before* calling the handler. So when PREDICT is running, history already contains the about-to-be-emitted PREDICT entry — predict subtracts 1 to recover the "prior PREDICTs" count, then adds 1 for the loop it's about to stamp. When ANALYZE is running, the current entry is ANALYZE (not PREDICT); the count of PREDICT entries already equals the current loop number. Each handler computes "current loop n" correctly given its position in the cycle.

**What is suspect:** the `or 1` fallback in analyze is dead code — ANALYZE only runs after at least one PREDICT (state machine guarantees), so history must contain ≥1 PREDICT entry. Defensive but unreachable.

**Refactor implication:** consolidating into a single `Context.current_loop_n` property is safe — but the property must branch on `current_phase`, not assume "count of PREDICTs". Otherwise predict reports `loop_n` one higher than reality.

### 7c. `validate_companion` contract

Defined at `hooks/scripts/invlang_validate.py:399`. Signature: `validate_companion(proposed_text: str, current_text: str | None) -> list[str]`. Returns list of error strings (empty = pass). Performs:

1. YAML block parsing of `proposed_text`.
2. If `current_text` is provided: append-only check + prediction-lifecycle diff (rules require both texts).
3. ~30 schema-rule checks on merged blocks: lead required fields, ID formats, ID references, edge authority (rule #18), refutation IDs, screen-result scope, lead predictions, authorization rules #19–#22, impact rules #29–#31, hypothesis fork distinctness (#23), persistence, prediction lifecycle, etc.

**Refactor implication for the append-validate seam (vertical #2):** the helper must accept both the full proposed text *after* concatenation AND the current on-disk text — passing only the new section breaks the append-only check and the prediction-lifecycle diff. Signature should be:
```python
append_and_validate(run_dir: Path, new_section: str) -> None  # raises on validator errors
```
which internally reads `investigation.md`, concatenates with separator, calls `validate_companion(proposed, current)`, and writes if errors is empty. The two handlers that currently bypass validation (`predict.py:589–593`, `report.py:768–772`) likely do so because validator runs as a PreToolUse hook on the actual write — confirm before extracting whether to fold them into the helper or document the bypass.

### 7d. Test stub topography

Confirmed: every test that exercises a handler stubs through the per-handler `_invoke_*` shim, not through `_subagent.invoke_subagent`:

- `test_handlers_contextualize.py` — `_invoke_ticket`, `_invoke_prologue` (lines 125–126).
- `test_handlers_gather.py` — `_invoke_gather` (line 789).
- `test_handlers_predict.py` — `_invoke_subagent` (~18 sites, lines 174–848).
- `test_handlers_report.py` — `_invoke_subagent` (lines 133–268+).
- `test_handlers_screen.py`, `test_handlers_analyze.py` — same pattern.

**Refactor implication for vertical #1 (`_subagent.py`):** removing the `_invoke_*` shims naïvely will break ~50 tests at once. Two paths:

a) **Preserve the shim, formalize it.** Make every handler expose `_invoke_subagent = invoke_subagent` (or partial-bound by agent name) as a single line. Keeps tests untouched, but the shim stays as design intent rather than accident.

b) **Replace with dependency injection.** Add `Context.invoke_subagent` (callable attribute) populated by `run_orchestrator.py`; tests construct `Context` with a stub callable. Cleaner long-term, but each test file gets a one-line touch.

Pick (a) for the first pass — the seam already works, and (b) is a separate refactor that touches every test file.

---

## 8. Confidence + remaining gaps

**Read in full during mapping:** `orchestrate.py`, `run_orchestrator.py`, `__init__.py`, `_subagent.py`, `_context_loader.py`, `_output_parser.py`, `contextualize.py`, `screen.py`, `predict.py`, `predict_fastpath.py`, `analyze.py`, all of `gather.py` and `report.py` (in chunks).

**Skimmed:** `env_memory.py` (350 of 514 lines); `_raw_manifest.py` (functions named only); `_markdown.py` (functions named only).

**Not read:** `agents/*.md` bodies; the `hooks/` tree (only know it exposes `invlang_validate.validate_companion` + `tag_tool_results` + `inject_env_context`); the `invlang/` package shape (predict and analyze depend on `invlang.queries`, `invlang.corpus.Companion` — inferred, not verified); `scripts/postmortem/leads/run.py`; `schemas/state.py` (used the imports — Phase enum, MAX_LOOPS, validate_transition).

**Want to verify before refactoring the corresponding vertical:**
- The hook→handler manifest contract: who writes what under `subagent_outputs/`, `subagent_audit.jsonl`, the manifest_dir consumed by `_raw_manifest`. **Block on:** vertical #8 (gather).
- The `invlang.queries` / `invlang.corpus` shape — predict and analyze depend on it. **Block on:** verticals #7 (predict priors) and #9 (analyze synthesis).
- Whether the two `validate_companion`-bypassing handlers (predict, report) intentionally rely on the PreToolUse hook firing on the actual `Write`. **Block on:** vertical #2 (append-validate seam).

---

## 9. Status (2026-04-28)

Verticals shipped in PR #145:

- ✅ #1 — `_subagent.make_invoker` shim factory.
- ✅ #2 — `_investigation_io.py` (`append_and_validate`, `validate_proposed_companion`, `append_unvalidated`).
- ✅ #3 — `_output_parser._extract_top_level_envelope` parametric extractor.
- ✅ #4 — `investigation_views.py` (per-mode trimmers split out of `_context_loader.py`).
- ✅ #5 — `_playbook.py` (`PlaybookMetadata`, `load_playbook_metadata` lifted out of contextualize; lazy imports in predict/report removed).
- ✅ #6 — `screen.py` routes Screen-table parse through `_playbook.load_screen_rows`.
- ✅ #7 — `predict_priors.py` (priors retrieval + rendering lifted out of predict).
- ✅ #10 (partial) — `report_termination.py` (verdicts + termination derivation/rationale/summary) + `report_benign_action.py`. The mechanical composers (`_compose_screen_match`, `_compose_report_md_screen`, `_compose_report_md_analyze`, `_compose_analyze_routed`) and the narrative-subagent dispatch stay in `report.py`; their interleaving with the main flow is non-obvious and the seam needs more mapping before extraction.

**Deferred from this PR:**

- ⏸ #8 — `gather.py` parallel-singletons path (lines 877–1035) interleaves manifest enrichment, fallback re-dispatch, and lead renumbering in ways that require deeper mapping before extraction. Preserve gather's complexity budget for now; revisit after the parallel-gather default flip lands and we have production traces showing which sub-paths are hot.
- ⏸ #9 — `analyze.py` `_synthesize_findings_block` (472–642) encodes invlang-schema conventions (verdict-mapping, default supporting_edges, name→id translation) that aren't documented anywhere else. Extract only after those conventions are written down.
- ⏸ #11 — `env_memory.py` is called only from predict via a try/except wrapper, ~1 commit/6mo. Defer until predict needs touching for an unrelated reason.
- ⏸ Remainder of #10 — REPORT mechanical composers + narrative dispatch. Need to trace the data-flow between `_compose_report_md_screen` and `_compose_report_md_analyze` to find a clean cut.
