---
title: Migrate handler on-disk format from yaml fences to ```invlang
status: doing
groups: invlang, dense-onfile
---

Foundation for the dense on-disk format landed via #160. Per-handler flips landing strict-cutover: `invlang_validate.py` flips to accept-only-`` ```invlang `` atomically with the final handler PR.

## Status — done

- [x] **Foundation** (#160) — parser at `_dense_parser.py`, primitives at `_dense_primitives.py`, validator hook updates, parity tests.
- [x] **GATHER + GATHER-composite** (#162) — `_gather_dense.py` wired at `gather.py:1448`.
- [x] **ANALYZE** (#162) — `_analyze_dense.py` wired at `analyze.py:664`.
- [x] **CONTEXTUALIZE / prologue** (#163 → replayed onto main as #165) — `contextualize.py` writes dense body straight into a `` ```invlang `` fence; readers (`screen.py`, `analyze.py`, `env_memory.py`, `predict_priors.py`, `env_memory_lint.py`) switched to `iter_companion_dicts`.
- [x] **SCREEN** (#166) — new `_screen_dense.py`; `screen.py` writes `` ```invlang ``. Also fixed a latent dense-parser bug: `_project_resolution` was storing `attr_updates` rows flat (`{target, key, value}`) but validator rule #22 requires `{target, updates: {key: value}}`. New `_append_attr_update` folds rows by target.
- [x] **PREDICT** (#167) — `predict.py:_compose_section()` now writes `hypothesize:` as `` ```invlang `` via `emit_hypothesize_dense(...)`; the fast-path audit trail was also moved out of a structured YAML fence into plain markdown bullets.
- [x] **REPORT / CONCLUDE on-disk write** (#168) — both compose paths in `report.py` (SCREEN-routed `~:496` and ANALYZE-routed `~:1400`) wrap `emit_conclude_dense(...)` output in a `` ```invlang `` fence before appending to `investigation.md`. `_conclude_dense.py` already existed; this PR is just the fence wrapper.
- [x] **Dense consultation row field-name fix** — `_analyze_dense._render_consult_row()` now emits `result` (not the stale `verdict` field name) for `:R consultations`, matching schema rule #11.

## Status — pending

- [x] **Validator strict cutover** (#170, commit `9f5d543`) — `invlang_validate._parse_blocks()` now rejects `` ```yaml `` fences in `investigation.md` with a precise error and parses only `` ```invlang ``. Legacy bare `:T conclude` fallback removed; `_parse_dense_conclude` helper deleted. `_check_append_only()` counts `INVLANG_BLOCK_RE` matches. `YAML_BLOCK_RE` dropped from `__all__` (still imported internally for the cutover-rejection scan).
- [x] **Live read-path cleanup** (#170) — gather/report/_prior_recall switched to `iter_companion_dicts()`. Shared helper `first_prologue_vertex_id()` extracted to `_markdown.py` and imported by both `gather.py` and `analyze.py` (closes the duplicated-prologue-readers cleanup item too). `_PROLOGUE_FENCE_RE` and the local `_YAML_BLOCK_RE` in `_prior_recall` are gone.
- [x] **Legacy dual-read cleanup in prompt/render helpers** (#170, commit `9f5d543`) — `investigation_views._INVLANG_OPEN_FENCES` narrowed to `{"```invlang"}`; analyze-mode prose-trim now keeps only structured dense fences. `screen._extract_prologue_yaml` docstring updated to dense-only. Screen subagent prompt-side fence (off-disk) intentionally left as `` ```yaml `` — flipping it requires a coordinated subagent prompt edit and is tracked separately below.
- [x] **Test suite update for validator cutover** (#170) — added dense `VALID_*_INVLANG` companions and rebuilt `FULL_COMPANION_MD` in `test_invlang_validate.py`; converted every red `_run_hook` integration test to dense fixtures; reframed `test_yaml_parse_error_*` tests as `test_yaml_fence_rejected_*`; collapsed `test_parse_blocks_yaml_and_invlang_coexist` + `test_parse_blocks_legacy_bare_conclude_still_works` into `test_parse_blocks_rejects_yaml_fence` in `test_invlang_dense_parity.py`; converted on-disk yaml fixtures in `test_handlers_analyze.py`, `test_handlers_gather.py`, `test_handlers_screen.py`, and `test_context_loader.py`. Also fixed an aliasing gap in `_dense_parser._parse_resolution_line` that was setting only `hypothesis_id` (the validator and walkers index on `hypothesis`); the dense parser now sets both.
- [ ] **Acceptance runs** — one end-to-end live eval per signature (5710 scenario A or B, 100001, 100110) producing a fully-dense `investigation.md` and clean `report.md` after the validator cutover.

## Cleanup We Should Do In The Cutover PR

- [x] **Consolidate duplicated prologue readers** (#170) — both handlers now import `first_prologue_vertex_id` from `_markdown.py`.
- [x] **Consolidate companion merging/walking** — `iter_companion_dicts()` is the single live-path walker; the remaining wrappers (`_prior_recall._merge_companion_blocks`, `report._extract_findings_blocks`) carry phase-specific semantics on top of it (hypothesis dedup; findings flattening + prose-form fallback). `invlang.corpus._merge_md_blocks` was rewritten to dense-only after the test corpus was discarded.
- [x] **Screen prompt-side fence** (`screen.py`) — flipped the input fence from `` ```yaml `` to `` ```invlang ``. New `emit_prologue_dense_body()` helper in `_prologue_dense.py`; `_extract_prologue_yaml` renamed `_extract_prologue_dense`; `agents/screen.md` updated with a dense-row cheat-sheet (input only — subagent stdout still emits yaml, tracked separately).
- [x] **Drop yaml corpus support** — `scripts/invlang/corpus.py` and `scripts/invlang/cli.py` no longer carry `YAML_BLOCK_RE` / `PILOT_CORPUS_FILES` / yaml-fence walking. In-repo pilot fixtures under `docs/experiments/investigation-language-pilot/case-*/walk-*.yaml` and `companion-v2*.yaml` deleted.
- [x] **Drop yaml fallbacks in `validate_report_precheck.py`** — `extract_conclude_yaml` renamed `extract_conclude_dense`; routes through fence-aware `parse_dense_companion`. `_check_frontier_closure` walks via `iter_companion_dicts` (no yaml-block scan).
- [x] **Dense parser projects to one canonical companion shape** (no shape tolerance in readers). The parser now projects:
   - `:H` `parent_type` / `parent_class` cells → `proposed_edge.parent_vertex.{type, classification}` (nested — yaml convention; matches every reader: `invlang_checks_hypothesis`, `corpus.hypothesis_topology`, `env_memory.extract_anchors`, `env_memory_lint`, `predict_priors`).
   - `:T shelved` rows → `lead.shelved` is a flat list of bare hypothesis ids (canonical companion shape); rationales (if any) land in the sibling `lead.shelved_rationales` map keyed by id, so `compute_final_status` can stay strict.
   - `:L findings` `fail_reason` cell → `outcome.failure_reason` (where postmortem and downstream readers expect it). `_gather_dense` and `_analyze_dense` emitters now write the cell from `outcome.failure_reason`, closing the previously-silent emit gap.
- [x] **`invlang_validate.extract_conclude_yaml` rename → `extract_conclude_dense`** and rerouted through the fence-aware `parse_dense_companion` so callers can pass raw `investigation.md` text. Old function name was misleading post-cutover.
- [x] **`postmortem.leads.extract._derive_result_shape`** widened to accept `attribute_updates` even when `outcome.observations` is absent (was previously gated inside the observations-dict branch).
- [x] **Test fixture helper** (`tests/_dense_fixture_helpers.py`) added so test fixtures can stay declarative as companion dicts. Production emitters remain strict; the helper fills test-only defaults (resolution `before_weight: "none"` + `severity: low`, contract `id: ac<n>` + `anchor_kind: org-authority` + `edge_ref: proposed`) before calling them. Live yaml fixtures in test_validate_report_precheck, test_handlers_report, test_invlang_dense_parity, test_analyze_prior_recall, test_handlers_predict, test_predict_fastpath_handler, test_postmortem_leads_extract, test_env_memory, test_env_memory_lint converted to dense.
- [x] **Removed yaml-only `findings:`/`gather:` alias test** (`TestFindingsGatherAlias` in test_postmortem_leads_extract). Aliasing was a yaml-only artifact; the dense surface uses `:L findings`.

Scope discipline: yes to consolidating methods during the cutover, but keep it narrowly tied to live `investigation.md` parsing / helper dedup. Avoid bundling unrelated format design changes or broad handler refactors into the strict-cutover PR.

## Out of scope, tracked elsewhere

- **Subagent stdout yaml contracts** (gather, gather-composite, predict, report, archetype-match, ticket-context, screen output blocks). Every prompt under `soc-agent/agents/` still ends with "emit EXACTLY this YAML, then STOP". Flipping these to dense invlang is a coordinated multi-subagent refactor with persister-side parsing changes (`_subagent.extract_terminal_yaml`, `extract_subagent_yaml.py`, `_output_parser`).

## Acceptance

- Every phase emits `` ```invlang `` fences on disk; zero `` ```yaml `` fences in `investigation.md` after the migration.
- `invlang_validate.py` accepts only `` ```invlang `` (strict cutover — no dual-accept window).
- No live handler path depends on YAML-only parsing of `investigation.md`; REPORT, ANALYZE recall, GATHER, SCREEN, and prompt trimmers all consume the dense surface correctly.
- Round-trip parity tests pass: parse-dense → serialize-yaml → parse-yaml produces the same structured payload as the legacy direct path.
- One end-to-end live eval per signature (5710 scenario A or B, 100001, 100110) writes a fully-dense `investigation.md` with no rejections and lands a clean `report.md`.

## Order of leverage

Validator cutover + live read-path cleanup → acceptance runs.

## Out of scope

- Dense format design changes; the schema is locked by the foundation parser.
- Subagent prompt rewrites (stdout dense contract is already in place across all phases).
- Migration of the `report.md` frontmatter (separate concern).
