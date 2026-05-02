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
- [ ] **Test suite update for validator cutover** — `tests/test_invlang_*.py` use handcrafted `` ```yaml `` fixtures that the new validator rejects. Convert the shared `VALID_*_YAML` fixtures (and the inline `_run_hook` integration tests) to dense `` ```invlang `` form so the rule-coverage stays intact.
- [ ] **Acceptance runs** — one end-to-end live eval per signature (5710 scenario A or B, 100001, 100110) producing a fully-dense `investigation.md` and clean `report.md` after the validator cutover.

## Cleanup We Should Do In The Cutover PR

- [x] **Consolidate duplicated prologue readers** (#170) — both handlers now import `first_prologue_vertex_id` from `_markdown.py`.
- [ ] **Consolidate companion merging/walking** — we now have overlapping logic in `_markdown.iter_companion_dicts()`, `_prior_recall._merge_yaml_blocks()`, `report.py:_extract_findings_blocks()`, and `invlang.corpus._merge_md_blocks()`. During cutover, it is worth centralizing the live-`investigation.md` read path around one shared dense-aware helper rather than keeping several partial readers in sync.
- [ ] **Screen prompt-side fence** (`screen.py:134`) — still passes a re-serialized YAML prologue to the screen subagent inside a `` ```yaml `` fence (off-disk, non-gating). Cutover commit `9f5d543` left it untouched because the screen subagent prompt template still expects yaml-shape input; flipping it requires a coordinated subagent prompt edit.

Scope discipline: yes to consolidating methods during the cutover, but keep it narrowly tied to live `investigation.md` parsing / helper dedup. Avoid bundling unrelated format design changes or broad handler refactors into the strict-cutover PR.

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
