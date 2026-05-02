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
- [x] **REPORT / CONCLUDE on-disk write** — both compose paths in `report.py` (SCREEN-routed `~:496` and ANALYZE-routed `~:1400`) wrap `emit_conclude_dense(...)` output in a `` ```invlang `` fence before appending to `investigation.md`. `_conclude_dense.py` already existed; this PR is just the fence wrapper.

## Status — pending

- [ ] **PREDICT** — flip `predict.py:318` and `:527` to use `_predict_dense` writer; emit `` ```invlang ``. (PR #167, in review.)
- [ ] **Validator cutover** — `invlang_validate.py` rejects `` ```yaml `` fences in `investigation.md`. Lands atomically *after* both PREDICT (#167) and REPORT have merged — kept separate from this PR to avoid coupling REPORT to PREDICT's merge order. Drops `YAML_BLOCK_RE` handling in `invlang_validate.py:403–411`, the legacy bare `:T conclude` fallback at `:435–440`, and the `` ```yaml `` reading paths in `investigation_views.py:121` / `gather.py:1389,1654` / `screen.py:100`.

## Follow-ups (not gating)

- [ ] **Latent `_analyze_dense._render_consult_row` field-name bug** — reads `r.get("verdict", "")` but the canonical anchor-consultation field is `result` (per schema rule #11). Untriggered today because analyze tests don't exercise consultations through the dense path; worth a small fix-and-test PR.
- [ ] **Screen prompt-side fence** (`screen.py:134`) — currently passes a re-serialized YAML prologue to the screen subagent inside a `` ```yaml `` fence. Honest to the contents today. Once the prologue is dense on main (now true post-#165), we can pass the dense body through and label it `` ```invlang `` instead.

## Acceptance

- Every phase emits `` ```invlang `` fences on disk; zero `` ```yaml `` fences in `investigation.md` after the migration.
- `invlang_validate.py` accepts only `` ```invlang `` (strict cutover — no dual-accept window).
- Round-trip parity tests pass: parse-dense → serialize-yaml → parse-yaml produces the same structured payload as the legacy direct path.
- One end-to-end live eval per signature (5710 scenario A or B, 100001, 100110) writes a fully-dense `investigation.md` with no rejections and lands a clean `report.md`.

## Order of leverage

PREDICT (#167) + REPORT (this PR) → validator cutover.

## Out of scope

- Dense format design changes; the schema is locked by the foundation parser.
- Subagent prompt rewrites (stdout dense contract is already in place across all phases).
- Migration of the `report.md` frontmatter (separate concern).
