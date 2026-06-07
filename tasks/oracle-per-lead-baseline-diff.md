---
title: Per-lead generative oracle + baseline-diff (retire footprint→router)
status: done
groups: defender, learning-loop
---

## Why

PR #249 (`experiments/oracle-overload-root-cause/`) re-examined PR #247's oracle
overload fix and concluded **decomposition** — running the oracle per-lead so each
isolated instance can't smuggle out-of-envelope events into the nearest lead — is the
load-bearing mechanism, with two complementary input fixes: dropping the prose `goal`
(drove fabrication-to-fill) and a deterministic `what_to_summarize` timestamp sanitizer.

v2 had adopted #247's two-stage **footprint → deterministic router** path. This change
**discards the router** and replaces it with a **per-lead generative oracle** — the
alternative decomposition #249 validated — chosen for its per-lead semantic richness.

## What landed

- **`learning/oracle.md`** (new; `footprint.md` deleted) — one `claude -p` per lead, fed
  only that lead's sanitized `what_to_characterize` + queries + a scrubbed sample event;
  no goal, no other leads, no alert. Output is a **signed diff over the baseline**
  ("standard environment noise"), mirroring the defender runtime's own
  deviation-from-baseline / absence-as-signal frame (`SKILL.md`):
  - `+` distinguishable → event mappings
  - `+` indistinguishable → `"<standard environment noise>"` (blend)
  - `−` baseline → `"<suppressed: REASON>"` (the story disables this lead's stream →
    predicted dark; **detection-by-absence**, exercises MITRE T1562.001 / T1070.002)
  - `0` → `events: []`
- **`learning/_loop_oracle.py`** (new) — `sanitize_wtc`, scrubbed-sample helper (ported
  from `main:_loop_exemplars.py`), per-lead prompt builder (drops goal), reply parser
  (rescues an unquoted `<suppressed: …>` marker that YAML mis-parses as a mapping), and
  `{projections:[{position,events}]}` assembly.
- **`learning/_loop_subagents.py`** — `footprint`→`oracle`; per-lead calls fanned out
  concurrently (`ThreadPoolExecutor`, `ORACLE_MAX_CONCURRENCY`); assembled in lead order.
- **`learning/_loop_orchestrate.py`** — router glue removed; `_write_validated_oracle`
  strips+validates the assembled doc.
- **`learning/_loop_validate.py`** — `projections`-only doc; events may be mapping OR
  marker string; `uncovered`/`unrouted_leads` dropped.
- **`learning/judge.md` + `judge_benign.md`** — source #5 rewritten for per-lead
  generative output; negative-claim rule extended to read `<suppressed: …>` (stream alive
  ⇒ caught; dark ⇒ consistent + detection-by-absence finding); `uncovered`/`unrouted`
  references removed.
- **Deleted:** `_oracle_router.py`, `scripts/lead_filters.py` (+ the projector's `filters`
  recovery) and their tests.

## Verification

- `learning/` suite: 92 passed. `tests/ -m "not llm"`: 267 passed, 7 skipped.
  (Combined `tests/ learning/` collection shows pre-existing sys.path-pollution errors not
  present per-dir; the one `tests/` failure is the live-`claude` `@pytest.mark.llm` gather
  test.) New unit tests cover sanitizer, scrub, per-lead parse (incl. unquoted-marker
  rescue), assembly, and validator marker acceptance.
- **Open / next session:** a live replay run through `learning/loop.py` to eyeball a real
  `projected_telemetry.yaml` (per-lead events / `[]` / noise / `<suppressed>` on a
  T1562-sampled story), and confirm the judge's detection-by-absence reading end-to-end.
