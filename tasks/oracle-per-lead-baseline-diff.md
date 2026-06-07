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

## Review hardening (post-`/code-review`)

Fixes folded in after an extra-high-effort review of the diff:

- **`lead_sample_text` glob over-match** — `{position}*.json` matched `10.json`/`11.json`
  for `position=1` on ≥10-lead runs (feeding another lead's shape skeleton). Tightened to
  `{position}.json` + `{position}[a-z].json`, mirroring the projector's suffix guard.
- **Judge prompt pointer removed** — `judge.md`/`judge_benign.md` told the judge to read
  `system.template` "from `lead_sequence`", a doc the judge is never handed (and the
  projection no longer carries those keys). Reworded to name the lead by position + the
  name/system it *does* see in `investigation.md`.
- **Suppression-marker parse** — an unquoted `<suppressed: REASON>` whose REASON held a
  second `: ` raised a YAML `ScannerError` that aborted the whole oracle direction. Replaced
  the post-hoc `_normalize_marker` mapping-rescue (which also corrupted legit single-field
  placeholder events) with a pre-parse quoting pass that survives any number of colons.
- **Validator marker strictness** — now rejects unrecognized/empty event strings and a
  marker mixed with mappings or duplicated (the "marker is the sole item" contract was
  prose-only). Raw reply is embedded in the parse `LoopError` for debuggability.
- **Sanitizer fixes** — `_CLOCK` now requires a `Z` (durations / local-time windows no
  longer clobbered); a scalar `what_to_summarize` is no longer iterated char-by-char;
  non-dict `lead_description` / `None` query params no longer crash; `dump_oracle_doc`
  keeps non-ASCII values literal (`allow_unicode=True`); oracle fan-out fails fast and
  cancels queued leads; non-integer `ORACLE_MAX_CONCURRENCY` fails with a clear message.

## Verification

- `learning/` suite (with the +12 review-hardening regression tests): see latest run.
- New unit tests cover the glob-overmatch guard, multi-colon suppression-marker parse,
  placeholder-event preservation, validator marker strictness, sanitizer Z-requirement,
  scalar/malformed `what_to_summarize`, empty-sample fallthrough, and unicode dump.
- Validated end-to-end on this v2 worktree: a live `learning/loop.py` replay producing a
  real `projected_telemetry.yaml` (per-lead events / `[]` / noise / `<suppressed>`) and the
  judge's detection-by-absence reading.
