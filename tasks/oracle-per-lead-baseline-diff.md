---
title: Per-lead generative oracle + baseline-diff (detection-by-absence)
status: done
groups: defender, learning-loop
---

## Why

PR #249 (`experiments/oracle-overload-root-cause/`) showed the single-call telemetry
oracle's projection overload (out-of-envelope events smuggled into the nearest lead) is
eliminated by **decomposition** — one generative call per lead — plus two input fixes:
dropping the prose `goal` (drove fabrication-to-fill) and a deterministic
`what_to_summarize` timestamp sanitizer. Ported here from the v2 worktree
(`defender-v2-env`), adapted to main's single-call-oracle baseline (main never carried
the footprint→router two-stage path, so there is nothing to delete here — this replaces
the all-leads `oracle.md`).

## What landed

- **`learning/oracle.md`** — rewritten: one `claude -p` per lead, fed only that lead's
  sanitized `what_to_characterize` + queries + a scrubbed sample event; no goal, no other
  leads, no alert. Output is a **signed diff over the baseline** ("standard environment
  noise"), the frame the runtime already reasons in (`SKILL.md` deviation-from-baseline):
  - `+` distinguishable → event mappings
  - `+` indistinguishable → `"<standard environment noise>"` (blend)
  - `−` baseline → `"<suppressed: REASON>"` (story disables this lead's stream →
    predicted dark; **detection-by-absence**, exercises MITRE T1562.001 / T1070.002)
  - `0` → `events: []`
- **`learning/_loop_oracle.py`** (new, shared with v2) — `sanitize_wtc`, scrubbed-sample
  helper (was `_loop_exemplars.redact_exemplar`), per-lead prompt builder (drops goal),
  reply parser (rescues an unquoted `<suppressed: …>` marker YAML mis-parses as a
  mapping), `{projections:[{position,events}]}` assembly.
- **`_loop_subagents.py`** — single-call `invoke_oracle` → per-lead, fanned out
  concurrently (`ORACLE_MAX_CONCURRENCY`), reassembled in lead order.
- **`_loop_validate.py`** — projection shape `{position, events}` (dropped the redundant
  `system`/`template` — the judge reads those from `lead_sequence`); events may be a
  mapping OR a marker string; added the no-alias `dump_oracle_doc`.
- **`judge.md` + `judge_benign.md`** — oracle source rewritten for the per-lead
  baseline-diff output; negative-claim rule extended to read `<suppressed: …>` (stream
  alive ⇒ caught; dark ⇒ detection-by-absence finding).
- **Removed** `_loop_exemplars.py` (its scrub logic moved into `_loop_oracle`; the old
  all-leads exemplar bundle is no longer assembled).

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

- `learning/` 103 passed (was 91; +12 regression tests for the fixes above);
  `tests/ -m "not llm"` 282 passed.
- Validated end-to-end on the v2 worktree: two live loop runs (actor→oracle→judge→persist)
  clean across both directions; all four oracle modes confirmed on live claude incl.
  `<suppressed>` detection-by-absence.
- **Follow-up:** both live runs produced all-empty projections (one confirmed correct by
  the judge — a cross-container attack). The per-lead oracle is deliberately conservative
  (no alert → won't bridge a story's friendly entity name to a lead's pinned id); worth a
  check that it isn't over-abstaining on genuine event leads.
