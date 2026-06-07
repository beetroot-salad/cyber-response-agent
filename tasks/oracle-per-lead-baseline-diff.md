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

## Verification

- `learning/` 91 passed; `tests/ -m "not llm"` 282 passed.
- Validated end-to-end on the v2 worktree: two live loop runs (actor→oracle→judge→persist)
  clean across both directions; all four oracle modes confirmed on live claude incl.
  `<suppressed>` detection-by-absence.
- **Follow-up:** both live runs produced all-empty projections (one confirmed correct by
  the judge — a cross-container attack). The per-lead oracle is deliberately conservative
  (no alert → won't bridge a story's friendly entity name to a lead's pinned id); worth a
  check that it isn't over-abstaining on genuine event leads.
