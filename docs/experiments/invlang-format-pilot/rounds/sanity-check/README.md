# Sanity Check — Pipeline Render

Goal: verify `render_prior.py` produces well-formed, differentiated
prior contexts across all (case × depth × arm) combinations before
investing in full experimental runs.

## What was rendered

Case 1 — `case-rule5710-monitoring-probe` (run-sourced, looks-benign × benign, full production-schema investigation.md):

| Depth   | Arm | Lines | Bytes |
|---------|-----|-------|-------|
| shallow | A   | 141   | 2691  |
| shallow | B   | 107   | 3340  |
| shallow | C   | 93    | 1568  |
| deep    | A   | 287   | 8983  |
| deep    | B   | 162   | 9317  |
| deep    | C   | 93    | 1568  |

Case 2 — `case-rule550-fim-restart-artifact` (run-sourced,
looks-malicious × benign, **prose-heavy** legacy investigation.md):

| Depth   | Arm | Lines |
|---------|-----|-------|
| shallow | A   | 93    |
| shallow | B   | 121   |
| shallow | C   | 95    |
| deep    | A   | 112   |
| deep    | B   | 172   |
| deep    | C   | 95    |

## What the numbers say

- **Depth separation works**: Case 1 deep/Arm A jumps from 141 → 287
  lines (more YAML blocks surfaced as more phases are retained).
- **Arm A ≠ Arm B** at both depths for Case 1: the shallow byte count
  is close (2691 vs 3340) because CONTEXTUALIZE has roughly balanced
  prose and YAML, but deep diverges sharply (line count 287 vs 162) —
  Arm A carries dense YAML gather/resolution blocks that Arm B
  compresses into prose.
- **Arm C is depth-invariant**, as designed — 93 lines at both cuts.
- **Case 2 exposes the schema gap**: shallow Arm A is 93 lines vs
  Arm B's 121 — Arm A is *smaller* than B, which is backwards if the
  YAML is supposed to carry more information. Root cause: Case 2's
  source investigation.md is pre-schema-lock format, with only one
  inline YAML block in ANALYZE. Case 2 cannot run the experiment
  fairly until its investigation.md is enriched.

## Ready / not ready

- **Case 1** — ready for full experimental runs.
- **Case 2** — requires investigation.md enrichment (prologue,
  hypothesize, gather YAML blocks in production schema) before use.
  Flagged in case.yaml `meta.notes` and above.
- **Case 7** (rule550 ssh-persistence synthetic) — hypothesis schema
  predates contract lock. See `cases/case-rule550-ssh-persistence/REWORK_NEEDED.md`.

## What the sanity check didn't do

- Invoke an actual hypothesize subagent. The next step is
  `run_arm.py` (still a stub) — wire it to the Anthropic SDK,
  invoke the `hypothesize` subagent with each rendered prior, capture
  output, and manually inspect for plausibility before building the
  scorer.
- Score anything. `score.py` is still a stub; writing it after we
  have at least one full (case × depth × arm) trial output to design
  the classifier against.
