# Arm B — Minimal + pre-commitments

You are the ANALYZE phase of a security-alert investigation loop.
Given a truncated investigation log (CONTEXTUALIZE + SCREEN +
HYPOTHESIZE) and the just-run GATHER output, produce the ANALYZE
(loop 1) block.

## Task

1. For each active hypothesis, assign a weight: `++` strongly
   supports, `+` weakly supports, `-` weakly refutes, `--` strongly
   refutes. Brief reasoning per grade.
2. Decide the next action: `CONCLUDE` or `HYPOTHESIZE`.
3. Note any hypothesis that remains adversarially live.

## Weight semantics

- `++` — evidence directly confirms a core prediction AND an
  attempted refutation failed (name the check or cite one the log
  satisfied).
- `+` — consistent but circumstantial.
- `-` — somewhat inconsistent.
- `--` — direct contradiction of a core prediction.

## Pre-commitments extracted from HYPOTHESIZE

This block is the **structured extraction** you get that Arm A doesn't.

### Adversarial status
- `?compromise-followup` — **adversarial, mandatory**. Must remain
  live until explicitly refuted with `--`. Refutation shape: no
  successful SSH login (rule 5501/5715) from the source IP in the
  forward window.
- `?monitoring-host-compromise` — **adversarial**. Must remain live
  until explicitly refuted with `--`. Refutation shape requires
  multiple converging checks (username rotation, parallel alerts,
  process audit, etc.) — absence of any single check is not `--`.

### Predictions per hypothesis (restated from HYPOTHESIZE)
- `?monitoring-loop-broken`: sentinel usernames only, burst window,
  no successful login, no parallel alerts on monitoring-host,
  process-list may show `monitoring_probe`.
- `?monitoring-bait-triggered`: sanctioned sentinel usernames
  (bait reuses monitoring names), burst = single discrete event
  not sustained, no successful login, process-list may show
  `monitoring_bait`.
- `?monitoring-host-compromise`: username rotation **beyond**
  sentinel set, OR sustained burst over the full hour, OR successful
  login in forward window, OR parallel alerts on monitoring-host,
  OR unexpected processes.
- `?internal-credential-guessing`: low volume, real-looking
  usernames. Preliminary refutation already holds.
- `?compromise-followup`: any successful auth from the source IP
  within the forward window.

### Named refutation checks (what would refute `++` before awarding it)
- For `?monitoring-bait-triggered` to go `++`: would require
  authoritative confirmation of the bait workload (process audit
  log, script ownership evidence). Circumstantial shape alone
  caps at `+`.
- For `?monitoring-host-compromise` to go `--`: would require
  (a) process ancestry on monitoring-host, OR (b) authoritative
  evidence the bait workload was the cause. Neither is accessible.

### Pitfalls per hypothesis (from HYPOTHESIZE pre-enumeration)
- `?bait`: short-lived; absence in process-list cannot refute.
- `?compromise`: attacker may deliberately stay within sentinel
  set; absence of rotation is NOT proof of innocence.
- `?loop-broken`: cron-driven loop could look periodic inside
  the burst; cadence violation alone may confuse bait vs loop.

## Output format

Same as Arm A — plain markdown ANALYZE block.

## Forbidden

Do not read:
- `docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/ground-truth-analyze.md`
- `docs/experiments/analyze-subagent-pilot/rounds/round-1/arm-A*` or `arm-C*` outputs
- `docs/experiments/investigation-language-pilot/case-real-rule5710/investigation.md`
- `docs/experiments/investigation-language-pilot/case-real-rule5710/report.md`

## Inputs

### Prior investigation log (truncated)
@docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/truncated-investigation.md

### Just-run GATHER output
@docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/lead-output.md

## Write your output to

`docs/experiments/analyze-subagent-pilot/rounds/round-1/arm-B.md`

Include a `## Self-report` section at the end listing: any context
you wished you had beyond what was provided, any items from the
pre-commitments extraction you actually used vs ignored, any claims
in your output you felt uncertain about.
