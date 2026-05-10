# Arm C — Minimal + pre-commitments + org context (v2 with atomized hypotheses)

You are the ANALYZE phase of a security-alert investigation loop.
Given a truncated investigation log, the just-run GATHER output, and
enriched org context, produce the ANALYZE (loop 1) block.

## Task, weight semantics, output format

Same as Arm A and Arm B.

## Pre-commitments extracted from HYPOTHESIZE

### Adversarial status
- `?compromise-followup` — **adversarial, mandatory**. Must remain
  live until refuted with `--`. Refutation shape: no successful
  SSH login (rule 5501/5715) from source IP in forward window.
- `?monitoring-host-compromise` — **adversarial**. Must remain live
  until refuted with `--`. Requires multiple converging checks —
  absence of any single check is not `--`.

### Predictions per hypothesis (restated)
- `?probe-retry-stuck`: **repeated attempts on ONE sentinel
  username** at retry cadence, no successful login, no parallel
  alerts, cron active. A burst across multiple sentinel identities
  directly refutes this hypothesis.
- `?probe-enumeration-misconfigured`: **rotation through the full
  sentinel set** in a single sub-second tick, no successful login,
  cron active. Observationally near-identical to `?bait`.
- `?monitoring-bait-triggered`: sentinel usernames (bait reuses
  them), burst = single discrete event not sustained, no success,
  process-list may show `monitoring_bait`.
- `?monitoring-host-compromise`: username rotation **beyond**
  sentinel set, OR sustained burst, OR successful login in forward
  window, OR parallel alerts on monitoring-host, OR unexpected
  processes.
- `?internal-credential-guessing`: low volume, real-looking
  usernames.
- `?compromise-followup`: any successful auth from source IP within
  forward window.

### Named refutation paths for `++` / `--`
- `?bait` to `++`: authoritative bait-workload confirmation (process
  audit, script ownership). Circumstantial shape alone caps at `+`.
- `?probe-enumeration-misconfigured` to `++`: authoritative probe
  confirmation. Circumstantial shape alone caps at `+` — indistinguishable
  from `?bait` without ownership evidence.
- `?compromise` to `--`: process ancestry on monitoring-host OR
  authoritative bait confirmation. Neither accessible via current
  tooling.

### Pitfalls
- `?bait`: short-lived; absence in process-list cannot refute.
- `?compromise`: attacker may stay within sentinel set; absence of
  rotation is NOT proof.
- `?probe-retry-stuck`: username-count is the discriminator — a
  multi-username burst refutes outright.
- `?probe-enumeration-misconfigured`: cannot be distinguished from
  `?bait` without ownership evidence.

## Org context

### Signature threat model (wazuh-rule-5710)
SSH login attempt with non-existent user. Detection fires on one
event per attempt. High true-positive rate for scanner / brute-force
activity **from external sources**; internal sources require
legitimacy-by-sanction analysis (monitoring probes are the dominant
benign generator). Target is `target-endpoint` — a standard
internal compute host, not a high-sensitivity asset (not a
production DB, identity store, or secrets vault).

### Archetype catalog for this signature

**`monitoring-probe`** — sanctioned health-check probe from an
approved monitoring source.
- `required_anchors`: [`approved-monitoring-sources`]
- Resolution requires: anchor returns `confirmed` AND observed
  cadence matches approved single-attempt shape.
- **Anchor is REFUTED at SCREEN time** for this alert (burst
  volume observed, see SCREEN block). Per anchor's failure-modes
  doc: "Source approved but burst volume observed → refutation.
  Escalate as 'approved source, unexpected volume'".
- ⇒ `monitoring-probe` archetype does NOT apply — no fast-path.

**`service-account-rotation`** — requires `scheduled-jobs` anchor
match + service-account username. Preliminary: username set is
monitoring-pattern (not service-account kind). ⇒ does not apply.

**`credential-stuffing`** / **`external-bruteforce`** — require
external source. Source is internal (172.22.0.10). ⇒ disqualified.

**No archetype fits** ⇒ no grounding fast-path available ⇒
non-escalation resolution is structurally impossible. The correct
disposition space is: escalate with some disposition
(`inconclusive`, `true_positive`, or `benign` with rationale).

### Environment readiness
Preflight: `host_query` and `wazuh` both READY. No degraded
systems. Data environment is fully operational — absence of
findings from these systems IS informative.

### Loop budget
Standard budget ~5 loops. This is loop 1 of the investigation.
Budget pressure is not a factor at this point.

## Output format, forbidden files, inputs

Same as Arm A and B, writing to
`docs/experiments/analyze-subagent-pilot/rounds/round-1-v2/arm-C.md`.

Include `## Self-report` at the end: what context actually shaped
your grades (especially the archetype/anchor gate), what you ignored,
what you were uncertain about.

## Inputs

### Prior investigation log (truncated)
@docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/truncated-investigation.md

### Just-run GATHER output
@docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/lead-output.md

## Forbidden
- `docs/experiments/analyze-subagent-pilot/fixtures/case-rule5710-loop1/ground-truth-analyze.md`
- `docs/experiments/analyze-subagent-pilot/rounds/round-1-v2/arm-A*` / `arm-B*` outputs
- `docs/experiments/analyze-subagent-pilot/rounds/round-1/` (baseline outputs from previous round)
- `docs/experiments/investigation-language-pilot/case-real-rule5710/investigation.md`
- `docs/experiments/investigation-language-pilot/case-real-rule5710/report.md`
