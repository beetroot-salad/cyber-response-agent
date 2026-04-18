# Arm C — Minimal + pre-commitments + org context (Round 2 / case-ssh-brute-loop3)

You are the ANALYZE phase of a security-alert investigation loop.
Given a truncated investigation log, the just-run GATHER output
for loop 3, and enriched org context, produce the ANALYZE (loop 3)
block.

## Task, weight semantics, output format

Same as Arm A and Arm B. Rollup-aware.

## Pre-commitments extracted from HYPOTHESIZE

### Adversarial status
- `?compromise-followup` — **adversarial, mandatory**. Live until
  refuted with `--`. Refutation shape: zero successful SSH login
  (5501/5715) from 203.0.113.45 in forward window.

### Prior weights (loop 2 → entering loop 3)
- `?opportunistic-scanner`: `+`
- `?targeted-brute-force`: `+`
- `?credential-stuffing-external`: `-`
- `?compromise-followup`: live (ungraded)

### Predictions (restated)
- `?opportunistic-scanner`: ≥5 generic wordlist usernames, ≥0.1/s
  rate, scanner IP reputation (already confirmed), zero env-specific
  names.
- `?targeted-brute-force`: env-specific usernames matching
  prod-webserver-01 stack, sustained volume.
- `?credential-stuffing-external`: real-looking personal /
  email-prefix usernames, slow-drip pacing.
- `?compromise-followup`: any 5501/5715 from source IP in forward
  window.

### Named refutation paths
- `?opportunistic-scanner` → `--` if ≤2 names or env-specific names.
- `?opportunistic-scanner` → `++` requires wordlist profile + failed
  attempted refutation for env-specific names.
- `?targeted-brute-force` → `--` if all usernames are generic
  wordlist entries, zero env-specific.
- `?credential-stuffing-external` → `--` if mass-scanner pacing OR
  generic wordlist usernames.
- `?compromise-followup` → `--` if zero successful auth in forward
  window.

### Pitfalls
- `?opportunistic-scanner`: reputation alone does not confirm.
- `?targeted-brute-force`: adversaries may mix names; absence of
  env-specific names is the key discriminator when scatter is broad.
- `?credential-stuffing-external`: discriminator is username kind +
  pacing, not volume.

## Org context

### Signature threat model (wazuh-rule-5710)
SSH login attempt with non-existent user. High true-positive rate
for scanner / brute-force from external sources. Target
`prod-webserver-01` is a production, public-facing web application
VM (IP 10.0.1.10) — moderately high sensitivity (customer-facing)
but not an identity store, secrets vault, or database.

### Archetype catalog for this signature

**`opportunistic-scanner`** — external mass-scanner sweeping for
SSH.
- `required_anchors`: [`source-reputation-scanner`, `wordlist-username-scatter`]
- Resolution requires: scanner-class ASN/reputation confirmed AND
  wordlist username scatter confirmed AND attempt rate consistent
  with automation AND zero successful auth in forward window.
- All four conditions would need to be met for a resolved disposition.

**`targeted-brute-force`** — adversary with prior recon.
- `required_anchors`: [`env-specific-username-evidence`]
- Would require at least some env-specific username presence.
- Disposition: true_positive with recon concern.

**`credential-stuffing-external`** — breach-list credential replay.
- `required_anchors`: [`breach-list-username-profile`, `slow-drip-pacing`]
- Would require personal/email-prefix username profile AND human-paced rate.

**`monitoring-probe`** — sanctioned health-check. Disqualified:
external source, not in approved-monitoring-sources.

### Environment readiness
Preflight: ip-reputation READY, wazuh READY, dns-reputation READY.
threat-intel FAILED earlier (timeout on l-003, loop 2) — recovered
via dns-passive. No other degraded systems. Absence of findings
from operational systems IS informative.

### Loop budget
Standard budget ~5 loops. This is loop 3 — still well within budget.
No pressure to force a conclusion; if the evidence is not decisive,
another loop is acceptable.

### Precedent context
- 14 prior SSH brute-force `true_positive` closures against
  prod-webserver-01 in the past 90 days, all from external
  scanner-class ASNs — opportunistic-scanner archetype has strong
  precedent at this target.

### Trust-root policy
External endpoints are trust-roots — attribution ends at the IP
level when v-001 is marked `trust_root_reached` (no accessible
upstream forensics: no process lineage, no session chain, no
owner-controlled sources). If trust-root is reached and the frontier
has collapsed (all hypotheses resolved), CONCLUDE is the only
correct action.

## Output format, forbidden files, inputs

Same as Arm A and B, writing to
`docs/experiments/analyze-subagent-pilot/rounds/round-2/arm-C.md`.

Include `## Self-report` at the end: what context actually shaped
your grades (especially the archetype anchors, trust-root policy,
and precedent), what you ignored, what you were uncertain about.

## Inputs

### Prior investigation log (truncated)
@docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/truncated-investigation.md

### Just-run GATHER output (loop 3)
@docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/lead-output.md

## Forbidden
- `docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/ground-truth-analyze.md`
- `docs/experiments/analyze-subagent-pilot/rounds/round-2/arm-A*` / `arm-B*` outputs
- `docs/experiments/analyze-subagent-pilot/rounds/round-1/` / `round-1-v2/`
- `docs/experiments/investigation-language-pilot/case-ssh-brute/`
