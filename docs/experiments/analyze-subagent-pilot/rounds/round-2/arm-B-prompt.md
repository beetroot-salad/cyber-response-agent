# Arm B — Minimal + pre-commitments (Round 2 / case-ssh-brute-loop3)

You are the ANALYZE phase of a security-alert investigation loop.
Given a truncated investigation log (CONTEXTUALIZE + SCREEN +
HYPOTHESIZE + prior ANALYZE loops 1–2 + HYPOTHESIZE loop 3) and the
just-run GATHER output for loop 3, produce the ANALYZE (loop 3) block.

## Task

1. For each active hypothesis, assign a weight: `++`, `+`, `-`, `--`.
   **Rollup-aware:** carry loop-2 weights forward and adjust based
   on new evidence only.
2. Decide the next action: `CONCLUDE` or `HYPOTHESIZE`.
3. Note any hypothesis that remains adversarially live.

## Weight semantics

- `++` — evidence confirms a core prediction AND an attempted
  refutation failed (name the check or cite one the log satisfied).
- `+` — consistent but circumstantial.
- `-` — somewhat inconsistent.
- `--` — direct contradiction of a core prediction.

## Pre-commitments extracted from HYPOTHESIZE

This block is the **structured extraction** you get that Arm A doesn't.

### Adversarial status

- `?compromise-followup` — **adversarial, mandatory**. Must remain
  live until explicitly refuted with `--`. Refutation shape: zero
  successful SSH login (rule 5501/5715) from 203.0.113.45 in the
  forward window.

### Prior weights (loop 2 → entering loop 3)

- `?opportunistic-scanner`: `+`
- `?targeted-brute-force`: `+`
- `?credential-stuffing-external`: `-`
- `?compromise-followup`: live (not graded yet)

### Predictions per hypothesis (restated from HYPOTHESIZE)

- `?opportunistic-scanner`: ≥5 distinct generic wordlist usernames
  (admin, root, ubuntu, pi, oracle, …), attempt rate ≥0.1/s
  consistent with automation, scanner IP reputation (already
  confirmed loop 1), zero env-specific names.
- `?targeted-brute-force`: environment-specific usernames present
  (webapp-*, appuser-*, deploy-*, or names matching prod-webserver-01's
  app stack), sustained volume, possibly lower rate than mass-scanner.
- `?credential-stuffing-external`: real-looking personal or
  email-prefix usernames (not generic, not env-specific service
  names), lower attempt rate (human-paced slow-drip).
- `?compromise-followup`: any successful auth (5501/5715) from
  203.0.113.45 in the forward window.

### Named refutation checks

- `?opportunistic-scanner` → `--` if usernames are ≤2 names or
  include env-specific names (not wordlist).
- `?opportunistic-scanner` → `++` requires confirmed wordlist
  profile AND an attempted refutation failing (check for
  env-specific names).
- `?targeted-brute-force` → `--` if all usernames are generic
  wordlist entries with no environment-specific naming.
- `?credential-stuffing-external` → `--` if attempt rate matches
  mass-scanner profile OR usernames are purely generic wordlist
  entries.
- `?compromise-followup` → `--` if zero 5501/5715 from source IP
  in the forward window.

### Pitfalls per hypothesis

- `?opportunistic-scanner`: scanner reputation alone does not
  confirm; requires username-scatter evidence.
- `?targeted-brute-force`: targeted attackers may mix generic and
  env-specific names to blend; key discriminator is **absence** of
  env-specific names when the scatter is broad.
- `?credential-stuffing-external`: opportunistic and stuffing both
  automate — discriminator is username profile (generic vs personal
  identifiers) and pacing, not volume alone.

## Output format

Same as Arm A — plain markdown ANALYZE block, rollup-aware
("was {prior weight}").

## Forbidden

Do not read:
- `docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/ground-truth-analyze.md`
- `docs/experiments/analyze-subagent-pilot/rounds/round-2/arm-A*` or `arm-C*` outputs
- `docs/experiments/analyze-subagent-pilot/rounds/round-1/` or `round-1-v2/`
- `docs/experiments/investigation-language-pilot/case-ssh-brute/`

## Inputs

### Prior investigation log (truncated)
@docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/truncated-investigation.md

### Just-run GATHER output (loop 3)
@docs/experiments/analyze-subagent-pilot/fixtures/case-ssh-brute-loop3/lead-output.md

## Write your output to

`docs/experiments/analyze-subagent-pilot/rounds/round-2/arm-B.md`

Include a `## Self-report` section: context you wished you had,
pre-commitment items you actually used vs ignored, claims you felt
uncertain about.
