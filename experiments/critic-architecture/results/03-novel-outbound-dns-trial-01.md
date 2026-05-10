# Trial 03-01 — novel-outbound-dns

Fixture: `03-novel-outbound-dns` (label: novel-no-playbook, expected: CRITIQUE or ESCALATE)

## Defender

Claim: malicious supply-chain beacon via fresh npm dependency in PR #9921; escalate and contain.
Reasoning: provenance damning (PR introduces the package, npm publish 80min before first DNS sighting); maintainer/domain shape matches typosquat tradecraft (no other packages, fresh registration, .live TLD); beacon shape (jittered ~30min, ~280B fixed payload) textbook C2; CI-runner blast radius non-trivial despite stateless host.
Disposition: **malicious**, escalate, quarantine package, revoke runner creds, block egress.
Load-bearing assumption: "`@quickmetrics/runtime-collector` is not a known-legitimate package whose telemetry endpoint a defender could verify against vendor documentation."

## Critic

Verdict: **CRITIQUE** (in the benign direction — symmetric)

1. Assumption attacked: same load-bearing assumption, attacked from the benign side.
2. Mechanism: package may be a legitimate obscure APM/RUM SDK with a documented telemetry endpoint; jittered cadence + small payload also matches real metrics-flush shapes, not only C2.
3. Observable consequence: if legitimate, the npm tarball contains `package.json` with `homepage`/`repository` URL and source files that hardcode `telemetry-collect.live` (or read from documented env var) plus README docs. If malicious, the endpoint will be obfuscated, dynamically constructed, or absent from README.
4. Lead: `npm view @quickmetrics/runtime-collector@0.1.2`, fetch tarball, grep for the literal `telemetry-collect.live` and surrounding documentation/config plumbing.
5. Prediction: string only in obfuscated/encoded blob or post-install script → defender's malicious call stands; string in documented config with public repo + changelog predating PR → benign SDK default, re-triage.

## Grading

| Dimension | Score | Note |
|---|---|---|
| Sharpness | 2 | attacks the actual load-bearing claim |
| Specificity | 2 | concrete check, predicted artifact differs cleanly between hypotheses |
| Grounding | 2 | alert facts only |
| Novelty vs single-agent | 2 | the defender's reasoning was so strong on the malicious side that a single-agent loop would likely have stopped there; a separate adversarial-direction agent forced the cheapest disconfirmation check |

Verdict match: ✅ CRITIQUE expected and produced.

## Finding

Critic is **bidirectional** — happily attacks a malicious-direction defender call by producing a benign hypothesis with an observable test. The role isn't "paranoia generator"; it's "attack the load-bearing assumption from whichever side flips the disposition." This is a stronger architecture than the original framing suggested.

## Baseline comparison (added in second pass)

Single-agent baseline: `?adversary-controlled-npm-dependency` (inspect tarball package.json scripts/postinstall + maintainer 2FA), `?adversary-controlled-c2-beacon` (threat-intel pivot), **`?legitimate-telemetry-from-new-dep` (lead: PR description/commits/reviewer comments for telemetry disclosure, package README, cadence vs build phases)**, `?adversary-controlled-pr-author-or-typosquat`, `?dns-tunnel-exfil` (subdomain entropy), `?secret-scope-assessment`.

**Critic novelty: marginal.** Baseline's `?legitimate-telemetry-from-new-dep` hypothesis already includes the benign-direction test (review PR description + package README for telemetry disclosure). Critic's specific check — grep the unpacked tarball for the literal `telemetry-collect.live` string in documented config plumbing — is sharper than baseline's general "review README." Baseline broader (6 hypotheses including DNS-tunnel and secret-scope assessment).

Revises the trial 1 grading: marginal sharpness edge, not the strong novelty initial inspection suggested.
