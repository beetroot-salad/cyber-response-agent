# Trial 01-01 — ssh-bastion-new-source

Fixture: `01-ssh-bastion-new-source` (label: ambiguous, expected: CRITIQUE)

## Defender

Claim: benign late-night admin action by jsmith finishing INC-8821.
Reasoning: key fingerprint matches across 4 corp IPs (compromise would need key exfil + physical pivot, high-effort); INC-8821 closed 16min before login explains timing; Building 7 wifi explains new subnet; signature low-specificity.
Disposition: **benign**, auto-close, link INC-8821 as precedent.
Load-bearing assumption: "src_ip → Building 7 wifi mapping is trustworthy and not spoofable from outside the physical building."

## Critic

Verdict: **CRITIQUE**

1. Assumption attacked: "Building 7 wifi explains new subnet" (treats 10.42.7.183 as trusted human-occupied wireless endpoint by subnet label).
2. Mechanism: T1563.001 SSH Hijacking / T1550.001 forwarded ssh-agent abuse from a compromised endpoint already on Building 7 wifi. Legitimate key fingerprint would match because the attacker rides jsmith's forwarded agent — no key exfil needed, defeating "high effort" argument.
3. Observable consequence: bastion sshd auth log line shows `SSH_AUTH_SOCK` set / agent-forwarding flag; 10.42.7.183 DHCP/MAC lookup resolves to a non-jsmith asset.
4. Lead: pull sshd auth log for this session, check agent-forwarding + TTY/parent-PID lineage; query DHCP/wifi-controller for 10.42.7.183 at 03:47Z (MAC, hostname, MDM owner); EDR cross-check on that host.
5. Prediction: IP resolves to a non-jsmith asset and bastion session shows agent-forwarding from upstream hop, not direct laptop login.

## Grading

| Dimension | Score | Note |
|---|---|---|
| Sharpness | 2 | attacks the actual load-bearing claim head-on |
| Specificity | 2 | named techniques + concrete observable + concrete lead |
| Grounding | 2 | uses only alert facts, no invented environment |
| Novelty vs single-agent | 2 | agent-forwarding pivot defeats "key exfil too expensive" — defender did not consider it, and this isn't a generic `?adversary-controlled-*` template |

Verdict match: ✅ CRITIQUE expected, CRITIQUE produced.

## Baseline comparison (added in second pass)

Single-agent baseline hypotheses: `?legitimate-followup-to-INC-8821`, `?new-corp-device-or-floor-move` (DHCP/MAC), `?adversary-controlled-endpoint` (EDR + key-file access on jsmith's workstation), `?adversary-controlled-account` (badge access Building 7), `?session-behavior-anomaly` (auditd/ttyrec), `?subnet-legitimacy` (CMDB on /24).

**Initial verdict: STRONG.** Baseline (single sample, default model) never produced the agent-forwarding (T1550.001) angle. Baseline's `?adversary-controlled-endpoint` checked for malware/persistence on the device; `?adversary-controlled-account` looked at badge data. Neither hit the cheapest-attack-path the critic identified.

## Sampling-variance correction (third pass)

Reran the same baseline prompt with model=sonnet explicit. **Sonnet baseline this time produced `?session-hijack-or-compromised-jump-host` — "captured agent-forwarded key or ssh-agent socket"** with lead "query bastion-01 auth logs for any agent-forwarding flag on this session." This is the same hypothesis as the critic's T1550.001 critique.

So the original "STRONG novelty" attribution was probably sampling variance, not an architecture effect. With N=1 per condition, the difference between "critic produced T1550.001" and "baseline produced T1550.001" is within the noise floor of stochastic decoding.

**Revised novelty: indeterminate at N=1.** Properly measuring this requires N-trial sampling per configuration to estimate the baseline's lead-set distribution. See `model_comparison.md`.
