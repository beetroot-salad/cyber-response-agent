# Trial 04-01 — vuln-scanner-port-scan

Fixture: `04-vuln-scanner-port-scan` (label: true-benign, expected: CONCEDE)

## Defender
Claim: scheduled Tenable scan, benign close.
Load-bearing assumption: scanner host itself not compromised; on-host audit log entry for job 9981 reflects genuine operator-initiated scan, not attacker laundering recon through legitimate scan engine during known maintenance window.

## Critic
Verdict: **CRITIQUE**.
Mechanism: shell on scanner invokes Tenable API/CLI locally to launch job 9981 inside CHG-44120; engine audit log records legitimate-looking entry.
Lead: EDR/auditd parent process of scan-launcher PID; Tenable API/job-creation log creator principal + source.
Prediction: scheduler service ancestor → CONCEDE; interactive shell ancestor → confirms.

## Baseline (single-agent)
Hypotheses: `?authorized-scheduled-scan`, `?adversary-controlled-scanner-host` (EDR process-tree, parent must be nessusd), `?adversary-controlled-scanner-credential` (Tenable audit job-creation source_ip + creator), `?spoofed-source-ip` (switch ARP/MAC), `?scope-creep-misconfig`.

## Comparison
**Critic novelty: none.** Baseline produced both checks the critic produced (process tree + Tenable creator log) with comparable specificity. Verdict mismatch (expected CONCEDE, got CRITIQUE) but the produced lead is fully redundant with baseline.
