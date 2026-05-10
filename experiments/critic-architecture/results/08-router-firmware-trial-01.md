# Trial 08-01 — router-firmware-anomaly

Fixture: `08-router-firmware-anomaly` (label: escalate-target, expected: ESCALATE)

## Defender
Claim: not characterizable from available telemetry; **escalate** to network eng + vendor TAC.
Load-bearing assumption: control-plane CPU has only the two documented spike triggers (config commit, full reconvergence); a third benign trigger would collapse the cluster to vendor-defect noise.

## Critic
Verdict: **CRITIQUE** (benign-direction, against an escalating defender — symmetric mode).
Mechanism: BGP scheduled soft route-refresh or RPKI/IRR prefix-list refresh from a route-server feed drives control-plane CPU and renegotiates sessions without a config commit.
Lead: `show log | i BGP|02:14|04:31|06:08`, `show bgp neighbor upstream-isp-1` reset reason + refresh counters, prefix-list/route-map mtimes.
Prediction: refresh/hold-expiry reason code on each reset + ~10-20s CPU duration → de-escalate to operational tuning.

## Baseline (single-agent)
Hypotheses (all investigation/escalation-leaning): `?bgp-session-instability-link-layer` (interface counters), `?bgp-control-plane-resource-exhaustion` (CoPP + mgmt-plane query log), `?adversary-controlled-control-plane` (netflow at TCP/179, malformed UPDATEs), `?adversary-controlled-mgmt-plane-access` (TACACS+/RADIUS), `?upstream-or-peer-side-induced-reset` (ISP packet capture), `?syslog-tampering-or-gap` (sequence numbers, NMS traps).

## Comparison
**Critic novelty: STRONG.** Baseline went straight to escalation/investigation across 6 hypotheses, all defensively framed. The critic produced the **most likely benign mechanism** (operational route-refresh) with a concrete vendor-syslog test — none of the baseline hypotheses captured this de-escalation path. This is the clearest case in the run where the architecture earned its complexity: the critic counter-anchored against a defensively-leaning defender to find a cheap disconfirmation.

Verdict mismatch (expected ESCALATE, got CRITIQUE) but the result is *better* than ESCALATE because the produced lead is runnable in vendor syslog (in scope per fixture spec).
