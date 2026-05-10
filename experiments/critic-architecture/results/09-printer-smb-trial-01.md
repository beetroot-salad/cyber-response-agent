# Trial 09-01 — printer-anomalous-smb

Fixture: `09-printer-anomalous-smb` (label: escalate-target, expected: ESCALATE)

## Defender
Claim: zero-baseline behavior with no host telemetry to ground benign explanation; **escalate** (suspicious).
Load-bearing assumption: source IP in SMB audit not spoofed — kerberos ticket genuinely originated from printer's NIC, not replayed from elsewhere.

## Critic
Verdict: **CRITIQUE** (benign-direction).
Mechanism: PrintCo firmware 5.18.2 (or recent config push) added SMB scan-to-folder / address-book health probe that opens session, tears down at 30s idle without enumerating.
Lead: printer admin web UI scan-to-folder destinations diffed against fileserver-prod-01 share list; fw 5.18.2 release notes / config-change timestamp.
Prediction: configured SMB destination + recent fw/config change timestamp → de-escalate; absent → escalate stands.

## Baseline (single-agent)
Hypotheses: `?scan-to-folder-misconfig` (admin web UI scan-to-SMB destinations), `?ad-gpo-or-print-server-driven-probe`, `?adversary-controlled-printer-firmware` (netflow non-SMB egress, additional internal targets), `?adversary-controlled-kerberos-ticket-theft` (DC 4768/4769 source IP), `?fileserver-side-trigger` (reverse SMB), `?baseline-artifact` (audit policy change history).

## Comparison
**Critic novelty: none.** Baseline's `?scan-to-folder-misconfig` covers the same admin-UI check with the same lead. Critic adds the firmware-changelog timestamp angle (when the feature was introduced) — minor incremental. Baseline broader (6 hypotheses including kerberos ticket theft check).

Verdict mismatch (expected ESCALATE, got CRITIQUE). Like fixture 08, the fixture didn't actually corner the critic into ESCALATE — the printer admin web UI is enough of an observable.
