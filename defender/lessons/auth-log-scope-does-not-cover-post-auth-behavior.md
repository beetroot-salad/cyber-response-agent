---
name: auth-log-scope-does-not-cover-post-auth-behavior
description: Auth-log leads expose login events only; claiming post-auth behavioral cleanliness requires a separate process-execution or network lead on the landing host.
source_finding_ids:
  - live-cross-tier-pivot-1/0
  - live-cross-tier-pivot-1/1
created_at: 2026-06-04T00:00:00Z
---

You ran a sshd-auth-baseline lead on the landing host and found no novel auth events. You then wrote "post-auth unremarkable" as a general behavioral conclusion. That verdict is out of scope for the evidence: auth logs record accept/reject events — they are structurally blind to commands executed, files written, crontab entries installed, and outbound connections after the session opened.

**The rule:** A sshd-auth lead can only refute (or support) hypotheses about *who authenticated* and *how*. It cannot speak to what the session did afterward.

If your hypothesis branch includes post-authentication actions (network scanning, persistence installation, lateral movement), you need at least one of:
1. A **process-execution lead** on the landing host (auditd execve, EDR process telemetry, or equivalent) covering the session window.
2. An **outbound-network lead** on the landing host covering the session window (flow records, netstat snapshots, firewall logs).
3. A **file-integrity or crontab-state lead** if persistence is in scope.

If those sources are unavailable, record the gap explicitly in `ceiling_test`, naming the landing host and the data source needed — not the auth lead that already ran. An absence of novel auth events is not a proxy for post-auth behavioral cleanliness.
