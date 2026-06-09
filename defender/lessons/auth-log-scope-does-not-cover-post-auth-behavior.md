---
name: auth-log-scope-does-not-cover-post-auth-behavior
description: Auth-log leads expose login events only; claiming post-auth behavioral cleanliness on any session host requires a separate process-execution lead covering the session window on that host.
source_finding_ids:
  - live-cross-tier-pivot-1/0
  - live-cross-tier-pivot-1/1
  - live-cross-tier-pivot-2/1
created_at: 2026-06-04T00:00:00Z
---

You ran a sshd-auth-baseline lead and found no novel auth events. You then wrote "post-auth unremarkable" (or equivalent) as a behavioral conclusion. That verdict is out of scope for the evidence: auth logs record accept/reject events — they are structurally blind to commands executed, files written, and connections made after the session opened. This applies to both roles:

- **Landing host**: auth log confirms session accepted; it cannot see what ran inside.
- **Source/workstation host**: auth log confirms account logged in from this machine; it cannot see what the actor ran *within* that session before pivoting onward.

For ControlMaster hijack, the discriminating signal is socket enumeration and `ssh -S` execution on the *source* host inside the session window — not the landing host's auth log.

**The rule:** A sshd-auth lead can only speak to *who authenticated* and *how*. It cannot speak to what the session did afterward, on either end.

If your hypothesis includes post-authentication actions (socket hijack, persistence installation, lateral movement), you need at least one of:
1. A **process-execution lead** on the session host (auditd execve, EDR telemetry) covering the session window.
2. An **outbound-network lead** covering the session window (flow records, firewall logs).
3. A **file-integrity lead** if persistence is in scope (see `authorized-pivot-fim-check-before-close`).

If those sources are unavailable, record the gap in `ceiling_test`, naming the specific host and data source — not the auth lead that already ran. An absence of novel auth events is not a proxy for behavioral cleanliness.
