---
name: source-host-integrity-unverified
description: when closing benign on an internal-source alert, verify you have a lead characterizing the source host itself — not just its traffic — or explicitly document why traffic evidence alone is dispositive
source_finding_ids:
  - livetest-5710/1
created_at: 2026-05-10T00:00:00Z
---

You classified the source IP as legitimate internal infrastructure based on its outbound traffic pattern. This characterizes *what arrived at the target* but not *what is running on the source*.

The gap: an attacker who has compromised the source host or container inherits its full observed behavior. If the monitoring service naturally cycles through a fixed set of usernames at a regular cadence, a compromised version does the same — SIEM leads characterizing traffic from that IP return identical results in both scenarios.

**Check next time — two paths both work:**

1. **Add a source-host lead**: Before closing benign, issue at least one lead that interrogates the source host itself (process tree, recent container image changes, unexpected child processes, outbound connections that the legitimate service would not make). If this lead confirms normal host behavior, the benign conclusion is well-grounded.

2. **Make the traffic case dispositive**: If no system in scope can reach the source host, ask whether the observed traffic pattern could plausibly be reproduced by an attacker who fully inherits the service's behavior. If yes, document this as a ceiling in `ceiling_rationale` and note the untested surface. If the traffic evidence is nevertheless strong enough to close (e.g., the pattern spans weeks with zero successes and includes only automation-specific account names), explain *why* source compromise would have changed the observable pattern — or acknowledge it wouldn't, and record that as a residual uncertainty in the report.

Do not treat high confidence in the traffic pattern as equivalent to confirmed source legitimacy. They are different claims.
