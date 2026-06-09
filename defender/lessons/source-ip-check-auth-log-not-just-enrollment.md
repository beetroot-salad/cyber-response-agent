---
name: source-ip-check-auth-log-not-just-enrollment
description: A source IP in a container exec or process alert needs an SSH auth-log query on the receiving host; enrollment records miss sshd entry events.
source_finding_ids:
  - live-falco-nettool-1/2
created_at: 2026-06-04T00:00:00Z
---

You resolved a source IP from the alert against enrollment or asset records (Elastic Agent registration, CMDB, network scan metadata) and concluded it was a known scanner or service host. You did not query the SSH authentication log on the host that would have accepted an inbound connection from that IP. For the attack class where an external actor SSHes in and then uses docker exec to run commands inside a container, the entry-point event lives in `logs-system.auth-*` on the receiving host — not in enrollment data.

Enrollment records identify what a host is; they do not record whether an external IP authenticated to it via SSH moments before the alert fired.

**When a source IP appears in a container exec or process alert:**
1. Look up the IP in enrollment/asset records to establish its identity — but treat that as one data point, not a disposition.
2. Query `logs-system.auth-*` (or the equivalent SSH auth index) on the container's host for sshd Accepted/Failed events in the window just before the alert. A successful `Accepted` from an external or unexpected IP is a first-order entry-point IOC.
3. If the auth index is unavailable or contains no events, name it as a ceiling_test gap — do not assume no entry occurred.

Skipping the auth-log query when a source IP resolves to a "known" host means the most unambiguous external-attacker signal may survive all investigation loops unexamined.
