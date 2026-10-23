---
name: post-auth-lead-targets-landing-host-not-source
description: After a suspicious short session, gather post-auth artifacts from the destination (landing) host, not from the source workstation.
telemetry_source: [sshd, fim, auditd]
attack_phase: [persistence, execution]
source_signature: [v2-sshd-success-after-failures]
source_finding_ids:
  - live-sshd-success-1/1
  - live-sshd-success-1/2
created_at: 2026-06-03T00:00:00Z
---

You flagged a 54ms SSH session as suspicious, recorded "process audit on the source workstation" as the ceiling_test gap, and closed without running any lead against the destination host. The attacker's operational phase — key persistence, socket access, log tampering — leaves evidence on the landing host (authorized_keys writes, SSH agent socket files, auth.log mutations), not on the source.

**The rule:** When a session duration, timing, or auth-failure cadence is anomalous and the session successfully reached a remote host:

1. The load-bearing follow-up lead is on the **destination host**, covering the window immediately after the session.
2. Query classes to consider: file-integrity events on SSH config paths (authorized_keys, known_hosts), SSH agent socket enumeration under /tmp/ssh-*, session-scoped process audit, log file size and mtime changes.
3. Misplacing the ceiling_test on the source host hides the attack surface — source attribution and destination artifact recovery are separate questions; do not conflate them.

If host-query coverage of the destination is absent, record that absence explicitly as the ceiling_test gap, naming the **destination hostname** — not the source-side process audit. The ceiling_test entry should identify the landing host, not the originating workstation.
