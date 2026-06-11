---
name: bastion-session-interactivity-signal
description: On bastion logins, check PTY allocation and session duration from sshd or auditd to distinguish interactive human pivots from automated scripts.
telemetry_source: [sshd, auditd]
attack_phase: [lateral-movement]
source_signature: [v2-cross-tier-ssh-pivot]
source_finding_ids:
  - live-cross-tier-pivot-1/2
created_at: 2026-06-04T00:00:00Z
---

You confirmed that a user authenticated to a jump host within their authorization baseline, then closed without checking whether the session was interactive or automated. The attack leg was a minutes-long interactive session with an in-shell discovery script running — exactly the signal that would distinguish it from the sub-second automated config-push on the adjacent leg.

**What to query:** sshd logs and auditd PAM session records expose PTY allocation (`pts/N` vs. no PTY), session duration (open/close delta), and — where auditd is available — per-session command counts via `USER_CMD` or execve records.

**When to run this:** Any time a bastion hypothesis covers an "authorized user within baseline" story where the expected concurrent traffic is automation (cron, CI push, config-management). The pivot bypass depends on the human session resembling routine developer access; PTY + session duration is the cheapest discriminator.

**Red flags:**
- PTY allocated on a jump host leg that should be a non-interactive script.
- Session duration of minutes on a bastion where the automation peer leg is sub-second.
- Non-zero command count on a leg your hypothesis labels as a passive pass-through.

If sshd or auditd coverage of the bastion is absent, record that as the `ceiling_test` gap; do not treat "no alert fired" as evidence the session was non-interactive.
