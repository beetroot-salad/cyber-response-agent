---
name: authorized-pivot-fim-check-before-close
description: Before closing an authorized SSH pivot benign, run a FIM or auditd lead on the landing user's authorized_keys; key appends with timestomped mtime produce no auth.log artifact.
telemetry_source: [fim, auditd]
attack_phase: [persistence]
source_signature: [v2-cross-tier-ssh-pivot]
source_finding_ids:
  - live-cross-tier-pivot-2/0
created_at: 2026-06-04T00:00:00Z
---

You confirmed authorization for both legs of a cross-tier SSH pivot and closed benign. You noted a post-auth gap in `ceiling_test` but framed it generically — "session commands, file writes, outbound connections" — without targeting the load-bearing persistence surface for this story class.

The attack path: actor appends a controlled public key to `~/.ssh/authorized_keys` for the landing user, then timestomps the file's mtime to match the oldest pre-existing entry. No auth.log event is produced. Mtime-based integrity checks see no change. The only detection surface is a FIM or auditd lead that recorded the write event at the time it happened.

**The rule:** When a cross-tier SSH pivot resolves as authorized, add a file-integrity or auditd lead before closing:

1. `~/.ssh/authorized_keys` for the landing user on the destination host, covering the session window.
2. `/etc/ssh/sshd_config` on the destination host (config-modification path).

If those sources are unavailable, name them by host and source type in `ceiling_test` — not the generic post-auth gap. "authorized_keys FIM on web-1 (auditd write events) not retrieved" is the correct ceiling entry; "session commands not retrieved" is not.

Authorized disposition does not clear persistence. The landing host's SSH config state at session close is outside what auth logs can see.
