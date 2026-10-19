---
case_id: ab3-B
disposition: malicious
confidence: high
---

Alert `v2-cross-tier-ssh-pivot` on `dev.dana` is confirmed malicious. Fetching the two anchor events (l-001) revealed: workstation leg = `office-ws-1` accepted password auth for `dev.dana` from loopback (::1) at 13:52:56Z; prod leg = `db-1` received "Invalid user dev.dana" from 172.18.0.14 (office-ws-1's network interface) at 13:52:57Z — one second later. The sshd auth sequence (l-003) showed this pattern repeated three times across a 7-minute window: 12 total failures against db-1 in three bursts of four, at 3–7 second cadence, each burst initiated sub-second after a workstation sshd acceptance — unambiguously automated tooling. The identity oracle (l-002) confirmed dev.dana is provisioned only for `dev-ws-1`, `office-ws-1`, and `jump-box-1`; db-1 is explicitly `authorized: false`, and sshd's "Invalid user" rejection confirms no account exists on db-1. Authz contract ac1 resolves `unauthorized`, forcing escalation. The working story is that automated ssh scanning or lateral-movement tooling is running under dev.dana's session on office-ws-1, probing the database tier from the workstation's own network interface. IR should acquire post-auth process execution on office-ws-1 covering the session window (13:46–13:53Z) to identify the specific tool and any upstream credential-harvest activity.
