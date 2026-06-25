---
case_id: e2e-v2sshd-338
disposition: inconclusive
confidence: medium
---

`v2-sshd-success-after-failures` on `office-ws-1`: all 3 failure events and the `dev.dana` success originated from `::1` (IPv6 loopback) in a 2-second automated cadence using password auth (l-001), confirming H2 (`?local-process-ssh-to-localhost`) — a local process on the host SSH'd to its own sshd — and directly refuting H1 (external scanner). `dev.dana` is an authorized active developer with sudo on this host (l-002, ac1: authorized) and is the CMDB-documented owner with no services or outbound trust edges configured (l-003); no persistence artifacts were installed post-session (authorized_keys empty across all accounts, sshd_config unchanged, l-005). The case cannot be closed benign because the initiating process is unidentifiable: process-execution telemetry (auditd/execve) is not collected on this non-containerized host (l-004 ceiling), and Zeek outbound data was inaccessible due to a permission gate (l-006 ceiling); CMDB documents no automation that would affirmatively explain the loopback-SSH retry pattern. Escalating inconclusive at medium confidence — behavioral indicators are broadly benign but the process identity gap, combined with no documented automation baseline, prevents clearing the initiating cause per `behavioral-anomaly-needs-affirmative-explanation`.
