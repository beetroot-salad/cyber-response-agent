## CONTEXTUALIZE

**Alert:** FIM-2026-0418-0117 — file-integrity-monitoring detected a modification to `/etc/cron.d/backup-tasks` on `prod-api-02`. New entry added at line 14: `*/15 * * * * root /usr/local/sbin/sync-metrics.sh`. The referenced executable `/usr/local/sbin/sync-metrics.sh` did not exist prior to the alert (no corresponding package-installed or FIM-whitelisted creation). Modification timestamp: 2026-04-18T03:47:22.004Z (off-hours).
**Source/target entity:** `prod-api-02` (10.0.3.27) — production API host, criticality High, part of the customer-facing web stack. Self-hosted (both anchor and target of the file modification).
**Key observables:**
- auditd `type=PATH` + `type=SYSCALL` records are available for the write — the modifying process's pid, uid/euid, parent pid, session id, and the full command-line of the syscall-invoking process can be recovered via follow-up query. The FIM alert payload itself contains only the file path + old/new inode + the high-level SYSCALL type (`openat` with `O_WRONLY|O_TRUNC`).
- uid of the modifying syscall: `0` (root).
- `/usr/local/sbin/sync-metrics.sh` content (read post-modification by FIM): invokes `curl` to POST to `https://metrics-ingest.hosted-vendor.example/v1/ingest` with system stats; calls `logger` on error. Sh-shebang, no obvious obfuscation.
- No prior tickets referencing `sync-metrics.sh`, `metrics-ingest.hosted-vendor.example`, or metrics ingestion changes on `prod-api-02`.
- No recent package-management events on `prod-api-02` in the 24h window preceding the modification (apt/yum/rpm history clean).
**Playbook hypotheses:** N/A — novel alert, no signature-specific playbook for FIM modifications to `/etc/cron.d/` on a production API host.
**Available leads:** `auditd-syscall-audit` (recover the modifying process's pid/ppid/sid + full command-line from auditd records at T), `session-audit` (SSH/login sessions on prod-api-02 in the T−30min to T window), `cm-deploy-audit` (config-management control plane — Ansible Tower / SaltStack / Puppet / Chef — query for any deploy run targeting prod-api-02 near T), `package-history` (apt/yum/rpm transaction logs), `script-analysis` (static + sandbox on `sync-metrics.sh`), `network-flow` (historical outbound from prod-api-02 to `metrics-ingest.hosted-vendor.example` or its resolved IP).
**Archetype matches:** N/A (no signature-specific archetypes).
**Data environment:** auditd READY (full syscall logging, 72h retention); CM control plane READY (Ansible Tower, queryable via API); session-audit READY; netflow READY; threat-intel READY.
**Ticket-context:** no prior investigations naming `prod-api-02` + `/etc/cron.d/`; no prior FIM modifications to `/etc/cron.d/` on any production API host in the 90-day retention window (novel pattern).
