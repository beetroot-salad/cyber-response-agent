## CONTEXTUALIZE

**Alert:** FALCO-2026-0418-0042 — `outbound_connection_unusual_dst` rule fired. Outbound TCP `connect()` from process with `uid=postgres` on `prod-db-03` to external IP `45.77.192.41` on port 443. Timestamp: 2026-04-18T14:22:17.311Z.
**Source entity:** `prod-db-03` (10.0.3.12) — production database host, criticality High+, runs PostgreSQL 15 for the customer-facing web application's primary transactional store. Falco-instrumented (5-minute ingest latency).
**Target entity:** `45.77.192.41` — external. Threat-intel classification: medium-low reputation (observed in scanner / staging infrastructure samples over the last 30 days, not on any confirmed-malicious block-list). Passive-DNS: one recent record — `api.postgresql-telemetry-eu.example` — not verified against vendor's published telemetry endpoint registry.
**Key observables:**
- Falco `evt.type = connect`, `proc.name = postgres`, `proc.uid = 999` (postgres role uid)
- Falco recorded `proc.pname` and `proc.aname[...]` ancestry fields but the alert payload we received contains only the top-level `proc.name`; the ancestry chain is available via follow-up query on the Falco event record.
- First observed connection from `prod-db-03` to `45.77.192.41` in the 90-day passive-netflow retention window.
- Destination port 443, TLS handshake completed (per netflow metadata).
- No concurrent user-facing application anomaly (app health green, latency nominal).
**Playbook hypotheses:** N/A — novel alert, no signature-specific playbook for Falco `outbound_connection_unusual_dst` on a production DB host.
**Available leads:** `process-execution-context` (Falco syscall record + ancestry), `network-flow` (netflow historical query), `query-log-snapshot` (PostgreSQL audit log; note: DDL + long-query logging enabled, short-query audit NOT captured), `session-audit` (SSH + DB-auth sessions on v-001), `extension-inventory` (installed postgres extensions + recent usage).
**Archetype matches:** N/A (no signature-specific archetypes; this is a first-of-kind investigation for this alert type on this host).
**Data environment:** Falco READY (syscall-level events, ~5min latency); netflow READY; PostgreSQL query-log READY for DDL + long-queries only (short-query audit off per performance-tuning standard); session-audit READY; threat-intel READY.
**Ticket-context:** no prior investigations naming `prod-db-03` or `45.77.192.41`; no prior `outbound_connection_unusual_dst` Falco alerts on any production DB host in the last 90 days (novel alert pattern for this environment).
