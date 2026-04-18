## CONTEXTUALIZE

**Alert:** NETFLOW-2026-0418-0009 — outbound byte-volume from `prod-api-01` exceeded the 95th-percentile baseline by 5.1× during the 02:00–04:00 UTC window (2026-04-18). Total egress in window: 4.7 GB against a baseline 95th of ~0.9 GB. No concurrent customer-facing traffic spike on the inbound side (no correlated 4xx/5xx storm, no request-rate increase).
**Source entity:** `prod-api-01` (10.0.3.14) — production API host, criticality High, part of the customer-facing web stack. Runs Python/Gunicorn app + sidecar log-shipper + node-exporter.
**Key observables:**
- netflow has per-flow attribution available: each flow carries `src_ip`, `dst_ip`, `dst_port`, `bytes_out`, `bytes_in`, `start_ts`, `end_ts`. Process-to-flow attribution is NOT in netflow itself but is queryable via the host's conntrack + process-socket inventory snapshots (5-minute granularity, retained 24h).
- top destinations by bytes during the window (from netflow, ranked): (1) `s3-prod-backups.aws-region-a.example` — 2.9 GB; (2) `metrics.internal-tsdb.example` — 0.8 GB; (3) `log-aggregator.internal.example` — 0.6 GB; (4) `cdn-origin.vendor-cdn.example` — 0.3 GB; (5) scattered other internal services — 0.1 GB combined.
- all listed destinations resolve to IPs that prod-api-01 has connected to in the 90-day window (no novel destinations).
- the 5.1× multiplier is concentrated on destination (1) — `s3-prod-backups`. Other destinations are within baseline.
- no Falco / EDR alerts on `prod-api-01` in the 24h window preceding the spike.
- app-level logs show the Python app handled normal request volume during the window (no internal error storms, no retry loops visible in app logs).
**Playbook hypotheses:** N/A — novel alert, no signature-specific playbook for off-hours egress-volume anomalies on production API hosts.
**Available leads:** `process-flow-attribution` (query the host's conntrack + process-socket snapshots during the window, join by 4-tuple to flows in netflow → which processes contributed bytes to which destinations), `backup-system-audit` (the org's backup-orchestration system's audit log — was a backup scheduled / triggered for prod-api-01 in the window?), `cm-deploy-audit` (config-management recent changes affecting backup config or log-shipper config on prod-api-01), `script-analysis` (any recently added script on the host running during the window), `object-storage-audit` (S3-bucket access log for `s3-prod-backups` — PUT events in the window, with object keys + sizes + principals).
**Archetype matches:** N/A (no signature-specific archetypes).
**Data environment:** netflow READY (90-day retention, 4-tuple level); host conntrack + process-socket snapshots READY (5-min granularity, 24h retention); backup-system audit READY; CM control plane READY; S3 bucket audit logs READY.
**Ticket-context:** no prior investigations naming `prod-api-01` + off-hours egress; no prior egress-volume anomaly alerts on any production API host in the 90-day window.
