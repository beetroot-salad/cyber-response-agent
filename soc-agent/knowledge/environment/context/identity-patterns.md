---
tags: [identity, classification]
---

# Identity Patterns

## Service Account Conventions

<!-- Example — replace with actual org conventions
| Pattern | Purpose | Expected Behavior |
|---------|---------|-------------------|
| svc-* | Service accounts | Automated, regular timing |
| backup-* | Backup jobs | Nightly, specific hosts |
| cron-* | Scheduled tasks | Cron-interval patterns |
| ansible-* | Config management | Deployment windows |
| nagios, zabbix, prometheus | Monitoring | Regular interval probes |
-->

## Admin / Privileged Account Patterns

<!-- Example — replace with actual org conventions
| Pattern | Privilege Level | Notes |
|---------|----------------|-------|
| adm-* | Domain admin | Should only auth from jump hosts |
| root | Local root | Direct root SSH should be disabled |
-->

## Monitoring Pattern

Usernames used by monitoring systems to probe SSH reachability. These
accounts typically do **not** exist as real users on the target host —
the point is to confirm sshd is answering on port 22, not to actually
log in. A failed-auth event from one of these usernames is expected
background noise from health-check infrastructure, not an attack.

| Pattern | Notes |
|---|---|
| nagios | Nagios core / NRPE |
| zabbix | Zabbix proxy / agent |
| prometheus | Prometheus blackbox exporter |
| testuser | Generic test/probe alias used by legacy monitoring |
| probe | Generic probe alias |
| healthcheck | Generic health-check alias |
| monitorprobe | Custom monitoring probe (playground deployment — see `playground/monitoring-host/workloads/`) |
| sensu | Sensu Go |

**Classification:** `monitoring-pattern` — when matched, the source should
also be classified via `ip-ranges.md`. A monitoring username from an
unknown/external source is NOT a monitoring probe and should be treated
as either credential-stuffing or a wordlist attack.

## Classification Logic

1. Match against known service account patterns → **automated / service**
2. Match against **monitoring pattern** (table above) → **monitoring-pattern** (diagnostic for probe / health-check traffic — pair with source classification from `ip-ranges.md`)
3. Match against admin patterns → **privileged / human admin**
4. Common attack-wordlist names (admin, root, user, test, oracle, postgres) → **generic** (high collision with both default accounts and brute-force wordlists; the label alone is not diagnostic)
5. Real-looking but unrecognized username → **unknown** (not in any known pattern set for this org)
