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

## Classification Logic

1. Match against known service account patterns → **automated / service**
2. Match against admin patterns → **privileged / human admin**
3. Common attack-wordlist names (admin, root, user, test, oracle, postgres) → **generic** (high collision with both default accounts and brute-force wordlists; the label alone is not diagnostic)
4. Real-looking but unrecognized username → **unknown** (not in any known pattern set for this org)
