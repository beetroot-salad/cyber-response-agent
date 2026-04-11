---
tags: [trust-anchor, authorization, automation]
provides: [scheduled-jobs]
---

# Scheduled Jobs

Confirms whether observed automated activity corresponds to a documented,
sanctioned scheduled job — source, target, identity, and cadence all
match a declared entry.

## Epistemic note

This anchor is the sanction counterpart to
`environment/context/identity-patterns.md`. Identity patterns classify
usernames as *service-account-shaped* (`svc-*`, `backup-*`, `cron-*`,
`ansible-*`); this anchor answers **which** specific service-account
activity is expected, on which schedule, from which source, against
which target.

A match here is load-bearing evidence that an alert matching a service-
account shape is in fact that service account doing its documented job.
A miss is a refutation, not just a non-confirmation — service-account-
shaped activity *without* a documented job is exactly the case this
anchor exists to flag.

## Question answered

For a given `(srcip, srcuser, target_host, alert_time)` tuple, is there
a declared scheduled job whose source, target, identity, and schedule
all match?

## Available systems

<!-- Example — replace with actual org systems
| System | Coverage | Access | Priority |
|--------|----------|--------|----------|
| Config management inventory (Ansible / Puppet / Chef) | Declarative job definitions | Git / API | Primary |
| Cron deployment registry | Per-host crontabs under version control | Git | Primary for host-local jobs |
| Rundeck / Jenkins scheduled runs | Ad-hoc scheduled tasks | API | Secondary |
| Internal scheduled-jobs wiki | Legacy / manually-tracked jobs | Scrape | Last resort |
-->

## Query

<!-- Example
`MCP: job_registry.find_active(srcip, srcuser, target_host, at_time, window=±5min)`
Returns: list of { job_id, source, target, identity, schedule, window_start, window_end, owner } or empty list
-->

## Playground Deployment

| Job | Source | Target | Identity | Schedule | Notes |
|-----|--------|--------|----------|----------|-------|
| `monitoring-host cron` | `172.22.0.10` | `target-endpoint` | monitoring-pattern usernames | every ~10 min | see `approved-monitoring-sources.md` for the SSH-probe specifics |

No other scheduled jobs exist in the playground deployment. Any
automated SSH activity that is not the monitoring cron is **not**
sanctioned by this anchor.

## Confirmation shape

A confirmation returns at least one job whose:

- Source matches the alert's `srcip`
- Target matches the alerting host
- Identity matches the alert's `srcuser`
- Schedule window contains the alert timestamp
- Job type is consistent with the observed activity (an SSH-health-check
  job for a 5710-shaped alert, a backup job for a file-read-shaped alert,
  etc.)

A job that runs on a *different* cadence than observed is not a
confirmation — it's evidence of something imitating the job's identity.

## Failure modes

- **Anchor unavailable / registry down:** escalate.
- **No matching job:** refutation. Service-account-shaped activity
  without a registered job entry is the core adversarial case this
  anchor catches — escalate with the closest near-miss cited.
- **Job exists but schedule window is outside the alert time:** escalate
  with the job cited so the analyst can investigate whether the job
  is misfiring or whether its credentials are being reused.
- **Job type mismatch with observed activity:** escalate with the job
  cited.
