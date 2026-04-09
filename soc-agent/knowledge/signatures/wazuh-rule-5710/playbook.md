---
signature_id: wazuh-rule-5710
last_updated: 2026-04-09
total_investigations: 0
resolution_rate: null
---

# Investigation Playbook: SSH Invalid User (5710)

This playbook is **steering, not procedure**. The investigation
methodology — hypothesis discipline, lead severity, verification and
scoping, escalation defaults, stop conditions — lives in the
`investigate` skill. This file provides only what is signature-specific.

The archetype catalog under `archetypes/` is partial: only the
escalation archetype `external-bruteforce` is authored so far. The
remaining common patterns are listed below as **starter hypotheses** —
story-shaped candidates the agent should consider during HYPOTHESIZE,
not anchored patterns ready for fast-path resolution.

## Archetypes

| Archetype | One-line description | File |
|---|---|---|
| `external-bruteforce` | High-volume credential guessing from an external source — escalation outcome | `archetypes/external-bruteforce.md` |

## Starter hypotheses

The remaining common patterns for this signature, recorded as starter
stories. Treat these as candidate explanations to consider, not as a
closed catalog.

### ?monitoring-probe
Automated health check from an internal monitoring system using a
test credential. Internal IP, monitoring-pattern username (testuser,
probe, nagios, zabbix, healthcheck), single attempt, regular
interval, no follow-up success.

### ?credential-stuffing
Leaked-credential replay — an external actor using credentials from
a breach. External IP, low volume (1-3 attempts), real-looking
usernames (not wordlist patterns), no successful login. May correlate
with recent breach disclosures.

### ?service-account-rotation
Automated job using stale credentials after a password rotation
event. Internal IP, service account pattern (`svc-*`, `backup-*`,
`cron-*`, `ansible-*`), regular timing (cron-like), no successful
login, recurring on a daily/weekly cadence.

## Screen

Fast-path patterns for automated resolution. The screen subagent
checks these before the full investigation loop. This table covers
the cases that resolve cleanly via mechanical pattern matching,
predating the archetype layer.

| Pattern | Indicators | Leads | Action | Precedent |
|---------|-----------|-------|--------|-----------|
| monitoring-probe | srcip: internal, username: monitoring-pattern (testuser/probe/nagios/zabbix/healthcheck), attempt_count: 1, successful_login_after: false | authentication-history, source-reputation | resolve → benign | monitoring-probe-001.json |

## Starter lead order

1. **`authentication-history`** — failed logins from same `srcip` in
   the last 5 minutes, plus successful logins from same `srcip`
   within 60s after the alert. Discriminates all four stories in a
   single query.
2. **`source-reputation`** — IP classification (internal vs external)
   plus historical alerts from the same `srcip` across all rules.
3. **`username-analysis`** — examine the attempted username(s)
   against known patterns: monitoring (testuser/probe/nagios), attack
   wordlist (admin/root/oracle), service account (`svc-*`/`backup-*`),
   or real-looking.

> **Recent-alert correlation** ("other alerts from this host in last
> 24h", "is this a repeat", "did 5712/5501/5715 also fire") is
> handled by the ticket-context subagent at CONTEXTUALIZE — its
> findings are already in the investigation context. Don't re-execute
> these queries; reference the ticket-context output for escalation
> signals.

## Scope

Standard for this signature: the alerting event and its immediate
context (5-minute window before, 60-second window after). Anything
beyond this requires escalation per the skill's stay-in-scope rule.
