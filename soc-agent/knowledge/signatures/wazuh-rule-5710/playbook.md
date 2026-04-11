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
checks these before the full investigation loop. Indicators are
**semantic predicates** — classifications derived from the environment
knowledge base, not raw alert-field comparisons. The screen subagent
must run the listed leads to obtain the evidence each indicator
references; pure alert-field matching is not sufficient.

| Pattern | Indicators | Leads | Action | Precedent |
|---|---|---|---|---|
| monitoring-probe | `source_classification: internal-monitoring-host` (resolved via `knowledge/environment/context/ip-ranges.md`) AND `username_classification: monitoring-pattern` (resolved via `knowledge/environment/context/identity-patterns.md`) AND `attempt_count_5min <= 2` AND `successful_login_after_60s: false` | authentication-history (scoped to `data.srcip:<srcip>`, 5-minute window before + 60-second window after the alert timestamp — this query is the evidence source for the attempt_count and successful_login_after indicators) | resolve → benign, confidence high | monitoring-probe-001.json |

**Indicator resolution:**

- **source_classification** — map the alert's `data.srcip` to a classification using `environment/context/ip-ranges.md`. Only `internal-monitoring-host` counts. `internal` alone is not sufficient — an unclassified internal IP is not a known monitoring source.
- **username_classification** — map the alert's `data.srcuser` to a pattern in `environment/context/identity-patterns.md`. The monitoring pattern matches usernames from the "Monitoring" row (nagios, zabbix, prometheus, and explicit aliases like testuser, probe, healthcheck, monitorprobe, sensu).
- **attempt_count_5min** — from the `authentication-history` lead: how many 5710 events from this srcip in the 5 minutes preceding the alert. The monitoring-probe pattern allows **at most 2** (the alert itself, plus optionally one prior probe tick that fell within the window). Any burst of 3+ disqualifies.
- **successful_login_after_60s** — from the same lead: was there any successful SSH login (rule group `authentication_success`) from this srcip in the 60 seconds after the alert. Monitoring-probe must be **false** — legitimate probes don't follow with a real session.

**Why a real query, not pure field matching:** `attempt_count_5min` and
`successful_login_after_60s` cannot be read from the alert itself — they
describe context that requires querying historical and forward-looking
events. This is by design: without a real query, the screen pattern reduces
to "does the alert look like monitoring?", which the bait workload
(`playground/monitoring-host/workloads/monitoring_bait.sh` — same srcip,
same username family, 5 attempts) would falsely match.

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
