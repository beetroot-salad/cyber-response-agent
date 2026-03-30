---
signature_id: wazuh-rule-5710
last_updated: 2026-03-29
total_investigations: 0
resolution_rate: null
---

# Investigation Playbook: SSH Invalid User (5710)

## Hypothesis Catalog

### ?monitoring-probe
Automated health check from an internal monitoring system (Nagios, Zabbix, Prometheus) using a test credential.

**Typical profile:** Internal IP, monitoring-pattern username (testuser, probe, nagios, zabbix, healthcheck), single attempt, regular interval, no follow-up success.

### ?brute-force
Credential guessing attack — external actor systematically trying username/password combinations.

**Typical profile:** External IP, multiple distinct usernames (admin, root, user, test, oracle...), high volume (>5 in 5 min), no successful login, attack wordlist usernames.

### ?credential-stuffing
Leaked credential replay — external actor using credentials from a data breach.

**Typical profile:** External IP, low volume (1-3 attempts), real-looking usernames (not wordlist patterns), no successful login, may correlate with recent breach disclosures.

### ?service-account-rotation
Automated job using stale credentials after a password rotation event.

**Typical profile:** Internal IP, service account pattern (svc-*, backup-*, cron-*, ansible-*), regular timing (cron-like), no successful login, recurring daily/weekly.

---

## Lead List

### authentication-history
**Query:** Failed logins from same srcip in last 5 minutes + successful logins from same srcip within 60s after alert.

**Discriminates:** All four hypotheses.

| Hypothesis | Prediction |
|------------|------------|
| ?monitoring-probe | Single attempt, no success, monitoring-pattern username |
| ?brute-force | Multiple attempts (>5), multiple distinct usernames, no success |
| ?credential-stuffing | 1-3 attempts, real-looking usernames, no success |
| ?service-account-rotation | Single attempt, service account username, no success, same alert recurring |

### source-reputation
**Query:** IP classification (internal/external) + historical alerts from same srcip across all rules.

**Discriminates:** Internal vs external hypotheses.

| Hypothesis | Prediction |
|------------|------------|
| ?monitoring-probe | Internal IP, other monitoring-related alerts from same source |
| ?brute-force | External IP, possibly seen in other attack patterns |
| ?credential-stuffing | External IP, likely no prior alerts |
| ?service-account-rotation | Internal IP, same alert recurring on schedule |

### recent-alert-correlation
**Query:** Other alerts from same agent (target host) in last 24 hours, especially rules 5712 (brute force composite), 5501/5715 (successful login).

**Discriminates:** Escalation signals.

| Hypothesis | Prediction |
|------------|------------|
| ?monitoring-probe | No correlated alerts (or only other monitoring noise) |
| ?brute-force | May have 5712 (brute force composite), multiple 5710s |
| ?credential-stuffing | Isolated alert, no composite triggers |
| ?service-account-rotation | Same 5710 recurring at regular intervals |

### username-analysis
**Query:** Examine the attempted username(s) against known patterns.

**Discriminates:** Monitoring vs attack vs service accounts.

| Hypothesis | Prediction |
|------------|------------|
| ?monitoring-probe | Username matches monitoring patterns: testuser, probe, nagios, zabbix, healthcheck |
| ?brute-force | Usernames from common attack wordlists: admin, root, user, test, oracle, postgres |
| ?credential-stuffing | Real-looking usernames that don't match obvious patterns |
| ?service-account-rotation | Service account patterns: svc-*, backup-*, cron-*, ansible-* |

---

## Screen

Fast-path patterns for automated resolution. The screen subagent checks these before the full investigation loop.

| Pattern | Indicators | Leads | Action | Precedent |
|---------|-----------|-------|--------|-----------|
| monitoring-probe | srcip: internal, username: monitoring-pattern (testuser/probe/nagios/zabbix/healthcheck), attempt_count: 1, successful_login_after: false | authentication-history, source-reputation | resolve → benign | monitoring-probe-001.json |

---

## Start With

**`authentication-history`** — It discriminates all four hypotheses in a single query and provides the most diagnostic information up front.

Follow with `source-reputation` to confirm internal/external classification, then `username-analysis` if the pattern isn't yet clear.

---

## Auto-Close Criteria

All must be true:
1. Exactly one hypothesis remains with `++` support
2. All adversarial hypotheses (brute-force, credential-stuffing) have `--` refutation
3. A matching precedent exists in `precedents/`
4. No escalation triggers present
5. `confidence` is `high`

## Escalation Criteria

Escalate immediately if ANY:
- External IP with >5 failures in 5 minutes
- Multiple distinct usernames from same external IP
- No hypothesis reaches `++` after pursuing all leads
- Evidence contradicts all hypotheses
- Critical asset involved (check signature context and organizational knowledge)
- Successful login follows from external IP (potential compromise)

## Scope

Investigation covers the alerting event and its immediate context (5-minute window before, 60-second window after). Do not expand scope beyond the signature's detection domain without escalating.
