---
signature_id: wazuh-rule-5710
name: SSH Invalid User
severity: medium
data_sources:
  - sshd
  - /var/log/auth.log
  - /var/log/secure
mitre: T1110 (Brute Force)
base_rate: high
---

# Wazuh Rule 5710: SSH Invalid User

## Signature Logic

Triggers when sshd logs an attempt to login using a non-existent user.

**Log pattern:**
```
Invalid user <username> from <IP> port <port>
```

**Example:**
```
Nov 15 02:30:00 server sshd[12345]: Invalid user testuser from 10.0.1.50 port 54321
```

**Parent rule:** 5700 (sshd messages grouping)

## Alert Fields

| Field | JSON Path | Description | Example |
|-------|-----------|-------------|---------|
| Source IP | `data.srcip` | Connection source IP | `10.0.1.50` |
| Username | `data.srcuser` | Invalid username attempted | `testuser` |
| Agent | `agent.name` | Host where event detected | `web-server-01` |
| Timestamp | `timestamp` | Event time | `2024-11-15T02:30:00Z` |

## Related Rules

| Rule ID | Description | Relationship |
|---------|-------------|--------------|
| 5700 | sshd messages grouping | Parent rule |
| 5501 | SSH successful login | Check for subsequent success |
| 5715 | SSH authentication success | Check for subsequent success |
| 5712 | SSH brute force attack | May fire if pattern continues |

## Threat & Motivation

An attacker attempting SSH brute force aims to gain initial access (MITRE T1110). The invalid user variant means they're guessing usernames, not just passwords — suggesting either:
- Opportunistic scanning (common, low sophistication)
- Targeted enumeration (rare, higher sophistication)

**Blast radius if real:** Full shell access to the target host, potential lateral movement.

## Known False Positives

1. **Monitoring probes** — Health check systems (Nagios, Zabbix) using test credentials. See: `precedents/monitoring-probe-001.json`
2. **User typos** — Legitimate users mistyping their username, followed by successful login
3. **Service account rotation** — Automated jobs using stale credentials after password rotation
4. **Scanner assessments** — Internal security scans during approved assessment windows

## Risk Indicators

### Lower Risk
1. Internal source IP (RFC1918 ranges)
2. Monitoring probe usernames (testuser, probe, nagios, zabbix)
3. Single attempt (no repetition)
4. Successful login follows shortly after
5. Known scanner IP during assessment window

### Higher Risk
1. External source IP
2. Multiple failed attempts (>5 in short window)
3. Multiple different usernames attempted
4. No subsequent successful login
5. Random or common attack usernames (admin, root, user)

## Field Notes

- Base rate is high — most SSH-exposed servers see continuous invalid user attempts from the internet
- Internal-source alerts are far more likely to be benign than external-source
- The username attempted is highly diagnostic: monitoring patterns vs. attack wordlists are distinct
- Time-of-day matters for service accounts (cron patterns) but not for external attacks
