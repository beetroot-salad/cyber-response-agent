---
signature_id: wazuh-rule-5710
name: SSH Invalid User
severity: medium
data_sources:
  - auth-events
created_at: 2024-11-15
updated_at: 2026-04-08
mitre:
  tactics: Initial Access
  techniques: T1110
references: null
related_signatures:
  - wazuh-rule-5712
base_rate:
  benign_pct: null
  sample_size: null
---

# Wazuh Rule 5710: SSH Invalid User

## Signature Logic

Wazuh built-in rule. The fundamental detected activity: **OpenSSH's `sshd`
process logged an authentication attempt for a username that does not
exist on the host.** OpenSSH writes this to `auth.log` (Debian/Ubuntu) or
`/var/log/secure` (RHEL family) before any password or key check happens.

The Wazuh sshd decoder parses the syslog line and extracts `srcip` and
`srcuser`. The parent rule 5700 catches all sshd messages; rule 5710 is a
child that matches the "Invalid user ..." pattern.

**Log pattern:**
```
Invalid user <username> from <IP> port <port>
```

**Example:**
```
Nov 15 02:30:00 server sshd[12345]: Invalid user testuser from 10.0.1.50 port 54321
```

## Related Rules

| Rule ID | Description | Relationship |
|---------|-------------|--------------|
| 5700 | sshd messages grouping | Parent rule (always fires first) |
| 5501 | SSH successful login | Check for subsequent success (compromise indicator) |
| 5715 | SSH authentication success | Check for subsequent success |
| 5712 | SSH brute force attack | Composite rule that fires when 5710 repeats |

## Threat & Motivation

**What the activity is.** Someone connected to the SSH port and submitted
a username that doesn't exist on the host. sshd logs this *before* the
password/key check, so we know nothing about credentials yet — only that
the username was wrong.

**Why an attacker would do this.** Brute-force credential guessing
(MITRE T1110). Attackers typically don't know what usernames exist on a
target, so they iterate through common ones (`admin`, `root`, `oracle`,
`postgres`, ...). Each invalid attempt produces this rule.

**Concrete attacker scenarios:**
- Mass scanning bot iterating a wordlist against SSH-exposed hosts
- Targeted enumeration trying to discover real account names before
  switching to password attacks
- Credential stuffing using usernames leaked from a third-party breach

**Legitimate reasons this fires.** Common in real environments:
- Monitoring systems using a test credential to verify SSH availability
- Users mistyping their username (often followed by a successful login)
- Service accounts using stale credentials after a password/account rotation
- Internal security scanners during approved assessment windows

**Blast radius if real.** Each individual 5710 doesn't grant access — the
auth check fails by definition. The risk is what *follows*: if the
attacker eventually guesses a valid username and password, they get a
shell on the host with that user's privileges.

## Risk Indicators

The risk on this signature comes from **two orthogonal axes**:

### Axis 1 — Source trust

Where did the connection originate?

- Internal RFC1918 source IP, especially from a known monitoring,
  scanner, or jumpbox subnet (lower risk)
- External source IP, no prior history (higher risk)
- External source IP that has fired other rules in the recent past
  (higher risk)

### Axis 2 — Pattern shape

Does this look like a single misfire or like an attack in progress?

- Single attempt, single username, especially a username that fits a
  recognized monitoring or service-account pattern (lower risk)
- Multiple attempts in a short window, multiple distinct usernames,
  usernames from common attack wordlists (higher risk; rule 5712 may
  also fire)
- Followed by a successful login from the same source (higher risk —
  potential compromise; check rules 5501 / 5715)

A trusted source + single-shot pattern is the low-risk quadrant. An
external source + high-volume / multi-username pattern is the high-risk
quadrant.
