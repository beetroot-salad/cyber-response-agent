# Wazuh Rule 5710: SSH Invalid User

## Overview

| Property | Value |
|----------|-------|
| **Rule ID** | 5710 |
| **Category** | Authentication / SSH |
| **Severity** | Medium (Level 5) |
| **MITRE ATT&CK** | T1110 (Brute Force) |
| **Parent Rule** | 5700 (sshd messages) |

## Description

Triggers when sshd logs an attempt to login using a non-existent user.

## Log Pattern

```
Invalid user <username> from <IP> port <port>
```

Example:
```
Nov 15 02:30:00 server sshd[12345]: Invalid user testuser from 10.0.1.50 port 54321
```

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

## Data Source

- **Log file**: `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS)
- **Service**: sshd (OpenSSH daemon)
- **Collection**: Wazuh agent log collection

## Lower Risk Indicators

1. Internal source IP (RFC1918 ranges)
2. Monitoring probe usernames (testuser, probe, nagios, zabbix)
3. Single attempt (no repetition)
4. Successful login follows shortly after
5. Known scanner IP during assessment window

## Higher Risk Indicators

1. External source IP
2. Multiple failed attempts (>5 in short window)
3. Multiple different usernames attempted
4. No subsequent successful login
5. Random or common attack usernames (admin, root, user)
