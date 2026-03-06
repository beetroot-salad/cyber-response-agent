# Rule: [SIGNATURE-ID]

> Replace this template with actual rule documentation

## Overview

- **Rule ID**: [e.g., wazuh-rule-5710]
- **Source**: [e.g., Wazuh, Falco, Custom]
- **Severity**: [Low/Medium/High/Critical]
- **Description**: [Brief description of what triggers this rule]

## Alert Fields

| Field | Description | Example |
|-------|-------------|---------|
| `srcip` | Source IP address | `10.0.1.50` |
| `srcuser` | Username attempted | `admin` |
| `agent` | Host where alert fired | `web-server-01` |

## Log Pattern

```
[Example log entry that triggers this rule]
```

## Risk Indicators

### Lower Risk (likely benign)
- Internal IP addresses (RFC1918)
- Known service account patterns
- Business hours activity
- Single attempt followed by success

### Higher Risk (potential threat)
- External IP addresses
- Multiple distinct usernames
- High frequency attempts
- After-hours activity
