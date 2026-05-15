# Inputs

## alert

```json
{
  "rule": {"id": 5710, "level": 5, "description": "sshd: attempt to login using a non-existent user."},
  "agent": {"name": "bastion-01", "ip": "10.4.2.18"},
  "data": {
    "srcip": "172.22.0.10",
    "srcuser": "ansible",
    "auth_attempts_window_s": 8,
    "auth_attempts_count": 1
  },
  "timestamp": "2026-05-14T01:07:33Z"
}
```

## actor_archetype

`external`

## actor_input

The defender ran these leads, in order:

1. `wazuh.alerts-by-srcip` — params: `{srcip: "172.22.0.10", window_start: "2026-05-13T00:00:00Z", window_end: "2026-05-14T02:00:00Z"}`
2. `wazuh.auth-events-by-srcip` — params: `{srcip: "172.22.0.10", window_start: "2026-05-14T00:00:00Z", window_end: "2026-05-14T02:00:00Z"}`
3. `host-query.cmdb-lookup-by-ip` — params: `{srcip: "172.22.0.10"}`

## mitre_menu

| ID | Name | Tactic |
|---|---|---|
| T1592.002 | Gather Victim Host Information: Software | Reconnaissance |
| T1595.002 | Active Scanning: Vulnerability Scanning | Reconnaissance |
| T1110.003 | Brute Force: Password Spraying | Credential Access |
| T1110.001 | Password Guessing | Credential Access |
| T1078 | Valid Accounts | Defense Evasion / Initial Access |
| T1133 | External Remote Services | Initial Access |
| T1071.001 | Web Protocols | Command and Control |
| T1090.003 | Proxy: Multi-hop Proxy | Command and Control |
| T1018 | Remote System Discovery | Discovery |
| T1082 | System Information Discovery | Discovery |
| T1021.004 | Remote Services: SSH | Lateral Movement |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion |
