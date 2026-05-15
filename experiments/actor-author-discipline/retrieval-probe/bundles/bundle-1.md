# Inputs

## alert

```json
{
  "rule": {"id": 5712, "level": 10, "description": "sshd: brute force trying to get access to the system. Authentication failed."},
  "agent": {"name": "bastion-01", "ip": "10.4.2.18"},
  "data": {
    "srcip": "172.22.0.43",
    "srcuser": "deploy",
    "dstuser": "deploy",
    "auth_attempts_window_s": 110,
    "auth_attempts_count": 14
  },
  "timestamp": "2026-05-14T03:14:22Z"
}
```

## actor_archetype

`internal`

## actor_input

The defender ran these leads, in order:

1. `wazuh.auth-events-by-host` — params: `{host: "bastion-01", window_start: "2026-05-14T03:00:00Z", window_end: "2026-05-14T03:30:00Z"}`
2. `wazuh.auth-events-by-srcip` — params: `{srcip: "172.22.0.43", window_start: "2026-05-14T02:00:00Z", window_end: "2026-05-14T04:00:00Z"}`
3. `host-query.process-tree-by-pid` — params: `{host: "bastion-01", pid_window_start: "2026-05-14T03:14:00Z", pid_window_end: "2026-05-14T03:15:00Z"}`
4. `wazuh.alerts-by-srcip` — params: `{srcip: "172.22.0.43", window_start: "2026-05-13T00:00:00Z", window_end: "2026-05-14T04:00:00Z"}`

## mitre_menu

| ID | Name | Tactic |
|---|---|---|
| T1078 | Valid Accounts | Defense Evasion / Initial Access |
| T1078.004 | Cloud Accounts | Initial Access |
| T1110.003 | Brute Force: Password Spraying | Credential Access |
| T1110.004 | Credential Stuffing | Credential Access |
| T1021.004 | Remote Services: SSH | Lateral Movement |
| T1059.004 | Unix Shell | Execution |
| T1610 | Deploy Container | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1592.002 | Gather Victim Host Information: Software | Reconnaissance |
| T1071.001 | Web Protocols | Command and Control |
| T1556.003 | Modify Authentication Process: Pluggable Authentication Modules | Credential Access |
