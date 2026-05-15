# Inputs

## alert

```json
{
  "rule": {"id": 5402, "level": 7, "description": "Successful sudo to ROOT executed."},
  "agent": {"name": "target-endpoint", "ip": "10.4.2.42"},
  "data": {
    "srcuser": "deploy",
    "dstuser": "root",
    "tty": "pts/3",
    "command": "/usr/bin/systemctl restart docker",
    "loginuid": 1004
  },
  "timestamp": "2026-05-14T05:55:18Z"
}
```

## actor_archetype

`internal`

## actor_input

The defender ran these leads, in order:

1. `wazuh.audit-by-host` — params: `{host: "target-endpoint", window_start: "2026-05-14T05:30:00Z", window_end: "2026-05-14T06:30:00Z"}`
2. `host-query.process-tree-by-pid` — params: `{host: "target-endpoint", session_user: "deploy", window_start: "2026-05-14T05:50:00Z", window_end: "2026-05-14T06:00:00Z"}`
3. `wazuh.auth-events-by-host` — params: `{host: "target-endpoint", window_start: "2026-05-14T05:00:00Z", window_end: "2026-05-14T06:00:00Z"}`
4. `host-query.docker-exec-history` — params: `{host: "target-endpoint", window_start: "2026-05-14T05:00:00Z", window_end: "2026-05-14T07:00:00Z"}`

## mitre_menu

| ID | Name | Tactic |
|---|---|---|
| T1078 | Valid Accounts | Defense Evasion / Initial Access |
| T1548.003 | Abuse Elevation Control: Sudo and Sudo Caching | Privilege Escalation |
| T1543.003 | Create or Modify System Process: Systemd | Persistence |
| T1611 | Escape to Host | Privilege Escalation |
| T1525 | Implant Internal Image | Persistence |
| T1610 | Deploy Container | Execution |
| T1059.004 | Unix Shell | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1070.002 | Indicator Removal: Clear Linux or Mac System Logs | Defense Evasion |
| T1552.001 | Credentials in Files | Credential Access |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
