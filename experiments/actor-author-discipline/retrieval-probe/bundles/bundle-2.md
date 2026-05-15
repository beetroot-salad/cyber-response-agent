# Inputs

## alert

```json
{
  "rule": {"id": 100001, "level": 12, "description": "Falco: Suspicious shell spawned in container outside dev-allowlist."},
  "agent": {"name": "target-endpoint", "ip": "10.4.2.42"},
  "data": {
    "container.id": "8a3f2c19b0e1",
    "container.image.name": "k8s-runner-prod:1.18.4",
    "proc.name": "bash",
    "proc.pname": "runc",
    "proc.cmdline": "bash",
    "user.uid": 0,
    "user.loginuid": -1
  },
  "timestamp": "2026-05-14T09:42:11Z"
}
```

## actor_archetype

`external`

## actor_input

The defender ran these leads, in order:

1. `wazuh.alerts-by-host` — params: `{host: "target-endpoint", window_start: "2026-05-14T09:00:00Z", window_end: "2026-05-14T10:00:00Z"}`
2. `host-query.process-tree-by-pid` — params: `{host: "target-endpoint", container_id: "8a3f2c19b0e1", pid_window_start: "2026-05-14T09:42:00Z", pid_window_end: "2026-05-14T09:43:00Z"}`
3. `host-query.docker-exec-history` — params: `{host: "target-endpoint", container_id: "8a3f2c19b0e1", window_start: "2026-05-14T09:00:00Z", window_end: "2026-05-14T10:00:00Z"}`
4. `wazuh.auth-events-by-host` — params: `{host: "target-endpoint", window_start: "2026-05-14T08:00:00Z", window_end: "2026-05-14T10:00:00Z"}`

## mitre_menu

| ID | Name | Tactic |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1133 | External Remote Services | Initial Access |
| T1610 | Deploy Container | Execution |
| T1059.004 | Unix Shell | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1078 | Valid Accounts | Defense Evasion / Initial Access |
| T1525 | Implant Internal Image | Persistence |
| T1611 | Escape to Host | Privilege Escalation |
| T1552.001 | Credentials in Files | Credential Access |
| T1071.001 | Web Protocols | Command and Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
