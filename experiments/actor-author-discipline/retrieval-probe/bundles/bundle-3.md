# Inputs

## alert

```json
{
  "rule": {"id": 550, "level": 7, "description": "Integrity checksum changed: /etc/pam.d/sshd"},
  "agent": {"name": "bastion-01", "ip": "10.4.2.18"},
  "syscheck": {
    "path": "/etc/pam.d/sshd",
    "mode": "scheduled",
    "size_before": 2147,
    "size_after": 2418,
    "uname_after": "root",
    "mtime_after": "2026-05-14T03:14:51Z",
    "sha256_after": "8f0a9c…"
  },
  "timestamp": "2026-05-14T03:30:02Z"
}
```

## actor_archetype

`internal`

## actor_input

The defender ran these leads, in order:

1. `wazuh.fim-history-by-path` — params: `{host: "bastion-01", path: "/etc/pam.d/sshd", window_start: "2026-05-13T00:00:00Z", window_end: "2026-05-14T04:00:00Z"}`
2. `host-query.process-tree-by-pid` — params: `{host: "bastion-01", path: "/etc/pam.d/sshd", touch_window_start: "2026-05-14T03:14:00Z", touch_window_end: "2026-05-14T03:16:00Z"}`
3. `wazuh.auth-events-by-host` — params: `{host: "bastion-01", window_start: "2026-05-14T03:00:00Z", window_end: "2026-05-14T04:00:00Z"}`
4. `host-query.find-recent-files` — params: `{host: "bastion-01", paths: ["/lib/security", "/etc/pam.d", "/tmp"], modified_within_minutes: 60}`

## mitre_menu

| ID | Name | Tactic |
|---|---|---|
| T1078 | Valid Accounts | Defense Evasion / Initial Access |
| T1556.003 | Modify Authentication Process: PAM | Credential Access / Persistence |
| T1543.003 | Create or Modify System Process: Systemd | Persistence |
| T1574.006 | Hijack Execution Flow: Dynamic Linker Hijacking | Persistence |
| T1059.004 | Unix Shell | Execution |
| T1027 | Obfuscated Files or Information | Defense Evasion |
| T1070.004 | Indicator Removal: File Deletion | Defense Evasion |
| T1562.006 | Impair Defenses: Indicator Blocking | Defense Evasion |
| T1110.003 | Brute Force: Password Spraying | Credential Access |
| T1021.004 | Remote Services: SSH | Lateral Movement |
| T1083 | File and Directory Discovery | Discovery |
| T1485 | Data Destruction | Impact |
