---
id: elastic.sudo-commands-svc-config-mgmt
status: established
filter_keys:
  index: logs-system.auth-*
  predicates:
    - {event_attr: host, op: eq, param: host}
---

## Goal

Sudo and privilege-escalation audit records in `system.auth` on a specific host within a time window. Use to enumerate commands executed under elevated privileges after an SSH login, identify the user invoking sudo, and detect unexpected privileged command execution. Keywords: sudo, COMMAND, PAM, privilege escalation, USER_CMD, system.auth, TTY, CWD.

## What to summarize

- Count of sudo COMMAND entries in the window
- Distinct users appearing in sudo log lines (USER= field embedded in `message`)
- Commands invoked (COMMAND= value extracted from `message`)
- TTY associated with each sudo invocation (TTY= field in `message`)
- Time distribution of sudo events (clustered vs. spread across the window)

## Filter binding

- `${host}` — hostname to filter on (`host.name`)
- `${start}`, `${end}` — time window bounds (ISO format)
- `${limit}` — row cap; 100 is typical for short investigation windows

## Query

```
data_stream.dataset: "system.auth" AND host.name: "${host}" AND (message: *"sudo"* OR message: *"COMMAND"*)
```

## Common pitfalls

- **Structured fields are not parsed.** Sudo audit records embed structured fields (TTY=, PWD=, USER=, COMMAND=) in the `message` string — Filebeat does not extract these into separate indexed fields. Extract by pattern match on the raw message.
- **Broad `sudo` filter.** `message: *"sudo"*` matches more than COMMAND lines — it also captures "pam_unix(sudo:session): session opened for service sudo" and similar session records. Use `message: *"COMMAND"*` to isolate executed command lines, or keep both terms to see the full sudo session lifecycle.
- **Same dataset as sshd auth events.** Sudo audit records land in `data_stream.dataset: "system.auth"` alongside sshd Accepted/Failed lines. A host-only filter without the sudo/COMMAND message filter will return the full auth stream.
