---
id: wazuh.sudo-commands
status: established
---

## Goal

Retrieve sudo and privileged command executions recorded by Wazuh on a given
host and/or for a given user. Covers PAM sudo, sudo rule fires (rule.groups:sudo),
and syslog-sourced sudo events. Used to characterize what privileged actions a
session performed — config changes, service restarts, user additions — and whether
the command list is consistent with a stated work item.

## What to summarize

- Count of sudo invocations in the window
- Commands executed (full command strings if available in `data.command` /
  `full_log`)
- User who ran sudo (`data.srcuser`) and target user (`data.dstuser`, usually root)
- Timing — first and last sudo event; gap between auth and first sudo
- Any failed sudo attempts (authentication failure or policy denial)

## Query

```bash
python3 defender/scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:sudo${host_clause}${user_clause}' \
  --window ${window} \
  --run-dir ${run_dir}
```

`${host_clause}` is `" AND agent.name:<host>"` when filtering by host, empty
otherwise. `${user_clause}` is `" AND data.srcuser:<user>"` when filtering by
the invoking user, empty otherwise.

## Common pitfalls

- `data.srcuser` is the user who ran sudo; `data.dstuser` is the target (root).
  Binding `data.dstuser:jsmith` finds cases where jsmith was impersonated, not
  where jsmith ran sudo.
- Command string may be in `full_log` rather than a dedicated `data.command`
  field depending on Wazuh decoder version. Check the Sample events in raw
  payload if `data.command` is absent.
- A missing sudo entry does not rule out privilege escalation — SUID binaries,
  capabilities, and direct root SSH do not go through sudo. Report absence
  accurately and note the caveat.
- Very short windows may capture zero events even when sudo ran, if the Wazuh
  agent flush interval is longer than the window.
