---
id: host-query.ssh-audit-by-user
params: [user, host, window]
data_tags: [ssh-sessions]
baseline: optional
---

## Goal

Retrieve detailed ssh session audit for a user on a host over a time
window: auth method, key fingerprint, agent-forwarding flag, parent
session lineage, exec sequence. Used when an alert raises a question
about session provenance the SIEM correlation alone cannot answer.

## What to characterize

- Auth method per session (`publickey`, `password`, `gssapi`)
- Key fingerprint(s) presented
- Agent-forwarding flag — and whether agent-forwarding has been seen
  for this user on this host before
- Parent session id and parent-pid lineage (the upstream hop chain
  that delivered the inbound connection)
- Exec sequence — first ~10 commands run after auth
- TTY allocation

## Query

```bash
python3 soc-agent/scripts/tools/host_query.py ssh-audit \
  --user ${user} --host ${host} --window ${window} \
  --run-dir ${run_dir}
```

## Common pitfalls

- Agent-forwarding is the cheap pivot for stolen-credential / stolen-key
  scenarios (T1550.001). A `false → true` flip on agent-forwarding for
  a user that has never used it on this host before is a strong
  signal; absolute "agent-forwarding seen" without the
  first-time-for-this-user qualifier is not.
- Parent session lineage is only as authoritative as the upstream hop
  audits; gaps in the chain (missing login session on a claimed
  upstream) are themselves findings.

## Baseline

When the lead asks "is this normal for this user on this host," the
optional baseline pulls 180-day session history for the same
`(user, host)` pair: count of agent-forwarded sessions, set of source
IPs, mean session length.
