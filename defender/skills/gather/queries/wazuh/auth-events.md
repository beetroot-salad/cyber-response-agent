---
id: wazuh.auth-events
---

## Goal

Retrieve authentication events (sshd login success/failure, sudo, PAM)
from the Wazuh alerts index, filtered by any combination of host, user,
and source IP. Used to characterize who is logging in where, from where,
with what success rate. Covers the by-host and by-user analyst questions
under one template — bind whichever filters the lead needs.

## What to characterize

- Source IP diversity (count of distinct `data.srcip`, top sources)
- Username diversity (count of distinct `data.dstuser`, top usernames)
  — when not already bound as a filter
- Host diversity (count of distinct `agent.name`, top hosts)
  — when not already bound as a filter
- Auth methods (`publickey`, `password`, etc., counts)
- Success/failure ratio (`rule.groups:authentication_success` vs
  `authentication_failed`)
- Timing pattern (burst, periodic, irregular) over the window
- Volume — total events and events/hour

## Query

```bash
python3 soc-agent/scripts/tools/wazuh_cli.py query \
  --query 'rule.groups:(authentication_success OR authentication_failed)${host_clause}${user_clause}${srcip_clause}' \
  --window ${window} \
  --run-dir ${run_dir}
```

`${host_clause}` is `" AND agent.name:<host>"` when filtering by host,
empty otherwise. Same shape for `${user_clause}` (`data.dstuser:<user>`)
and `${srcip_clause}` (`data.srcip:<ip>`). Bind whichever the lead
requires; leave the rest empty.

## Filter binding

Filters are mutually composable; bind only the ones the lead actually
fixes. Each filter takes a literal value of a specific shape:

- `host` → `agent.name:<hostname>` (Wazuh agent name, e.g. `bastion-01.corp`).
- `user` → `data.dstuser:<username>` (the destination/target username).
- `srcip` → `data.srcip:<IPv4>` (a literal address, e.g. `10.42.7.183`).
  **Never bind a hostname here** — `data.srcip` is indexed as IP, so a
  hostname literal silently matches zero events. To answer "events
  where the source is host X," resolve X to its IP first or filter on
  `agent.name` if the question is about events recorded by host X's
  agent.

The template is for **inbound authentication events recorded by the
target's agent**. Asking "did host X originate outbound auth" is a
different measurement (process / sshd-client telemetry, not the
alerts index) and is not in scope for this template — escalate as an
unrunnable lead rather than misbinding `srcip` to host X.

## Common pitfalls

- NAT collapse: a single `data.srcip` may aggregate many real sources;
  inspect username diversity and session ids before claiming "single
  origin."
- Window edges: same-second bursts straddle window boundaries. Bracket
  with a forward lookahead (e.g. `--end T0+60s`) when the alert
  timestamp is the leading edge.
- Service accounts vs human accounts have very different shapes; cross
  with `environment/context/identity-patterns` if available.
- Stale credentials cause periodic failures after password rotation —
  looks like low-grade brute force but isn't.

## Baseline

When deviation framing is in play (rate / volume claims, "new source
IP" claims), shift the window 7 days earlier (or 30 days for sparse
identity patterns) and re-run with the same filter binding. Compare
keys per-key — host set, source IP set, timing distribution.
