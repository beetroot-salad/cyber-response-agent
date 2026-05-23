---
id: wazuh.auth-events
status: established
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
- Source port diversity (`unique_source_ports`, rotation pattern) — high
  port rotation (hundreds of distinct ports) is a signature of automated
  tooling; low rotation suggests manual or scripted fixed-config origin

## Query

```bash
python3 defender/scripts/tools/wazuh_cli.py query \
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
- `srcip` → `data.srcip:<IPv4 or IPv6 literal>` (e.g. `10.42.7.183` or
  `2001:db8::1`).

### REFUSE: hostname bound to `srcip`

`data.srcip` is indexed as an IP-typed field. Wazuh silently returns
zero events when the literal is not an IP — there is no error, no
warning, no type-mismatch signal in the response. The empty result
looks identical to "this IP genuinely had no auth activity," and the
defender will read it that way.

**If the lead's intent is "events where the source is host X":**
1. If a separate template resolves X → IP, run that first and rebind
   `srcip` to the resolved literal.
2. If "host X originated outbound auth" is the actual measurement, this
   is **not in scope for this template** — `auth-events` is the
   inbound-auth alerts index. Outbound auth is process / sshd-client
   telemetry, a different system. Refuse the dispatch and report
   "unrunnable: outbound-auth-from-host is not measured by Wazuh
   alerts; needs a different system or template."

A value bound to `srcip` that is not a parseable IP literal is a
configuration error — the gather subagent must refuse to run rather
than executing the query and reporting "0 events."

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
- **`--window` param vs. actual query window.** Observed: passing
  `--window 24h` produced `query_window.duration_hours: 48` in the
  payload — wazuh_cli anchors the window relative to the alert
  timestamp, not the current time, so the effective span can exceed
  the literal param value. Always check `query_window.start` /
  `query_window.end` in the raw payload before asserting coverage
  bounds; do not assume the param value equals the queried duration.

## Baseline

When deviation framing is in play (rate / volume claims, "new source
IP" claims), shift the window 7 days earlier (or 30 days for sparse
identity patterns) and re-run with the same filter binding. Compare
keys per-key — host set, source IP set, timing distribution.
