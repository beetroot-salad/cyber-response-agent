---
id: elastic.host-agent-by-ip
status: established
---

## Goal

Resolve an IP address to a hostname via Elastic Agent telemetry by searching for logs where `host.ip` matches the target address. Identifies the machine whose agent reports owning that IP. Complements `ip-to-host-search` (which finds traffic sourced FROM the IP via `source.ip`/`client.ip`): use this when you need to find which host IS the IP, not which hosts SAW traffic from it.

## What to summarize

- `host.name` values associated with the `host.ip` match (the machine that owns this IP)
- Distinct `data_stream.dataset` values confirming the host-IP pairing across sources
- `@timestamp` range of matching records (confirms the agent was reporting during the investigated period)
- Count of distinct `host.name` values (more than one indicates NAT or VIP)

## Filter binding

- `${ip}` — IP address to resolve via the `host.ip` field
- `index` (optional) — data stream or index pattern to search; defaults to `logs-*`. Pass as a named param, not as a positional argument (see pitfall below).

## Query

```
host.ip: "${ip}"
```

Use `logs-*` as the index. A limit of 10–20 is sufficient; agent metadata repeats this field across many log streams simultaneously.

## Common pitfalls

- **NAT / VIP addresses**: If the IP is a shared gateway or virtual IP, multiple distinct hosts may report the same `host.ip`. Check the count of distinct `host.name` values before concluding the IP resolves to a single machine.
- **Agents that do not run Elastic Agent**: Hosts shipping logs via syslog or Beats without Elastic Agent metadata enrichment do not populate `host.ip`. In that case fall back to `sshd-source-ip-activity` or `ip-to-host-search`.
- **`search` is not a valid subcommand.** The CLI accepts `health-check`, `query`, and `alerts`; passing `search` returns `exit=2: invalid choice: 'search'`. Use `query`.
- **Pass the index as a named param, not as a positional argument.** When specifying a non-default index, pass it as the named `index` param with the filter expression as the first positional (`arg0`). Reversing the order — index as `arg0`, filter as `arg1` — returns `exit=2: unrecognized arguments: <filter>`.
