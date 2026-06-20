---
id: elastic.ip-to-host-search
status: established
engine: esql
---

## Goal

Resolve an IP address to host(s) and the data sources that saw it — across all
event streams (`logs-*`) via the structured `source.ip` / `client.ip` (the IP as
a connection peer) and `host.ip` (the IP as a reporting agent's own address). Use
to attribute an unknown IP to a host/account and see which datasets observed it.
Keyword recall: ip to host, reverse lookup, attribution, source.ip, client.ip,
host.ip, which host, who is this IP. Subsumes the former `host-agent-by-ip`.

**Wide/superset** — narrow by restricting the index (`FROM logs-zeek.*`) or
dropping a predicate to one role of the IP.

## Query

```esql
FROM logs-*
| WHERE @timestamp >= "${start}" AND @timestamp < "${end}"
        AND (source.ip == "${ip}" OR client.ip == "${ip}" OR host.ip == "${ip}")
| STATS events     = COUNT(*),
        first_seen = MIN(@timestamp),
        last_seen  = MAX(@timestamp)
        BY host.name, data_stream.dataset
| SORT events DESC
```

- *Self-identification* ("which host *is* this IP"): narrow to `host.ip == "${ip}"`
  and read `BY host.name` — but see the pitfall (shared bridge IPs make `host.ip`
  noisy here; the `source.ip`/`client.ip` peer view is usually more decisive).
- *Peer view* ("which hosts talked to this IP"): drop `host.ip`, keep
  `source.ip`/`client.ip`.

## Pitfalls

- **Some streams carry no `host.name`** — Zeek (`zeek.connection`/`zeek.ssl`)
  describes a flow by IPs only, so those rows group under a null `host.name`; the
  `data_stream.dataset` column still tells you the IP was seen there. Cross-resolve
  via cmdb / the agent-tagged streams (`system.auth`, `nginx.access`).
- **`host.ip` is multi-valued and shared.** In this env many hosts report the same
  docker-bridge address in `host.ip`, so a `host.ip` match can return several
  hosts — prefer the `source.ip`/`client.ip` peer evidence for attribution.
