---
id: elastic.zeek-outbound-by-source
status: established
engine: esql
---

## Goal

Zeek network-connection records (`logs-zeek.connection-*`) for a source IP over a
window — connection count, distinct destinations, ports, and bytes moved. Use to
characterize a host's outbound network behavior: fan-out, beaconing, bulk
transfer, port scanning. Keyword recall: zeek, conn.log, connection, outbound,
source.ip, destination.ip, destination.port, beaconing, exfil, bytes.

**Wide/superset** — narrow by dropping the predicates/`BY` keys the lead doesn't
need (e.g. add `destination.port == ...` to scope a port; drop `BY` for a bare
count).

## Query

```esql
FROM logs-zeek.connection-*
| WHERE @timestamp >= "${start}" AND @timestamp < "${end}"
        AND source.ip == "${source_ip}"
| STATS conns      = COUNT(*),
        bytes_out  = SUM(source.bytes),
        bytes_in   = SUM(destination.bytes),
        dest_ips   = COUNT_DISTINCT(destination.ip),
        first_seen = MIN(@timestamp),
        last_seen  = MAX(@timestamp)
        BY destination.ip, destination.port
| SORT conns DESC
```

- *Fan-out / scan check*: drop the `BY` and read `dest_ips` + `conns` — a high
  `dest_ips` or many distinct `destination.port` is the scan signal.
- *Beaconing*: add `BY bucket = DATE_TRUNC(1 minute, @timestamp)` to see cadence.

## Pitfalls

- **Zeek records carry no `host.name`** — the connection is described by
  `source.ip`/`destination.ip`, not a reporting host. Resolve IPs to hosts via
  `ip-to-host-search` / cmdb if the lead needs names.
- **Direction.** `source.bytes` is bytes the source sent (outbound), `destination.bytes`
  is bytes it received. A NAT/proxy hop can collapse the apparent source IP — confirm
  the source is the real origin, not a gateway, before attributing volume.
