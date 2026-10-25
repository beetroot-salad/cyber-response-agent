---
id: elastic.squid-proxy-access
status: established
verb: esql
params: []
body_substitutions: [end, src, start]
---

## Goal

Squid forward-proxy access log (`logs-squid.access-*`) over a window — outbound
HTTP/S egress attributed by the authenticated proxy identity (`user.name`), the
originating container (`source.ip`), the destinations reached (`url.original`), and
the byte volume moved. Use to surface exfiltration or tool-download over the
sanctioned proxy, C2 beaconing to an unusual host, or a compromised credential
egressing from a host that has no business using the proxy. Keyword recall: squid,
proxy, forward proxy, egress, exfiltration, CONNECT, user.name, url.original,
outbound, `squid.result_status`, TCP_MISS, DENIED, `http.response.bytes`, data
transfer, beacon.

**Wide/superset** — carries the originating-IP filter axis and a per-identity /
per-method aggregation. **Narrow it to the lead**: drop `source.ip` for a
proxy-wide identity view, add `user.name == "..."` to scope one credential, or add
`url.original LIKE "*host*"` to scope one destination.

## Query

ES|QL. Server-side aggregation — the result rows ARE the answer. The `soc` logformat
is dissected to ECS positions at ingest, so filter structured fields directly (not a
message blob).

```esql
FROM logs-squid.access-*
| WHERE @timestamp >= "${start}" AND @timestamp < "${end}"
        AND source.ip == "${src}"
| STATS requests      = COUNT(*),
        denied        = COUNT(*) WHERE squid.result_status LIKE "*DENIED*",
        bytes_out     = SUM(http.response.bytes),
        distinct_dest = COUNT_DISTINCT(url.original),
        first_seen    = MIN(@timestamp),
        last_seen     = MAX(@timestamp)
        BY identity = user.name,
           method   = http.request.method
| SORT requests DESC
```

**Narrowing examples:**

- *Proxy-wide identity mix* ("who is egressing at all"): drop the `source.ip`
  predicate, keep `BY identity, method`; the row-per-identity view shows which
  credential drove the egress and how much left.
- *One credential's egress* ("what did dev.dana pull through the proxy"): add
  `AND user.name == "dev.dana"`, add `BY dest = url.original` and drop the counters
  for the per-destination breakdown.
- *One destination* ("who reached pastebin"): add `AND url.original LIKE
  "*pastebin*"`, `BY identity, source.ip`.

## Pitfalls

- **`host.name` is `soc-playground`, not the egressing host** — the log is tailed from
  the Squid container's volume on the VPS, so every row shares the proxy's host. The
  originating workload is `source.ip` (the container that made the request) and the
  actor is `user.name` (the basic-auth identity); never attribute by `host.name`.
- **`source.ip` is the container, `user.name` is the identity, and they can disagree** —
  a stolen credential used from an unexpected `source.ip` is exactly the exfil shape;
  read the two axes together rather than trusting either alone.
- **Sparse-to-dark under baseline.** No baseline workload routes egress through the
  proxy, so a quiet window legitimately returns zero — read an empty result as "no
  proxied egress", not as a dark stream. This also means a *single* authenticated
  request is already anomalous; there is no volume floor to clear.
- **`squid.result_status` is `Ss/Hs`** (e.g. `TCP_MISS/200`, `TCP_DENIED/407`) — a
  `DENIED` with `407` is an unauthenticated attempt, a `TCP_MISS/200` is a served
  request; split on the status when distinguishing probing from successful transfer.
