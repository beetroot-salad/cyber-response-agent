---
id: elastic.nginx-access-history
status: established
verb: esql
params: []
body_substitutions: [end, host, src, start]
---

## Goal

nginx HTTP access log (`logs-nginx.access-*`) on a web host over a window — request
volume, the status-code mix, how many distinct URL paths a client touched, and the
methods used. Use to surface web scanning / path enumeration, an authentication or
error-code burst, or an unexpected client hammering a web tier. Keyword recall: nginx,
access log, http, GET, POST, url.path, status 404, 401, 403, source.ip, web-1, web-2,
scanner, path enumeration, `http.response.status_code`, `http.request.method`.

**Wide/superset** — carries the host + client-IP filter axes and a status/method
aggregation. **Narrow it to the lead**: drop `source.ip` for a host-wide view, add a
`url.path` predicate to scope one endpoint, or drop a `BY` key you don't need.

## Query

ES|QL. Server-side aggregation — the result rows ARE the answer.

```esql
FROM logs-nginx.access-*
| WHERE @timestamp >= "${start}" AND @timestamp < "${end}"
        AND host.name == "${host}"
        AND source.ip == "${src}"
| STATS requests       = COUNT(*),
        client_errors  = COUNT(*) WHERE http.response.status_code >= 400
                                    AND http.response.status_code < 500,
        not_found      = COUNT(*) WHERE http.response.status_code == 404,
        distinct_paths = COUNT_DISTINCT(url.path),
        first_seen     = MIN(@timestamp),
        last_seen      = MAX(@timestamp)
        BY host.name,
           client = source.ip,
           method = http.request.method
| SORT requests DESC
```

**Narrowing examples:**

- *Host-wide status mix* ("what is web-1 serving"): drop the `source.ip` predicate,
  keep `BY host.name, method`; the `not_found` / `client_errors` counters give the
  error shape without naming a client.
- *One client's footprint* ("what did 172.18.0.x hit"): keep `source.ip`, add
  `BY status = http.response.status_code` and drop the counters; the row-per-status
  breakdown shows whether the client was scanning (many 404s, high `distinct_paths`)
  or using the app (200s, low `distinct_paths`).
- *One endpoint's traffic* ("who is calling /admin"): add `AND url.path == "..."`,
  `BY source.ip`.

## Pitfalls

- **The health-probe baseline is 404-heavy but path-thin.** Metricbeat's
  `/nginx_status` probe from `127.0.0.1` runs continuously and 404s, so a bare 404
  count is dominated by baseline. A scan is distinguished by **`distinct_paths` and a
  non-loopback `source.ip`**, not by the 404 count alone — filter `source.ip !=
  "127.0.0.1"` (or scope to a client) before reading the error shape.
- **`source.ip` is the immediate client**, which for proxied traffic is the proxy, not
  the origin. `nginx.access.remote_ip_list` carries the `X-Forwarded-For` chain when
  present; reach for it only when the origin matters and a forwarder is in front.
- **High volume** — `logs-nginx.access-*` runs to thousands of rows per host per hour
  under baseline; always aggregate (`STATS`), never pull docs.
