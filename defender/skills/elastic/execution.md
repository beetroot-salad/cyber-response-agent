# Elastic — execution

Read this file when gather is dispatched against `system: elastic`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface. It carries the verb surface, query syntax, and index scoping.

## Verbs

Reached with the **`query` tool** — there is no command, no shim, and no `--help`.
Params bind **by name**, with literal JSON types (`"limit": 20`, never `"20"`).

```
query(system="elastic", verb="health-check", params={})
query(system="elastic", verb="query",  params={"native_query": "<query_string>", "start": "<iso>", "end": "<iso>", "limit": 20, "index": "<pattern>"})
query(system="elastic", verb="alerts", params={"native_query": "<query_string>", "start": "<iso>", "end": "<iso>", "limit": 20, "index": "<pattern>"})
query(system="elastic", verb="esql",   params={"query": "<ES|QL pipe>"})
```

Only `native_query` (for `query`/`alerts`) and `query` (for `esql`) are required;
the rest have defaults. `limit` is clamped to a 20-doc cap — read the envelope's
`total` for magnitudes, never pull-and-count.

`esql` runs a server-side **ES|QL** aggregation and returns the result table
(`{columns, row_count, values}`) — the rows ARE the answer, with the aggregation
scalars computed over the full match, so you never pull docs and reduce them. The
whole query (index via `FROM`, filter via `WHERE`, window via `@timestamp`
comparison, aggregation via `STATS`) lives in the pipe, which is why `esql` takes
no `start`/`end`/`limit`/`index`. Nothing shells out, so the pipe is just a JSON
string — `|` separators and newlines alike are safe, with no quoting or escaping
rule to get wrong. ES|QL caps the returned grouping rows at **1000** by default, so
a wide `BY` (high-cardinality grouping) is silently truncated — narrow the `BY` or
add an explicit `LIMIT`. Prefer `esql` for any count / distribution / cardinality /
timing dimension; use `query` (KQL search) only when you need raw event
documents themselves.

**Do not Read `elastic_cli.py` source to discover params.** This doc plus the
systems catalog in your dispatch prompt is the authoritative surface, and a call
with an unknown/missing/mistyped param is rejected with the declared list anyway.
The source is ~500 lines and reading it shows up as the single largest source of
wasted Read calls across runs. If a param you need isn't here, treat it as
unsupported and escalate — don't infer one from the source.

`query` / `alerts` emit a JSON payload
`{"index": ..., "total": ..., "returned": ..., "truncated": ..., "hits": [...]}`
where `hits` is the array of `_source` docs. That payload IS the output
(there is no separate formatted-text mode); gather captures it under
`gather_raw/{lead_id}/{seq}.json`.

## Connectivity & credentials

The adapter resolves the cluster connection and credentials itself —
you never source secrets, export anything, manage a tunnel, or probe
the connection.

## Exit codes

- `0` — success (includes a connected-but-empty result; 0 hits is a
  finding, not an error — see gather SKILL §3.5 validity check)
- `1` — query error (malformed query string, unknown index)
- `2` — connectivity / auth failure. The data source is unreachable:
  **stop and escalate immediately** with the error. Do not retry-probe,
  run `netstat`/`ss`/`docker`, or hunt for `.env` — that's a
  data-source outage, not a query problem.
- `64` — a usage mistake in YOUR call: an unknown verb, or an
  unknown/missing/mistyped param name (e.g. passing `kql` where the verb
  declares `native_query`). This is the one class you can fix yourself —
  the rejection names the declared verb/param roster; re-issue the call
  with a declared param. It never trips the circuit breaker (a typo of
  yours cannot mask a healthy system), so a param mistake is not a
  data-source outage.

## Query syntax

`query_string` syntax (lucene). KQL covers the same vocabulary for the
common case; the adapter passes the string through unmodified. Common
forms used by v2 gather templates:

- Field exact: `process.name: "sshd"`, `falco.rule: "Adding ssh keys to authorized_keys"`
- Substring on `message`: `message: *"Failed password"*`
- Disjunction: `host.name: ("web-1" OR "web-2")`
- Boolean: `data_stream.dataset: "system.auth" AND process.name: "sudo"`
- Squid by user: `user.name: "sre.alice" AND data_stream.dataset: "squid.access"`
- Zeek by destination: `destination.ip: "172.18.0.20" AND data_stream.dataset: "zeek.connection"`
- Postgres auth failures: `data_stream.dataset: "postgresql.log" AND message: *"authentication failed"*`
- Nginx 5xx on a host: `host.name: "web-1" AND data_stream.dataset: "nginx.access" AND http.response.status_code: [500 TO 599]`
- Keycloak LOGIN events: `loggerName: "org.keycloak.events" AND message: *'type="LOGIN"'*` (note the quoted-substring shape — events are key=value text inside `message`)
- Unbound query for a domain: `data_stream.dataset: "unbound.queries" AND message: *"example.com"*`

## Index-pattern selection

The `index` param of the `query` / `alerts` verb overrides the
per-verb default — bind it by name (`params={"index": "<pattern>"}`),
there is no flag. Common scopes:

- `index: 'logs-system.auth-*'` — sshd / sudo / PAM only
- `index: 'logs-falco.alerts-*'` — Falco rule-fires only
- `index: 'logs-system.syslog-*'` — general syslog only
- `index: 'logs-zeek.connection-*'` — Zeek flow records only (the `connection` dataset is what other vendors call `conn.log`)
- `index: 'logs-zeek.*'` — every Zeek dataset (conn/dns/http/ssl/files/ssh)
- `index: 'logs-squid.access-*'` — Squid proxy attribution only
- `index: 'logs-postgresql.log-*'` — Postgres queries / auth / lifecycle only
- `index: 'logs-nginx.access-*'` — nginx requests only (separate from `nginx.error`)
- `index: 'logs-keycloak.events-*'` — Keycloak Quarkus log + events stream (scope further with `loggerName:`)
- `index: 'logs-unbound.queries-*'` — Unbound resolver query/reply lines
- `index: '.internal.alerts-security.alerts-default-*'` — alerts surface (the `alerts` verb's default)
