# Elastic — execution

Read this file when gather is dispatched against `system: elastic`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface. It carries the CLI surface, query syntax, and index scoping.

## CLI

```bash
defender-elastic health-check
defender-elastic query  '<query_string>' [--index P] [--start T] [--end T] [--limit N] [--raw]
defender-elastic alerts '<query_string>' [--index P] [--start T] [--end T] [--limit N] [--raw]
defender-elastic esql   '<ES|QL pipe>'
```

`esql` runs a server-side **ES|QL** aggregation and returns the result table
(`{columns, row_count, values}`) — the rows ARE the answer, computed exactly over
the full match, so you never pull docs and reduce them. The whole query (index via
`FROM`, filter via `WHERE`, window via `@timestamp` comparison, aggregation via
`STATS`) lives in the pipe; `esql` takes no `--index/--start/--end/--limit`.
Prefer it for any count / distribution / cardinality / timing dimension; use
`query` (KQL search) only when you need raw event documents themselves.

**Do not Read `elastic_cli.py` source to discover flags.** This doc
plus `defender-elastic {subcommand} --help` is the authoritative
surface. The source is ~500 lines and reading it shows up as the
single largest source of wasted Read calls across runs. If a flag
you need isn't here or in `--help`, treat it as unsupported and
escalate — don't infer one from the source.

Output is formatted markdown (summary + 5 sample lines + first 3 raw
_source docs) by default; `--raw` emits a JSON envelope
`{"index": ..., "total": ..., "returned": ..., "truncated": ..., "hits": [...]}`
suitable for `gather_raw/{position}.json`.

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

`--index` overrides the per-subcommand default. Common scopes:

- `--index 'logs-system.auth-*'` — sshd / sudo / PAM only
- `--index 'logs-falco.alerts-*'` — Falco rule-fires only
- `--index 'logs-system.syslog-*'` — general syslog only
- `--index 'logs-zeek.connection-*'` — Zeek flow records only (the `connection` dataset is what other vendors call `conn.log`)
- `--index 'logs-zeek.*'` — every Zeek dataset (conn/dns/http/ssl/files/ssh)
- `--index 'logs-squid.access-*'` — Squid proxy attribution only
- `--index 'logs-postgresql.log-*'` — Postgres queries / auth / lifecycle only
- `--index 'logs-nginx.access-*'` — nginx requests only (separate from `nginx.error`)
- `--index 'logs-keycloak.events-*'` — Keycloak Quarkus log + events stream (scope further with `loggerName:`)
- `--index 'logs-unbound.queries-*'` — Unbound resolver query/reply lines
- `--index '.internal.alerts-security.alerts-default-*'` — alerts surface (the `alerts` subcommand's default)
