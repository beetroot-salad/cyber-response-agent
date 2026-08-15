# Elastic — execution

Read this file when gather is dispatched against `system: elastic`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface. It carries the verb surface, query syntax, and index scoping.

## Verbs

Reached with the **`query` tool** — there is no command, no shim, and no `--help`.
Params bind **by name**, with literal JSON types (`"limit": 20`, never `"20"`).

**Call `list_verbs(system="elastic")` for the verbs you may run and the params each one
binds**, with types, defaults and which are required. It reads the adapter's live
signatures and is filtered to your grant, so it is the same surface the `query` tool
enforces — a param it names will bind, one it omits is refused.

`limit` is clamped to a 20-doc cap — read the envelope's `total` for magnitudes, never
pull-and-count.

`sort` is `@timestamp` order and takes `"desc"` (the default, newest first) or
`"asc"` (oldest first); any other value is refused. It decides **which end of your
window** the 20-doc cap keeps, so it is the difference between "what happened last
here" and "what happened first here" — ask for `"asc"` whenever the question is
what *started* something, or the answer will be the tail of the window. It is not
pagination: there is no third slice to ask for, and a middle one is reached by
narrowing `start`/`end` or by aggregating with `esql`. The result envelope echoes
the `sort` it used.

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

**Do not Read `elastic_adapter.py` source to discover params** — `list_verbs` already
answers that from the same signatures, and the source is ~500 lines that show up as the
single largest source of wasted Read calls across runs. If a param you need is not in
`list_verbs`' answer, it does not exist: treat it as unsupported and escalate rather than
inferring one from the source.

`query` / `alerts` emit a JSON payload
`{"index": ..., "total": ..., "returned": ..., "sort": ..., "truncated": ..., "hits": [...]}`
where `hits` is the array of `_source` docs and `sort` echoes the order the
20-doc cap was taken in (so the payload on disk says which end of the window
it holds). That payload IS the output
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
- Text on `message`: `message: "Failed password"` — a **bare quoted phrase**, no wildcards
- Disjunction: `host.name: ("web-1" OR "web-2")`
- Boolean: `data_stream.dataset: "system.auth" AND process.name: "sudo"`
- Squid by user: `user.name: "sre.alice" AND data_stream.dataset: "squid.access"`
- Zeek by destination: `destination.ip: "172.18.0.20" AND data_stream.dataset: "zeek.connection"`
- Postgres auth failures: `data_stream.dataset: "postgresql.log" AND message: "authentication failed"`
- Nginx 5xx on a host: `host.name: "web-1" AND data_stream.dataset: "nginx.access" AND http.response.status_code: [500 TO 599]`
- Keycloak LOGIN events: `loggerName: "org.keycloak.events" AND message: "type LOGIN"` (the events are
  key=value text inside `message`; the analyzer drops the `=` and the quotes, so match the *tokens*
  in order — writing the punctuation into the phrase does not match more precisely, and wrapping it
  in wildcards matches everything, see below)
- Unbound query for a domain: `data_stream.dataset: "unbound.queries" AND message: "example.com"`

**Never wrap a phrase in `*`.** `message: *"Failed password"*` looks like a substring match and is
not one: the parser reads the bare `*` as a wildcard term matching every document that has a
`message` field, so the clause is a **silent no-op** — no error, no warning, and `total` comes back
identical to the same query with the clause deleted. In a disjunction it matches all of them, so
the filter you thought narrowed the search returned the whole index instead. `message` is an
analyzed text field: a quoted phrase already matches that token sequence *anywhere* in the value,
which is the substring behaviour the `*` was reaching for. If a query's `total` does not move when
you add a `message` clause, this is why.

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

**An alert's own index names are backing indices, not patterns.**
`ancestor_events[].index` in `alert.json` carries the concrete write-backing
index behind a datastream — `.ds-logs-system.auth-default-2026.07.27-000004`.
The adapter allowlists datastream *patterns*, so binding that verbatim is
refused (`index '…' falls outside the configured patterns`). Map it to its
pattern before you bind it: a `.ds-`-prefixed name containing `system.auth`
is `logs-system.auth-*`, `falco.alerts` is `logs-falco.alerts-*`, and so on —
the dataset segment between `.ds-logs-` and `-default-…` is the pattern's stem.
