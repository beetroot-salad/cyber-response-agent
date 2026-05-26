---
name: defender-elastic
description: Elastic Stack system reference — what data the v2 playground Elasticsearch holds, what it cannot answer here, how to read its output, and how the defender adapter dispatches queries.
---

Elasticsearch is the v2 playground's single search backend. It carries
Filebeat-shipped raw events from Elastic Agent on each role host, Falco
syscall alerts, and the detection-engine signals emitted by the custom
rules in `playground-v2/detection-rules/`. All v2 query routing — Falco,
system auth, syslog, security alerts — goes through one adapter
(`elastic_cli.py`) against this one cluster.

The file is split by audience. The **Visibility surface** section is
read by the defender (gather routing, judge), the author (template
scaffolding), and the actor-reviewer judge — it describes what the v2
ES instance can answer, regardless of how queries are dispatched. The
**Execution** section is read only by code paths that actually
dispatch queries.

## Visibility surface

### Two query surfaces

Both surfaces share one Elasticsearch cluster, one adapter, one auth
context — only the default index pattern and the field vocabulary differ.

| Subcommand | Surface | Default index pattern |
|---|---|---|
| `query` | Raw events from Elastic Agent + Falco | `logs-*` |
| `alerts` | Detection-engine signals from custom rules | `.internal.alerts-security.alerts-default-*` |

`query` is for "did this thing happen / what does the timeline look
like" against the raw stream. `alerts` is for "what other rule fires
in this neighborhood / what's the alert family on this host" against
SIEM-generated signals.

### Data streams currently populated (`query` surface)

| Data stream | Source | What it carries |
|---|---|---|
| `logs-system.auth-*` | sshd, sudo, PAM via filebeat | `/var/log/auth.log` lines per host (Accepted/Failed sshd, sudo COMMAND=, pam_unix session open/close) |
| `logs-system.syslog-*` | journal / syslog via filebeat | general syslog (cron, baseline activity, daemon noise) |
| `logs-falco.alerts-*` | Falco eBPF syscall monitor | rule-fire records with `falco.rule`, `falco.priority`, `falco.output_fields.{container.name,proc.name,user.name,proc.cmdline}` |
| `logs-zeek.connection-*` | Zeek conn.log via Elastic Zeek integration | per-flow records with ECS `source.{ip,port,bytes,packets}`, `destination.{...}`, `network.{protocol,transport,community_id,direction}`, plus `zeek.connection.*` |
| `logs-zeek.dns-*` | Zeek dns.log | DNS query/answer pairs with `dns.question.name`, `dns.answers[]`, `dns.response_code` |
| `logs-zeek.http-*` | Zeek http.log | HTTP requests with `http.request.method`, `url.original`, `user_agent.original`, and `user.name` extracted from Squid CONNECT basic-auth |
| `logs-zeek.ssl-*` | Zeek ssl.log | TLS handshakes — `tls.server.subject`, `tls.cipher`, `tls.version`, SNI under `zeek.ssl.server_name` |
| `logs-zeek.files-*` | Zeek files.log | file transfers seen on the wire — `file.hash.*`, `file.mime_type`, `file.size` |
| `logs-zeek.ssh-*` | Zeek ssh.log | SSH handshakes (client/server versions, auth result) — separate from sshd's auth.log: this is the wire-side view |
| `logs-squid.access-*` | Squid access log (custom `soc` format) | per-request: `user.name` (basic-auth), `source.ip`, `url.original`, `http.request.method`, `http.response.bytes`, `squid.result_status`, `squid.elapsed_ms` |
| `logs-postgresql.log-*` | Postgres `/var/log/postgresql/postgresql-*-main.log` on `db-1` | per-statement records with `postgresql.log.{database,user,query,error_severity}`, `message`. Carries auth failures, slow queries, connection lifecycle |
| `logs-nginx.access-*` | nginx `/var/log/nginx/access.log` on `web-1` / `web-2` | combined-log-format requests parsed to ECS: `source.ip`, `http.{request.method,response.status_code,response.body.bytes,version}`, `url.original`, `user_agent.*` |
| `logs-nginx.error-*` | nginx `/var/log/nginx/error.log` on `web-1` / `web-2` | error/warn/notice lines from nginx itself — config reload, upstream timeouts, worker crashes; queryable via `log.level` |
| `logs-elastic_agent.*` | Agent self-telemetry | agent / filebeat / metricbeat / fleet_server status — useful only for grounding "did the agent ship anything in this window" |

### Detection rules currently installed (`alerts` surface)

Authored under `playground-v2/detection-rules/`, installed via
`playground-v2/scripts/install_detection_rules.py`. Each emits hits
into `.internal.alerts-security.alerts-default-*` with full
`kibana.alert.*` envelope.

| `kibana.alert.rule.rule_id` | Source data | Detection |
|---|---|---|
| `v2-sshd-failed-auth-burst` | `logs-system.auth-*` | ≥5 sshd `Failed password` events on one host in 5 min |
| `v2-sshd-success-after-failures` | `logs-system.auth-*` | EQL: ≥3 `Failed password` then 1 `Accepted password` on same host in 10 min |
| `v2-falco-suspicious-network-tool` | `logs-falco.alerts-*` | `falco.rule:"Launch Suspicious Network Tool in Container"` |
| `v2-falco-authorized-keys-modification` | `logs-falco.alerts-*` | `falco.rule:"Adding ssh keys to authorized_keys"` |
| `v2-cross-tier-ssh-pivot` | `logs-system.auth-*` | EQL: successful sshd on `dev-ws-*`/`office-ws-*` then any sshd on `web-*`/`db-*`/`jump-box-*` within 15 min |

### Gaps

Things this Elasticsearch deployment **cannot** answer:

- **No parsed `user.name` / `source.ip` on sshd auth events.** The
  `logs-system.auth` filebeat integration emits the raw syslog
  `message` but does not extract the OpenSSH-format fields (`Failed
  password for <user> from <ip>`). Treat `user.name` / `source.ip` as
  derivable only by message-substring matching, not as filterable
  fields. Means: brute-force / pivot rules currently key on `host.name`
  only.
- **Falco events name `host.hostname` as `soc-playground`** (the Docker
  host VPS), not the role-host container. Per-container attribution
  lives in `falco.output_fields.container.name`. When asking "which
  host fired this Falco alert", group/filter on
  `falco.output_fields.container.name`, not `host.name`.
- **No CMDB / IdP integration on the events side.** Host role
  ("is web-1 prod?") and identity authorization ("is sre.alice
  permitted to sudo on db-1?") are out of band — see the cmdb /
  keycloak stubs in the v2 stack for separate adapters (not yet built
  in defender).
- **No process tree across Falco events.** Falco names the
  parent process via `falco.output_fields.proc.pname`, but does not
  chain further back; full ancestry requires the host's own audit
  records, which are not collected.
- **No ticket history.** Ticket / change-management state is in the
  v2 stub (`ticket-server` / `change-mgmt`) and not in ES.

### Read guidance

- **Empty result ≠ refutation.** Before treating a zero count as
  evidence of absence, verify the query parses (no unknown fields,
  no `text:` mode in keyword Lucene), and confirm the time window
  covers a period the data stream was actually shipping.
- **`logs-*` is a wide pattern.** Without an `event.dataset` or
  `data_stream.dataset` filter, your query searches every shipped
  stream including metricbeat noise. For focused queries, scope to
  one data-stream explicitly: `--index 'logs-system.auth-*'` etc.
- **Time anchors.** Use explicit `--start` / `--end` rather than
  relative-now defaults; the rule engine and the agent ship-time
  drift relative to each other and rounding-to-now hides one-second
  ordering questions.
- **`message:*"substring"*` is needed for sshd field extraction.**
  Treat `message` as a single keyword field; wildcard substrings
  retrieve the OpenSSH lines.

### When to use

- **Use the `query` surface for**: what events were emitted, by which
  host, in what time window; baseline characterization (counts,
  cadence) over a stream; cross-stream correlation when joined by
  host/user identifiers that are present in both.
- **Use the `alerts` surface for**: what other detection-engine rules
  fired against the same host in a wider window (good for "is this
  alert a one-off or part of a campaign"); confirming a referenced
  rule by `rule_id`.
- **Use both** when an alert's underlying events deserve direct
  inspection — the `alerts` hit names a rule but the discriminating
  signal usually lives in the raw events under it.

## Execution

### CLI

```bash
defender/scripts/tools/elastic_cli.py health-check
defender/scripts/tools/elastic_cli.py query '<query_string>' [--index P] [--start T] [--end T] [--limit N] [--raw]
defender/scripts/tools/elastic_cli.py alerts '<query_string>' [--index P] [--start T] [--end T] [--limit N] [--raw]
```

**Do not Read `elastic_cli.py` source to discover flags.** This
SKILL plus `elastic_cli.py {subcommand} --help` is the authoritative
surface. The source is ~500 lines and reading it shows up as the
single largest source of wasted Read calls across runs. If a flag
you need isn't here or in `--help`, treat it as unsupported and
escalate — don't infer one from the source.

Output is formatted markdown (summary + 5 sample lines + first 3 raw
_source docs) by default; `--raw` emits a JSON envelope
`{"index": ..., "total": ..., "returned": ..., "truncated": ..., "hits": [...]}`
suitable for `gather_raw/{position}.json`.

### Connectivity

The v2 ES cluster only exposes `127.0.0.1:9200` on the Hetzner VPS;
the adapter expects an SSH tunnel from the devcontainer:

```bash
ssh -fN -L 9200:localhost:9200 -L 5601:localhost:5601 soc-playground
```

If the tunnel is down, `health-check` exits 2 with a connect error.
`config.env` lists `ELASTICSEARCH_URL=https://localhost:9200`; override
via env vars (`ELASTICSEARCH_URL=...`) when running against a different
deployment.

### Credentials

The CLI handles credentials itself — agents do **not** need to source
`.env` or export anything. Resolution order:

1. `V2_ELASTIC_PASSWORD` environment variable (highest priority).
2. `V2_ELASTIC_PASSWORD=...` line in `playground-v2/.env` (auto-read).

`V2_ELASTIC_USERNAME` defaults to `elastic` when unset.

If the CLI exits with a credentials error, the password is genuinely
missing from both — restore `playground-v2/.env` or export the var;
do not chain shell substitutions to work around it.

### Query syntax

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

### Index-pattern selection

`--index` overrides the per-subcommand default. Common scopes:

- `--index 'logs-system.auth-*'` — sshd / sudo / PAM only
- `--index 'logs-falco.alerts-*'` — Falco rule-fires only
- `--index 'logs-system.syslog-*'` — general syslog only
- `--index 'logs-zeek.connection-*'` — Zeek flow records only (the `connection` dataset is what other vendors call `conn.log`)
- `--index 'logs-zeek.*'` — every Zeek dataset (conn/dns/http/ssl/files/ssh)
- `--index 'logs-squid.access-*'` — Squid proxy attribution only
- `--index 'logs-postgresql.log-*'` — Postgres queries / auth / lifecycle only
- `--index 'logs-nginx.access-*'` — nginx requests only (separate from `nginx.error`)
- `--index '.internal.alerts-security.alerts-default-*'` — alerts surface (the `alerts` subcommand's default)
