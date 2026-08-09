---
name: defender-elastic
description: Elastic Stack system reference — what data the v2 playground Elasticsearch holds, what it cannot answer here, how to read its output, and how the defender adapter dispatches queries.
---

Elasticsearch is the v2 playground's single search backend. It carries
Filebeat-shipped raw events from Elastic Agent on each role host, Falco
syscall alerts, and the detection-engine signals emitted by the custom
rules in `playground-v2/detection-rules/`. All v2 query routing — Falco,
system auth, syslog, security alerts — goes through one adapter
(`elastic_adapter.py`) against this one cluster.

This file is the **Visibility surface** — read by the defender (gather
routing, judge), the author (template scaffolding), and the
actor-reviewer judge. It describes what the v2 ES instance can answer,
regardless of how queries are dispatched. The **Execution** surface
(CLI, query syntax, index scoping, connectivity) lives in the adjacent
`execution.md`, read only by the gather subagent when it dispatches a
query — not by the orchestrator, which routes here and never queries a
data source directly.

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
| `logs-keycloak.events-*` | Keycloak file log (JSON format) | every Quarkus log line as a JSON envelope: `loggerName`, `level`, `message`, `timestamp`, `threadName`. Filter `loggerName: "org.keycloak.events"` to scope to the events stream (LOGIN, LOGOUT, REFRESH_TOKEN, LOGIN_ERROR, etc.); event detail (`type=`, `username=`, `clientId=`, `ipAddress=`) is in `message` as substring-queryable text |
| `logs-unbound.queries-*` | Unbound `/var/log/unbound/unbound.log` | per-query + per-reply lines: `<ts> unbound[1:0] info: <client_ip> <name>. <qtype> <qclass>` (query) and `... <rcode> <rtt> <flags> <size>` (reply). No parser — query by substring on `message`. Complements `logs-zeek.dns-*` (zeek sees the wire; unbound sees the resolver's view) |
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
  one data-stream explicitly: `params={"index": "logs-system.auth-*"}`
  on `query` / `alerts`, or the `FROM` clause in an ES|QL pipe.
- **Time anchors.** Bind the window explicitly — `params={"start":
  "<iso>", "end": "<iso>"}` on `query` / `alerts`, a `@timestamp`
  comparison in an ES|QL pipe — rather than leaning on relative-now
  defaults; the rule engine and the agent ship-time drift relative to
  each other and rounding-to-now hides one-second ordering questions.
  A window is also the only control you have over *which* docs a
  capped `query` returns: it sorts newest-first and takes the first
  20, so a wide window bracketing an alert hands back the window's
  tail and can exclude the alert's own events entirely. Bracket the
  pivot tightly, or aggregate with `esql`, which has no such cap.
- **There are no flags.** Every verb binds its declared params **by
  name** through the `query` tool (`params={...}`) — there is no
  command line, no `--index`, no `--start`, and an unknown or
  mistyped param is rejected before it reaches Elasticsearch.
- **Match `message` with a bare quoted phrase — `message: "Failed password"`.**
  It is an analyzed *text* field, not a keyword, so a phrase already
  matches that token sequence anywhere in the line, which is what
  retrieves the OpenSSH entries. Wrapping it in wildcards
  (`message: *"substring"*`) is a **silent no-op**: the bare `*` parses
  as a term matching every document with a `message` field, so the
  clause narrows nothing and `total` comes back unchanged — with no
  error to tell you. In ES|QL the wildcard form *is* correct
  (`message LIKE "*session opened*"`); the two languages differ here.

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

CLI invocation, query syntax, index scoping, connectivity, and exit
codes live in `execution.md` — read by gather only.
