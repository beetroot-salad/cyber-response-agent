# State-surface adapter skills — handoff

The v2 stack's continuous log streams are now in Elastic (auth/syslog,
falco, zeek.*, squid.access, postgresql.log, nginx.{access,error},
keycloak.events, unbound.queries, elastic_agent.*). What remains is the
**state-surface** tier — five FastAPI stubs and per-host live state — where
the right shape is a query-on-demand adapter, not a log integration. This
doc is the handoff for adding those adapters as defender-side skills.

Read `defender/docs/system-skill-shape.md` first; the per-system
SKILL.md split (Visibility surface / Execution) and the four
Visibility fields (`available_queries`, `gaps`, `read_guidance`,
`when_to_use`/`when_not_to_use`) are the contract. This doc only
adds what's specific to the state-surface tier.

## Systems to onboard

Five stubs (auth-less FastAPI on the compose network, see
`playground-v2/CLAUDE.md` §Stub services) plus host live state.
SKILL.md dirs are **unprefixed** — match the `defender/skills/elastic/`
precedent, not the table-name column:

| System | Service | Internal URL | VPS loopback | SKILL dir |
|---|---|---|---|---|
| CMDB | `cmdb` | `http://cmdb:8080` | `127.0.0.1:8001` | `defender/skills/cmdb/` |
| Identity | `identity` | `http://identity:8080` | `127.0.0.1:8005` | `defender/skills/identity/` |
| Change-mgmt | `change-mgmt` | `http://change-mgmt:8080` | `127.0.0.1:8003` | `defender/skills/change-mgmt/` |
| Threat-intel | `threat-intel` | `http://threat-intel:8080` | `127.0.0.1:8002` | `defender/skills/threat-intel/` |
| Ticket-server | `ticket-server` | `http://ticket-server:8080` | `127.0.0.1:8004` | `defender/skills/ticket/` |
| Host live state | n/a | n/a | n/a (`docker exec`) | `defender/skills/host-state/` |

Endpoints + return shapes are listed per service in
`playground-v2/CLAUDE.md` §Stub services. Copy the verbs you need into
the per-system SKILL — don't redocument them here, they drift.

## Connection model — pick `docker exec`, not SSH tunnels

The stubs publish on VPS loopback for debugging, so SSH tunnels (5
forwards: 8001, 8002, 8003, 8004, 8005) are *possible* but high-friction.
The adapter pattern that matches what the defender's runtime view of the
playground looks like:

```python
# Wrap docker --context soc-playground exec <host> curl ... as the transport.
# Hosts already have Docker DNS for every stub, so:
docker --context soc-playground exec web-1 \
  curl -fsS http://cmdb:8080/hosts/web-1
```

Three reasons this beats tunnels:

1. **No port management** — one `docker exec` works for all five stubs
   plus future ones.
2. **Same reachability the agent investigates against** — if a stub is
   down inside the network, the adapter sees it the same way an in-cluster
   client would.
3. **No new auth surface** — `docker --context soc-playground` is already
   configured for elastic_cli's needs.

Pick any role host as the curl bastion (`web-1` is fine). The adapter CLI
shells out to `docker --context soc-playground exec web-1 curl ...` and
parses the response. The Bash permission allow rule covers it once added.

For the host-state adapter, the same primitive is the entire transport:
`docker --context soc-playground exec <target_host> <command>`. No HTTP.

## Adapter CLI shape — mirror `elastic_cli.py`

Each adapter is `defender/scripts/adapters/{system}_cli.py`. Conventions
that need to match `elastic_cli.py`:

- A `VERBS` mapping keyed by verb name (plus `health-check`) — one plain
  annotated function per verb, no argparse, invoked through the `query` tool.
- Each command prints its result as JSON on stdout, unconditionally —
  the payload IS the output, with no wrapper envelope around it. The
  shape is the payload's own: `{index, total, returned, truncated,
  hits}` for an elastic `query`/`alerts`, a flat object for a cmdb
  `get-host`, a list/object for a `list-*` verb. `defender-sql` reduces
  it with `FROM data` binding the payload's own top-level keys. There is
  no human pretty-print mode. Keep each command's payload shape stable
  across releases — drift breaks replay. Gather persists it by-ref under
  `gather_raw/{lead_id}/{seq}.json`.
- Exit codes: `0` success, `1` query error (404, schema mismatch,
  bad arg), `2` connectivity/auth failure.
- **Don't** Read the CLI source to discover params — the SKILL.md +
  the `VERBS` registry's annotations are the authoritative surface (per the
  memory-recorded discipline in the elastic SKILL).

Config at `defender/knowledge/environment/systems/{system}/config.env`
declaring `{SYSTEM}_HOST=web-1`, `{SYSTEM}_URL_BASE=http://{system}:8080`,
`{SYSTEM}_TIMEOUT_SEC=10`. The adapter loads via the same `DEFENDER_DIR /
knowledge/environment/systems/{system}/config.env` pattern as
elastic_cli.

## Verbs (minimum viable surface)

Implement the read-only verbs only — `/admin/*` endpoints are chaos-mode
write surfaces, not investigation reads, and shouldn't be in the
adapter. Each verb takes keyword-only params (shown in parentheses), not
`--flags` or positionals:

- **cmdb**: `get-host` (`host`), `list-hosts` (optional `role`,
  `criticality`, `owner`), `list-roles`.
- **identity**: `can-access` (`user`, `host` — the load-bearing primitive:
  agent asks "is `dev.dana` authorized on `db-1`?"), `get-user` (`user`),
  `list-authorized-hosts` (`user`).
- **change-mgmt**: `active-changes` (`host`, `at` — the timestamp must be UTC
  ISO 8601; discipline this in the SKILL's read_guidance), `get-change` (`cr_id`).
- **threat-intel**: `lookup` (an IP or domain). **Gap to call out
  loudly**: the stub returns synthetic `{verdict: "unknown", score: 0}`
  on miss — never 404. Agent must not treat `unknown` as
  refutation; it's the absence of a signal.
- **ticket-server**: `list-tickets` (optional `status`, `label`, `q`),
  `get-ticket` (`key`). v1's `playground_ticket_cli.py` (in
  `soc-agent/scripts/tools/`) is a reference shape, not a drop-in —
  the v2 ticket-server is the same code but the adapter conventions
  should match v2 elastic_cli, not v1.
- **host-state**: `proc-tree` (`host`), `passwd` (`host`), `authorized-keys`
  (`host`, optional `user`), `fim-checksum` (`host`, `path`), `package-list`
  (`host`). Each wraps a single `docker --context soc-playground exec <host>
  <cmd>` inside the verb; per-verb timeout budget; never `--it`.

## Permissions

Since #611 a data-source adapter is not on any bash lane. The gather subagent
calls the in-process typed `query` tool (`runtime/query_tool.py`), which
dispatches `(system, verb, params)` against the verb registry
(`runtime/verbs.py`'s `ModuleVerbRegistry`, discovered by glob over
`scripts/adapters/*_cli.py`). That registry IS the allowlist — a system or verb
not in it is rejected — so a new adapter auto-gates by dropping its
`{system}_cli.py` (with a `VERBS` mapping) into `scripts/adapters/`, no per-CLI
permission entry needed. The main loop is denied data-source access entirely
(the gather subagent is the data-access layer); the per-agent grant model
(`runtime/permission/`, #575) gates what remains on the read-only bash lanes.

The adapter may shell out to `docker --context soc-playground exec *` internally,
but that runs inside the in-process verb — it is never a model-authored command
reaching the gate.

## Audit

v2 has no `tool_audit.jsonl` PostToolUse hook (per the elastic
SKILL handoff context). The audit surface is:

- `investigation.md` — `:L` rows record `system: {system-name}`, the
  query/target, and the gather subagent's observations.
- `gather_raw/{lead_id}/{seq}.json` — the adapter's JSON payload,
  persisted per-lead by the gather subagent. **This is the only
  literal-tool-IO capture today.** Adapters MUST emit a stable
  payload shape for this to be useful — drift breaks replay.

If we ever add per-call audit, the natural shape is a PreToolUse hook
on `Bash` matching `*/defender/scripts/adapters/*` that appends to a
`tool_audit.jsonl`. Not in scope for this batch.

## Per-system SKILL `gaps` to declare upfront

These are deployment-specific facts every adapter SKILL should put in
`gaps` so the agent doesn't fail-stop on them:

- **threat-intel**: `verdict: unknown` is the lookup-miss shape, not a
  signal. Refutation requires `verdict ∈ {benign, malicious, suspicious}`.
- **change-mgmt**: in-memory store resets on container restart; seed
  reloads on startup but ad-hoc POSTs do not survive. Read-side
  queries are reliable; write-side history is not.
- **cmdb**: overlay endpoints are chaos-mode scaffolding. Agent reads
  through the merged view (`GET /hosts/{name}` already includes
  overlay), never the underlay.
- **identity**: read-only, snapshotted from `keycloak/realm.yaml` ×
  `hosts/inventory.yaml` at startup. Realm changes via Keycloak admin
  UI do **not** reflect until container restart — flag this in
  `read_guidance`.
- **ticket-server**: shared with v1's `playground_ticket_cli.py`; the
  endpoint shapes are identical. If/when v2 forks the surface, the
  adapter and SKILL drift point will be here.
- **host-state**: outputs are point-in-time. Two calls 60s apart can
  legitimately disagree on, e.g., process tables. Declare in
  `read_guidance` that host-state observations carry a
  `captured_at` and the agent should not cross-time-window them.

## Batching and implementation order

All six adapters land in **one batch / one PR**. The order below is
the recommended build sequence within that batch (validate the transport
pattern on small surfaces first), not a multi-PR split:

1. **identity** — load-bearing for legitimacy checks; the
   `can_access` primitive is the cleanest API to start against.
2. **cmdb** — small surface, lets you validate the `docker exec curl`
   transport pattern.
3. **host-state** — different shape (no HTTP) — exercises the v2
   adapter contract on a non-REST source.
4. **change-mgmt**, **threat-intel** — straightforward once 1–3 are
   stable.
5. **ticket-server** — last; v1's `playground_ticket_cli.py` already
   works but doesn't match v2 conventions. Decide port-vs-rewrite at
   this point in the batch, but it ships with the others, not after.

## What's deliberately out of scope

- **Streaming stub access logs** (uvicorn `INFO` lines per HTTP
  request). They're trivially streamable via a Custom Logs integration
  on the FastAPI container's stdout file, but the signal value during
  a real investigation is near zero (you'd query the API directly, not
  search its access log). Skip until a debugging need surfaces.
- **Writeable verbs** (`POST /admin/overlay`, `POST /changes`, etc.).
  Those are chaos-mode controls, not investigation reads. They belong
  to a future chaos control-plane, not the adapter.
- **A unified state-surface CLI**. Per-system CLIs match the
  per-system SKILL split; one mega-CLI would re-introduce drift the
  system-skill-shape doc was built to avoid.
