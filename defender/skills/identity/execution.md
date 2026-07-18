# Identity stub — execution

Read this file when gather is dispatched against `system: identity`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface.

## Verbs

Reached with the **`query` tool** — there is no command, no shim, and no `--help`.
Params bind **by name**, with literal JSON types: `enabled` is a real boolean
(`true`/`false`), and a quoted `"false"` is rejected — it would have meant the
opposite.

```
query(system="identity", verb="health-check",          params={})
query(system="identity", verb="can-access",            params={"user": "<user>", "host": "<host>"})
query(system="identity", verb="get-user",              params={"user": "<user>"})
query(system="identity", verb="list-authorized-hosts", params={"user": "<user>"})
query(system="identity", verb="list-users",            params={"role": "X", "enabled": true})
query(system="identity", verb="list-roles",            params={})
```

`can-access` requires both `user` and `host`; `list-users`' two params are
optional filters.

**Do not Read `identity_adapter.py` source to discover params.** This file plus the
systems catalog in your dispatch prompt is the authoritative surface, and a call
with an unknown/missing/mistyped param is rejected with the declared list anyway.

Each verb returns the upstream JSON response unchanged (the FastAPI
response body). That payload IS the output; the harness captures it
under `gather_raw/{lead_id}/{seq}.json`.

## Connectivity

Transport is `docker --context soc-playground exec <bastion> curl
http://identity:8080/...`. The bastion (default `web-1`) is any role
host on the compose network — every host has Docker DNS for the stub.
No SSH tunnel needed; the same docker context already used by
elastic_cli for rule installs is reused here.

If a call exits 2 (connectivity / docker / upstream), the data source
is unreachable: **stop and escalate immediately** with the error — do
not probe with `docker`/`netstat`/`ss` or hunt for config. That's a
data-source outage, not a query problem (see gather SKILL §3.5 validity check).

## Config

`defender/knowledge/environment/systems/identity/config.env` declares
`IDENTITY_URL_BASE`, `IDENTITY_BASTION_HOST`, `IDENTITY_TIMEOUT_SEC`.
All three can be overridden by environment variables of the same
names for ops convenience.

## Exit codes

- `0` — success (including `authorized: false` as a legitimate answer)
- `1` — query error (user not found, malformed arg)
- `2` — connectivity / docker / upstream 5xx
- `64` — a usage mistake in YOUR call: an unknown verb, or an
  unknown/missing/mistyped param name (e.g. a quoted `"false"` where the
  verb declares a boolean `enabled`). The one class you can fix yourself
  — the rejection names the declared verb/param roster; re-issue with a
  declared param. It never trips the circuit breaker, so a param typo is
  not a data-source outage.
