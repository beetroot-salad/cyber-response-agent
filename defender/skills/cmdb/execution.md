# CMDB stub — execution

Read this file when gather is dispatched against `system: cmdb`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface.

## Verbs

Reached with the **`query` tool** — there is no command, no shim, and no `--help`.
Params bind **by name**, with literal JSON types.

```
query(system="cmdb", verb="health-check", params={})
query(system="cmdb", verb="get-host",   params={"host": "<name>"})
query(system="cmdb", verb="list-hosts", params={"role": "X", "criticality": "X", "owner": "X"})
query(system="cmdb", verb="list-roles", params={})
```

`get-host` requires `host`; every `list-hosts` param is an optional filter.

**Do not Read `cmdb_cli.py` source to discover params.** This file plus the systems
catalog in your dispatch prompt is the authoritative surface, and a call with an
unknown/missing/mistyped param is rejected with the declared list anyway.

Each verb returns the upstream JSON response unchanged — a flat object
for `get-host`, a list/object for `list-hosts` / `list-roles`. That
payload IS the output; the harness captures it under
`gather_raw/{lead_id}/{seq}.json`.

`get-host` is keyed by inventory host name (e.g. `scanner-1`, `web-1`).
Feeding a runtime identifier — container id, docker container name —
404s. If a lead needs the inventory record for a runtime entity, run
the resolution lead first (`list-hosts` plus inventory-side fields, or
the identity stub's `list-authorized-hosts <user>` if the principal is
a user), then bind the resolved name into `get-host`.

## Connectivity

Transport is `docker --context soc-playground exec <bastion> curl
http://cmdb:8080/...`. Bastion default `web-1`. No SSH tunnel needed.

## Config

`defender/knowledge/environment/systems/cmdb/config.env` declares
`CMDB_URL_BASE`, `CMDB_BASTION_HOST`, `CMDB_TIMEOUT_SEC`. All three can
be overridden by environment variables of the same names.

## Exit codes

- `0` — success
- `1` — query error (host not found, malformed arg)
- `2` — connectivity / docker / upstream 5xx
