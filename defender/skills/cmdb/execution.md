# CMDB stub — execution

Read this file when gather is dispatched against `system: cmdb`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface.

## Verbs

Reached with the **`query` tool** — there is no command, no shim, and no `--help`.
Params bind **by name**, with literal JSON types.

**Call `list_verbs(system="cmdb")` for the verbs you may run and the params each one
binds**, with types, defaults and which are required. It reads the adapter's live
signatures and is filtered to your grant, so it is the same surface the `query` tool
enforces — a param it names will bind, one it omits is refused. Don't Read
`cmdb_adapter.py` to discover params either. (cmdb declares a role-listing verb that
gather's grant withholds; `list_verbs` will not show it, which is correct — it is not
part of gather's catalog.)

Each verb returns the upstream JSON response unchanged — a flat object
for `get-host`, a list/object for `list-hosts`. That
payload IS the output; the harness captures it under
`gather_raw/{lead_id}/{seq}.json`.

`get-host` is keyed by inventory host name (e.g. `scanner-1`, `web-1`).
Feeding a runtime identifier — container id, docker container name —
404s. If a lead needs the inventory record for a runtime entity, run
the resolution lead first (`list-hosts` plus inventory-side fields),
then bind the resolved name into `get-host`.

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
- `64` — a usage mistake in YOUR call: an unknown verb, or an
  unknown/missing/mistyped param name (e.g. `name` where the verb
  declares `host`). The one class you can fix yourself — the rejection
  names the declared verb/param roster; re-issue with a declared param.
  It never trips the circuit breaker, so a param typo is not a
  data-source outage.
