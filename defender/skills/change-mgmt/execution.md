# Change-management stub — execution

Read this file when gather is dispatched against `system: change-mgmt`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface.

## Verbs

```
query(system="change-mgmt", verb="health-check",   params={})
query(system="change-mgmt", verb="active-changes", params={"host": "<h>", "at": "<iso>"})
query(system="change-mgmt", verb="get-change",     params={"cr_id": "<cr_id>"})
query(system="change-mgmt", verb="list-changes",   params={"status": "X", "host": "h", "active_at": "<iso>"})
```

Reached with the **`query` tool** — there is no command, no shim, and no `--help`.
Params bind **by name**, with literal JSON types. `active-changes` requires both
`host` and `at`; every `list-changes` param is an optional filter.

**Do not Read `change_mgmt_adapter.py` source to discover params.** This file plus the
systems catalog in your dispatch prompt is the authoritative surface, and a call
with an unknown/missing/mistyped param is rejected with the declared list anyway.

**`at` and `active_at` must be UTC ISO 8601** (e.g.
`2026-04-24T12:00:00Z`). The verb validates the shape and rejects
local-time / date-only forms before dispatching — a silent timezone
mismatch is harder to diagnose than a refusal.

Each verb returns the upstream JSON response unchanged.

## Connectivity

Transport is `docker --context soc-playground exec <bastion> curl
http://change-mgmt:8080/...`. Bastion default `web-1`.

## Config

`defender/knowledge/environment/systems/change-mgmt/config.env`
declares `CHANGE_MGMT_URL_BASE`, `CHANGE_MGMT_BASTION_HOST`,
`CHANGE_MGMT_TIMEOUT_SEC`.

## Exit codes

- `0` — success
- `1` — query error (CR not found, malformed `--at`)
- `2` — connectivity / docker / upstream 5xx
- `64` — a usage mistake in YOUR call: an unknown verb, or an
  unknown/missing/mistyped param name (e.g. `cr` where the verb declares
  `cr_id`). The one class you can fix yourself — the rejection names the
  declared verb/param roster; re-issue with a declared param. It never trips
  the circuit breaker, so a param typo is not a data-source outage.
