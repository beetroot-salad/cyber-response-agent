# CMDB stub — execution

Read this file when gather is dispatched against `system: cmdb`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface.

## CLI

```bash
defender-cmdb health-check
defender-cmdb get-host <name> [--raw]
defender-cmdb list-hosts [--role X] [--criticality X] [--owner X] [--limit N] [--raw]
defender-cmdb list-roles [--raw]
```

**Do not Read `cmdb_cli.py` source to discover flags.** This file plus
`defender-cmdb {subcommand} --help` is the authoritative surface.

`--raw` emits the upstream JSON response unchanged, suitable for
`gather_raw/{position}.json`. Default output is short formatted text
that includes the full JSON record for `get-host` and a per-row
summary for `list-hosts`.

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
