# Identity stub — execution

Read this file when gather is dispatched against `system: identity`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface.

## CLI

```bash
defender/scripts/tools/identity_cli.py health-check
defender/scripts/tools/identity_cli.py can-access <user> <host> [--raw]
defender/scripts/tools/identity_cli.py get-user <user> [--raw]
defender/scripts/tools/identity_cli.py list-authorized-hosts <user> [--raw]
defender/scripts/tools/identity_cli.py list-users [--role X] [--enabled true|false] [--limit N] [--raw]
defender/scripts/tools/identity_cli.py list-roles [--raw]
```

**Do not Read `identity_cli.py` source to discover flags.** This file
plus `identity_cli.py {subcommand} --help` is the authoritative
surface. If a flag you need isn't here or in `--help`, treat it as
unsupported and escalate.

`--raw` emits the upstream JSON response unchanged (the FastAPI
response body), suitable for `gather_raw/{position}.json`. Default
output is short formatted text.

## Connectivity

Transport is `docker --context soc-playground exec <bastion> curl
http://identity:8080/...`. The bastion (default `web-1`) is any role
host on the compose network — every host has Docker DNS for the stub.
No SSH tunnel needed; the same docker context already used by
elastic_cli for rule installs is reused here.

If `health-check` exits 2, check `docker --context soc-playground ps`
for the bastion + the `identity` container.

## Config

`defender/knowledge/environment/systems/identity/config.env` declares
`IDENTITY_URL_BASE`, `IDENTITY_BASTION_HOST`, `IDENTITY_TIMEOUT_SEC`.
All three can be overridden by environment variables of the same
names for ops convenience.

## Exit codes

- `0` — success (including `authorized: false` as a legitimate answer)
- `1` — query error (user not found, malformed arg)
- `2` — connectivity / docker / upstream 5xx
