# Host-state stub — execution

Read this file when gather is dispatched against `system: host-state`.
Defender does not read this file; it sees only `SKILL.md`'s visibility
surface.

## Verbs

```
query(system="host-state", verb="health-check",      params={})
query(system="host-state", verb="container-inspect", params={"container_id": "<container_id>"})
query(system="host-state", verb="proc-tree",         params={"host": "<host>"})
query(system="host-state", verb="passwd",            params={"host": "<host>"})
query(system="host-state", verb="authorized-keys",   params={"host": "<host>", "user": "U"})
query(system="host-state", verb="fim-checksum",      params={"host": "<host>", "path": "<path>"})
query(system="host-state", verb="package-list",      params={"host": "<host>"})
```

Reached with the **`query` tool** — there is no command, no shim, and no `--help`.
Params bind **by name**, with literal JSON types. `authorized-keys`' `user`
defaults to `root`; every other param above is required.

**Do not Read `host_state_adapter.py` source to discover params.** This file plus the
systems catalog in your dispatch prompt is the authoritative surface, and a call
with an unknown/missing/mistyped param is rejected with the declared list anyway.

Each verb returns a JSON object with `captured_at` and the
verb-specific payload. The host-keyed verbs (`proc-tree`, `passwd`,
`authorized-keys`, `fim-checksum`, `package-list`) also carry `host` plus
their payload field (`ps_output`, `entries`, `keys`, `sha256`, `packages`);
`container-inspect` keys on `container_id` and carries `name` + `image`.

## Connectivity

Transport is `docker --context soc-playground exec <host> <command>`
— same docker context as the HTTP stubs but no curl indirection. The
`<host>` is the target role container directly, not a bastion.

`health-check` does not pick a host; it lists which hosts in the
known inventory are currently running under the docker context.

## Config

This adapter has **no `config.env`**. The docker context name
(`soc-playground`) is hardcoded in
`defender/scripts/adapters/_stub_transport.py`, and the per-verb timeout
default lives in `host_state_adapter.py`. There is nothing else to
configure; if a knob is needed in the future (e.g. a non-default
docker context), promote `DOCKER_CONTEXT` to an env var before adding
a config file.

## Safety

- `--user` is validated against a strict username regex
  (`[a-zA-Z_][a-zA-Z0-9._-]{0,63}`) before being interpolated into
  the `getent` argv. Refused values exit 1 with a clear message.
- `fim-checksum <path>` is validated against a safe-path regex and
  must be absolute. Refused values exit 1.
- Bastions / target hosts are passed to `docker exec` as a separate
  argv element (not via a shell), so a malformed name fails at
  docker's parser rather than running anything unintended.

## Exit codes

- `0` — success (including absent `authorized_keys` file)
- `1` — verb-level error (host unknown to docker, user not present,
  file not found)
- `2` — docker context unreachable / timeout
- `64` — a usage mistake in YOUR call: an unknown verb, or an
  unknown/missing/mistyped param name (e.g. `container` where the verb
  declares `container_id`). The one class you can fix yourself — the
  rejection names the declared verb/param roster; re-issue with a declared
  param. It never trips the circuit breaker, so a param typo is not a
  data-source outage.
