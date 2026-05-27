---
name: defender-elastic
description: Elastic Stack — the v2 environment's primary event store. Indexes all syscall (Falco), network (Zeek), proxy (Squid), DB (Postgres), web (Nginx), and auth (Keycloak, sshd) events. Query via elastic_cli.py for any "what events did we see for X" lead. Not for asset/identity state — that lives in cmdb / identity.
---

# elastic system reference

Query via `python3 {defender_dir}/scripts/tools/elastic_cli.py query '<KQL or EQL>' --start ... --end ... --raw`. Use `--help` for the full surface; do not read source.

Fields follow ECS conventions. Falco events sit under `falco.output_fields.*`.

## Known data-source quirks

- **`falco.output_fields.container.name` returns `<NA>`** for short-lived
  containers where Falco's container-plugin docker-socket lookup races
  the container exit. The syscall enricher always populates
  `falco.output_fields.container.id`, which is the substitute field —
  use it for any lead asking for container identity. Cross-reference
  to `container.name` via `docker inspect` only if the lead requires
  the human-readable name specifically.

- **`falco.output_fields.user.name` returns `<NA>`** for processes
  running with effective UID outside the container's `/etc/passwd`.
  `falco.output_fields.user.uid` (numeric) is always populated and
  is the substitute field.
