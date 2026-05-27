---
name: defender-elastic
description: Elastic Stack — the v2 environment's primary event store. Indexes all syscall (Falco), network (Zeek), proxy (Squid), DB (Postgres), web (Nginx), and auth (Keycloak, sshd) events. Query via elastic_cli.py for any "what events did we see for X" lead. Not for asset/identity state — that lives in cmdb / identity.
---

# elastic system reference

Query via `python3 {defender_dir}/scripts/tools/elastic_cli.py query '<KQL or EQL>' --start ... --end ... --raw`. Use `--help` for the full surface; do not read source.

Fields follow ECS conventions. Falco events sit under `falco.output_fields.*`.
