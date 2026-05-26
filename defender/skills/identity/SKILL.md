---
name: defender-identity
description: Identity stub system reference — realm-role × inventory-role authorization in the v2 playground. Source of truth for "is this user permitted on this host?", as opposed to /etc/passwd which only reports who got seeded.
---

The identity stub is a FastAPI service over `keycloak/realm.yaml ×
hosts/inventory.yaml`. It snapshots the realm-role × inventory-role
join at container startup and exposes a per-user authorization view.
It is the **load-bearing source for legitimacy resolution** in v2 — a
user appearing in `/etc/passwd` on a host is necessary but not
sufficient evidence of authorization; the identity stub's
`can_access` answer is.

This file is split by audience. **Visibility surface** is read by the
defender (gather routing, judge), the author skill, and the
actor-reviewer judge. **Execution** is read only by code paths that
dispatch queries.

## Visibility surface

### available_queries

| Subcommand | Measurement |
|---|---|
| `can-access <user> <host>` | `{authorized, via, role, sudo, shell}` — the discriminating legitimacy answer |
| `get-user <user>` | Full user record with `authorized_hosts` + `sudo_hosts` derived |
| `list-authorized-hosts <user>` | Just the host list (faster than `get-user` when only the set matters) |
| `list-users [--role X] [--enabled true]` | Realm user catalog (filterable) |
| `list-roles` | Inventory-role ↔ realm-role mapping |

### gaps

- **Read-only, snapshotted at container startup.** Changes made via
  the Keycloak admin UI or `kcadm.sh` do **not** reflect until the
  identity container restarts. If a hypothesis hinges on a recent
  realm change, escalate rather than treat the stub as authoritative.
- **No overlay / chaos endpoints.** The cmdb stub has
  `/admin/overlay/{name}` for stale-CMDB scenarios; identity
  deliberately does not. Stale-IdP scenarios are deferred.
- **No identity-event history.** The stub answers the current
  snapshot. Login events, MFA challenges, and session traces live in
  Keycloak's event log (Elastic `logs-keycloak.events-*` data
  stream), not here.
- **`/etc/passwd` divergence is a join-bug signal, not a stub gap.**
  If `getent passwd <user>` on a host disagrees with
  `authorized_hosts` for that host, the seeding ran wrong — treat the
  identity stub as the policy view, the host as the materialized
  view, and escalate the divergence.

### read_guidance

- **`authorized: false` with `via: null`** means the realm × inventory
  join produces no edge for that pair. It is a real refutation, not
  an absence-of-signal.
- **`authorized: true, via: "override"`** indicates a per-host
  `users:` override in `hosts/inventory.yaml` (e.g. dev.dana's
  per-workstation sudo). Treat overrides as legitimate but
  signal-bearing — they describe non-policy edges.
- **`sudo: true` means the role mapping grants sudo on that host.**
  It does not mean a sudo invocation was observed — pair with
  `logs-system.auth-*` (sudo COMMAND= lines) for execution evidence.
- **Disabled users still have a record.** `get-user` on a disabled
  user returns `enabled: false` plus the still-derived
  `authorized_hosts` (the join is structural). Use `enabled` as the
  active-or-not signal, not absence of the record.

### when_to_use

- **Use for legitimacy resolution** — every `legitimacy_contract`
  on a hypothesis whose disposition depends on "was X authorized on
  Y" resolves through `can-access`.
- **Use for scope-checking** an observed login or sudo event — does
  the user actually have a role mapping for that host, or is this
  cross-credential anomaly?
- **Use for user-enumeration cross-checks** — pair `list-users
  --role developer` with cmdb's `list-hosts --role dev-ws` to derive
  expected user-host pairs.

### when_not_to_use

- **Not for "did the user log in"** — that's `logs-system.auth-*` in
  Elastic, or `logs-keycloak.events-*` for OIDC flows.
- **Not for current-session state** — no sessions surface; cross
  identity-stub with `logs-keycloak.events-*` (LOGIN/LOGOUT events)
  for live session attribution.
- **Not for recent realm edits.** Container restart needed to pick
  up Keycloak admin UI changes; if the question is "what does the
  realm look like *right now*", query Keycloak directly.

## Execution

### CLI

```bash
defender/scripts/tools/identity_cli.py health-check
defender/scripts/tools/identity_cli.py can-access <user> <host> [--raw]
defender/scripts/tools/identity_cli.py get-user <user> [--raw]
defender/scripts/tools/identity_cli.py list-authorized-hosts <user> [--raw]
defender/scripts/tools/identity_cli.py list-users [--role X] [--enabled true|false] [--limit N] [--raw]
defender/scripts/tools/identity_cli.py list-roles [--raw]
```

**Do not Read `identity_cli.py` source to discover flags.** This
SKILL plus `identity_cli.py {subcommand} --help` is the authoritative
surface. If a flag you need isn't here or in `--help`, treat it as
unsupported and escalate.

`--raw` emits the upstream JSON response unchanged (the FastAPI
response body), suitable for `gather_raw/{position}.json`. Default
output is short formatted text.

### Connectivity

Transport is `docker --context soc-playground exec <bastion> curl
http://identity:8080/...`. The bastion (default `web-1`) is any role
host on the compose network — every host has Docker DNS for the
stub. No SSH tunnel needed; the same docker context already used by
elastic_cli for rule installs is reused here.

If `health-check` exits 2, check `docker --context soc-playground ps`
for the bastion + the `identity` container.

### Config

`defender/knowledge/environment/systems/identity/config.env` declares
`IDENTITY_URL_BASE`, `IDENTITY_BASTION_HOST`, `IDENTITY_TIMEOUT_SEC`.
All three can be overridden by environment variables of the same
names for ops convenience.

### Exit codes

- `0` — success (including `authorized: false` as a legitimate answer)
- `1` — query error (user not found, malformed arg)
- `2` — connectivity / docker / upstream 5xx
