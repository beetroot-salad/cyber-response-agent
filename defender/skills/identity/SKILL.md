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

This file is the **visibility surface** — read by the defender, the
author skill, and the actor-reviewer judge. CLI invocation details
(subcommand flags, transport, exit codes) live in `execution.md`,
read only by gather. The defender treats this system as a question
source; gather decides how to ask.

## Visibility surface

### questions_answered

This system answers legitimacy questions about a principal — does a
named user (realm identity) have an authorized role on a named host
in the inventory, and what shape does that role grant (sudo, shell)?
Lookups about a session's *runtime* representation (a container id,
a numeric uid observed in telemetry) are not directly answerable here;
the principal must first be resolved to a realm identity. Whether that
resolution happens at gather time or in a prior lead is gather's
choice — the defender names the legitimacy question, not the input
path.

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

CLI invocation, connectivity, config, and exit codes live in
`execution.md` — read by gather only.
