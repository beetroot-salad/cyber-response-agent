---
name: defender-cmdb
description: CMDB stub system reference — host inventory (role, criticality, owner, change window, trust edges) in the v2 playground. Source of truth for what a host is supposed to be.
---

The CMDB stub is a FastAPI service over `hosts/inventory.yaml`. It
loads the inventory `hosts:` list into an immutable `BASE` dict at
startup and shallow-merges an in-memory `OVERLAY` over it on every
read. The merged view is what callers see — overlay endpoints exist
for chaos scenarios and are **not** exposed by this adapter.

This file is split by audience. **Visibility surface** is read by the
defender, the author skill, and the actor-reviewer judge.
**Execution** is read only by code paths that dispatch queries.

## Visibility surface

### available_queries

| Subcommand | Measurement |
|---|---|
| `get-host <name>` | Effective record (role, criticality, owner, os, change_window, trust_edges_out, users). Keyed by host name (e.g. `scanner-1`, `web-1`). |
| `list-hosts [--role X] [--criticality X] [--owner X]` | Filtered host list |
| `list-roles` | Inventory-role catalog |

### gaps

- **Overlay is invisible by design.** This adapter only reads the
  merged view. A stale-CMDB chaos run flips a field via
  `POST /admin/overlay/{name}` — the adapter sees the new value as
  if it were always true. There is no way through this adapter to
  ask "is this field overlay-sourced?" — that distinction is
  intentionally hidden, since "should the agent trust CMDB?" is the
  scenario being exercised.
- **No history surface.** The stub answers point-in-time only — no
  "what was web-1's owner two weeks ago." Inventory edits land via
  rebuilding the stub image, not via tracked transitions.
- **No tag / label graph.** Hosts have flat scalar fields; no
  multi-valued labels for ad-hoc tagging. If a hypothesis needs
  "all hosts tagged X," derive from `list-hosts` + a filter rather
  than expecting a tag endpoint.
- **`users:` per-host overrides are visible but unfiltered.**
  `get-host` returns the `users:` block when one exists, but there
  is no endpoint to filter hosts by per-host user; use the identity
  stub's `list-authorized-hosts <user>` instead.

### read_guidance

- **Treat fields as ground truth for "what should be."** A host
  whose actual-state contradicts CMDB (e.g. nginx running on a host
  CMDB calls `dev-ws`) is a divergence finding, not a CMDB bug.
- **Empty `trust_edges_out` is a real refutation.** A host with no
  declared outbound edges legitimately cannot reach other tiers; an
  observed outbound connection is signal.
- **`criticality` is sandbox / dev / preprod / prod.** Treat
  `sandbox` and `dev` as "alerts here are low priority absent
  cross-tier evidence." Don't auto-escalate based on criticality
  alone — pair with a real anomaly.
- **Filter result is a flat list, not paginated.** Total counts in
  the response envelope are the full match count; no `next_cursor`.
  If `--limit` is reached in raw mode, narrow the filter — there is
  no second page.

### when_to_use

- **Use for "is this host prod / who owns it"** — owner + criticality
  inform escalation routing and disposition.
- **Use for "is this connection in policy"** — `trust_edges_out` on
  the source host vs the destination host's role.
- **Use to enumerate a tier** — `list-hosts --role web` gives the
  expected populated set; observed members outside that set are a
  candidate finding.

### when_not_to_use

- **Not for runtime host attribution.** Elastic's `host.name` /
  `falco.output_fields.container.name` is the runtime view; CMDB is
  the policy view. They can disagree — that disagreement is itself
  the signal to surface, not something to paper over.
- **Hosts only — no container records.** CMDB has no `container.id`,
  `container.name`, or image fields. A host that happens to run as a
  container is in CMDB under its host name (e.g. `scanner-1`), not
  under its docker id. Feeding `container.id` or `container.name` into
  `get-host` always 404s, even when the underlying host exists.
- **Not for identity-on-host.** Use the identity stub for "which
  users are authorized on host X"; cmdb's `users:` block is a
  per-host override surface, not the authoritative join.

## Execution

### CLI

```bash
defender/scripts/tools/cmdb_cli.py health-check
defender/scripts/tools/cmdb_cli.py get-host <name> [--raw]
defender/scripts/tools/cmdb_cli.py list-hosts [--role X] [--criticality X] [--owner X] [--limit N] [--raw]
defender/scripts/tools/cmdb_cli.py list-roles [--raw]
```

**Do not Read `cmdb_cli.py` source to discover flags.** This SKILL
plus `cmdb_cli.py {subcommand} --help` is the authoritative surface.

`--raw` emits the upstream JSON response unchanged, suitable for
`gather_raw/{position}.json`. Default output is short formatted text
that includes the full JSON record for `get-host` and a per-row
summary for `list-hosts`.

### Connectivity

Transport is `docker --context soc-playground exec <bastion> curl
http://cmdb:8080/...`. Bastion default `web-1`. No SSH tunnel needed.

### Config

`defender/knowledge/environment/systems/cmdb/config.env` declares
`CMDB_URL_BASE`, `CMDB_BASTION_HOST`, `CMDB_TIMEOUT_SEC`. All three
can be overridden by environment variables of the same names.

### Exit codes

- `0` — success
- `1` — query error (host not found, malformed arg)
- `2` — connectivity / docker / upstream 5xx
