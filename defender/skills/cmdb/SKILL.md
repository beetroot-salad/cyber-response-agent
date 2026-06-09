---
name: defender-cmdb
description: CMDB stub system reference — host inventory (role, criticality, owner, change window, trust edges) in the v2 playground. Source of truth for what a host is supposed to be.
---

The CMDB stub is a FastAPI service over `hosts/inventory.yaml`. It
loads the inventory `hosts:` list into an immutable `BASE` dict at
startup and shallow-merges an in-memory `OVERLAY` over it on every
read. The merged view is what callers see — overlay endpoints exist
for chaos scenarios and are **not** exposed by this adapter.

This file is the **visibility surface** — read by the defender, the
author skill, and the actor-reviewer judge. CLI invocation details
(subcommand flags, transport, exit codes) live in `execution.md`,
read only by gather. The defender treats this system as a question
source; gather decides how to ask.

## Visibility surface

### questions_answered

This system answers inventory questions about a host — what role does
the inventory assign it, what criticality / owner / change-window
applies, what trust edges does it declare outbound. The principal is
the host as inventory knows it. Lookups about a session's *runtime*
representation (a container id observed in telemetry, a docker name)
are not the principal here; if a lead needs the inventory record for a
runtime entity, that entity must first be resolved to its inventory
name. Whether that resolution happens at gather time or via a prior
lead is gather's choice — the defender names the inventory question,
not the input path.

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
- **Not for identity-on-host.** Use the identity stub for "which
  users are authorized on host X"; cmdb's `users:` block is a
  per-host override surface, not the authoritative join.

## Execution

CLI invocation, connectivity, config, and exit codes live in
`execution.md` — read by gather only.
