---
name: defender-ticket
description: Ticket-server stub system reference — read-only ticket lookups for the v2 playground. Resolves incident / case context referenced from an alert or required for precedent matching.
---

The ticket-server stub is the v1 FastAPI app reused under
playground-v2's compose (kept in `/workspace/playground/ticket-server`
so v1 integrations stay working). v1's
`soc-agent/scripts/tools/playground_ticket_cli.py` is a separate
ActionContract-shaped adapter for that ecosystem; this adapter is
v2-flavored (`_stub_transport.py` + docker-exec-curl + `--raw`) and
read-only.

This file is split by audience. **Visibility surface** is read by
the defender, the author skill, and the actor-reviewer judge.
**Execution** is read only by code paths that dispatch queries.

## Visibility surface

### available_queries

| Subcommand | Measurement |
|---|---|
| `list-tickets [--status X] [--label X] [--q X]` | Filtered ticket list with summary + labels |
| `get-ticket <key>` | Full ticket record incl. description + comments |

### gaps

- **Seed-driven; no live human ticket authoring.** Tickets present
  in the store come from
  `playground/ticket-server/seed/tickets.json` (bind-mounted) plus
  any `POST /tickets` calls earlier in the session. Absence of a
  ticket for a hypothesis is not refutation — the seed is a
  curated, sparse subset.
- **No cross-link surface.** Tickets do not reference CRs, hosts, or
  users in a structured way; references live in free-text
  description / comments and must be substring-matched via `--q`.
- **No history surface.** `get-ticket` returns current status; no
  transition log. Comments are append-only and form the closest
  proxy.
- **Schema lock — v1 shape.** The store carries v1 ticket fields
  (`key`, `summary`, `description`, `status`, `resolution`,
  `labels`, `comments`). Add-field migration would diverge v1 and
  v2; the schema is intentionally frozen until both pipelines stop
  consuming the shared seed.

### read_guidance

- **`status` ∈ {open, in-progress, resolved, closed}.** Closed
  tickets carry a `resolution` field; open tickets have
  `resolution: null`.
- **`labels` are short tags.** Common ones: `brute-force`,
  `false-positive`, `change-window`, `escalated`. Treat them as
  curator-supplied hypothesis hints, not refutations.
- **`--q` matches against summary OR description, case-insensitive.**
  Use for free-text searches when the precise key isn't known.
- **Comments are signal-bearing.** Resolution rationale and
  related-ticket references typically live in comment bodies, not
  in structured fields.

### when_to_use

- **Use for precedent matching at REPORT time** — when a similar
  alert has been investigated before, the matched_ticket_id is the
  citation; use `get-ticket` to confirm the precedent's disposition
  is still applicable.
- **Use for "is this alert already on the SOC's radar"** —
  `list-tickets --q <host or user>` finds open work touching the
  same entities.
- **Use to enumerate by label** — `list-tickets --label
  false-positive` for known-FP precedents.

### when_not_to_use

- **Not for ticket creation.** This adapter is read-only by design;
  ticket writes go through the act-mode close path, not
  investigation reads.
- **Not for change-window context.** Use the change-mgmt stub for
  CR-scoped questions; ticket labels may mention CRs but the
  authoritative answer is in change-mgmt.
- **Not for identity / authorization context.** Use the identity
  stub; tickets may reference users in free text but do not encode
  authorization.

## Execution

### CLI

```bash
defender/scripts/tools/ticket_cli.py health-check
defender/scripts/tools/ticket_cli.py list-tickets [--status X] [--label X] [--q X] [--limit N] [--raw]
defender/scripts/tools/ticket_cli.py get-ticket <key> [--raw]
```

**Do not Read `ticket_cli.py` source to discover flags.** This SKILL
plus `ticket_cli.py {subcommand} --help` is the authoritative
surface.

`--raw` emits the upstream JSON response unchanged.

### Connectivity

Transport is `docker --context soc-playground exec <bastion> curl
http://ticket-server:8080/...`. Bastion default `web-1`.

### Config

`defender/knowledge/environment/systems/ticket/config.env` declares
`TICKET_URL_BASE`, `TICKET_BASTION_HOST`, `TICKET_TIMEOUT_SEC`.

### Exit codes

- `0` — success
- `1` — query error (ticket not found, malformed arg)
- `2` — connectivity / docker / upstream 5xx
