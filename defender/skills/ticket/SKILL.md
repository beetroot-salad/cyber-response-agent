---
name: defender-ticket
description: Ticket-server stub system reference — read-only ticket lookups for the v2 playground. Resolves incident / case context referenced from an alert or required for precedent matching.
---

The ticket-server stub is a FastAPI app under playground-v2's compose
(`playground-v2/ticket-server`), carried over when the v1 lab was
retired. This adapter is v2-flavored (`_stub_transport.py` +
docker-exec-curl) and read-only.

This file briefs **gather**, which reaches this store through the `query`
tool — its verb_grant names `list-tickets` only. The judge's closed-ticket
reads (a full-record lookup and the store's key grammar) are separate typed
tools it registers directly (`learning/pipeline/judge/closed_ticket_tool.py`);
they are not part of gather's catalog and are not documented here.
**Execution** is read only by code paths that dispatch queries.

## Visibility surface

### available_queries

| Verb | Measurement |
|---|---|
| `list-tickets` | Filtered ticket list with summary + labels (by status, label, or free-text query) |

### gaps

- **Seed-driven; no live human ticket authoring.** Tickets present
  in the store come from
  `playground-v2/ticket-server/seed/tickets.json` (bind-mounted) plus
  any `POST /tickets` calls earlier in the session. Absence of a
  ticket for a hypothesis is not refutation — the seed is a
  curated, sparse subset.
- **No cross-link surface.** Tickets do not reference CRs, hosts, or
  users in a structured way; references live in free-text
  description / comments and must be substring-matched via `--q`.
- **No history surface.** A ticket lookup returns current status only; no
  transition log. Comments are append-only and form the closest
  proxy.
- **Schema lock — v1 shape.** The store carries v1 ticket fields
  (`key`, `summary`, `description`, `status`, `resolution`,
  `labels`, `comments`). Add-field migration would diverge v1 and
  v2; the schema is intentionally frozen until both pipelines stop
  consuming the shared seed.

### read_guidance

- **`status` ∈ {open, in_progress, closed}.** Closed
  tickets carry a `resolution` field; open tickets have
  `resolution: null`.
- **The current investigation's own ticket is excluded by identity.**
  Gather removes that record from `list-tickets` results before the payload
  is cached. Other open and in-progress tickets remain available for
  correlation, including tickets whose free text references the current case.
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
  citation; confirm the precedent's disposition is still applicable via
  `list-tickets` free-text-searched on the ticket key.
- **Use for "is this alert already on the SOC's radar"** —
  `list-tickets` free-text-searched on a host or user finds open work
  touching the same entities.
- **Use to enumerate by label** — `list-tickets` on the
  `false-positive` label for known-FP precedents.

### when_not_to_use

- **Not for ticket creation.** This adapter is read-only by design.
  Case-history tickets are written *outside* this read path — by the
  `run.py` / `run.py` `--update-ticket` post-step
  (`scripts/case_history/ticket_writer.py`), which opens a ticket when the alert
  is raised and closes it with the disposition. That writer is a learning
  post-step, not an investigation surface; do not call it from a run.
- **Not for change-window context.** Use the change-mgmt stub for
  CR-scoped questions; ticket labels may mention CRs but the
  authoritative answer is in change-mgmt.
- **Not for identity / authorization context.** Use the identity
  stub; tickets may reference users in free text but do not encode
  authorization.

## Execution

Verb surface, connectivity, config, and exit codes live in
`execution.md` — read by gather only.
