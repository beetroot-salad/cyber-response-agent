---
name: defender-change-mgmt
description: Change-management stub system reference — authorized-change-window lookups for the v2 playground. Resolves "was there a CR covering this host at this time?" for legitimacy contracts that depend on planned-change context.
---

The change-mgmt stub is a FastAPI service over YAML seed +
in-memory store. It exposes seeded CRs, ad-hoc CRs (POSTed by the
attack runner or chaos tooling), and rolling standing CRs
(materialized from a recurring schedule). This adapter is
**read-only** — write surfaces are chaos-mode controls, not
investigation reads.

This file is split by audience. **Visibility surface** is read by
the defender, the author skill, and the actor-reviewer judge.
**Execution** is read only by code paths that dispatch queries.

## Visibility surface

### available_queries

| Subcommand | Measurement |
|---|---|
| `active-changes --host <h> --at <iso>` | CRs covering host at the given instant — the discriminating "was this in a CR" lookup |
| `get-change <id>` | One CR by id |
| `list-changes [--status approved] [--host h] [--active-at iso]` | Filtered CR list |

### gaps

- **In-memory store; resets on container restart.** Seed and
  standing CRs reload from disk on startup, but ad-hoc POSTs do not
  survive. If a CR was POSTed by a recent attack run, its absence
  after a restart is a normal cleanup, not a finding.
- **No CR-history surface.** The store doesn't track transitions
  over time. `get-change` returns current status; no audit log of
  who changed status when.
- **Standing CRs cover a narrow slice.** The standing layer
  materializes only the windows declared in `seed/standing.yaml` —
  most baseline activity is intentionally **not** CR-covered.
  Absence of a CR is the realistic case, not the exception.
- **Time windows are UTC throughout.** The stub does no timezone
  normalization. A local-time `--at` value will silently look up
  the wrong instant.

### read_guidance

- **`active-changes` returning `[]` is a real refutation.** No CR
  covers this host at this instant. Pair with the alert timestamp,
  not "now," when checking historical events.
- **A returned CR is presence, not scope-match.** Always cross-check
  the CR's `hosts` list, its `window_start`/`window_end`, and (if
  the contract demands it) the responsible identity. An attack
  runner can POST a `CHG-RUNNER-…` CR whose host scope is
  deliberately wrong — presence alone is not sufficient legitimacy.
- **Synthetic CRs from the attack runner are real records in the
  store.** They look identical to legitimate CRs in the response.
  Treat the source field, the CR id prefix, and the requester as
  signal-bearing — `CHG-RUNNER-…` is the attack runner's
  convention.

### when_to_use

- **Use for legitimacy contracts that depend on planned change.**
  "Was this admin-style action covered by an approved CR at the
  observed time?" → `active-changes` against the host + alert
  timestamp.
- **Use for cross-checking a referenced CR id** — `get-change` on
  a CR id named in an alert payload or a ticket comment.
- **Use to enumerate currently-active CRs** — `list-changes --status
  in_progress` for what's executing right now; `--status approved`
  for what's been signed off but not yet started. Status enum:
  `planned`, `approved`, `in_progress`, `implemented`, `cancelled`.

### when_not_to_use

- **Not for ticket / incident state.** Use the ticket-server stub
  for incidents; CRs and tickets are separate stores.
- **Not for "what change happened to this host."** The stub knows
  what changes were *planned*; it does not track what was *actually
  executed*. Pair with host-state or Elastic event logs for
  execution evidence.
- **Not for retrospective scope.** No history surface — a CR closed
  yesterday is still queryable by id but its scope at the time of
  closure is what the record reflects today.

## Execution

### CLI

```bash
defender-change-mgmt health-check
defender-change-mgmt active-changes --host <h> --at <iso>
defender-change-mgmt get-change <cr_id>
defender-change-mgmt list-changes [--status X] [--host h] [--active-at iso] [--limit N]
```

**Do not Read `change_mgmt_cli.py` source to discover flags.** This
SKILL plus `defender-change-mgmt {subcommand} --help` is the
authoritative surface.

**`--at` and `--active-at` must be UTC ISO 8601** (e.g.
`2026-04-24T12:00:00Z`). The CLI validates the shape and rejects
local-time / date-only forms before dispatching — a silent timezone
mismatch is harder to diagnose than a refusal.

Each subcommand emits the upstream JSON response unchanged.

### Connectivity

Transport is `docker --context soc-playground exec <bastion> curl
http://change-mgmt:8080/...`. Bastion default `web-1`.

### Config

`defender/knowledge/environment/systems/change-mgmt/config.env`
declares `CHANGE_MGMT_URL_BASE`, `CHANGE_MGMT_BASTION_HOST`,
`CHANGE_MGMT_TIMEOUT_SEC`.

### Exit codes

- `0` — success
- `1` — query error (CR not found, malformed `--at`)
- `2` — connectivity / docker / upstream 5xx
