# Case-history write path (issue #317)

Design context for the runtime → ticket-store write path. This is the first slice
of #317; the read/seed/judge-confirm work is a separate change. When this doc and
the code disagree, the code wins.

## Why

The benign (FP-direction) learning loop wants to ground dispositions in the org's
*past closed cases* — ticket history as a confirmable policy authority, not just
routing. That requires a case-history store that **accrues from runs** (no
bootstrapping). The store exists (`playground/ticket-server`) but starts empty.
This slice makes each investigated alert write a case into it, so the read PR has
real history to sample and confirm against.

It is shipped first because it is fully testable today and because *running* it is
what manufactures the read PR's fixtures.

## Decisions

- **Realistic lifecycle — the defender closes, it does not create-closed.** A ticket
  pre-exists when the alert is raised; the defender responds and closes it. Modeled
  as a thin **bridge** (open ticket at `materialize_run_dir`) + a post-run
  **transition-to-closed**. This is more faithful than writing a closed ticket from
  nothing, and it makes idempotency fall out for free: create-once (a replay's
  `POST /tickets` returns 409 = already there), close-is-idempotent.

- **Anti-corruption boundary — internal model ≠ external model.** `report.md`
  (+ `alert.json`) is the *internal* case model; the ticket schema is the *external*
  model. `scripts/tools/case_ticket.py` is the **only** code that knows both: it
  parses the internal artifacts into a `CaseRecord` and maps that to/from ticket
  payloads (the "de-facto schema" — disposition+reason ride `resolution`, signature
  rides a `sig:` label, since the frozen v1 ticket has no such fields). The drivers,
  the report schema, and (PR 2) the learning reader never bind to ticket field names.
  When the store changes (e.g. Elastic Cases), only the mapper + transport move.

- **Decoupled stores / config.** The case-history store has its own config
  (`systems/case-history/config.env`, `CASE_HISTORY_*`), distinct from the read-side
  gather adapter's `systems/ticket/config.env` (`TICKET_*`), even though both point
  at the same ticket-server today. The case-history the loop accrues is conceptually
  the learning store, not the customer ticketing SoR the defender reads during an
  investigation; the split keeps that explicit for a real deployment. The write path
  also carries **no `defender.learning` import** — runtime and learning stay
  decoupled (the disposition enum is mirrored locally, drift-guarded by a test).

- **Not the gather adapter.** The writer is a driver **post-step**, separate from the
  read-only `ticket_cli.py` (which is deliberately read-only and lives inside the
  gather gate regime). It uses the low-level transport primitives (`docker_exec_curl`
  + `split_status`), **not** `http_post` — `http_post` `sys.exit`s on error, which is
  right for a CLI adapter but fatal for an in-process post-step.

- **Never breaks the run.** Like `cross_check_tables` / `visualize`, every failure —
  missing config, unreachable stub, HTTP error, missing/invalid `report.md` — is a
  WARN and a return, never a raise/exit. A crashed run with no `report.md` leaves the
  ticket open (investigation incomplete — realistic).

- **Opt-in, deferred product target.** `--update-ticket` (default off) on both
  engines; users turn it on per deployment. The helper is engine-agnostic (one
  helper, two call sites). Only the playground target (the stub) is wired; a
  real-customer target rides the future act-mode close path and is out of scope.

- **Thin write, all dispositions.** The runtime writes only id / signature /
  disposition / reason, and writes **every** disposition (benign, inconclusive,
  malicious) — the store is the full case history. Filtering to benign-and-survived
  for seeding, and enriching the resolution with grounded predicates + the
  adversarial-survival flag, is the offline loop's job (PR 2).

## Shape

- `scripts/tools/case_ticket.py` — pure: `CaseRecord`, `read_case_record`, the mapper
  (`alert_to_open_payload`, `case_record_to_close`, `parse_disposition_from_resolution`).
- `scripts/tools/ticket_writer.py` — I/O: `open_case_ticket` (bridge) /
  `close_case_ticket` (+ `ticket_write.json` receipt), non-fatal.
- `run.py` / `run_pai.py` — `--update-ticket`: open after materialize, close after
  `cross_check_tables`.
- `knowledge/environment/systems/case-history/config.env` — `CASE_HISTORY_*`.

The `ticket_write.json` receipt (`{key, status, url, ok}`) is the seam the read PR /
offline enrichment keys on.
