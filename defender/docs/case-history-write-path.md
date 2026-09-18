# Case-history write path (issue #317, gated by #767)

Design context for the runtime → ticket-store write path. This is the first slice
of #317; the read/seed/judge-confirm work is a separate change. #767 then changed
what the write IS — a comment, not a close — and put a person's close between the
write and any later run's read of it; the decisions below are annotated where that
moved them. When this doc and the code disagree, the code wins.

## Why

The benign (FP-direction) learning loop wants to ground dispositions in the org's
*past closed cases* — ticket history as a confirmable policy authority, not just
routing. That requires a case-history store that **accrues from runs** (no
bootstrapping). The store exists (`playground-v2/ticket-server`) but starts empty.
This slice makes each investigated alert write a case into it, so the read PR has
real history to sample and confirm against.

It is shipped first because it is fully testable today and because *running* it is
what manufactures the read PR's fixtures.

## Decisions

- **Realistic lifecycle — the defender records, a person closes (#767).** A ticket
  pre-exists when the alert is raised; the defender investigates and RECORDS its
  findings onto it as a comment; a person reviews the case and closes it. Modeled
  as a thin **bridge** (open ticket at `materialize_run_dir`) + a post-run
  **comment**. The close is the person's act and doubles as the release: a later
  run's gather is served a case's comments only once its status is the mapping's
  `released.status` (`closed`), and the writer never appends behind that close —
  it reads the case back first and refuses with a `refused-released` receipt.
  Idempotency still falls out: create-once (a replay's `POST /tickets` returns
  409 = already there); a re-run of an open case appends a second comment, which
  the person's close then covers too.

- **Anti-corruption boundary — internal model ≠ external model.** `report.md`
  (+ `alert.json`) is the *internal* case model; the ticket schema is the *external*
  model. `scripts/case_history/case_ticket.py` is the **only** code that knows both: it
  parses the internal artifacts into a `CaseRecord` and maps that to/from ticket
  payloads. The drivers, the report schema, and (PR 2) the learning reader never bind
  to ticket field names. When the store changes (e.g. Elastic Cases), only the mapper,
  the transport, and the mapping config move.

- **The mapping is configuration, not code.** The de-facto schema — which internal
  facts land in which ticket fields, the `sig:` label, the comment body template
  `{disposition} — {cause}\n\n{narrative}`, the agent's `comment.author`, the
  `released.status` a person's close moves a case to, and the dotted `source.*`
  paths into `alert.json` — lives in
  `knowledge/environment/systems/case-history/mapping.yaml` and is *rendered* by
  the mapper. Changing the convention (label prefix, body format, which alert
  field is the signature, which status means "reviewed") is a config edit, no code
  change. Nothing decodes a disposition back out of the store any more: the
  proposed disposition is the comment's first line for a person to read, and the
  person's own verdict is the closed case's `resolution`.

- **Decoupled stores / config.** The case-history store has its own config
  (`systems/case-history/config.env`, `CASE_HISTORY_*`), distinct from the read-side
  gather adapter's `systems/ticket/config.env` (`TICKET_*`), even though both point
  at the same ticket-server today. The case-history the loop accrues is conceptually
  the learning store, not the customer ticketing SoR the defender reads during an
  investigation; the split keeps that explicit for a real deployment. The write path
  also carries **no `defender.learning` import** — runtime and learning stay
  decoupled (the disposition enum is mirrored locally, drift-guarded by a test).

- **Not the gather adapter.** The writer is a driver **post-step**, separate from the
  read-only `ticket_adapter.py` (which is deliberately read-only and lives inside the
  gather gate regime). It uses the low-level transport primitives (`docker_exec_curl`
  + `split_status`), **not** `http_post` — `http_post` `sys.exit`s on error, which is
  right for a CLI adapter but fatal for an in-process post-step.

- **Never breaks the run.** Like `cross_check_tables` / `visualize`, every failure —
  missing config, unreachable stub, HTTP error, a mapping that cannot say what
  "released" is spelled — is a WARN, a receipt and a return, never a raise/exit. A
  report with no parsable disposition still records, with a fixed host sentence. A
  crashed run with no `report.md` leaves the ticket open and uncommented
  (investigation incomplete — realistic).

- **Opt-in, deferred product target.** `--update-ticket` (default off) on both
  engines; users turn it on per deployment. The helper is engine-agnostic (one
  helper, two call sites). Only the playground target (the stub) is wired; a
  real-customer target rides the future act-mode close path and is out of scope.

- **Thin write, all dispositions.** The runtime writes one comment — `{author,
  body}`, the body bounded at 4096 bytes on the wire — and writes **every**
  disposition (benign, inconclusive, malicious) as a proposal for the person to
  read. The store is the full case history; what a later run may read of it is the
  person's close, not anything the writer decides.

## Shape

- `scripts/case_history/case_ticket.py` — pure: `CaseRecord`, `read_case_record`, the
  mapper (`alert_to_open_payload`, `case_record_to_comment`), the release predicate
  (`release_predicate` / `is_released`) the read screen and the writer both decide
  with, rendering from the mapping config.
- `knowledge/environment/systems/case-history/mapping.yaml` — the de-facto schema
  (field mapping + conventions + the released status), editable without touching code.
- `scripts/case_history/ticket_writer.py` — I/O: `open_case_ticket` (bridge) /
  `record_case_ticket` (one read-back, one comment POST, a `ticket_write.json`
  receipt on every branch), non-fatal.
- `runtime/ticket_screen.py` + `runtime/query_tool.py` — the read side: an
  unreleased case's comments are served to no model; a released case is served whole.
- `run.py` — `--update-ticket`: open after materialize, record after
  `cross_check_tables`.
- `knowledge/environment/systems/case-history/config.env` — `CASE_HISTORY_*`.

The `ticket_write.json` receipt (`{key, status, url, ok}`) has no reader: it is a
per-run trace for an operator, not a seam anything keys on.
