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
  `released.status` (`closed`). What makes that status MEAN "a person did this" is
  structural, not a check: the defender's client has no transition call at all —
  create and comment are the only writes it can make, and `test_767_writer.py` /
  `test_1047_ticket_lane.py` keep it that way. (In a real store this is the
  agent credential's permission scheme; in the playground, which has no auth, the
  client is the enforcement.) The writer also looks before it appends — one
  read-back, and a `refused-released` receipt if the case is already closed — but
  that is a courtesy against commenting on a case the person has finished with,
  not the gate: a close landing between the read and the write still gets the
  comment. Idempotency still falls out: create-once (a replay's `POST /tickets`
  returns 409 = already there); a re-run of an open case appends a second
  comment, which the person's close then covers too.

- **Cut-short runs record per exit class (#1047 O2), still as comments.** The exit
  class comes in-process from `run.py` off the driver's own summary, never off
  anything in the run dir. `aborted` → an escalation note (no verdict; "environment
  appears unreachable, escalate"), ticket stays open. `request-limit` /
  `retry-exhausted` → the record, proposing the host's forced `unresolved`; with no
  usable report (the forced close itself failed) → the escalation note.
  `budget` / `store` → no call at all. Anything else → the record off the report.
  A run whose model had already closed when the cut landed (`closed_before_cut`)
  records its own verdict instead. Before #767 the forced-close arms CLOSED the
  ticket; that is the one thing this design cannot allow, since a host-set `closed`
  would read to every later run as a person's approval.

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
  report that is missing or carries no parsable disposition still records, with a
  fixed host sentence and no proposal in it — the person sees on the ticket that
  the run ended with nothing to propose, rather than inferring it from silence.
  (The cut-short exit classes above take their own arms first.)

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
  `record_case_ticket` (one read-back, at most one comment POST, a `ticket_write.json`
  receipt on every branch that called out; no transition call exists), non-fatal.
- `runtime/ticket_screen.py` + `runtime/query_tool.py` — the read side: an
  unreleased case's comments are served to no model; a released case is served whole.
- `run.py` — `--update-ticket`: open after materialize, record after
  `cross_check_tables`.
- `knowledge/environment/systems/case-history/config.env` — `CASE_HISTORY_*`.

The `ticket_write.json` receipt (`{key, status, url, ok}`) has no reader: it is a
per-run trace for an operator, not a seam anything keys on.
