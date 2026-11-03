# Case comment path (issue #317, gated by #767, reshaped by #1359)

Design context for the runtime → case-system write path. This started as the first slice
of #317 and was changed by #767 (the write is a comment, never a close) and by #1359 (the
comment goes through the tenant's case-system adapter onto the ticket the alert names). When
this doc and the code disagree, the code wins.

## Why

The benign (FP-direction) learning loop wants to ground dispositions in the org's *past closed
cases*, and a person reviewing a case wants the defender's findings on the ticket they already
have. Each investigated alert, run with `--update-ticket`, adds one comment of findings to its
case; a person closes it.

## Decisions

- **The defender records, a person closes (#767).** The ticket already exists when the alert
  fires (a real SOC's alert-to-ticket automation made it; the playground stands in for that with
  its own step). The run only ever adds one comment: it never creates a ticket, changes fields or
  moves its status. What makes a close MEAN "a person did this" is structural: the comment action
  is not a verb (`kit.verbs.COMMENT_ACTION`, refused in any adapter's `VERBS`), so no grant, query
  tool or model reaches it; and its call carries the host's write-back token, the only token with
  `rw`, matched by the proxy against the system's declared write routes (the docker route has no
  token layer; there the transport's write-endpoint table holds the first layer alone). The writer
  does not read the case back before it appends (#1221 A1).

- **The product owns what and when; the adapter owns how (#1359 P1).** Exit-class rules, comment
  content, agent tag, stale-knowledge sentence, the 4096-byte bound and the receipt are the
  product's and identical for every store. The request shape, the text format, what a status means
  and the ticket's web link are the adapter's: each case-recording adapter exports
  `add_case_comment(ctx, *, key, body) -> link | None`, found by name on the loaded module, never
  imported by product code. The ready-made `jira` and `servicenow` adapters carry no verbs
  (`VERBS = {}`); the playground's `ticket` adapter has the action beside its read verbs.

- **The ticket is the one the alert names (#1359 P3).** The tenant's `alert-mapping.yaml` maps a
  fourth optional fact, `case_key`, onto a field the alerting system sets (the alert's own id, or
  a key its automation writes), never one copied from the logged activity. It is read once at run
  start and recorded; at most 128 printable ASCII characters, no `/`, `\`, `;` or whitespace, not
  made only of dots. A refused or absent key records none and the receipt says the alert names no
  ticket. The key is sent as one percent-encoded path segment.

- **Which system records cases is the tenant's setting.** `settings/case-record.yaml` names the
  `system:` and the `comment.body:` template. A tenant without the file has no case system and
  needs none. `tenant check` and the record step share one judgement (`systems/case_system.py`):
  the system on the roster, its adapter accepted and exporting the action, its `check_settings`
  and, through the credential proxy, a declared write route. The settings are read once when the
  run begins (D-18); a folder still holding `systems/case-history/` is told to move to the file.

- **Cut-short runs record per exit class (#1047 O2), still as comments.** The exit class comes
  in-process from `run.py` off the driver's own summary. `aborted` → an escalation note (no
  verdict), ticket stays open. `request-limit` / `retry-exhausted` → the record, proposing the
  host's forced `unresolved`; with no usable report → the escalation note. `budget` / `store` /
  `provider-down` → no call at all. Anything else → the record off the report. A run whose model
  had already closed when the cut landed (`closed_before_cut`) records its own verdict.

- **Anti-corruption boundary.** `report.md` (+ the run's alert record) is the internal case model;
  the ticket is the external one. `tenancy/case_ticket.py` renders the comment from the tenant's
  template; the drivers and the report schema never bind to ticket field names.

- **One transport.** The comment goes through the shared adapter transport's host write entry
  (`_stub_transport.http_write`: docker route or proxy route, any 2xx is success, a 4xx is an
  `UpstreamFault` carrying the store's status, a 5xx or unreachable store a `TransportFault`).
  There is no second copy of either route in the writer.

- **Never breaks the run.** Every failure is a WARN, a receipt and a return, never a raise/exit.
  The write-back token is minted at the record step; a run that cannot sign goes on and the
  receipt says the write-back token could not be minted.

- **Opt-in.** `--update-ticket` (default off); `--episode` refuses it.

## Shape

- `tenancy/case_ticket.py` — pure: `CaseRecord`, `read_case_record`, `CaseRecordSettings`
  (`settings/case-record.yaml`), the comment renderer, the agent tag (`agent_comment_tag`,
  `posted_comment`).
- `systems/case_system.py` — the shared judgement of the case system and its legacy-folder finding.
- `investigation/ticket_writer.py` — I/O: `record_case_ticket` (at most one comment, a receipt on
  every branch that called out), `clear_receipt`.
- `integrations/{ticket,jira,servicenow}_adapter.py` — the adapters' `add_case_comment`.
- `run.py` — `--update-ticket`: clear the receipt at run start; at run end judge the case
  settings, mint the write-back token, call `record_case_ticket`.

The receipt (`{key, status, url, ok, reason}`) is a sidecar beside the run dir,
`<runs_base>/<run id>.ticket-write.json`, out of the box's reach. `key` is the ticket key (empty
when the alert names none); `url` is the ticket's web link when the adapter gives one, null on
every error receipt. Its one reader is the run page's ticket line.
