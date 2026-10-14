# #1165 current intent and design — 2026-10-14

Base: c0ceb90dccb1d87c8c4783000ffbe887d41e46c5. This is the implementation candidate, incorporating the owner-approved plan and independent design review. Background evidence and predecessor links: design.md in this directory. Engineering principles: docs/principles.md. The October 6 issue design is superseded where it conflicts with this document.

## Intent

- O1: Durable run-record reads and host writes within runtime/**, hooks/**, scripts/gather_tools/**, scripts/case_history/** use the Run handed down from the repository, except finite declared residue. The same handle reaches actual production entry points; ceremonial handle calls followed by path I/O do not satisfy this obligation.
- O2: Host writes of model-file views use Run operations. Local layout, bytes, ordering and presence remain compatible except the owner-approved exclusion of unexpected inherited entries.
- O3: Run operations have store meanings, not held-open streams or whole-log rewrites. Extend existing generic handles; no new typed domain-model redesign.
- O4: Preserve record-specific validation and effective failures, including logging/best-effort cases. Preserve logger lifecycle and encoding, source missing/refusal distinctions, and existing query parser tolerance. Scope is not new corruption/content policy.
- O5: Host record mutations walk folders below the trust root without following links at mutation time. Pair refusal tests with valid-folder positive controls. A root spelling may follow its own host-owned alias as existing core does.
- O6: RunState remains the single per-execution owner of live budgets, breaker, query rows and oracle clock. Query writes keep the existing lock and ordering; a refused file-view append leaves the row in state and its seq spent.
- O7: Fork seeding retains the current alert for the same alert ID even if bytes changed, and skips unexpected inherited files before reading. Recognized artifacts retain existing validation/content/copy-failure behavior. Source evidence selection at the branch point is unchanged.

Non-obligations: actual database/blob backend or sink transport (#1082), stronger query/claim domain types, crash recovery, path-seam deletion, tool_trace retirement, publishing/PR/merge. Read-only model working-file access and the model-tools existing held-root backend are allowed residue. SQLite stays on session_store.open_store. Budget/breaker/query live reads stay in memory, not residue path reads. Probe, staged-file cleanup and explicitly enumerated non-run learning/worktree I/O remain outside record migration. Individually identified source enumeration and legacy-link-presence operations may remain residue; durable recognized source record contents must use the source Run. No blanket source exemption.

## Data and architecture

Keep Run's existing five groups and RunRecord metadata. Existing .path remains for mounts, identities and allowed working-file reads. RunState is independent; do not add process-global tables or reload its state from disk.

Driver receives required run: Run and derives directory/id. AgentDeps carries Run beside shared RunState; roles without a run may carry None but live durable-record writers must refuse absence rather than reconstruct a Run. Adapt production callers and test harnesses. The already-opened source Run is a separate source argument, propagated through driver/store factory, branch validation, seeding and source-session lookup; do not embed a live Run into BranchSpec serialization. Constructors stay confined to run_repository.

Extend generic RecordHandle capabilities with the following agreed names (tests may use these names):
- read_result(*, errors='strict') -> existing _io.RecordRead; read_bytes() -> _io.BytesRead; read_rows() -> (rows, malformed_count, RecordRead). Preserve existing read() -> str|None. Use existing bound/core readers and result categories. Resolution/tree OSError becomes refused, with absence distinguished; bad addressing ValueError propagates. A caller retains its current treatment of absence/refusal (e.g. investigation source unreadability seeds empty).
- append_text(text) and start_stream(text): run wire log and policy denials; review traces append_text only. No re-encoding encoded text. Empty append_text performs the actual append/create operation, required for reopening.
- create(text_or_bytes): queries only, for a one-time seed before normal append. Existing append(rows) stays for queries and lessons. Preserve JSON encoding/key order.
- seed(text): investigation only, validates proposed against itself, retains fresh-sibling refusal, then writes through rooted core. Ordinary investigation.write validates against existing content. report.write validates against None, matching close_tool.
- delete(): ticket_write only, missing success; rooted leaf deletion follows no parent links, while preserving ordinary unlink(missing_ok=True) leaf behavior (including safe removal of a leaf symlink). Caller keeps best-effort logged failure.
- run_end.write replaces; leads.write remains exclusive/write-once and maps existing collisions/faults to CLAIMED/ALREADY_CLAIMED/NOT_CLAIMED unchanged.
Use a single authoritative per-member capability declaration; retain compatibility with existing primary-verb metadata where needed and update the spec mirrors intentionally. Unsupported operations are absent. Do not silently change unrelated member behavior.

## Flows

### Queries and documents
record_query remains the authoritative producer of row columns, seq, digests and payload addressing. Under the same state lock: parameter validation before any write; payload best-effort via Run; parsed row into state; append row via Run. Errors before row construction record nothing. File append errors leave state row intact. Existing payload size cap and null payload reference on persistence failure remain. Fork seeding records inherited rows into state after the seeded table write succeeds, as today. Retain actual artifact schema gates; no arbitrary caller-selected validation bypass.

Host investigation writes, gather summaries, lesson-loaded rows, lead claims, reports/review records, run-end, session pointer, ticket receipt and scrub verdict migrate. Source record reads migrate where reached by running investigation. Pure JSON/JSONL parsing is not file I/O.

### Logging
RequestLogger keeps in-memory messages, pricing counters and sequences. Add RequestLogger.from_record(record) for run sinks. Preserve RequestLogger(path) for learning and other non-run scopes. Run-backed sinks invoke record operations and never hold open a file.
Preserve canonical single-active identity and ever-opened tracking. First construction performs start_stream(''); reopen performs append_text(''), including recreation when absent and eager refusal when planted. Register identities only after successful initialization. Wire file remains eager. denial_logger is lazy, created on first denial; initialization OSError logs once and caches null fallback; later append failures propagate. close marks closed and releases active identity; further record writes raise ValueError('...closed...'), while budget-refusal logging retains its suppressor. Encoding is encode_wire_record + newline (ensure_ascii=True). Review trace row and any raw reply remain one text append with unchanged bytes. Preserve wire/review errors instead of inheriting unrelated partial-failure swallowing. Remove wire record logger_factory coupling.

### Forks
Use current source selection and prefix slicing. Canonical recognized names are exactly those the layout owner produces: raw payload index names, lead claims, gather summaries, selected queries. Do not coerce noncanonical spellings (01.json) into a different name. Unexpected entries are skipped without reads/traversal or new content validation. Recognized files are copied as opaque bytes, including invalid UTF-8; refused recognized reads/copies still fail. Current alert wins; missing-alert fallback retains verified source copy and matching alert-record semantics. No new different-alert-ID policy.

### Run-end and box lifecycle
Pass Run into run-end and ticket paths. Bind verdict read/write operations before box startup and thread optional callbacks through start_box, stop_and_scrub and scrub as necessary. Cover startup failure, teardown failure, successful scrub, skipped scrub and unsandboxed marking (including verdict read). Preserve failure precedence and best-effort logs. Learning worktrees retain explicitly non-run path callbacks. Do not fix unrelated scrub/verdict semantics.

## Census and executable contract

Sweep directory scope above with #1133's current vocabulary and resolver, plus path-seam readers and owner-derived target tracing from scripts/lint/_astlib.py. Classify each occurrence by target, direction and residue category; unresolved possible record targets are findings. Calls and references count. Compare multiset/counts, keyed by module, enclosing scope and resolved callee, never line. New duplicate bypasses within an exempt scope and stale residue must fail. Known nonrecord settings/skill/scratch I/O is explicitly classified; residue must not hide unclassified records. No new baseline allowance.

Tests combine real handle/core/fault behavior, real production/replay wiring, exact bytes/presence, and synthetic planted census bypasses. Preserve RunState and replay regressions. Independent contract review precedes immutable tests-only commit. Honest and adversarial implementers start from that same commit in isolated worktrees, never reading each other's implementation. Contract repairs are independent reviewed tests-only commits. Required acceptance: both reports reconciled; focused and full non-live CI suite, gate-marked tests and applicable lint/type gates pass; unavailable checks are reported, not claimed passing. Every pytest invocation uses flock /tmp/defender-pytest.lock and worktree-root PYTHONPATH. No push/PR without another request.

Independent design review accepted after corrections for seed baseline, tri-state address failures, logger eager reopen/closure, receipt deletion, all scrub verdict paths, complete source propagation and census multiplicity. Detailed evidence inherited in design.md; new grounding was source reads, not executed behavior probes. Baseline test attempt in planning could not acquire shared lock and is not a pass.

## Inherited grounding claims

```yaml
claims:
  - id: A-C-current-alert
    kind: referential
    claim: Current fork seeding preserves an existing sibling alert rather than comparing source bytes.
    probe: Read defender/runtime/branch/_seed.py::_inherit_evidence at the grounding base.
    probe_kind: read
    observed: Source alert copy is conditional on the sibling alert not existing; source alert integrity is verified when copied.
    verdict: holds
  - id: A-C-copy-scope
    kind: referential
    claim: Current evidence copy admits arbitrary plain-file payload names within selected lead directories.
    probe: Read defender/runtime/branch/_seed.py::_inherit_lead_dir and _copy_artifact at the grounding base.
    probe_kind: read
    observed: Every sorted entry within a selected lead directory is passed to the plain-file copy without a payload-name filter.
    verdict: holds
  - id: A-C-run-state
    kind: referential
    claim: The current runtime has a per-execution RunState with budget, breaker, query rows and oracle clock.
    probe: Read defender/runtime/run_state.py and branch/_seed.py at the grounding base.
    probe_kind: read
    observed: RunState holds those fields; seeding calls inherit_rows after writing inherited query rows.
    verdict: holds
  - id: A-C-storage-revision
    kind: referential
    claim: Newer owner decisions supersede the exactly-four-file and run-end-ingestion premises.
    probe: gh issue view 1235 --json title,body,comments; gh issue view 1082 --json title,body,comments.
    probe_kind: read
    observed: October 11 classification adds query and lead-claim views and drops run-end box-output ingestion; October 12 revision adopts one RunState.
    verdict: holds
  - id: A-C-stale-platform
    kind: referential
    claim: The checked-in platform document still contains older projection-at-completion prose.
    probe: Read docs/platform-design.md sections 4.5 and 4.6 at the grounding base.
    probe_kind: read
    observed: Local tool trace upload once at completion and plain-file projection remain described, conflicting with newer live-audit and storage direction.
    verdict: holds
```

Compatibility clarification: alert_record retains write-once write and exposes explicit generic replace for the existing missing-alert fork fallback, which replaces a stale sibling record through rooted I/O. Text reads retain the existing universal-newline normalization; byte reads remain opaque.
