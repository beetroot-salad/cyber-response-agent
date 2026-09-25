# Run records — every kind of file a run reads and writes

The inventory issue #1076 asked for: one page naming every record kind a run has and where it
lives. #1077 turns that inventory into the file-backed `Run` handle: `defender/_run_paths.py`
(`RunPaths`), `defender/_episode_paths.py` (`EpisodePaths`) and `defender/_tenant.py` own every
name a run or episode record carries, and `defender/_run_handle.py` (`Run`, `RunRecord`,
`RecordHandle`, `ArchivedWorld`) wraps them into the handle application code addresses by
`(tenant_id, run_id)`.

**This page is generated.** `scripts/lint/lint_run_records.py` renders the table below from the
one checked-in table of record kinds:

- `run-records-kinds.tsv` — one row per record *kind*: its path template, which table it
  belongs to, the read gate's deny mode, its archived-as spelling and which sub-collection of
  the handle owns it.

The gate itself no longer derives a reader/writer census from call sites: `lint_run_records.scan`
is a **name-keyed** static check — no code outside the four owner modules may spell a run or
episode record's name, whole or as a composed part, and any join whose right operand is such a
name is a finding regardless of what the left operand is called. A second, narrower pass tags
values derived from `RunPaths`/`EpisodePaths` construction and flags a literal-free join onto one.
See the owner modules' own docstrings for the full contract; `run-records.tsv` (the old call-site
census) and the page's former per-kind reader/writer tables retired with it.

## The model this page uses

- **Tenant** owns worlds and runs, recorded at `<runs_base>/_tenant.json` (`defender/_tenant.py`).
  No code carries more than one tenant today; the record is the sole authority for the tenant a
  run stamps.
- **World** — an environment as investigated. A *base* world is the capture unchanged
  (`role: "A"`, `runtime/branch/_family.py:59`, exactly one per family, `:503-507`); an
  *overlay* world is a base world plus a one-axis overlay (`World.overlay`, `:289-300`). Two
  strings name a world: the short **label** (`World.world_id`, `:292`, keys `worlds/<label>/`
  in an archive) and the episode-qualified **token** `<episode>.<label>`
  (`ResumeWorld.world_id`, `:886-897`, keys `served/<token>.jsonl`). An unforked run stamps the
  tenant's `base_world_id`.
- **Episode** — a family of runs forked from one source run at one message. It is a grouping,
  not an ownership level: the fork point is declared once in `family.yaml` (`source_run_dir`,
  `source_run_id`, `branch_message_id`, `fences_at`; `_family.py:85, 411-415`), and a sibling
  links to its world only through its run id, `<episode_id>-<label>` (`:920-922`).
- **Run** — the unit of record, addressed by `(tenant_id, run_id)` through `Run.for_tenant`.
  Every forked sibling is a run with its own run dir under the episode
  (`<episode>/runs/<run_id>`, `learning/branch/archive.py:74`). The archive's `worlds/<label>/`
  is a screened *projection* of that run dir (`ArchivedWorld`), not a `Run` itself (section 5).
- **Alert → run** is one-to-many.

Locations are relative to one of four roots: `<run>` (the run dir), `<runs_base>` (its
parent — also where the tenant record lives), `<sessions>` (`<runs_base>/../sessions`,
`runtime/session_store.py`), and `<episode>` = `$DEFENDER_EPISODES_BASE/<episode_id>`
(`learning/branch/cli.py`). The episodes base is a *configured* location with no default: it
must sit outside the runs base, so no runs-base walker counts a sibling as an ordinary run, and
outside the checkout.

**"When"** is one of: *host* (written by host code before the agent's first turn, so the box can
neither forge nor suppress it), *live* (during the run), *end* (at or after close), *later* (by
a tool that runs over a finished run).

**"Denied to"** carries the read gate's *mode*, from `runtime/permission/files.py::decide_read`:
*shape* (a `gather_raw` payload is denied unless the role declares a matching read shape),
*outright* (every role: the wire-log dir, `provenance.json`), *confined* (the case answer key is
denied to the confined learning roles), and the declarative secrets/ground-truth denylist. *cap*
means the read is admitted but goes through the payload read cap and untrusted frame
(`is_captured_payload`), which `decide_read` never consults. Sidecars outside the run dir are
unreachable by root containment rather than by a named deny.

<!-- generated: run-records kinds table — edit run-records-kinds.tsv and run scripts/lint/lint_run_records.py --render -->

| kind | table | path | denied to | archived as | sub-collection | note |
|---|---|---|---|---|---|---|
| alert | 1 | `alert.json` | — (deliberately not in the answer key, `_run_paths.py:197-198`) | alert.json | run.facts.alert | input copied by the host |
| report | 1 | `report.md` | confined | report.md | run.documents.report | the close tool is its only writer; no role holds a write grant for it (`close_tool.py:1`) |
| investigation | 1 | `investigation.md` | confined | investigation.md | run.documents.investigation | seeds (lead-0, branch resume) write it before the first turn; the document tool during |
| queries | 1 | `executed_queries.jsonl` | confined | staged as a table | run.tables.queries | append-only; the gather lane's denial rows land here too |
| source_refs | 1 | `source_refs.yaml` | confined (`_run_paths.py:202-204`) | — | run.documents.source_refs | no writer in this repo — consumed only; test helpers fabricate it (`tests/conftest.py:202`); `tests/test_orchestrate_thresholds.py:509` records that its writer is gone |
| gather_raw | 1 | `gather_raw/<lead>/<seq>.json` | shape | staged as a table | run.tables.payloads | by-ref payloads; the model reaches them by the bash `cat` lane only |
| lead_claim | 1 | `gather_raw/<lead>.lead.json` | shape (same dir) | with gather_raw | run.tables.leads | per-lead claim sidecar, exclusive create |
| gather_summaries | 1 | `gather_summaries/<lead>.md` | — | gather_summaries/ | run.documents.gather_summaries |  |
| lead_author | 1 | `lead_author/` | — | — | run.documents.lead_author | learning-stage outputs under a run dir; learning-internal |
| wire_log | 1 | `wire_logs/llm_requests.jsonl` | outright | — (dropped) | run.observability.wire_log | `review_roles` is a second writer into the same log |
| forward_check_trace | 1 | `wire_logs/<prefix>.<stem>.<n>.trace.jsonl` | outright (dir) | — | run.observability.forward_check_trace | the learning verifier writes into the CITED run's dir after the fact |
| review_trace | 1 | `wire_logs/review_<role>_trace.jsonl` | outright (dir) | — | run.observability.review_trace |  |
| review_record | 1 | `review_record.<turn>.json` | — | — | run.observability.review_record | one per close attempt |
| tool_trace | 1 | `tool_trace.jsonl` | — | — | run.observability.tool_trace | a whole-file rebuild from the session store, written once after the agent returns |
| policy_denials | 1 | `policy_denials.jsonl` | — | — | run.tables.policy_denials |  |
| budget | 1 | `budget.json` | — | — | run.observability.budget | counter, locked json |
| circuit_breaker | 1 | `circuit_breaker.json` | — | — | run.observability.circuit_breaker | counter |
| lessons_loaded | 1 | `lessons_loaded.jsonl` | — | lessons_loaded.jsonl | run.observability.lessons_loaded | receipt of corpus consumption; `hooks/record_lesson_load` is the reader-side classifier |
| ticket_write | 1 | `ticket_write.json` | — | — | run.observability.ticket_write |  |
| ticket_reads | 1 | `ticket_reads/<seq>.json` | cap | — | run.tables.ticket_reads | retired writer (the old pipeline judge, `permission/files.py:394-395`); only the path shape (`_run_paths.py:190`) and the read cap survive |
| session_pointer | 1 | `session_store_pointer.json` | — | — | run.observability.session_pointer | written by the driver before the first turn |
| runtime_html | 1 | `runtime.html` | (inlines MAIN's transcript; safe on timing only, `_run_paths.py:63-68`) | — | run.observability.runtime_html | mirrored to `<main checkout>/run-visualizations/`, written as the checkout's owner (`visualize_run.render_and_mirror`, #1084) |
| box_sentinel | 1 | `.box-sentinel` | — | — | run.observability.box_sentinel | `unlink_on_fault=False` (`_lifecycle.py:105-106`), left behind on a fault as evidence (`:96-102`); the mount-check sentinel `.box-sentinel-<uuid>` (`:109-117`) is a different, self-cleaning family |
| provenance | 1 | `provenance.json` | outright | provenance.json | run.facts.provenance | stamped by the host at materialize time |
| run_end | 2 | `<run>.run-end.json` | — | run_end.json (renamed, `archive.py:148`) | run.facts.run_end | cleared by the host at `run_common.py:71-77` before a reused id |
| scrub_verdict | 2 | `<run>.scrub-verdict.json` | — | scrub_verdict.json (renamed, `archive.py:79`) | run.facts.scrub_verdict |  |
| accounting | 2 | `<run>.accounting_failures.json` | — | — | run.facts.accounting |  |
| session_db | 3 | `<sessions>/<lineage id>.db` | — | — | run.session.session_db | SQLite; the connection at `_bare_connect` carries every read and append |
| family | 4 | `family.yaml` | — | — | episode.family | the fork point, declared once per episode |
| family_stamp | 4 | `provenance.json` | — | — | episode.family_stamp | a different shape from the run stamp; written by `verify_family` |
| review_yaml | 4 | `review.yaml` | — | — | episode.review | written at `Step.REVIEW`, before the siblings run; the outcome is merged in at the end (`cli.py:1120`) |
| samples | 4 | `samples.yaml` | — | — | episode.samples | written at `Step.QUESTIONER`, before the model call |
| judge_yaml | 4 | `judge.yaml` | — | — | episode.judge |  |
| judge_draw | 4 | `worlds/<label>/judge/<n>.yaml, worlds/family/judge/<n>.yaml` | — | — | episode.judge_draw |  |
| timing | 4 | `timing.json` | — | — | episode.timing | per launcher step |
| staged | 4 | `staged.yaml` | — | — | episode.staged | the sole record that a cluster write happened |
| served | 4 | `served/base.jsonl, served/<token>.jsonl` | — | — | episode.served | base: primed once by the host before any sibling; <token>: appended live per sibling |
| priming_lock | 4 | `served/.priming` | — | — | episode.priming_lock | `O_CREAT\|O_EXCL`; never unlinked, so a crashed priming leaves the episode permanently claimed |
| stage_trace | 4 | `wire_logs/<stage>.trace.jsonl, wire_logs/<agent>_framed_trace.jsonl` | — | — | episode.stage_trace | episode-root wire traces of the learning stages |
| learning_html | 4 | `learning.html` | — | — | episode.learning_html |  |
| episode_runs | 4 | `runs/<episode_id>-<label>/` | — | — | episode.episode_runs | a sibling's real run dir; its files take their table-1 kinds |
| archive_proj | 4 | `worlds/<label>` | — | — | episode.archive_proj | the archive copy itself (section 5) |
| tool_seam |  | `(the role's declared read/write targets)` | — | — | — | the model's generic read/write/edit file tools; the kind is decided by the gate at the call |
| tenant | 2 | `_tenant.json` | — | — | tenant | D2: created once when absent |

<!-- end generated -->

## 5. The archive projection (`<episode>/worlds/<label>/`)

`learning/branch/archive.archive_episode` copies **exactly** the set `_single_files` declares:
`report.md`, `investigation.md`, `provenance.json`, the scrub verdict (as `scrub_verdict.json`),
the run-end record (as `run_end.json`), `lessons_loaded.jsonl`, `alert.json`; plus the
`gather_summaries/` directory, the two tables (`executed_queries.jsonl` and `gather_raw/`)
through `lead_repository.stage_tables`, and a `run_dir` text pointer (never a link). Every read
is lstat-screened first and a planted link archives nothing. Everything else — wire logs,
traces, counters, denials, review records, the session pointer, `runtime.html`,
`ticket_write.json`, the tenant record — does not survive the copy. `ArchivedWorld.at(world_dir)`
is the read-only handle over this projection; it is not a `Run`.

## 6. Not a run record

Marked here so a reader does not mistake these for a kind this page owns.

- **Learning queues, locks and markers** under `LoopPaths` (`learning/core/config.py`):
  `_pending*/`, `author-queue/`, `_pending_delivery/`, `.stuck.jsonl`, batch markers.
- **Quarantine** of a tainted worktree: tar + manifest (`learning/core/quarantine.py`).
- **Checked-in corpora a run consumes**: lessons, knowledge, skills, the gather query catalog,
  `lead-zero.yaml`, `bash_policy.json`, prompts and templates. `lessons_loaded.jsonl` is the
  in-run receipt of consumption and is a run record; the corpora themselves are not.
- **Eval case inputs and result trees** (`evals/`).
- **Rendered pages outside a run or episode** (`queues.html`, `lessons.html`) and the untracked
  `run-visualizations/` mirror at the main checkout's top level (#1084).
- The corpus curators' own wire traces under `_pending/wire_logs/`, learning state rather than a
  run record; the review step's scratch `served/` tree, which is not the episode's.
- Repo and worktree files, git plumbing, container identity files, stdio and subprocess pipes,
  scratch files.
