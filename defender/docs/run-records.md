# Run records — every kind of file a run reads and writes

The inventory issue #1076 asked for: one page naming every record kind a run has, who writes
it, who reads it, when in the run's life it is written, and which kinds cross a package
boundary. It is the list the run handle (#1077) is built from. It moves nothing and renames
nothing; the code is still the spec. **Citation convention:** every writer and reader cell
cites the *call* that writes or reads (or the function that holds it), never the constant that
spells the name; the constants are listed once under the `RunPaths` and `archive.py` name
owners. Tests are excluded throughout. Cold-reviewed 2026-09-20; every cell was re-resolved.

## The model this page uses

- **Tenant** owns worlds and runs. No code carries a tenant today; #1077 introduces it.
- **World** — an environment as investigated. A *base* world is the capture unchanged
  (`role: "A"`, `runtime/branch/_family.py:59`, exactly one per family, `:503-507`); an
  *overlay* world is a base world plus a one-axis overlay (`World.overlay`, `:289-300`). Two
  strings name a world: the short **label** (`World.world_id`, `:292`, keys `worlds/<label>/`
  in an archive) and the episode-qualified **token** `<episode>.<label>`
  (`ResumeWorld.world_id`, `:886-897`, keys `served/<token>.jsonl`). An unforked run carries no
  world id at all.
- **Episode** — a family of runs forked from one source run at one message. It is a grouping,
  not an ownership level: the fork point is declared once in `family.yaml` (`source_run_dir`,
  `source_run_id`, `branch_message_id`, `fences_at`; `_family.py:85, 411-415`), and a sibling
  links to its world only through its run id, `<episode_id>-<label>` (`:920-922`).
- **Run** — the unit of record. Every forked sibling is a run with its own run dir under the
  episode (`<episode>/runs/<run_id>`, `learning/branch/archive.py:74`). The archive's
  `worlds/<label>/` is a screened *projection* of that run dir, not the run dir (section 5).
- **Alert → run** is one-to-many.

Locations are relative to one of four roots: `<run>` (the run dir), `<runs_base>` (its
parent), `<sessions>` (`<runs_base>/../sessions`, `runtime/session_store.py:673-677`), and
`<episode>` = `$DEFENDER_EPISODES_BASE/<episode_id>` (`learning/branch/cli.py:131-151,
196-206`). The episodes base is a *configured* location with no default: it must sit outside the
runs base, so no runs-base walker counts a sibling as an ordinary run, and outside the checkout.
Two comments in the tree still describe it as under the learning state (`branch/capture.py:133`,
`branch/ledger.py:526`); this page is the one place it is right.

**"When"** is one of: *host* (written by host code before the agent's first turn, so the box can
neither forge nor suppress it), *live* (during the run), *end* (at or after close), *later* (by
a tool that runs over a finished run).

**"Denied to"** carries the read gate's *mode*, from `runtime/permission/files.py::decide_read`:
*shape* (a `gather_raw` payload is denied unless the role declares a matching read shape,
`:202-203`), *outright* (every role: the wire-log dir `:210-211`, `provenance.json` `:212-213`),
*confined* (the case answer key is denied to the confined learning roles, `:240-241`), and the
declarative secrets/ground-truth denylist (`:40`, applied `:252-253`). *cap* means the read is
admitted but goes through the payload read cap and untrusted frame (`is_captured_payload`
`:452`, caller `runtime/tools/_deps.py:84`), which `decide_read` never consults. Sidecars outside
the run dir are unreachable by root containment rather than by a named deny.

## 1. Records inside the run dir

| kind | path under `<run>` | writer | when | readers | denied to | crosses boundary | archived as |
|---|---|---|---|---|---|---|---|
| alert | `alert.json` | `run_common.materialize_run_dir` copies the input (`run_common.py:80`); a branch sibling's seed re-copies it (`runtime/branch/_seed.py:251`) | host | runtime (`orient.py:64, 73`), learning (`judge/render.py:749`, archive), scripts (`case_history/ticket_writer.py:99`, visualize), evals (`held_out.py:50`) | — (deliberately not in the answer key, `_run_paths.py:197-198`) | yes | `alert.json` |
| report | `report.md` | runtime close tool, its only writer (`close_tool.py:432`); no role holds a write grant for it | end | learning (judge, questioner, archive `:176`; `branch/episode.py` reads the *archived* copy, `:12-13`), scripts (`case_history/case_ticket.py:196-205`, visualize), evals (`held_out.py:50, 155`) | confined | yes | `report.md` |
| investigation | `investigation.md` | runtime document tool (`tools/_document.py:357, 729`, via the MAIN write grant `driver/_build.py:194`); the lead-0 seed (`lead_zero/_capture.py:389`) and a sibling's resume seed (`branch/_seed.py:205`) write it before the first turn | host + live | runtime (compaction, close gate, lead-zero), learning (judge, questioner, verify_forward), scripts (visualize, `lessons/lessons_frontier.py:781`) | confined | yes | `investigation.md` |
| queries | `executed_queries.jsonl` | **scripts** `gather_tools/record_query.append_query_row` (`:300`, append at `:367`) | live | runtime (`query_tool.py:533, 831`, `branch/_seed.py`, `branch/_frontier.py:454`, lead-zero), learning (`lead_repository.py:549`, judge) | confined | yes | staged by `lead_repository.stage_tables` |
| source_refs | `source_refs.yaml` | **no writer in this repo** — consumed only; test helpers fabricate it (`tests/conftest.py:202`), and `tests/test_orchestrate_thresholds.py:509` records that its writer is gone | — | learning (`author/lessons/run.py:106-115`, `author/verify_forward/forward.py:23-37`); the questioner explicitly does not (`author/questioner/run.py:8-10`) | confined (`_run_paths.py:202-204`) | no (learning only) | — |
| gather_raw | `gather_raw/l-<lead>/<seq>.json` | scripts `gather_tools/record_query.persist_payload` (`:264-268`) | live | runtime bash `cat` lane (`tools/_bash.py`, by-ref only), learning (`lead_repository.stage_tables`, judge) | shape | yes | staged as a table |
| lead_claim | `gather_raw/<lead>.lead.json` | hooks `record_lead.py:63` (exclusive create) | live | runtime (`branch/_frontier.py:442-469`), learning (`lead_repository.load_leads`, `:177-178`) | shape (same dir) | yes | with `gather_raw` |
| gather_summaries | `gather_summaries/<lead>.md` | runtime `tools_gather.py:426` | live | runtime (`driver/_build.py:306`), learning (archive `:187`, judge) | — | yes | `gather_summaries/` |
| lead_author | `lead_author/` | learning lead-author stage (`leads/lead_author/__init__.py:128-130`) | later | learning (same stage only; `evals/harness_lead.py` spawns the stage and reads nothing here) | — | no (learning only) | — |
| wire_log | `wire_logs/llm_requests.jsonl` | runtime `observe.RequestLogger` (path `observe.py:257-269`) | live | scripts (`visualize/visualize_messages.py`); `review_roles.py` is a second *writer* into it | outright | yes | — (dropped) |
| forward_check_trace | `wire_logs/<prefix>.<stem>.<n>.trace.jsonl` | **learning** forward-check verifier, written into the CITED run's dir (`author/verify_forward/checks.py:72`, `engine.py:66`) | later | operator debugging only | outright (dir) | yes (learning writes into a run) | — |
| review_trace | `wire_logs/review_<role>_trace.jsonl` | runtime `challenge_gate._write_trace_row` | live | scripts (`visualize/visualize_runtime.py:480-482`) | outright (dir) | yes | — |
| review_record | `review_record.<turn>.json` | runtime `challenge_gate.write_review_record` (`:158-167`), called from `close_tool.py:406-410` and the CHALLENGED arm `:622-623` | end (per close attempt) | learning (`judge/family.py:196-200`, `judge/__init__.py:555`), scripts (`visualize/visualize_runtime.py:396`, `visualize_episode.py:219`) | — | yes | — |
| tool_trace | `tool_trace.jsonl` | runtime `observe.write_trace` (`:339`), called once after the agent returns (`driver/__init__.py:705`; empty-trace fallback `:709`); a whole-file replace rebuilt from the session store | end | scripts only (`visualize_run.py:334`, `visualize_runtime.py:779`, `visualize_episode.py:88, 295`) | — | yes | — |
| policy_denials | `policy_denials.jsonl` | runtime `observe.RequestLogger.log_policy_denial` (`:178`, path `:245-246`), from `query_tool.py:657` | live | scripts (`visualize/visualize_run.py:307-320`); the gather lane also records a parallel denial row in `queries` (`record_query.py:697`) | — | yes | — |
| budget | `budget.json` | hooks `budget_enforcer.py:72-120` (through `hooks/_run_dir.update_json_locked`, `:28`) | live | runtime (`driver/_budget.py:49`, `lead_zero/_capture.py:317`), scripts (`workspace_map.py:33`, suppression only) | — | yes | — |
| circuit_breaker | `circuit_breaker.json` | runtime `circuit_breaker.record_outcome` (`:130, 151`) | live | runtime (`lead_zero/_capture.py:237`) | — | no | — |
| lessons_loaded | `lessons_loaded.jsonl` | runtime `tools/_deps.py:251`, "the ONE writer" (`:231`); `hooks/record_lesson_load` is the reader-side classifier | live | learning (`judge/render.py:699`, archive, `ops/trace_lesson.py`) | — | yes | `lessons_loaded.jsonl` |
| ticket_write | `ticket_write.json` | scripts `case_history/ticket_writer.py:280` | end | none found | — | no | — |
| ticket_reads | `ticket_reads/<seq>.json` | **retired** — the old pipeline judge's closed-ticket tool (`permission/files.py:394-395`); only the path shape (`_run_paths.py:190`) and the read cap survive | — | runtime read cap (`permission/files.py:452`) | cap | no | — |
| session_pointer | `session_store_pointer.json` | runtime `session_store.write_case_pointer` (`:735`) from the driver at start | live (before the first turn) | runtime (`branch/_spec.py:166-173`), learning (`branch/cli.py:602`) | — | yes | — |
| runtime_html | `runtime.html` | scripts `visualize/visualize_run.py:73` | later | scripts (`visualize_episode.py:1780-1833`, links); copied to `run-visualizations/` (`visualize_run.py:80`) | (inlines MAIN's transcript; safe on timing only, `_run_paths.py:58-66`) | no | — |
| box_sentinel | `.box-sentinel` | runtime `box/_lifecycle.py:73` (`unlink_on_fault=False`, `:105-106`; left behind on a fault as evidence, `:96-102`). The mount-check sentinel `.box-sentinel-<uuid>` (`:109-117`) is a different, self-cleaning family | host | runtime (same module) | — | no | — |
| provenance | `provenance.json` | `run_common.materialize_run_dir` (`run_common.py:98`) | host | runtime (read gate `permission/files.py:333`), learning (`branch/cli.verify_family`, archive `:178`), scripts (`workspace_map` suppression) | outright | yes | `provenance.json` |

## 2. Records beside the run dir (siblings under `<runs_base>`)

All three are written outside the box's writable mount so the model can neither plant nor
suppress them. No read-gate deny names them; root containment keeps every role out.

| kind | path | writer | when | readers | crosses boundary | archived as |
|---|---|---|---|---|---|---|
| run_end | `<run>.run-end.json` | runtime `run_end.write_sidecar` (`:116, 125`; path `:113`); cleared by the host at `run_common.py:71-77` before a reused id | end | runtime (`scrub.tree_verified`), learning (archive `:181`; the judge via the `truncated_by` vocabulary) | yes | `run_end.json` (renamed, `archive.py:148`) |
| scrub_verdict | `<run>.scrub-verdict.json` | runtime `scrub._write_verdict` (`:134, 139`; path `:129`) | end | runtime (`scrub.py:162`), learning (archive, `author/branch.py:185` unlinks, `core/quarantine.py:60`) | yes | `scrub_verdict.json` (renamed, `archive.py:79`) |
| accounting | `<run>.accounting_failures.json` | hooks `budget_enforcer.py:204, 217` (path `:153-155`) | live | hooks (same module, `:167`) | no | — |

## 3. Session history

| kind | path | writer | when | readers | crosses boundary |
|---|---|---|---|---|---|
| session_db | `<sessions>/<lineage id>.db` (SQLite) | runtime `session_store.append` (`:370`) from `selection.py:90, 138` and `driver/_build.py:397`; opened and bound at `driver/__init__.py:586-620` | live | runtime (resume/fork join it), learning (`branch/cli.py`), scripts (`visualize/visualize_run.py:70-72`) | yes |

The key is a **lineage** id: a fresh run mints `uuid4().hex` (`driver/__init__.py:586`); a
resume or fork joins the source's store and rebinds to its id (`:593-620`). One DB spans a run
and its resumes and forks. Two runs of one alert are two DBs. The pointer in the run dir
(table 1, `session_pointer`) is how a run resolves to its transcript. The alert-derived
`case-<sha256[:16]>` in `run_common.py:286` keys the curation queue and is unrelated. Session
history is a **run record** (`run.session` in #1077); the shared file is a detail of the file
backend.

## 4. Episode-level records (under `<episode>`)

The launcher's step order is QUESTIONER, STAGING, REVIEW, RUNS, VERIFY, JUDGE
(`learning/branch/steps.py:52-57`); "host" below means before `RUNS`.

| kind | path | writer | when | readers |
|---|---|---|---|---|
| family | `family.yaml` | launcher, `runtime/branch/_family.py:656` via `learning/branch/cli.py:1677` (name `:55`) | host | every sibling, review, judge, archive, episode page |
| family_stamp | `provenance.json` at the episode root (a different shape from the run stamp) | launcher `branch/cli._write_family_stamp` (`:1070`, write `:1101-1104`), called from `verify_family` (`:1062`) | end of family | learning (`archive.read_family_stamp`, `:107-131`), scripts (`visualize_episode.py:262`) |
| review_yaml | `review.yaml` | learning `branch/review.py:328-330` | host (`Step.REVIEW`); the episode outcome is merged in at the end (`cli.py:1120`) | judge, episode page |
| samples | `samples.yaml` | launcher `branch/cli.write_questioner_samples` (`:1563`, write `:1586`), inside `Step.QUESTIONER` before the model call | host | judge, episode page |
| judge_yaml | `judge.yaml` | learning `judge/__init__._write_judge_yaml` (`:900, 908`) | after archive | enqueue re-read, episode page |
| judge_draw | `worlds/<label>/judge/<n>.yaml`, `worlds/family/judge/<n>.yaml` | learning `judge/__init__.py:396` (dir name `archive.py:98`) | after archive | episode page |
| timing | `timing.json` | learning `branch/timing.Timing.record` (`:70`, write `:96`) | live (per launcher step) | episode page |
| staged | `staged.yaml` | learning `branch/staging.record_staged` (`:396`, write `:416-422`) — the sole record that a cluster write happened | host (`Step.STAGING`) | learning (`staging.py:548, 662`, `branch/cli.py:1401`), scripts (`visualize_episode.py:246`) |
| served (base) | `served/base.jsonl` | learning `branch/capture.prime_base` (`:61`, append `:133`) from `cli.py:312`; empty-capture fallback `cli.py:339` | host, once | ledger (`ledger.py:450`), judge |
| served (world) | `served/<token>.jsonl` | learning `branch/ledger.Ledger.record` (`:484`, append `:526`) | live (per sibling) | ledger, judge |
| priming_lock | `served/.priming` | learning `branch/cli.prepare_episode` (`:303-305`, `O_CREAT\|O_EXCL`); never unlinked, so a crashed priming leaves the episode permanently claimed | host | same function |
| stage_trace | `wire_logs/<stage>.trace.jsonl`, `wire_logs/<agent>_framed_trace.jsonl` | learning stages via `runtime/observe.py:272-282` (`judge/__init__.py:423-424`) | live | visualizers |
| learning_html | `learning.html` | scripts `visualize/visualize_episode.py:85, 1389` | later | humans |
| episode_runs | `runs/<episode_id>-<label>/` | each sibling's own `materialize_run_dir` | host | as table 1 |

## 5. The archive projection (`<episode>/worlds/<label>/`)

`learning/branch/archive.archive_episode` (`:291-349`: `copy2` `:314`, `stage_tables` `:322`,
`copytree` `:330`, pointer `:347`) copies **exactly** the set `_single_files` declares
(`:157-184`): `report.md`, `investigation.md`, `provenance.json`, the scrub verdict (as
`scrub_verdict.json`), the run-end record (as `run_end.json`), `lessons_loaded.jsonl`,
`alert.json`; plus the `gather_summaries/` directory (`:187-189`), the two tables
(`executed_queries.jsonl` and `gather_raw/`) through `lead_repository.stage_tables`
(`:532-569`), and a `run_dir` text pointer (`:82, 347`, never a link). Every read is
lstat-screened first and a planted link archives nothing. Everything else in table 1 — wire
logs, traces, counters, denials, review records, the session pointer, `runtime.html`,
`ticket_write.json` — does not survive the copy. The "archived as" column in tables 1 and 2
records this per kind. The appendix tags the copy's call sites `archive_proj`.

## 6. Not a run record

Marked here so the sweep can attribute a call site to them explicitly.

- **Learning queues, locks and markers** under `LoopPaths` (`learning/core/config.py:72-133`):
  `_pending*/`, `author-queue/`, `_pending_delivery/`, `.stuck.jsonl`, batch markers
  (`learning/core/markers.py:16, 35`).
- **Quarantine** of a tainted worktree: tar + manifest (`learning/core/quarantine.py:40-60`).
- **Checked-in corpora a run consumes**: lessons, knowledge, skills, the gather query catalog
  (`runtime/tools_gather.py:76`), `lead-zero.yaml` (`runtime/lead_zero_config.py:32`),
  `bash_policy.json`, prompts and templates. Out of scope by decision: `lessons_loaded.jsonl`
  is the in-run receipt of consumption and #1079 owns the corpora.
- **Eval case inputs** (`evals/oracle_golden`: `manifest.yaml`, `oracle_visible/`, `hidden/`,
  `expected.yaml`, controls) and **eval result trees** (`evals/harness.py:73-105`,
  `harness_lead.py:132-136`: `rc.txt`, `git_log.txt`, `timing.txt`, `verdict.txt`).
- **Rendered pages outside a run or episode** (`queues.html`, `lessons.html`) and the checked-in
  `run-visualizations/` tree (#1084).
- The corpus curators' own wire traces under `_pending/wire_logs/` (`learning/core/config.py:282`),
  learning state rather than a run record; the review step's scratch `served/` tree
  (`learning/branch/review.py:163`), which is not the episode's.
- Repo and worktree files, git plumbing, container identity files (`/etc/hostname`,
  `/proc/self/mountinfo`, `runtime/box/_docker.py:250-253`), stdio and subprocess pipes,
  scratch files.

## 7. Sub-collections for the run handle (#1077)

Rows with *crosses boundary = yes*, grouped by the concept the handle names:

| sub-collection | kinds | append/write owner | readable mid-run |
|---|---|---|---|
| `run.alert` | alert | host | yes |
| `run.report` | report | runtime (end) | no |
| `run.log` | investigation | runtime (seeds before the first turn, tool during) | yes |
| `run.queries` | queries, policy_denials | scripts gather lane / runtime observe (append-only) | yes — must survive |
| `run.leads` | lead_claim, gather_summaries | hooks / runtime | yes — must survive |
| `run.payloads` | gather_raw | scripts gather lane | by-ref only, shape-gated |
| `run.session` | session_db, session_pointer | runtime | yes |
| `run.review` | review_record, review_trace | runtime | trace live, record at close |
| `run.traces` | wire_log, tool_trace, lessons_loaded, budget, forward_check_trace | runtime / hooks; the learning verifier appends its own trace later | wire log live but denied outright; tool trace only at end |
| `run.provenance` | provenance, run_end, scrub_verdict | host / runtime end | `provenance.json` denied outright; the two sidecars unreachable by containment |

Learning-internal kinds (`source_refs`, `lead_author`, `ticket_reads`) and episode-level kinds
(table 4) are not sub-collections of the run handle.

## Appendix — call-site attribution

Every raw file-access call site in `runtime/`, `learning/`, `scripts/`, `evals/`, `hooks/`,
`run.py`, `run_common.py` and `defender/_*.py` (tests excluded), matched by
`open(`, `read_text`/`write_text`, the `_io` helpers, `json.load`/`json.dump`, `read_bytes`/
`write_bytes`, `shutil.copy*`, and `.jsonl` literals. Column 2 is a kind id from the tables
above, `NOT:<tag>` for a non-record (tags follow section 6), or `NEW:<id>` for a kind the sweep
found that no table named — after the sweep every `NEW:` was folded into a table row, so none
remain; `archive_proj` tags the archive copy's own call sites (section 5). `tool_seam` marks the model's generic read and write tools (`runtime/tools/_files.py:54,
157, 199`): the file they touch is whichever record the role's grant names (MAIN's
`investigation.md`, a curator's corpus target; `report.md` is in no role's write grant), so the kind is decided by the
read/write gate at the call, not by the seam.

Tags: `not_file_io` = the match is a path builder, a constant, a docstring or an in-memory
buffer; `sysfile` = container identity files; the rest follow section 6.

| call site | kind | op | function | when | note |
|---|---|---|---|---|---|
| `_corpus.py:55` | NOT:corpus | read | `iter_lessons` | n-a | reads each lesson .md file from the corpus dir |
| `_corpus.py:198` | NOT:corpus | read | `read_query_template` | n-a | reads a query-template file from the corpus |
| `_first_party_key.py:13` | NOT:repo | read | `_read_env_key` | n-a | reads a repo .env file for ANTHROPIC_API_KEY, not a run record |
| `_flock.py:31` | NOT:not_file_io | append | `open_lock` | n-a | generic lock-file opener; attributed at callers |
| `_io.py:40` | NOT:not_file_io | read | `read_text_utf8` | n-a | generic helper; attributed at callers |
| `_io.py:41` | NOT:not_file_io | read | `read_text_utf8` | n-a | generic helper; attributed at callers |
| `_io.py:44` | NOT:not_file_io | read | `read_text_soft` | n-a | generic helper; attributed at callers |
| `_io.py:46` | NOT:not_file_io | read | `read_text_soft` | n-a | generic helper; attributed at callers |
| `_io.py:82` | NOT:not_file_io | read | `read_guarded` | n-a | generic helper; attributed at callers |
| `_io.py:110` | NOT:not_file_io | read | `read_guarded` | n-a | generic helper; attributed at callers |
| `_io.py:115` | NOT:not_file_io | read | `read_plain` | n-a | generic helper; attributed at callers |
| `_io.py:141` | NOT:not_file_io | read | `read_plain` | n-a | generic helper; attributed at callers |
| `_io.py:315` | NOT:not_file_io | read | `_walk_chain` | n-a | generic helper; attributed at callers |
| `_io.py:512` | NOT:not_file_io | read | `Bound._directory_fd` | n-a | generic helper; attributed at callers |
| `_io.py:547` | NOT:not_file_io | read | `bind` | n-a | generic helper; attributed at callers |
| `_io.py:643` | NOT:not_file_io | read | `read_jsonl_rows` | n-a | generic helper; attributed at callers |
| `_io.py:644` | NOT:not_file_io | read | `read_jsonl_rows` | n-a | generic helper; attributed at callers |
| `_io.py:647` | NOT:not_file_io | read | `read_jsonl_rows_report` | n-a | generic helper; attributed at callers |
| `_io.py:657` | NOT:not_file_io | read | `read_jsonl_rows_report` | n-a | generic helper; attributed at callers |
| `_io.py:675` | NOT:not_file_io | append | `append_jsonl` | n-a | generic helper; attributed at callers |
| `_io.py:679` | NOT:not_file_io | append | `append_jsonl` | n-a | generic helper; attributed at callers |
| `_io.py:685` | NOT:not_file_io | write | `write_atomic` | n-a | generic helper; attributed at callers |
| `_io.py:686` | NOT:not_file_io | write | `write_atomic` | n-a | generic helper; attributed at callers |
| `_io.py:762` | NOT:not_file_io | write | `open_nofollow_fd` | n-a | generic helper; attributed at callers |
| `_io.py:771` | NOT:not_file_io | write | `open_nofollow_fd` | n-a | generic helper; attributed at callers |
| `_io.py:777` | NOT:not_file_io | write | `locked_for_rewrite` | n-a | generic helper; attributed at callers |
| `_io.py:783` | NOT:not_file_io | write | `locked_for_rewrite` | n-a | docstring naming write_guarded, not a call site |
| `_io.py:788` | NOT:not_file_io | write | `locked_for_rewrite` | n-a | generic helper; attributed at callers |
| `_io.py:795` | NOT:not_file_io | write | `write_guarded` | n-a | generic helper; attributed at callers |
| `_io.py:814` | NOT:not_file_io | write | `write_guarded` | n-a | generic helper; attributed at callers |
| `_io.py:822` | NOT:not_file_io | write | `write_guarded` | n-a | generic helper; attributed at callers |
| `_io.py:839` | NOT:not_file_io | append | `write_guarded` | n-a | generic helper; attributed at callers |
| `_io.py:847` | NOT:not_file_io | write | `write_guarded` | n-a | generic helper; attributed at callers |
| `_io.py:855` | NOT:not_file_io | write | `open_guarded` | n-a | generic helper; attributed at callers |
| `_io.py:866` | NOT:not_file_io | write | `open_guarded` | n-a | generic helper; attributed at callers |
| `_provenance.py:387` | provenance | write | `_provenance.write` | host-before-agent | writes the per-run provenance stamp before the box exists |
| `_provenance.py:403` | provenance | read | `_provenance.read` | n-a | reads the per-run provenance stamp |
| `_report.py:110` | report | read | `read_report` | end | reads a completed run's report.md |
| `_run_paths.py:71` | NOT:not_file_io | read | `(module scope)` | n-a | string constant for the wire-log filename, not a call site |
| `_run_paths.py:132` | NOT:not_file_io | read | `RunPaths.executed_queries` | n-a | path-builder property, not itself I/O; attributed at callers |
| `_run_paths.py:203` | NOT:not_file_io | read | `(module scope)` | n-a | frozenset of record filenames, not a call site |
| `_scaffold_rules.py:222` | NOT:corpus | read | `check_system_skill` | n-a | reads a system's SKILL.md for frontmatter validation |
| `_yaml.py:305` | NOT:corpus | read | `load_reviewed_mapping` | n-a | reads a reviewed policy file, e.g. verb-grants.yaml or lead-zero.yaml |
| `evals/harness.py:40` | NOT:eval_case | read | `materialize` | n-a | locates scenario's findings.jsonl input before validating/copying it |
| `evals/harness.py:43` | NOT:queue | copy | `materialize` | n-a | seeds scenario findings.jsonl into materialized _pending/findings.jsonl queue |
| `evals/harness.py:47` | NOT:eval_case | copy | `materialize` | n-a | copies scenario's fixture "runs" dir into materialized learning/runs tree |
| `evals/harness.py:52` | NOT:corpus | copy | `materialize` | n-a | seeds scenario lesson fixtures into materialized defender/lessons corpus dir |
| `evals/harness.py:81` | NOT:eval_result | copy | `capture_results` | n-a | harvests materialized lessons/*.md into the harness's own result dir |
| `evals/harness.py:87` | NOT:eval_result | copy | `capture_results` | n-a | harvests materialized _pending/* files into the harness's own result dir |
| `evals/harness.py:92` | NOT:eval_result | write | `capture_results` | n-a | writes git_log.txt into the harness result dir |
| `evals/harness.py:94` | NOT:eval_result | write | `capture_results` | n-a | writes author.stdout capture into the harness result dir |
| `evals/harness.py:95` | NOT:eval_result | write | `capture_results` | n-a | writes author.stderr capture into the harness result dir |
| `evals/harness.py:96` | NOT:eval_result | write | `capture_results` | n-a | writes rc.txt (author return code) into the harness result dir |
| `evals/harness.py:100` | NOT:eval_result | write | `capture_results` | n-a | writes timing.txt (wall seconds + effort) into the harness result dir |
| `evals/harness_lead.py:38` | NOT:repo | copy | `materialize` | n-a | copies real defender/learning package .py/.md source into sandboxed tmp tree |
| `evals/harness_lead.py:42` | NOT:repo | copy | `materialize` | n-a | copies real defender/_untrusted.py source module into sandboxed tmp tree |
| `evals/harness_lead.py:44` | NOT:corpus | copy | `materialize` | n-a | copies the real gather query catalog into the sandboxed tmp tree |
| `evals/harness_lead.py:53` | NOT:corpus | copy | `materialize` | n-a | copies real skills/*/SKILL.md files into the sandboxed tmp tree |
| `evals/harness_lead.py:58` | NOT:tmp | write | `materialize` | n-a | writes a synthetic stub adapter (VERBS={}) to satisfy the resolver in the sandbox |
| `evals/harness_lead.py:64` | NOT:eval_case | copy | `materialize` | n-a | overlays scenario's catalog_overlay fixture onto the materialized query catalog |
| `evals/harness_lead.py:76` | NOT:eval_case | copy | `materialize` | n-a | copies scenario's single fixture run dir into the sandboxed runs/ tree |
| `evals/harness_lead.py:130` | NOT:eval_result | write | `capture` | n-a | writes lead_author.stdout capture into the harness result dir |
| `evals/harness_lead.py:131` | NOT:eval_result | write | `capture` | n-a | writes lead_author.stderr capture into the harness result dir |
| `evals/harness_lead.py:132` | NOT:eval_result | write | `capture` | n-a | writes rc.txt (lead-author return code) into the harness result dir |
| `evals/harness_lead.py:134` | NOT:eval_result | write | `capture` | n-a | writes git_log.txt into the harness result dir |
| `evals/harness_lead.py:136` | NOT:eval_result | write | `capture` | n-a | writes head_show.txt (git show --stat HEAD) into the harness result dir |
| `evals/harness_lead.py:137` | NOT:eval_result | write | `capture` | n-a | writes verdict.txt (PASS/FAIL + notes) into the harness result dir |
| `evals/harness_lead.py:138` | NOT:eval_result | copy | `capture` | n-a | captures post-run query catalog state into the harness result dir as catalog_after |
| `evals/harness_lead.py:156` | NOT:eval_case | read | `main` | n-a | reads scenario's expect.json verdict spec |
| `evals/held_out.py:81` | NOT:eval_case | read | `load_held_out_fixtures` | n-a | reads held-out fixture's ground_truth.yaml label |
| `evals/oracle_golden/audit_judge.py:100` | NOT:eval_case | read | `audit_set` | n-a | reads a case's expected.yaml hand labels |
| `evals/oracle_golden/audit_judge.py:245` | NOT:eval_case | read | `verdict_set` | n-a | reads a case's manifest.yaml to check defective/derived status |
| `evals/oracle_golden/audit_judge.py:248` | NOT:eval_case | read | `verdict_set` | n-a | reads a case's projections/<tag>.yaml oracle projection |
| `evals/oracle_golden/audit_judge.py:250` | NOT:eval_case | read | `verdict_set` | n-a | reads a case's cached labels/<judge-tag>.json |
| `evals/oracle_golden/audit_judge.py:417` | NOT:eval_result | write | `main` | n-a | writes the audit's JSON report to the --out path |
| `evals/oracle_golden/controls.py:385` | NOT:eval_case | read | `_operation_window` | n-a | reads a case's manifest.yaml for its attack/operation window |
| `evals/oracle_golden/controls.py:407` | NOT:eval_case | read | `lead_queries` | n-a | reads a case's oracle_visible/leads.jsonl for its queries |
| `evals/oracle_golden/controls.py:476` | NOT:eval_case | write | `main` | n-a | writes one measured control record under hidden/controls/<lead_id>/<seq>.json |
| `evals/oracle_golden/generate_case.py:100` | NOT:eval_case | read | `scenario_entry` | n-a | reads the playground-v2 attacks catalog.yaml to find a scenario entry |
| `evals/oracle_golden/generate_case.py:321` | NOT:eval_case | write | `synthesise_alert` | n-a | writes the synthesised alert.json case input |
| `evals/oracle_golden/generate_case.py:353` | NOT:corpus | read | `write_environment` | n-a | reads the environment_template.yaml template |
| `evals/oracle_golden/generate_case.py:354` | NOT:eval_case | write | `write_environment` | n-a | writes the case's environment.yaml from the template |
| `evals/oracle_golden/generate_case.py:363` | NOT:eval_case | write | `write_manifest` | n-a | writes the case's manifest.yaml |
| `evals/oracle_golden/generate_case.py:491` | NOT:eval_case | read | `main` | n-a | reads the playground-v2 runner record's meta.json for case generation |
| `evals/oracle_golden/generate_case.py:514` | NOT:eval_case | write | `main` | n-a | writes the case's controls.yaml provenance note |
| `evals/oracle_golden/judge.py:95` | NOT:corpus | read | `prompts_sha8` | n-a | hashes the label/verdict prompt files |
| `evals/oracle_golden/judge.py:165` | NOT:eval_case | read | `_payload_entry` | n-a | reads one observed payload under hidden/observed/<lead_id> |
| `evals/oracle_golden/judge.py:206` | NOT:eval_case | read | `load_case_leads` | n-a | reads a case's oracle_visible/leads.jsonl |
| `evals/oracle_golden/judge.py:251` | NOT:eval_case | read | `load_lead_inputs` | n-a | reads one control record under hidden/controls/<lead_id> |
| `evals/oracle_golden/judge.py:263` | NOT:eval_case | read | `load_lead_inputs` | n-a | reads a case's environment.yaml |
| `evals/oracle_golden/judge.py:272` | NOT:eval_case | read | `load_lead_inputs` | n-a | reads a case's oracle_visible/samples/<lead_id>.txt |
| `evals/oracle_golden/judge.py:276` | NOT:eval_case | read | `load_lead_inputs` | n-a | reads a case's oracle_visible/story.md |
| `evals/oracle_golden/judge.py:515` | NOT:corpus | read | `_pass` | n-a | reads the label or verdict judge prompt file |
| `evals/oracle_golden/migrate_esql_encoding.py:202` | NOT:eval_case | read | `migrate_file` | n-a | reads one observed/controls JSON payload in the golden corpus to migrate |
| `evals/oracle_golden/migrate_esql_encoding.py:224` | NOT:eval_case | write | `migrate_file` | n-a | rewrites that observed/controls JSON payload in place after migration |
| `evals/oracle_golden/record_held_out.py:41` | NOT:eval_case | read | `main` | n-a | reads case's manifest.yaml to confirm split=held-out |
| `evals/oracle_golden/record_held_out.py:56` | NOT:eval_case | read | `main` | n-a | reads case's scores/<tag>.json to record |
| `evals/oracle_golden/record_held_out.py:66` | NOT:eval_result | read | `main` | n-a | reads held_out_ledger.yaml before appending a new entry |
| `evals/oracle_golden/record_held_out.py:79` | NOT:eval_case | read | `main` | n-a | hashes the case's scores/<tag>.json being ledgered |
| `evals/oracle_golden/record_held_out.py:85` | NOT:eval_result | read | `main` | n-a | reads held_out_ledger.yaml header text to preserve it on rewrite |
| `evals/oracle_golden/record_held_out.py:86` | NOT:eval_result | write | `main` | n-a | appends the new entry, rewriting held_out_ledger.yaml |
| `evals/oracle_golden/report.py:101` | NOT:eval_case | read | `load_golden_cases` | n-a | reads a case's manifest.yaml |
| `evals/oracle_golden/report.py:104` | NOT:eval_case | read | `load_golden_cases` | n-a | reads a case's scores/*.json recorded scores |
| `evals/oracle_golden/report.py:375` | NOT:eval_result | write | `main` | n-a | writes the rollup report JSON to the --json out path |
| `evals/oracle_golden/score.py:360` | NOT:eval_case | read | `measure_case` | n-a | reads a case's cached labels/<judge-suffix>.json |
| `evals/oracle_golden/score.py:376` | NOT:eval_case | write | `measure_case` | n-a | writes the case's labels/<judge-suffix>.json label cache |
| `evals/oracle_golden/score.py:425` | NOT:eval_case | read | `_measured` | n-a | reads a case's manifest.yaml |
| `evals/oracle_golden/score.py:430` | NOT:eval_case | read | `_measured` | n-a | reads a case's projections/<tag>.yaml oracle projection |
| `evals/oracle_golden/score.py:584` | NOT:eval_case | read | `forbidden_values` | n-a | reads a case's expected.yaml for its must_not_emit clause |
| `evals/oracle_golden/score.py:729` | NOT:eval_case | write | `main` | n-a | writes the score summary to case_dir/scores/<tag>.json |
| `evals/oracle_golden/story_from_run.py:109` | NOT:eval_case | read | `main` | n-a | reads playground-v2 attack runner's meta.json to render a story |
| `evals/oracle_golden/story_from_run.py:122` | NOT:eval_case | write | `main` | n-a | writes rendered story.md, an oracle_visible case input |
| `evals/oracle_golden/validate_cases.py:72` | NOT:eval_case | read | `check_case` | n-a | REQUIRED_FILES literal naming case-relative paths later checked for existence |
| `evals/oracle_golden/validate_cases.py:80` | NOT:eval_case | read | `_leads_of` | n-a | reads a case's oracle_visible/leads.jsonl |
| `evals/oracle_golden/validate_cases.py:106` | NOT:eval_case | read | `check_case` | n-a | reads a case's manifest.yaml |
| `evals/oracle_golden/validate_cases.py:110` | NOT:eval_case | read | `check_case` | n-a | reads a case's oracle_visible/story.md |
| `evals/oracle_golden/validate_cases.py:136` | NOT:eval_case | read | `load_known_defects` | n-a | reads the oracle_golden known_defects.yaml waiver registry |
| `evals/oracle_golden/validate_cases.py:212` | NOT:eval_case | read | `check_seq_keying` | n-a | checks existence of a case's oracle_visible/leads.jsonl |
| `evals/oracle_golden/validate_cases.py:282` | NOT:eval_case | read | `control_problems_by_record` | n-a | checks existence of a case's oracle_visible/leads.jsonl |
| `evals/oracle_golden/validate_cases.py:306` | NOT:eval_case | read | `control_problems_by_record` | n-a | reads one control record under hidden/controls |
| `evals/oracle_golden/validate_cases.py:479` | NOT:eval_case | read | `check_environment` | n-a | reads a case's environment.yaml |
| `evals/oracle_golden/validate_cases.py:531` | NOT:eval_result | read | `check_held_out_ledger` | n-a | reads held_out_ledger.yaml to check recorded entries |
| `evals/oracle_golden/validate_cases.py:544` | NOT:eval_case | read | `check_held_out_ledger` | n-a | hashes a case's scores/<tag>.json to compare against the ledger |
| `evals/oracle_golden/validate_cases.py:582` | NOT:eval_case | read | `coverage` | n-a | checks existence of a case's oracle_visible/leads.jsonl |
| `evals/oracle_golden/validate_cases.py:592` | NOT:eval_case | read | `coverage` | n-a | reads one control record under hidden/controls to tally live/dead |
| `evals/oracle_golden/validate_cases.py:656` | NOT:eval_case | read | `main` | n-a | reads each case's manifest.yaml to index by id |
| `hooks/_run_dir.py:18` | NOT:not_file_io | read | `update_json_locked` | n-a | docstring describing a rejected touch+open approach, not code |
| `hooks/_run_dir.py:28` | budget | write | `update_json_locked` | live | locks/opens a run-dir json state file (budget.json; also circuit_breaker.json) |
| `hooks/_run_dir.py:73` | budget | read | `read_json_locked` | live | reads a run-dir json state file (budget.json; also accounting_failures sidecar) |
| `hooks/budget_enforcer.py:120` | budget | write | `_write_budget_atomic` | live | atomically rewrites budget.json with updated call counters |
| `hooks/budget_enforcer.py:204` | accounting | write | `_write_accounting_failure` | live | atomically rewrites <run>.accounting_failures.json sidecar |
| `hooks/budget_enforcer.py:217` | accounting | write | `_record_alias_refusal` | live | rewrites accounting sidecar, appending an alias-refusal entry |
| `hooks/inject_system_skill_description.py:26` | NOT:corpus | read | `read_description` | host-before-agent | reads a system's skills/<system>/SKILL.md to get its description |
| `hooks/record_lead.py:63` | lead_claim | write | `claim_lead` | live | exclusive-creates gather_raw/<lead>.lead.json claim sidecar |
| `learning/_pydantic_stage.py:62` | NOT:corpus | read | `build_stage_agent` | n-a | reads the stage's role prompt file before building the agent |
| `learning/author/drain.py:85` | NOT:queue | n-a | `module constant` | n-a | names the host-side forward-check gap-ledger sidecar under _pending |
| `learning/author/drain.py:191` | NOT:queue | n-a | `graveyard_file` | n-a | names a channel's graveyard/deadletter sidecar path |
| `learning/author/drain.py:222` | NOT:queue | n-a | `stuck_report_file` | n-a | names a channel's stuck-report sidecar path |
| `learning/author/drain.py:300` | NOT:queue | read | `retire` | n-a | reads queue rows to bump/retire by id |
| `learning/author/drain.py:347` | NOT:queue | append | `_bump_rows` | n-a | appends retired rows to a channel's graveyard file |
| `learning/author/drain.py:428` | NOT:queue | read | `_tick` | n-a | reads a channel's queue file for this tick's batch |
| `learning/author/drain.py:1056` | NOT:corpus | read | `_restore_unapproved_files` | n-a | reads a corpus file's bytes to check against tick-start snapshot |
| `learning/author/drain.py:1058` | NOT:corpus | write | `_restore_unapproved_files` | n-a | restores an unapproved corpus file to its pre-tick bytes |
| `learning/author/drain.py:1076` | NOT:corpus | write | `_restore_from_snapshot` | n-a | restores a corpus file the repair spawn deleted, from snapshot |
| `learning/author/drain.py:1117` | NOT:queue | append | `_append_gap_record` | n-a | appends a durable gap-ledger record for a terminal forward-check finding |
| `learning/author/drain.py:1210` | NOT:corpus | read | `_byte_identical_to_head` | n-a | reads a changed corpus file's raw bytes to compare against HEAD |
| `learning/author/drain.py:1221` | NOT:corpus | read | `_cited_ids` | n-a | reads a corpus lesson file's frontmatter to find its cited queue ids |
| `learning/author/drain.py:1240` | NOT:corpus | read | `_read_or_empty` | n-a | reads a corpus file's text, empty on failure |
| `learning/author/drain.py:1355` | NOT:queue | append | `_retire_unkeyable` | n-a | appends unkeyable rows to a channel's graveyard file |
| `learning/author/drain.py:1442` | NOT:queue | read | `stuck_record_count` | n-a | counts records on a channel's stuck report |
| `learning/author/drain.py:1458` | NOT:queue | read | `_record_stuck` | n-a | reads a channel's stuck report to fold consecutive-tick count |
| `learning/author/drain.py:1475` | NOT:queue | append | `_record_stuck` | n-a | appends a new stuck-tick record to a channel's stuck report |
| `learning/author/drain.py:1491` | NOT:corpus | read | `_snapshot_corpus` | n-a | snapshots every corpus file's bytes at tick start |
| `learning/author/drain.py:1565` | NOT:corpus | read | `_restore_corpus` | n-a | reads a corpus file's current bytes to check against the snapshot |
| `learning/author/drain.py:1567` | NOT:corpus | write | `_restore_corpus` | n-a | restores a corpus file to its pre-agent snapshot bytes |
| `learning/author/lessons/run.py:111` | source_refs | read | `disposition_for` | end | reads a cited run's source_refs.yaml normalized_disposition |
| `learning/author/shared.py:461` | NOT:queue | append | `write_disposition_report` | n-a | appends a line naming what a tick declined, beside _pending |
| `learning/author/verify_forward/checks.py:72` | forward_check_trace | write | `_verify` | end | names the forward-check verifier's wire trace written into <cited_run_dir>/wire_logs/<prefix>.<stem>.<n>.trace.jsonl, the CITED run's own dir |
| `learning/author/verify_forward/forward.py:30` | source_refs | read | `load_run_context` | end | reads a cited case's source_refs.yaml disposition for forward-check |
| `learning/author/verify_forward/forward.py:37` | investigation | read | `load_run_context` | end | reads a cited case's investigation.md transcript for forward-check |
| `learning/branch/archive.py:29` | NOT:not_file_io | n-a | `n-a` | n-a | module docstring prose, not a call site |
| `learning/branch/archive.py:153` | NOT:not_file_io | write | `_single_files` | end | names the archived lessons_loaded.jsonl copied into worlds/<label>/ |
| `learning/branch/archive.py:314` | archive_proj | copy | `archive_episode` | end | copies a sibling's seven single-file roles into worlds/<label>/ |
| `learning/branch/archive.py:330` | archive_proj | copy | `archive_episode` | end | copies gather_summaries/ into worlds/<label>/gather_summaries |
| `learning/branch/archive.py:347` | archive_proj | write | `archive_episode` | end | writes the worlds/<label>/ text pointer naming the source run dir |
| `learning/branch/capture.py:133` | served | append | `prime_base` | host-before-agent | appends primed family-tier rows into the episode's served/base.jsonl |
| `learning/branch/capture.py:180` | gather_raw | read | `_captured_call` | host-before-agent | reads the source run's captured payload to prime the base |
| `learning/branch/cli.py:289` | served | read | `prepare_episode` | host-before-agent | lists served/*.jsonl to check for stale per-world rows before priming |
| `learning/branch/cli.py:305` | priming_lock | write | `prepare_episode` | host-before-agent | creates served/.priming lock (<episode>/served/.priming) so only one launcher primes an episode; cleared by hand after a crashed launcher |
| `learning/branch/cli.py:339` | served | write | `prepare_episode` | host-before-agent | writes an empty served/base.jsonl when the source captured nothing |
| `learning/branch/cli.py:776` | scrub_verdict | read | `_scrub_ran` | end | reads a sibling run's scrub-verdict sidecar to check the reap scan ran |
| `learning/branch/cli.py:1101` | family_stamp | write | `_write_family_stamp` | end | writes the episode's family stamp provenance.json |
| `learning/branch/cli.py:1409` | staged | write | `_run_episode` | host-before-agent | creates the empty staged.yaml comment header before any name is staged |
| `learning/branch/cli.py:1586` | samples | write | `write_questioner_samples` | host-before-agent | writes the episode's samples.yaml corpus-sample document |
| `learning/branch/cli.py:1725` | investigation | read | `_fence_count` | host-before-agent | reads the source run's investigation.md to count fences at the branch point |
| `learning/branch/cli.py:1764` | alert | read | `_alert_document` | host-before-agent | reads the source run's alert.json for the questioner prompt |
| `learning/branch/episode.py:288` | served | read | `_answers` | end | reads a world's or base served ledger file into a key-to-answer map |
| `learning/branch/ledger.py:102` | served | read | `module constant (BASE_FILENAME)` | live | names the family's base.jsonl capture filename under served/ |
| `learning/branch/ledger.py:338` | served | write | `Ledger.for_world` | live | builds served/<world_id>.jsonl path for a sibling's own ledger |
| `learning/branch/ledger.py:362` | served | append | `Ledger.declare` | host-before-agent | creates the sibling's empty served/<world_id>.jsonl ledger at world setup |
| `learning/branch/ledger.py:450` | served | read | `Ledger._absorb` | host-before-agent | folds base/world served rows into the in-memory memo |
| `learning/branch/ledger.py:526` | served | append | `Ledger.record` | live | appends one served call's row to the sibling's own ledger during the run |
| `learning/branch/questioner/__init__.py:157` | NOT:corpus | read | `_prompt` | n-a | reads a shipped questioner prompt file |
| `learning/branch/questioner/__init__.py:262` | NOT:corpus | read | `_questioner_lessons_section` | n-a | reads a defender/lessons-questioner/ candidate lesson file |
| `learning/branch/questioner/__init__.py:513` | investigation | read | `read_frontier` | host-before-agent | reads the source run's investigation.md to build the questioner's frontier prefix |
| `learning/branch/review.py:134` | NOT:tmp | read | `ScratchLedger.base_rows` | n-a | reads the review's scratch base file outside the episode |
| `learning/branch/review.py:161` | NOT:tmp | write | `scratch_ledger` | n-a | creates an empty scratch base file for the review replay |
| `learning/branch/review.py:163` | NOT:tmp | write | `scratch_ledger` | n-a | builds the review's own scratch ledger path outside the episode |
| `learning/branch/review.py:297` | served | read | `review` | live | reads the episode's real served/base.jsonl capture to find drifted keys |
| `learning/branch/seams.py:77` | stage_trace | write | `model_seam` | host-before-agent | names the episode wire_logs trace file for the questioner's LLM call |
| `learning/branch/staging.py:419` | staged | append | `record_staged` | host-before-agent | appends one durable, fsynced row to the episode's staged.yaml |
| `learning/branch/staging.py:606` | review_yaml | read | `merge_review` | end | reads existing review.yaml before merging a new block |
| `learning/branch/staging.py:617` | review_yaml | write | `merge_review` | end | writes the merged review.yaml document |
| `learning/branch/timing.py:76` | NOT:not_file_io | n-a | `n-a` | n-a | docstring prose describing write_guarded, not a call site |
| `learning/branch/timing.py:96` | timing | write | `StageClock.record` | live | rewrites the episode's timing.json after each completed step |
| `learning/core/config.py:91` | NOT:queue | n-a | `LoopPaths.pitfalls` | n-a | names the pitfalls queue file path |
| `learning/core/config.py:92` | NOT:queue | n-a | `LoopPaths.pitfalls` | n-a | names the pitfalls queue's consumed sidecar path |
| `learning/core/config.py:134` | NOT:queue | n-a | `LoopPaths.pending_file` | n-a | names the defender findings queue file path |
| `learning/core/config.py:150` | NOT:queue | n-a | `LoopPaths.findings` | n-a | names the findings queue's consumed sidecar path |
| `learning/core/config.py:158` | NOT:queue | n-a | `LoopPaths.questioner_findings_file` | n-a | names the questioner findings queue file path |
| `learning/core/config.py:170` | NOT:queue | n-a | `LoopPaths.questioner_findings` | n-a | names the questioner findings queue's consumed sidecar path |
| `learning/core/config.py:282` | NOT:queue | write | `StageWiring.for_batch` | n-a | names the corpus-curator's wire trace under <state_root>/_pending/wire_logs/<batch_id>.<pid>.trace.jsonl; written by run_stage's RequestLogger, operator-debug only reader |
| `learning/core/drains.py:188` | NOT:queue | read | `_pending_queue_counts` | n-a | counts authorable vs held rows in a queue file for the wake gate |
| `learning/core/drains.py:290` | NOT:queue | read | `_drain_one_curator` | n-a | reads channel rows to record a stuck fault when a curator faults |
| `learning/core/drains.py:662` | NOT:queue | read | `_pending_deliveries` | n-a | reads a pending-delivery record json under _pending_delivery |
| `learning/core/markers.py:17` | NOT:queue | write | `_enqueue_marker` | n-a | writes a run-keyed marker into a LoopPaths queue dir |
| `learning/core/markers.py:36` | NOT:queue | write | `enqueue_case_for_curation` | n-a | writes a case-keyed curation marker into the author queue |
| `learning/core/markers.py:46` | NOT:queue | write | `rewrite_marker` | n-a | rewrites a queue marker's spec atomically |
| `learning/core/markers.py:68` | NOT:queue | write | `requeue_marker` | n-a | stages a re-queue marker before hard-linking it into the slot |
| `learning/core/markers.py:185` | NOT:queue | read | `_read_spec` | n-a | reads a claimed marker's spec row |
| `learning/core/markers.py:203` | NOT:queue | write | `quarantine_marker` | n-a | writes an unreadable marker into the queue's failed/ dead-letter dir |
| `learning/core/persist.py:74` | NOT:queue | read | `_rewrite_queue` | n-a | reads current queue rows before merging the rewrite |
| `learning/core/persist.py:76` | NOT:queue | write | `_rewrite_queue` | n-a | rewrites the queue file wholesale with survivors |
| `learning/core/persist.py:86` | NOT:queue | append | `_rewrite_queue` | n-a | appends consumed rows to a channel's consumed sidecar |
| `learning/core/persist.py:304` | NOT:queue | append | `append_pitfalls` | n-a | appends failing rows verbatim to the pitfalls queue |
| `learning/core/persist.py:308` | NOT:queue | read | `read_pitfalls` | n-a | reads all pitfalls queue rows |
| `learning/core/persist.py:321` | NOT:queue | read | `rotate_pitfalls` | n-a | reads pitfalls queue rows to select this batch's consumed set |
| `learning/core/quarantine.py:51` | NOT:quarantine | write | `_archive_tree` | n-a | writes the gzipped tar archive of a tainted worktree |
| `learning/core/quarantine.py:64` | NOT:quarantine | read | `_tree_verdict` | n-a | reads a quarantined worktree's own scrub-verdict sidecar |
| `learning/core/quarantine.py:135` | NOT:quarantine | write | `preserve_tainted_tree` | n-a | writes the quarantine manifest json beside the tar archive |
| `learning/frontend/build.py:534` | NOT:viz_out | write | `main` | n-a | writes lessons.json posture view alongside lessons.html |
| `learning/frontend/build.py:537` | NOT:viz_out | write | `main` | n-a | writes lessons.html rendered posture page |
| `learning/frontend/build.py:544` | NOT:viz_out | write | `main` | n-a | writes queues.json alongside queues.html |
| `learning/frontend/build.py:546` | NOT:viz_out | write | `main` | n-a | writes queues.html rendered queue page |
| `learning/frontend/serialize.py:217` | NOT:viz_out | write | `main` | n-a | writes lessons.json posture contract |
| `learning/frontend/serialize_queues.py:160` | NOT:queue | read | `_rows` | n-a | tolerant read of a queue/graveyard/stuck file for the queue page |
| `learning/frontend/serialize_queues.py:209` | NOT:queue | read | `_json_files` | n-a | reads *.json records from a pending-delivery-like dir for the queue page |
| `learning/judge/__init__.py:345` | stage_trace | write | `_run_world_draws` | end | names the episode wire_logs trace file for one judge draw's LLM call |
| `learning/judge/__init__.py:396` | judge_draw | write | `_run_world_draws` | end | writes one judge draw worlds/<label>/judge/<n>.yaml |
| `learning/judge/__init__.py:424` | stage_trace | write | `_write_wire_log` | end | builds episode wire_logs/<agent>_framed_trace.jsonl path for the judge's own summary |
| `learning/judge/__init__.py:436` | stage_trace | write | `_write_wire_log` | end | writes the judge's one-line wire-log summary record |
| `learning/judge/__init__.py:908` | judge_yaml | write | `_write_judge_yaml` | end | writes the episode's judge.yaml grade record |
| `learning/judge/enqueue.py:206` | NOT:not_file_io | n-a | `n-a` | n-a | docstring prose about write_guarded, not a call site |
| `learning/judge/enqueue.py:225` | NOT:queue | read | `_append_validated_rows` | n-a | reads a findings queue to count malformed rows, no-op append |
| `learning/judge/enqueue.py:235` | NOT:queue | read | `_append_validated_rows` | n-a | reads findings queue rows before dedup append |
| `learning/judge/enqueue.py:255` | NOT:queue | read | `_append_validated_rows` | n-a | checks findings queue's trailing byte before append |
| `learning/judge/enqueue.py:259` | NOT:queue | append | `_append_validated_rows` | n-a | appends new finding rows to a findings queue |
| `learning/judge/enqueue.py:490` | judge_draw | read | `draws_on_disk_report` | end | reads a judge draw worlds/<X>/judge/<n>.yaml on the bare re-enqueue path |
| `learning/judge/family.py:1155` | served | read | `world_ledger_name` | live | the relative spelling of a world's served/<token>.jsonl ledger name |
| `learning/lead_repository.py:203` | lead_claim | read | `load_leads` | end | reads gather_raw/<lead>.lead.json claim sidecar |
| `learning/lead_repository.py:253` | queries | read | `load_queries_report` | end | reads executed_queries.jsonl table rows |
| `learning/lead_repository.py:487` | gather_raw | read | `corpus_samples` | host-before-agent | reads a query's raw payload for a corpus document sample |
| `learning/lead_repository.py:552` | queries | copy | `stage_tables` | end | copies executed_queries.jsonl into the learning run dir's table |
| `learning/lead_repository.py:563` | gather_raw | copy | `stage_tables` | end | copies gather_raw/ tree into the learning run dir's table |
| `learning/lead_repository.py:573` | NOT:not_file_io | n-a | `n-a` | n-a | docstring prose describing copy2, not a call site |
| `learning/lead_repository.py:578` | NOT:not_file_io | n-a | `n-a` | n-a | docstring prose describing copytree, not a call site |
| `learning/lead_repository.py:593` | gather_raw | copy | `refusing_copy2` | end | per-entry copy during stage_tables' gather_raw copytree |
| `learning/lead_repository.py:714` | investigation | read | `narration_crosscheck_from_run` | end | reads investigation.md for narration crosscheck |
| `learning/leads/draft_synthesis.py:331` | NOT:corpus | write | `synthesize_drafts` | n-a | writes a new draft query template under the catalog's _draft/ dir |
| `learning/leads/lead_author/__init__.py:130` | lead_author | write | `_write_state` | end | writes a lead_author/ stage output file under a run |
| `learning/leads/lead_author/_handoff.py:231` | NOT:corpus | read | `_draft_contradicts_skill` | n-a | reads a system-skill draft file's contradicts_skill flag |
| `learning/leads/lead_author/_rules.py:78` | NOT:corpus | read | `_frontmatter_id` | n-a | reads a catalog or skills file's frontmatter id |
| `learning/leads/lead_render.py:36` | NOT:corpus | read | `render_query` | n-a | reads a gather query catalog template to render its query body |
| `learning/leads/pitfalls_curator.py:337` | NOT:corpus | read | `_readable_pair` | n-a | reads the pitfalls reducer skill doc to compare against HEAD |
| `learning/leads/pitfalls_curator.py:647` | NOT:queue | append | `_graveyard_dropped_rows` | n-a | appends terminally-dropped pitfalls rows to the pitfalls graveyard |
| `learning/ops/trace_lesson.py:136` | lessons_loaded | read | `in_context_cases` | end | path to a run's lessons_loaded.jsonl, read next for exposures |
| `learning/ops/trace_lesson.py:142` | lessons_loaded | read | `in_context_cases` | end | reads lessons_loaded.jsonl rows filtered by lesson_name |
| `learning/ops/trace_lesson.py:204` | NOT:corpus | read | `main` | n-a | reads a lesson markdown file from defender/lessons |
| `run.py:423` | NOT:not_file_io | copy | `_screened_source_alert` | n-a | docstring referencing materialize_run_dir's alert copy |
| `run_common.py:80` | alert | copy | `materialize_run_dir` | host-before-agent | copies the alert into the new run dir as alert.json |
| `run_common.py:112` | NOT:not_file_io | copy | `_stamp` | n-a | docstring referencing the alert copy above; not a call site |
| `run_common.py:212` | NOT:eval_case | read | `held_out_alert_digests` | n-a | reads held-out fixture alert.json bytes to digest |
| `run_common.py:220` | alert | read | `is_held_out_alert_copy` | end | reads the run's alert.json bytes to check held-out status |
| `run_common.py:286` | alert | read | `enqueue_curation` | end | reads the run's alert.json bytes to derive case_id |
| `runtime/bash_policy.py:21` | NOT:corpus | read | `_load_policy` | n-a | reads bash_policy.json deny-list corpus file |
| `runtime/box/_alias.py:107` | NOT:tmp | read | `probe (box-side script)` | host-before-agent | opens box cwd fd; alias-ban probe scratch, unrelated to run records |
| `runtime/box/_alias.py:120` | NOT:tmp | write | `write_src (box-side script)` | host-before-agent | writes probe scratch file <prefix>-src for the hard-link test |
| `runtime/box/_alias.py:124` | NOT:tmp | write | `write_create (box-side script)` | host-before-agent | writes probe scratch file <prefix>-create as the ordinary-create control |
| `runtime/box/_docker.py:250` | NOT:sysfile | read | `_own_container_ids` | host-before-agent | NOT: reads host /etc/hostname to identify this container |
| `runtime/box/_docker.py:253` | NOT:sysfile | read | `_own_container_ids` | host-before-agent | NOT: reads host /proc/self/mountinfo for the container's full id |
| `runtime/box/_lifecycle.py:73` | box_sentinel | write | `_plant` | host-before-agent | writes .box-sentinel token host-side before the box starts |
| `runtime/branch/__init__.py:208` | queries | read | `validate` | host-before-agent | reads executed_queries.jsonl to check the source run captured evidence |
| `runtime/branch/_family.py:629` | family | read | `_read_document` | host-before-agent | reads the episode's family.yaml manifest through the guarded lane |
| `runtime/branch/_family.py:656` | family | write | `write_family` | host-before-agent | writes family.yaml manifest into the episode dir |
| `runtime/branch/_family.py:669` | family | read | `manifest_digest` | host-before-agent | re-reads family.yaml to compute/recheck its content digest |
| `runtime/branch/_family.py:917` | NOT:not_file_io | read | `ResumeWorld.ledger_path` | n-a | pure property building served/<world_id>.jsonl path, no I/O |
| `runtime/branch/_frontier.py:321` | investigation | read | `frontier_at_branch` | host-before-agent | reads source run's investigation.md to compute the frontier at branch point |
| `runtime/branch/_frontier.py:454` | queries | read | `_known_leads` | host-before-agent | reads executed_queries.jsonl lead ids for the branch census |
| `runtime/branch/_seed.py:52` | NOT:not_file_io | read | `_INHERITED` | n-a | tuple naming inherited filenames, not itself I/O |
| `runtime/branch/_seed.py:150` | investigation | read | `seed_investigation` | host-before-agent | reads source run's investigation.md to cut the sibling's seed |
| `runtime/branch/_seed.py:205` | investigation | write | `seed_investigation` | host-before-agent | writes the cut prefix as the sibling's investigation.md seed |
| `runtime/branch/_seed.py:251` | alert | write | `_inherit_evidence` | host-before-agent | copies source run's alert.json bytes into the sibling run dir |
| `runtime/branch/_seed.py:264` | queries | read | `_inherit_evidence` | host-before-agent | reads source executed_queries.jsonl rows, filtered by inherited leads |
| `runtime/branch/_seed.py:265` | queries | write | `_inherit_evidence` | host-before-agent | writes filtered rows as the sibling's executed_queries.jsonl |
| `runtime/branch/_seed.py:281` | NOT:not_file_io | copy | `_inherit_lead_dir` | n-a | docstring prose naming shutil.copytree, not code |
| `runtime/branch/_seed.py:333` | NOT:not_file_io | copy | `_copy_artifact` | n-a | docstring prose naming shutil.copytree, not code |
| `runtime/branch/_seed.py:339` | gather_raw | copy | `_copy_artifact` | host-before-agent | copies one gather_raw/lead_claim/gather_summaries entry into the sibling |
| `runtime/branch/_spec.py:166` | session_pointer | read | `open_source_store` | host-before-agent | reads session_store_pointer.json to resolve/verify the source store |
| `runtime/challenge_gate.py:167` | review_record | write | `write_review_record` | live | writes review_record.<turn>.json beside the run |
| `runtime/challenge_gate.py:240` | NOT:not_file_io | write | `review_trace_path` | n-a | pure path builder for wire_logs/review_<role>_trace.jsonl, no I/O here |
| `runtime/challenge_gate.py:290` | review_trace | append | `_write_trace_row` | live | appends one metadata(+raw reply) row to review_<role>_trace.jsonl |
| `runtime/circuit_breaker.py:89` | circuit_breaker | read | `_load` | live | reads circuit_breaker.json breaker state for a system |
| `runtime/close_tool.py:432` | report | write | `_commit` | live | writes report.md with the close tool's rendered disposition |
| `runtime/driver/__init__.py:511` | alert | read | `_alert_doc_soft` | host-before-agent | reads alert.json for item3's correlation-contract dispatch |
| `runtime/driver/__init__.py:709` | tool_trace | write | `run_investigation` | end | writes an empty tool_trace.jsonl fallback when write_trace itself failed |
| `runtime/driver/__init__.py:717` | NOT:not_file_io | write | `run_investigation` | n-a | stderr print naming tool_trace.jsonl, not a file op |
| `runtime/driver/_build.py:263` | NOT:corpus | read | `_gather_instructions` | n-a | reads GATHER's skills/gather/SKILL.md system prompt |
| `runtime/driver/_build.py:334` | investigation | read | `_fold_decision` | live | reads investigation.md to decide whether to fold this turn |
| `runtime/driver/_prompts.py:48` | NOT:corpus | read | `_main_instructions` | n-a | reads MAIN's SKILL.md system prompt body |
| `runtime/lead_zero/__init__.py:256` | investigation | read | `_is_declared` | host-before-agent | reads investigation.md to check whether a lead id is declared |
| `runtime/lead_zero/__init__.py:281` | alert | read | `resolve_lead_zero` | host-before-agent | reads alert.json to resolve lead-0's correlation lead |
| `runtime/lead_zero/_capture.py:106` | queries | read | `_rows_for` | host-before-agent | reads executed_queries.jsonl rows for one lead during lead-0 |
| `runtime/lead_zero/_capture.py:173` | gather_raw | read | `_last_row_seq` | host-before-agent | reads a gather_raw payload json to elide a captured document |
| `runtime/lead_zero/_capture.py:241` | circuit_breaker | read | `_breaker_failures` | host-before-agent | reads circuit_breaker.json to count system failures for item1 |
| `runtime/lead_zero/_capture.py:379` | investigation | read | `_declare_l_finding` | host-before-agent | reads investigation.md before appending lead-0's declaration |
| `runtime/lead_zero/_capture.py:389` | investigation | write | `_declare_l_finding` | host-before-agent | writes lead-0's :L findings row into investigation.md |
| `runtime/observe.py:35` | NOT:not_file_io | write | `POLICY_DENIALS` | n-a | string constant naming policy_denials.jsonl, not itself I/O |
| `runtime/observe.py:116` | wire_log | write | `RequestLogger.__init__` | host-before-agent | opens wire_logs/llm_requests.jsonl (also policy_denials.jsonl for denial logger) |
| `runtime/observe.py:392` | tool_trace | write | `write_trace` | end | writes tool_trace.jsonl with usage/result events after the run |
| `runtime/orient.py:64` | alert | read | `_alert_signature` | host-before-agent | reads alert.json to extract rule id for lessons signature |
| `runtime/orient.py:73` | alert | read | `_raw_alert` | host-before-agent | reads alert.json raw text for the orientation prompt section |
| `runtime/orient.py:89` | NOT:corpus | read | `_invlang_grammar` | n-a | reads skills/invlang/SKILL.md grammar reference into the prompt |
| `runtime/permission/files.py:543` | investigation | read | `decide_write` | live | reads investigation.md baseline to gate an append-only write |
| `runtime/permission/files.py:582` | investigation | read | `_decide_investigation_write` | live | reads investigation.md baseline for the frames-suite gate wrapper |
| `runtime/review/__init__.py:34` | NOT:corpus | read | `role_prompt` | n-a | reads a review role's prompt .md file verbatim |
| `runtime/run_end.py:125` | run_end | write | `write_sidecar` | end | writes <run>.run-end.json sidecar beside the run dir |
| `runtime/scrub.py:139` | scrub_verdict | write | `_write_verdict` | end | writes <tree>.scrub-verdict.json beside the scanned tree |
| `runtime/scrub.py:162` | scrub_verdict | read | `tree_verified` | end | reads scrub verdict sidecar to check ran:true |
| `runtime/session_store.py:750` | session_pointer | write | `write_case_pointer` | live | writes session_store_pointer.json naming the case/session |
| `runtime/session_store.py:754` | session_pointer | read | `resolve_store_path` | live | reads session_store_pointer.json for store_path |
| `runtime/session_store.py:765` | session_pointer | read | `resolve_session_id` | live | reads session_store_pointer.json for session_id |
| `runtime/tools/_deps.py:251` | lessons_loaded | append | `_record_lesson_load` | live | appends a row to lessons_loaded.jsonl on a corpus read/push |
| `runtime/tools/_document.py:97` | investigation | read | `read_companion` | live | reads investigation.md once per model request via read_plain |
| `runtime/tools/_document.py:357` | investigation | write | `_tool_append_block` | live | writes an appended block onto investigation.md |
| `runtime/tools/_document.py:729` | investigation | write | `_tool_fix_row` | live | writes a repaired/deleted flagged row back into investigation.md |
| `runtime/tools/_files.py:48` | NOT:not_file_io | read | `_probe_read_text` | n-a | docstring naming read_text_utf8(p), not the call itself |
| `runtime/tools/_files.py:54` | tool_seam | read | `_probe_read_text` | live | model-declared read-allowed path; read by read/edit-file tools |
| `runtime/tools/_files.py:157` | tool_seam | write | `_tool_write_file` | live | model-declared write_allow path (MAIN: investigation.md; curators: corpus targets) |
| `runtime/tools/_files.py:199` | tool_seam | write | `_tool_edit_file` | live | model-declared write_allow path, same target set as write_file |
| `runtime/tools_gather.py:428` | gather_summaries | write | `_persist_gather_summary` | live | writes gather_summaries/<lead_id>.md wrapped summary |
| `runtime/verb_roster.py:94` | NOT:corpus | write | `generate_roster` | n-a | writes generated verb-roster.md under skills/<role>/ |
| `runtime/verb_roster.py:105` | NOT:corpus | read | `load_roster` | n-a | reads committed verb-roster.md under skills/<role>/ |
| `runtime/verb_roster.py:219` | NOT:corpus | read | `audit_read_surfaces` | n-a | reads SKILL.md/execution.md/query templates for a verb-mention audit |
| `runtime/verbs.py:544` | NOT:repo | read | `read_roster` | host-before-agent | reads an adapter module's source bytes to parse verb names |
| `scripts/adapters/_stub_transport.py:110` | NOT:corpus | read | `_parse_env_file` | n-a | reads a system's knowledge/environment config.env file |
| `scripts/adapters/elastic_adapter.py:129` | NOT:corpus | read | `config_from` | n-a | reads knowledge/environment/systems/elastic/config.env |
| `scripts/adapters/tacit_knowledge_adapter.py:261` | NOT:corpus | read | `read_registry` | n-a | reads skills/<system>/registry.yaml tacit-knowledge registry |
| `scripts/case_history/case_ticket.py:89` | NOT:corpus | read | `_load_mapping` | n-a | reads knowledge/environment/systems/case-history mapping.yaml |
| `scripts/case_history/case_ticket.py:214` | alert | read | `read_case_record` | end | reads alert.json to derive the ticket signature_id |
| `scripts/case_history/ticket_writer.py:101` | alert | read | `open_case_ticket` | end | reads alert.json to build the open-ticket payload |
| `scripts/case_history/ticket_writer.py:280` | ticket_write | write | `_write_receipt` | end | writes the ticket_write.json receipt after posting |
| `scripts/gather_tools/record_query.py:223` | queries | read | `lead_rows` | live | reads executed_queries.jsonl rows for a lead |
| `scripts/gather_tools/record_query.py:268` | gather_raw | write | `persist_payload` | live | writes the gather_raw payload sidecar for a query result |
| `scripts/gather_tools/record_query.py:367` | queries | append | `append_query_row` | live | appends a row to executed_queries.jsonl |
| `scripts/gather_tools/record_query.py:415` | queries | read | `system_for_payload_operands` | live | reads executed_queries.jsonl to attribute a payload's system |
| `scripts/gather_tools/sql.py:195` | NOT:tmp | write | `_run` | live | writes stdin payload to a scratch tempdir, not a run record |
| `scripts/gather_tools/sql.py:224` | NOT:stdio | write | `_run` | live | writes query result rows to stdout |
| `scripts/lessons/lessons_fm.py:116` | NOT:corpus | read | `cmd_show` | n-a | reads a lesson .md file from the corpus for display |
| `scripts/lessons/lessons_frontier.py:781` | investigation | read | `main` | n-a | reads investigation.md given via --investigation CLI arg |
| `scripts/visualize/visualize_data.py:61` | investigation | read | `split_investigation_phases` | end | reads investigation.md to split into phases |
| `scripts/visualize/visualize_episode.py:83` | NOT:repo | read | `(module scope)` | n-a | reads the episode page's own stylesheet asset |
| `scripts/visualize/visualize_episode.py:88` | NOT:not_file_io | read | `(module scope)` | n-a | string constant naming tool_trace.jsonl, not a call site |
| `scripts/visualize/visualize_episode.py:1058` | NOT:not_file_io | read | `_load_wire_logs` | n-a | filters directory entries by .jsonl suffix; not I/O |
| `scripts/visualize/visualize_episode.py:1061` | NOT:not_file_io | read | `_load_wire_logs` | n-a | filters entries by _framed_trace.jsonl suffix; not I/O |
| `scripts/visualize/visualize_episode.py:1063` | NOT:not_file_io | read | `_load_wire_logs` | n-a | derives a trace stem string; not I/O |
| `scripts/visualize/visualize_episode.py:1069` | NOT:not_file_io | read | `_load_wire_logs` | n-a | filters entries by _trace.jsonl suffix; not I/O |
| `scripts/visualize/visualize_episode.py:1071` | NOT:not_file_io | read | `_load_wire_logs` | n-a | derives a trace stem string; not I/O |
| `scripts/visualize/visualize_episode.py:1390` | learning_html | write | `_write_page` | end | writes learning.html at the episode root |
| `scripts/visualize/visualize_messages.py:34` | wire_log | read | `load_messages` | end | reads the run's wire log, with legacy fallback |
| `scripts/visualize/visualize_primitives.py:16` | NOT:repo | read | `(module scope)` | n-a | reads the shared stylesheet asset, not a run record |
| `scripts/visualize/visualize_primitives.py:143` | alert | read | `render_alert_block` | end | reads alert.json to render the alert block |
| `scripts/visualize/visualize_primitives.py:145` | alert | read | `render_alert_block` | end | fallback raw read of alert.json when JSON parse fails |
| `scripts/visualize/visualize_run.py:73` | runtime_html | write | `render_and_mirror` | end | writes runtime.html at the run root |
| `scripts/visualize/visualize_run.py:80` | NOT:viz_out | copy | `render_and_mirror` | end | mirrors runtime.html into run-visualizations/ outside the run dir |
| `scripts/visualize/visualize_run.py:289` | NOT:repo | read | `(module scope)` | n-a | reads the shared runtime.js asset, not a run record |
| `scripts/visualize/visualize_run.py:317` | policy_denials | read | `_render_policy_denials_section` | end | reads policy_denials.jsonl to render denial rows |
| `scripts/visualize/visualize_run.py:334` | tool_trace | read | `render_runtime_page` | end | reads tool_trace.jsonl for event stats |
| `scripts/visualize/visualize_runtime.py:403` | review_record | read | `_review_records` | end | reads each review_record.<n>.json attempt file |
| `scripts/visualize/visualize_runtime.py:429` | review_trace | read | `_review_trace` | end | reads a review_<role>_trace.jsonl wire log |
| `scripts/visualize/visualize_runtime.py:779` | tool_trace | read | `_lesson_changes` | end | checks tool_trace.jsonl mtime to bound a git log |
| `scripts/visualize/visualize_runtime.py:781` | NOT:not_file_io | read | `_lesson_changes` | n-a | string literal in a not-found branch, not a call site |

