# Run records — every kind of file a run reads and writes

The inventory issue #1076 asked for: one page naming every record kind a run has, who writes
it, who reads it, when in the run's life it is written, and which kinds cross a package
boundary. It is the list the run handle (#1077) is built from. It moves nothing and renames
nothing; the code is still the spec.

**This page is generated.** Tables 1–4, 7 and the appendix are rendered from two checked-in
tables by `scripts/lint/lint_run_records.py`, which CI runs as a gate:

- `run-records.tsv` — one row per file-access *call site* in the sweep set: path, line, kind,
  op, enclosing function, when, note. Found by AST and resolved through the lint suite's callee
  resolver, so a docstring that mentions a call is not a site and an aliased import still is.
- `run-records-kinds.tsv` — one row per record *kind*: the static columns a call site cannot
  carry (path pattern, table, read-gate deny mode, archived-as, sub-collection, and `via` for a
  record read through a top-level helper the sweep sees only as the helper).

The gate fails on a call site with no row, a row whose call is gone, or a page that differs from
its tables. Edit the tables and run `--render`; `--refresh` re-points line numbers after code
moves. A writer or reader cell cites the call that reads or writes; the one exception is a row
tagged *names it*, the line that mints a filename for a shared writer seam (a stage's trace
name), kept as evidence because the seam's own call is generic. The sweep covers the builtin
and `os` openers, `json.load`/`dump`, `shutil` copies and removals, `tarfile.open`,
`sqlite3.connect`, every `defender._io` reader and writer, and the duck-typed path and
`_io.Bound` methods; it does not see a subprocess writing a file or a SQL statement on an open
connection, so the bash lane and the session store are attributed at their opener. Tests are
excluded throughout.

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
Two comments in the tree still describe it elsewhere — under the runs base (`branch/capture.py:133`)
and under the learning state root (`branch/ledger.py:526`); this page is the one place it is right.

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

<!-- generated: run-records tables — edit run-records.tsv / run-records-kinds.tsv and run scripts/lint/lint_run_records.py --render -->

## 1. Records inside the run dir

| kind | path | writer | when | readers | denied to | crosses boundary | archived as | note |
|---|---|---|---|---|---|---|---|---|
| alert | `alert.json` | **top**: `materialize_run_dir` (`run_common.py:80`); **runtime**: `_inherit_evidence` (`runtime/branch/_seed.py:251`) | host | **learning**: `_alert_document` (`learning/branch/cli.py:1764`), `json_mapping` (`learning/judge/family.py:648`), `_sibling_row` (`learning/judge/render.py:376`), `sibling_union` (`learning/judge/render.py:430`); **top**: `is_held_out_alert_copy` (`run_common.py:220`), `enqueue_curation` (`run_common.py:286`); **runtime**: `_inherit_evidence` (`runtime/branch/_seed.py:251`), `_alert_doc_soft` (`runtime/driver/__init__.py:511`), `resolve_lead_zero` (`runtime/lead_zero/__init__.py:281`), `_alert_signature` (`runtime/orient.py:64`), `_raw_alert` (`runtime/orient.py:73`); **scripts**: `read_case_record` (`scripts/case_history/case_ticket.py:214`), `open_case_ticket` (`scripts/case_history/ticket_writer.py:101`), `render_alert_block` (`scripts/visualize/visualize_primitives.py:143`), `render_alert_block` (`scripts/visualize/visualize_primitives.py:145`) | — (deliberately not in the answer key, `_run_paths.py:197-198`) | yes | alert.json | input copied by the host |
| report | `report.md` | **runtime**: `_commit` (`runtime/close_tool.py:431`), `_commit` (`runtime/close_tool.py:432`) | end | **top**: `read_report` (`_report.py:110`); **learning**: `_verdicts` (`learning/branch/episode.py:214`), `read_archived_report` (`learning/judge/family.py:1182`) | confined | yes | report.md | the close tool is its only writer; no role holds a write grant for it (`close_tool.py:1`) Read via: `_report.read_report` from `learning/core/validate.py:23`, `learning/ops/trace_lesson.py:119`, `scripts/visualize/visualize_primitives.py:130`, `evals/held_out.py:57`. |
| investigation | `investigation.md` | **runtime**: `seed_investigation` (`runtime/branch/_seed.py:205`), `_declare_l_finding` (`runtime/lead_zero/_capture.py:389`), `_tool_append_block` (`runtime/tools/_document.py:357`), `_tool_fix_row` (`runtime/tools/_document.py:729`) | host + live | **learning**: `load_run_context` (`learning/author/verify_forward/forward.py:37`), `_fence_count` (`learning/branch/cli.py:1725`), `read_frontier` (`learning/branch/questioner/__init__.py:513`), `_read_archived_text` (`learning/judge/family.py:1031`), `narration_crosscheck_from_run` (`learning/lead_repository.py:714`); **runtime**: `frontier_at_branch` (`runtime/branch/_frontier.py:321`), `seed_investigation` (`runtime/branch/_seed.py:150`), `_fold_decision` (`runtime/driver/_build.py:334`), `_is_declared` (`runtime/lead_zero/__init__.py:256`), `_declare_l_finding` (`runtime/lead_zero/_capture.py:379`), `decide_write` (`runtime/permission/files.py:543`), `_decide_investigation_write` (`runtime/permission/files.py:582`), `read_companion` (`runtime/tools/_document.py:97`); **scripts**: `main` (`scripts/lessons/lessons_frontier.py:781`), `split_investigation_phases` (`scripts/visualize/visualize_data.py:61`), `_load_world_archive` (`scripts/visualize/visualize_episode.py:965`) | confined | yes | investigation.md | seeds (lead-0, branch resume) write it before the first turn; the document tool during |
| queries | `executed_queries.jsonl` | **learning**: `stage_tables` (`learning/lead_repository.py:547`); **runtime**: `_inherit_evidence` (`runtime/branch/_seed.py:265`); **scripts**: `append_query_row` (`scripts/gather_tools/record_query.py:367`) | host + live + later | **learning**: `load_queries_report` (`learning/lead_repository.py:253`), `stage_tables` (`learning/lead_repository.py:552`); **runtime**: `validate` (`runtime/branch/__init__.py:208`), `_known_leads` (`runtime/branch/_frontier.py:454`), `_inherit_evidence` (`runtime/branch/_seed.py:264`), `_rows_for` (`runtime/lead_zero/_capture.py:106`); **scripts**: `lead_rows` (`scripts/gather_tools/record_query.py:223`), `system_for_payload_operands` (`scripts/gather_tools/record_query.py:415`) | confined | yes | staged as a table | append-only; the gather lane's denial rows land here too |
| source_refs | `source_refs.yaml` | **learning**: `stage_tables` (`learning/lead_repository.py:547`) | later | **learning**: `disposition_for` (`learning/author/lessons/run.py:111`), `load_run_context` (`learning/author/verify_forward/forward.py:30`) | confined (`_run_paths.py:202-204`) | no | — | no writer in this repo — consumed only; test helpers fabricate it (`tests/conftest.py:202`); `tests/test_orchestrate_thresholds.py:509` records that its writer is gone |
| gather_raw | `gather_raw/l-<lead>/<seq>.json` | **top**: `materialize_run_dir` (`run_common.py:79`); **runtime**: `_inherit_lead_dir` (`runtime/branch/_seed.py:308`), `_copy_artifact` (`runtime/branch/_seed.py:339`); **scripts**: `persist_payload` (`scripts/gather_tools/record_query.py:267`), `persist_payload` (`scripts/gather_tools/record_query.py:268`) | host + live | **learning**: `_captured_call` (`learning/branch/capture.py:180`), `corpus_samples` (`learning/lead_repository.py:487`), `stage_tables` (`learning/lead_repository.py:563`), `_copy` (`learning/lead_repository.py:593`); **runtime**: `_copy_artifact` (`runtime/branch/_seed.py:339`), `_capture_issue` (`runtime/lead_zero/_capture.py:173`) | shape | yes | staged as a table | by-ref payloads; read through the bash `cat` lane only |
| lead_claim | `gather_raw/<lead>.lead.json` | **hooks**: `claim_lead` (`hooks/record_lead.py:47`), `claim_lead` (`hooks/record_lead.py:63`), `claim_lead` (`hooks/record_lead.py:83`), `claim_lead` (`hooks/record_lead.py:97`) | live | **learning**: `load_leads` (`learning/lead_repository.py:203`) | shape (same dir) | yes | with gather_raw | per-lead claim sidecar, exclusive create |
| gather_summaries | `gather_summaries/<lead>.md` | **runtime**: `_inherit_lead_dir` (`runtime/branch/_seed.py:313`), `_persist_gather_summary` (`runtime/tools_gather.py:427`), `_persist_gather_summary` (`runtime/tools_gather.py:428`) | host + live | **learning**: `lead_chain` (`learning/judge/family.py:615`), `summary_lead_ids` (`learning/judge/family.py:873`), `_check_gather_summaries` (`learning/judge/family.py:1065`), `_archive_notes` (`learning/judge/family.py:1306`); **runtime**: `_copy_artifact` (`runtime/branch/_seed.py:339`) | — | yes | gather_summaries/ |  |
| lead_author | `lead_author/` | **learning**: `_write_state` (`learning/leads/lead_author/__init__.py:129`), `_write_state` (`learning/leads/lead_author/__init__.py:130`) | end + later | — | — | no | — | learning-stage outputs under a run dir; learning-internal |
| wire_log | `wire_logs/llm_requests.jsonl` | **runtime**: `__init__` (`runtime/observe.py:116`) | live | **scripts**: `load_messages` (`scripts/visualize/visualize_messages.py:34`) | outright | yes | — (dropped) | `review_roles` is a second writer into the same log |
| forward_check_trace | `wire_logs/<prefix>.<stem>.<n>.trace.jsonl` | **learning**: `_verify` (`learning/author/verify_forward/checks.py:72`) names it | end | — | outright (dir) | no | — | the learning verifier writes into the CITED run's dir after the fact |
| review_trace | `wire_logs/review_<role>_trace.jsonl` | **runtime**: `_write_trace_row` (`runtime/challenge_gate.py:289`), `_write_trace_row` (`runtime/challenge_gate.py:290`) | live | **scripts**: `_review_trace` (`scripts/visualize/visualize_runtime.py:429`) | outright (dir) | yes | — |  |
| review_record | `review_record.<turn>.json` | **runtime**: `write_review_record` (`runtime/challenge_gate.py:167`) | live | **scripts**: `_review_records` (`scripts/visualize/visualize_runtime.py:403`) | — | yes | — | one per close attempt |
| tool_trace | `tool_trace.jsonl` | **runtime**: `run_investigation` (`runtime/driver/__init__.py:709`), `write_trace` (`runtime/observe.py:392`) | end | **scripts**: `_result_event` (`scripts/visualize/visualize_episode.py:942`), `render_runtime_page` (`scripts/visualize/visualize_run.py:334`) | — | yes | — | a whole-file rebuild from the session store, written once after the agent returns |
| policy_denials | `policy_denials.jsonl` | **runtime**: `__init__` (`runtime/observe.py:116`) | live | **scripts**: `_render_policy_denials_section` (`scripts/visualize/visualize_run.py:317`) | — | yes | — | Read via: written through `observe.RequestLogger` opened by `observe.denial_logger` (`:245-252`), from `query_tool.py:657`. |
| budget | `budget.json` | **hooks**: `update_json_locked` (`hooks/_run_dir.py:28`), `_write_budget_atomic` (`hooks/budget_enforcer.py:120`) | live | **hooks**: `update_json_locked` (`hooks/_run_dir.py:33`), `read_json_locked` (`hooks/_run_dir.py:73`), `read_json_locked` (`hooks/_run_dir.py:75`) | — | yes | — | counter, locked json Read via: `hooks/budget_enforcer.read_budget` (`:75`) from `runtime/driver/_budget.py:49` and `runtime/lead_zero/_capture.py:317`. |
| circuit_breaker | `circuit_breaker.json` | **hooks**: `update_json_locked` (`hooks/_run_dir.py:28`) | live | **hooks**: `update_json_locked` (`hooks/_run_dir.py:33`), `read_json_locked` (`hooks/_run_dir.py:75`); **runtime**: `_load` (`runtime/circuit_breaker.py:89`), `_breaker_failures` (`runtime/lead_zero/_capture.py:241`) | — | yes | — | counter Read via: written through `hooks/_run_dir.update_json_locked` from `runtime/circuit_breaker.record_outcome` (`:151`). |
| lessons_loaded | `lessons_loaded.jsonl` | **runtime**: `_record_lesson_load` (`runtime/tools/_deps.py:251`) | live | **learning**: `_render_bound_world` (`learning/judge/render.py:699`), `in_context_cases` (`learning/ops/trace_lesson.py:142`) | — | yes | lessons_loaded.jsonl | receipt of corpus consumption; `hooks/record_lesson_load` is the reader-side classifier |
| ticket_write | `ticket_write.json` | **scripts**: `_write_receipt` (`scripts/case_history/ticket_writer.py:280`) | end | — | — | no | — |  |
| ticket_reads | `ticket_reads/<seq>.json` | — | — | — | cap | no | — | retired writer (the old pipeline judge, `permission/files.py:394-395`); only the path shape (`_run_paths.py:190`) and the read cap survive |
| session_pointer | `session_store_pointer.json` | **runtime**: `write_case_pointer` (`runtime/session_store.py:750`) | live | **runtime**: `open_source_store` (`runtime/branch/_spec.py:166`), `resolve_store_path` (`runtime/session_store.py:754`), `resolve_session_id` (`runtime/session_store.py:765`) | — | yes | — | written by the driver before the first turn Read via: `session_store.resolve_store_path` from `scripts/visualize/visualize_run.py:72`. |
| runtime_html | `runtime.html` | **scripts**: `render_and_mirror` (`scripts/visualize/visualize_run.py:73`) | end | — | (inlines MAIN's transcript; safe on timing only, `_run_paths.py:63-68`) | no | — | copied to `run-visualizations/` (`visualize_run.py:80`) |
| box_sentinel | `.box-sentinel` | **runtime**: `_plant` (`runtime/box/_lifecycle.py:73`), `_probe_sentinel` (`runtime/box/_lifecycle.py:100`), `_probe_sentinel` (`runtime/box/_lifecycle.py:102`) | host | — | — | no | — | `unlink_on_fault=False` (`_lifecycle.py:105-106`), left behind on a fault as evidence (`:96-102`); the mount-check sentinel `.box-sentinel-<uuid>` (`:109-117`) is a different, self-cleaning family |
| provenance | `provenance.json` | **top**: `write` (`_provenance.py:387`) | host | **top**: `read` (`_provenance.py:403`) | outright | yes | provenance.json | stamped by the host at materialize time Read via: `_provenance.read` from `run.py:378` and `learning/branch/cli._stamp_of` (`cli.py:807`); the read gate resolves its name (`runtime/permission/files.py:333`). |

## 2. Records beside the run dir (siblings under `<runs_base>`)

All three are written outside the box's writable mount so the model can neither plant nor suppress them. No read-gate deny names them; root containment keeps every role out.

| kind | path | writer | when | readers | crosses boundary | archived as | note |
|---|---|---|---|---|---|---|---|
| run_end | `<run>.run-end.json` | **top**: `materialize_run_dir` (`run_common.py:73`); **runtime**: `write_sidecar` (`runtime/run_end.py:125`) | host + end | — | yes | run_end.json (renamed, `archive.py:148`) | cleared by the host at `run_common.py:71-77` before a reused id Read via: `run_end.sidecar_path` from the archive copy (`learning/branch/archive.py:181`). |
| scrub_verdict | `<run>.scrub-verdict.json` | **runtime**: `_write_verdict` (`runtime/scrub.py:139`) | end | **learning**: `_scrub_ran` (`learning/branch/cli.py:776`); **runtime**: `tree_verified` (`runtime/scrub.py:162`) | yes | scrub_verdict.json (renamed, `archive.py:79`) |  |
| accounting | `<run>.accounting_failures.json` | **hooks**: `_write_accounting_failure` (`hooks/budget_enforcer.py:204`), `_record_alias_refusal` (`hooks/budget_enforcer.py:217`) | live | **hooks**: `update_json_locked` (`hooks/_run_dir.py:33`), `read_json_locked` (`hooks/_run_dir.py:73`), `read_json_locked` (`hooks/_run_dir.py:75`) | yes | — | Read via: read through `hooks/_run_dir.read_json_locked` from `hooks/budget_enforcer.py:213`. |

## 3. Session history

The session key is a **lineage** id: a fresh run mints `uuid4().hex` (`runtime/driver/__init__.py:586`); a resume or fork joins the source's store and rebinds to its id (`:593-620`). One DB spans a run and its resumes and forks. Two runs of one alert are two DBs. The pointer in the run dir (`session_pointer`) is how a run resolves to its transcript. The alert-derived `case-<sha256[:16]>` in `run_common.py:286` keys the curation queue and is unrelated. Session history is a **run record** (`run.session` in #1077); the shared file is a detail of the file backend.

| kind | path | writer | when | readers | crosses boundary | archived as | note |
|---|---|---|---|---|---|---|---|
| session_db | `<sessions>/<lineage id>.db` | **runtime**: `open_store` (`runtime/session_store.py:695`) | live | **runtime**: `_bare_connect` (`runtime/session_store.py:283`) | yes | — | SQLite; the connection at `_bare_connect` carries every read and append Read via: `session_store.open_store_for_read` from `scripts/visualize/visualize_run.py:72`; appends through `session_store.append` (`:370`) from `runtime/selection.py:90, 138` and `runtime/driver/_build.py:397`. |

## 4. Episode-level records (under `<episode>`)

The launcher's step order is QUESTIONER, STAGING, REVIEW, RUNS, VERIFY, JUDGE (`learning/branch/steps.py:52-57`); "host" below means before `RUNS`.

| kind | path | writer | when | readers | crosses boundary | archived as | note |
|---|---|---|---|---|---|---|---|
| family | `family.yaml` | **runtime**: `write_family` (`runtime/branch/_family.py:651`), `write_family` (`runtime/branch/_family.py:656`) | host | **learning**: `screened_yaml_mapping` (`learning/judge/family.py:158`); **runtime**: `_read_document` (`runtime/branch/_family.py:629`), `manifest_digest` (`runtime/branch/_family.py:669`) | yes | — | the fork point, declared once per episode |
| family_stamp | `provenance.json (episode root)` | **learning**: `_write_family_stamp` (`learning/branch/cli.py:1101`) | end | **learning**: `read_family_stamp` (`learning/branch/archive.py:117`) | no | — | a different shape from the run stamp; written by `verify_family` |
| review_yaml | `review.yaml` | **learning**: `merge_review` (`learning/branch/staging.py:616`), `merge_review` (`learning/branch/staging.py:617`) | end + later | **learning**: `_recorded_outcome` (`learning/branch/episode.py:102`), `merge_review` (`learning/branch/staging.py:606`), `_default_review_reader` (`learning/judge/family.py:184`) | no | — | written at `Step.REVIEW`, before the siblings run; the outcome is merged in at the end (`cli.py:1120`) |
| samples | `samples.yaml` | **learning**: `write_questioner_samples` (`learning/branch/cli.py:1586`) | host | **learning**: `_default_samples_reader` (`learning/judge/family.py:218`) | no | — | written at `Step.QUESTIONER`, before the model call |
| judge_yaml | `judge.yaml` | **learning**: `_write_judge_yaml` (`learning/judge/__init__.py:908`) | end | **learning**: `screened_yaml_mapping` (`learning/judge/family.py:158`) | no | — |  |
| judge_draw | `worlds/<label>/judge/<n>.yaml, worlds/family/judge/<n>.yaml` | **learning**: `_prepare_world_prompt` (`learning/judge/__init__.py:315`), `_run_world_draws` (`learning/judge/__init__.py:383`), `_run_world_draws` (`learning/judge/__init__.py:396`), `_grade_bound_episode` (`learning/judge/__init__.py:706`) | end + later | **learning**: `draws_on_disk_report` (`learning/judge/enqueue.py:490`); **scripts**: `_load_draws` (`scripts/visualize/visualize_episode.py:823`) | yes | — |  |
| timing | `timing.json` | **learning**: `record` (`learning/branch/timing.py:96`) | live | **learning**: `read_stage_timings` (`learning/branch/timing.py:149`) | no | — | per launcher step |
| staged | `staged.yaml` | **learning**: `_run_episode` (`learning/branch/cli.py:1409`), `record_staged` (`learning/branch/staging.py:414`), `record_staged` (`learning/branch/staging.py:419`) | host + later | **learning**: `read_staged` (`learning/branch/staging.py:376`) | no | — | the sole record that a cluster write happened |
| served | `served/base.jsonl, served/<token>.jsonl` | **learning**: `prime_base` (`learning/branch/capture.py:133`), `prepare_episode` (`learning/branch/cli.py:302`), `prepare_episode` (`learning/branch/cli.py:339`), `<module>` (`learning/branch/ledger.py:102`) names it, `for_world` (`learning/branch/ledger.py:338`) names it, `declare` (`learning/branch/ledger.py:361`), `declare` (`learning/branch/ledger.py:362`), `record` (`learning/branch/ledger.py:526`), `world_ledger_name` (`learning/judge/family.py:1155`) names it | host + live + later | **learning**: `_answers` (`learning/branch/episode.py:288`), `_absorb` (`learning/branch/ledger.py:450`), `review` (`learning/branch/review.py:297`), `_read_world_ledger` (`learning/judge/family.py:907`), `_missing_required_input` (`learning/judge/family.py:1328`) | no | — | base: primed once by the host before any sibling; <token>: appended live per sibling |
| priming_lock | `served/.priming` | **learning**: `prepare_episode` (`learning/branch/cli.py:305`), `prepare_episode` (`learning/branch/cli.py:350`) | host + later | — | no | — | `O_CREAT\|O_EXCL`; never unlinked, so a crashed priming leaves the episode permanently claimed |
| stage_trace | `wire_logs/<stage>.trace.jsonl, wire_logs/<agent>_framed_trace.jsonl` | **learning**: `model_seam` (`learning/branch/seams.py:77`) names it, `_run_world_draws` (`learning/judge/__init__.py:345`) names it, `_write_wire_log` (`learning/judge/__init__.py:436`); **runtime**: `stage_trace_path` (`runtime/observe.py:281`) | host + end | **scripts**: `_load_wire_logs` (`scripts/visualize/visualize_episode.py:1053`), `_load_wire_logs` (`scripts/visualize/visualize_episode.py:1065`), `_load_wire_logs` (`scripts/visualize/visualize_episode.py:1077`) | yes | — | episode-root wire traces of the learning stages |
| learning_html | `learning.html` | **scripts**: `_write_page` (`scripts/visualize/visualize_episode.py:1390`) | end | — | no | — |  |
| episode_runs | `runs/<episode_id>-<label>/` | **learning**: `start_family` (`learning/branch/cli.py:707`) | host | **scripts**: `_build_roster` (`scripts/visualize/visualize_episode.py:870`) | yes | — | a sibling's real run dir; its files take their table-1 kinds |
| archive_proj | `worlds/<label>/*` | **learning**: `_screen_destinations` (`learning/branch/archive.py:265`), `archive_episode` (`learning/branch/archive.py:309`), `archive_episode` (`learning/branch/archive.py:314`), `archive_episode` (`learning/branch/archive.py:330`), `archive_episode` (`learning/branch/archive.py:347`), `verify_family` (`learning/branch/cli.py:1039`), `_run_episode` (`learning/branch/cli.py:1429`) | end + later | **learning**: `_archived_labels` (`learning/branch/episode.py:152`), `json_mapping` (`learning/judge/family.py:648`), `_missing_required_input` (`learning/judge/family.py:1332`), `_repository_leads` (`learning/judge/family.py:1635`); **scripts**: `_load_episode` (`scripts/visualize/visualize_episode.py:780`), `_load_world_leads` (`scripts/visualize/visualize_episode.py:1003`) | yes | — | the archive copy itself (section 5) |

## 7. Sub-collections for the run handle (#1077)

Kinds whose call sites span more than one package (*crosses boundary = yes*), grouped by the concept the handle names. Derived from tables 1–3; a kind with `subcollection` empty in `run-records-kinds.tsv` is learning-internal or episode-level and is not a sub-collection.

| sub-collection | kinds | write owner(s) | writes when |
|---|---|---|---|
| `run.alert` | alert | runtime, top | host |
| `run.report` | report | runtime | end |
| `run.log` | investigation | runtime | host + live |
| `run.queries` | queries, policy_denials | learning, runtime, scripts | host + live + later / live |
| `run.payloads` | gather_raw | runtime, scripts, top | host + live |
| `run.leads` | lead_claim, gather_summaries | hooks, runtime | live / host + live |
| `run.traces` | wire_log, tool_trace, budget, lessons_loaded | hooks, runtime | live / end / live / live |
| `run.review` | review_trace, review_record | runtime | live / live |
| `run.session` | session_pointer, session_db | runtime | live / live |
| `run.provenance` | provenance, run_end, scrub_verdict | runtime, top | host / host + end / end |

<!-- end generated -->

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
- **Quarantine** of a tainted worktree: tar (`learning/core/quarantine.py:41-52`) + manifest (`:135`).
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

## Appendix — call-site attribution

Every file-access call site in `runtime/`, `learning/`, `scripts/`, `evals/`, `hooks/` and the
top-level `defender/*.py` modules (tests excluded), found by AST and resolved through the lint
suite's callee resolver, so a docstring that mentions `open(` is not a site and an aliased
import still is. Rendered from `run-records.tsv` by `scripts/lint/lint_run_records.py`, which
fails CI when a site has no row or a row's call is gone. Column 2 is a kind id from the tables
above, `NOT:<tag>` for a non-record (tags follow section 6), or `archive_proj` for the archive
copy's own call sites (section 5). `tool_seam` marks the model's generic read and write tools:
the file they touch is whichever record the role's grant names, so the kind is decided by the
gate at the call, not by the seam. `NOT:not_file_io` rows are the generic `_io` helpers
themselves, attributed at their callers.

| call site | kind | op | function | when | note |
|---|---|---|---|---|---|
| `_corpus.py:55` | NOT:corpus | read | `iter_lessons` | n-a | reads each lesson .md file from the corpus dir |
| `_corpus.py:198` | NOT:corpus | read | `read_query_template` | n-a | reads a query-template file from the corpus |
| `_first_party_key.py:13` | NOT:repo | read | `_read_env_key` | n-a | reads a repo .env file for ANTHROPIC_API_KEY, not a run record |
| `_flock.py:30` | NOT:queue | mkdir | `open_lock` | n-a | parent dir for a generic queue/repo lock file, not a run record |
| `_flock.py:31` | NOT:not_file_io | append | `open_lock` | n-a | generic lock-file opener; attributed at callers |
| `_io.py:41` | NOT:not_file_io | read | `read_text_utf8` | n-a | generic helper; attributed at callers |
| `_io.py:169` | NOT:not_file_io | read | `read_plain` | n-a | generic _io reader internal, path-agnostic |
| `_io.py:315` | NOT:not_file_io | read | `_walk_chain` | n-a | generic helper; attributed at callers |
| `_io.py:463` | NOT:not_file_io | read | `read` | n-a | generic _io reader internal, path-agnostic |
| `_io.py:469` | NOT:not_file_io | read | `read_jsonl` | n-a | generic _io reader internal (delegates to self.read), path-agnostic |
| `_io.py:512` | NOT:not_file_io | read | `_directory_fd` | n-a | generic helper; attributed at callers |
| `_io.py:547` | NOT:not_file_io | read | `bind` | n-a | generic helper; attributed at callers |
| `_io.py:657` | NOT:not_file_io | read | `read_jsonl_rows_report` | n-a | generic helper; attributed at callers |
| `_io.py:678` | NOT:not_file_io | mkdir | `append_jsonl` | n-a | generic JSONL-append primitive internal, path-agnostic |
| `_io.py:679` | NOT:not_file_io | append | `append_jsonl` | n-a | generic helper; attributed at callers |
| `_io.py:771` | NOT:not_file_io | write | `open_nofollow_fd` | n-a | generic helper; attributed at callers |
| `_io.py:822` | NOT:not_file_io | write | `write_guarded` | n-a | generic helper; attributed at callers |
| `_io.py:832` | NOT:not_file_io | write | `write_guarded` | n-a | generic write-guarded primitive internal, path-agnostic |
| `_io.py:835` | NOT:not_file_io | unlink | `write_guarded` | n-a | cleanup of its own staged temp file on a failed write, path-agnostic |
| `_io.py:875` | NOT:not_file_io | mkdir | `_ensure_dir_component` | n-a | generic guarded-mkdir component internal, path-agnostic |
| `_io.py:943` | NOT:not_file_io | mkdir | `guarded_mkdir` | n-a | creates the trust-root base dir itself, path-agnostic |
| `_io.py:976` | NOT:not_file_io | unlink | `sweep_staged` | n-a | sweeps orphaned staged files tree-wide, path-agnostic |
| `_provenance.py:387` | provenance | write | `write` | host | writes the per-run provenance stamp before the box exists |
| `_provenance.py:403` | provenance | read | `read` | n-a | reads the per-run provenance stamp |
| `_report.py:110` | report | read | `read_report` | end | reads a completed run's report.md |
| `_scaffold_rules.py:222` | NOT:corpus | read | `check_system_skill` | n-a | reads a system's SKILL.md for frontmatter validation |
| `_yaml.py:305` | NOT:corpus | read | `load_reviewed_mapping` | n-a | reads a reviewed policy file, e.g. verb-grants.yaml or lead-zero.yaml |
| `evals/harness.py:35` | NOT:eval_case | mkdir | `materialize` | n-a | mkdir tmp/defender/learning/_pending for materialized eval scenario |
| `evals/harness.py:36` | NOT:eval_case | mkdir | `materialize` | n-a | mkdir tmp/defender/lessons for materialized eval scenario |
| `evals/harness.py:43` | NOT:queue | copy | `materialize` | n-a | seeds scenario findings.jsonl into materialized _pending/findings.jsonl queue |
| `evals/harness.py:47` | NOT:eval_case | copy | `materialize` | n-a | copies scenario's fixture "runs" dir into materialized learning/runs tree |
| `evals/harness.py:52` | NOT:corpus | copy | `materialize` | n-a | seeds scenario lesson fixtures into materialized defender/lessons corpus dir |
| `evals/harness.py:76` | NOT:eval_result | mkdir | `capture_results` | n-a | mkdir eval results output dir under evals/results |
| `evals/harness.py:79` | NOT:eval_result | mkdir | `capture_results` | n-a | mkdir lessons_out under eval results dir |
| `evals/harness.py:81` | NOT:eval_result | copy | `capture_results` | n-a | harvests materialized lessons/*.md into the harness's own result dir |
| `evals/harness.py:84` | NOT:eval_result | mkdir | `capture_results` | n-a | mkdir pending_out under eval results dir |
| `evals/harness.py:87` | NOT:eval_result | copy | `capture_results` | n-a | harvests materialized _pending/* files into the harness's own result dir |
| `evals/harness.py:92` | NOT:eval_result | write | `capture_results` | n-a | writes git_log.txt into the harness result dir |
| `evals/harness.py:94` | NOT:eval_result | write | `capture_results` | n-a | writes author.stdout capture into the harness result dir |
| `evals/harness.py:95` | NOT:eval_result | write | `capture_results` | n-a | writes author.stderr capture into the harness result dir |
| `evals/harness.py:96` | NOT:eval_result | write | `capture_results` | n-a | writes rc.txt (author return code) into the harness result dir |
| `evals/harness.py:100` | NOT:eval_result | write | `capture_results` | n-a | writes timing.txt (wall seconds + effort) into the harness result dir |
| `evals/harness.py:119` | NOT:eval_result | mkdir | `main` | n-a | mkdir evals/results top-level dir |
| `evals/harness.py:121` | NOT:eval_case | mkdir | `main` | n-a | mkdir evals/_tmp scenario container dir |
| `evals/harness.py:124` | NOT:eval_case | mkdir | `main` | n-a | mkdir this scenario's materialized tmp dir |
| `evals/harness.py:139` | NOT:eval_case | write | `main` | n-a | rmtree cleanup of materialized scenario tmp dir |
| `evals/harness_lead.py:28` | NOT:eval_case | mkdir | `materialize` | n-a | mkdir tmp/defender/learning materialized tree |
| `evals/harness_lead.py:37` | NOT:eval_case | mkdir | `materialize` | n-a | mkdir parent dirs copying learning .py/.md into tmp |
| `evals/harness_lead.py:38` | NOT:repo | copy | `materialize` | n-a | copies real defender/learning package .py/.md source into sandboxed tmp tree |
| `evals/harness_lead.py:42` | NOT:repo | copy | `materialize` | n-a | copies real defender/_untrusted.py source module into sandboxed tmp tree |
| `evals/harness_lead.py:44` | NOT:corpus | copy | `materialize` | n-a | copies the real gather query catalog into the sandboxed tmp tree |
| `evals/harness_lead.py:49` | NOT:eval_case | mkdir | `materialize` | n-a | mkdir tmp/defender/scripts/adapters materialized tree |
| `evals/harness_lead.py:52` | NOT:eval_case | mkdir | `materialize` | n-a | mkdir parent dir copying skill SKILL.md into tmp |
| `evals/harness_lead.py:53` | NOT:corpus | copy | `materialize` | n-a | copies real skills/*/SKILL.md files into the sandboxed tmp tree |
| `evals/harness_lead.py:58` | NOT:tmp | write | `materialize` | n-a | writes a synthetic stub adapter (VERBS={}) to satisfy the resolver in the sandbox |
| `evals/harness_lead.py:64` | NOT:eval_case | copy | `materialize` | n-a | overlays scenario's catalog_overlay fixture onto the materialized query catalog |
| `evals/harness_lead.py:76` | NOT:eval_case | copy | `materialize` | n-a | copies scenario's single fixture run dir into the sandboxed runs/ tree |
| `evals/harness_lead.py:129` | NOT:eval_result | mkdir | `capture` | n-a | mkdir results_lead output dir for scenario |
| `evals/harness_lead.py:130` | NOT:eval_result | write | `capture` | n-a | writes lead_author.stdout capture into the harness result dir |
| `evals/harness_lead.py:131` | NOT:eval_result | write | `capture` | n-a | writes lead_author.stderr capture into the harness result dir |
| `evals/harness_lead.py:132` | NOT:eval_result | write | `capture` | n-a | writes rc.txt (lead-author return code) into the harness result dir |
| `evals/harness_lead.py:134` | NOT:eval_result | write | `capture` | n-a | writes git_log.txt into the harness result dir |
| `evals/harness_lead.py:136` | NOT:eval_result | write | `capture` | n-a | writes head_show.txt (git show --stat HEAD) into the harness result dir |
| `evals/harness_lead.py:137` | NOT:eval_result | write | `capture` | n-a | writes verdict.txt (PASS/FAIL + notes) into the harness result dir |
| `evals/harness_lead.py:138` | NOT:eval_result | copy | `capture` | n-a | captures post-run query catalog state into the harness result dir as catalog_after |
| `evals/harness_lead.py:156` | NOT:eval_case | read | `main` | n-a | reads scenario's expect.json verdict spec |
| `evals/harness_lead.py:158` | NOT:eval_result | mkdir | `main` | n-a | mkdir results_lead top-level dir |
| `evals/harness_lead.py:161` | NOT:eval_case | write | `main` | n-a | rmtree refused tmp dir, inside-repo safety check |
| `evals/harness_lead.py:179` | NOT:eval_case | write | `main` | n-a | rmtree cleanup of materialized scenario tmp dir |
| `evals/held_out.py:81` | NOT:eval_case | read | `load_held_out_fixtures` | n-a | reads held-out fixture's ground_truth.yaml label |
| `evals/oracle_golden/audit_judge.py:100` | NOT:eval_case | read | `audit_set` | n-a | reads a case's expected.yaml hand labels |
| `evals/oracle_golden/audit_judge.py:245` | NOT:eval_case | read | `verdict_set` | n-a | reads a case's manifest.yaml to check defective/derived status |
| `evals/oracle_golden/audit_judge.py:248` | NOT:eval_case | read | `verdict_set` | n-a | reads a case's projections/<tag>.yaml oracle projection |
| `evals/oracle_golden/audit_judge.py:250` | NOT:eval_case | read | `verdict_set` | n-a | reads a case's cached labels/<judge-tag>.json |
| `evals/oracle_golden/audit_judge.py:417` | NOT:eval_result | write | `main` | n-a | writes the audit's JSON report to the --out path |
| `evals/oracle_golden/controls.py:385` | NOT:eval_case | read | `_operation_window` | n-a | reads a case's manifest.yaml for its attack/operation window |
| `evals/oracle_golden/controls.py:407` | NOT:eval_case | read | `lead_queries` | n-a | reads a case's oracle_visible/leads.jsonl for its queries |
| `evals/oracle_golden/controls.py:475` | NOT:eval_case | mkdir | `main` | n-a | mkdir per-lead dir before writing control window json |
| `evals/oracle_golden/controls.py:476` | NOT:eval_case | write | `main` | n-a | writes one measured control record under hidden/controls/<lead_id>/<seq>.json |
| `evals/oracle_golden/generate_case.py:100` | NOT:eval_case | read | `scenario_entry` | n-a | reads the playground-v2 attacks catalog.yaml to find a scenario entry |
| `evals/oracle_golden/generate_case.py:321` | NOT:eval_case | write | `synthesise_alert` | n-a | writes the synthesised alert.json case input |
| `evals/oracle_golden/generate_case.py:353` | NOT:corpus | read | `write_environment` | n-a | reads the environment_template.yaml template |
| `evals/oracle_golden/generate_case.py:354` | NOT:eval_case | write | `write_environment` | n-a | writes the case's environment.yaml from the template |
| `evals/oracle_golden/generate_case.py:363` | NOT:eval_case | write | `write_manifest` | n-a | writes the case's manifest.yaml |
| `evals/oracle_golden/generate_case.py:485` | NOT:eval_case | mkdir | `_recruit` | n-a | mkdir case_dir/.generate scratch dir while generating golden case |
| `evals/oracle_golden/generate_case.py:491` | NOT:eval_case | read | `_recruit` | n-a | reads the playground-v2 runner record's metadata file for case generation |
| `evals/oracle_golden/generate_case.py:514` | NOT:eval_case | write | `_recruit` | n-a | writes the case's controls.yaml provenance note |
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
| `evals/oracle_golden/report.py:374` | NOT:eval_result | mkdir | `main` | n-a | mkdir parent dir before writing rollup report json |
| `evals/oracle_golden/report.py:375` | NOT:eval_result | write | `main` | n-a | writes the rollup report JSON to the --json out path |
| `evals/oracle_golden/score.py:360` | NOT:eval_case | read | `measure_case` | n-a | reads a case's cached labels/<judge-suffix>.json |
| `evals/oracle_golden/score.py:375` | NOT:eval_result | mkdir | `measure_case` | n-a | mkdir parent dir before writing judge label cache |
| `evals/oracle_golden/score.py:376` | NOT:eval_case | write | `measure_case` | n-a | writes the case's labels/<judge-suffix>.json label cache |
| `evals/oracle_golden/score.py:425` | NOT:eval_case | read | `_measured` | n-a | reads a case's manifest.yaml |
| `evals/oracle_golden/score.py:430` | NOT:eval_case | read | `_measured` | n-a | reads a case's projections/<tag>.yaml oracle projection |
| `evals/oracle_golden/score.py:584` | NOT:eval_case | read | `forbidden_values` | n-a | reads a case's expected.yaml for its must_not_emit clause |
| `evals/oracle_golden/score.py:728` | NOT:eval_result | mkdir | `main` | n-a | mkdir parent dir before writing case score summary json |
| `evals/oracle_golden/score.py:729` | NOT:eval_case | write | `main` | n-a | writes the score summary to case_dir/scores/<tag>.json |
| `evals/oracle_golden/story_from_run.py:109` | NOT:eval_case | read | `main` | n-a | reads the playground-v2 attack runner's metadata file to render a story |
| `evals/oracle_golden/story_from_run.py:121` | NOT:eval_case | mkdir | `main` | n-a | mkdir parent dir before writing story.md for golden case |
| `evals/oracle_golden/story_from_run.py:122` | NOT:eval_case | write | `main` | n-a | writes rendered story.md, an oracle_visible case input |
| `evals/oracle_golden/validate_cases.py:80` | NOT:eval_case | read | `_leads_of` | n-a | reads a case's oracle_visible/leads.jsonl |
| `evals/oracle_golden/validate_cases.py:106` | NOT:eval_case | read | `check_case` | n-a | reads a case's manifest.yaml |
| `evals/oracle_golden/validate_cases.py:110` | NOT:eval_case | read | `check_case` | n-a | reads a case's oracle_visible/story.md |
| `evals/oracle_golden/validate_cases.py:136` | NOT:eval_case | read | `load_known_defects` | n-a | reads the oracle_golden known_defects.yaml waiver registry |
| `evals/oracle_golden/validate_cases.py:306` | NOT:eval_case | read | `control_problems_by_record` | n-a | reads one control record under hidden/controls |
| `evals/oracle_golden/validate_cases.py:479` | NOT:eval_case | read | `check_environment` | n-a | reads a case's environment.yaml |
| `evals/oracle_golden/validate_cases.py:531` | NOT:eval_result | read | `check_held_out_ledger` | n-a | reads held_out_ledger.yaml to check recorded entries |
| `evals/oracle_golden/validate_cases.py:544` | NOT:eval_case | read | `check_held_out_ledger` | n-a | hashes a case's scores/<tag>.json to compare against the ledger |
| `evals/oracle_golden/validate_cases.py:592` | NOT:eval_case | read | `coverage` | n-a | reads one control record under hidden/controls to tally live/dead |
| `evals/oracle_golden/validate_cases.py:656` | NOT:eval_case | read | `main` | n-a | reads each case's manifest.yaml to index by id |
| `hooks/_run_dir.py:28` | budget,circuit_breaker | write | `update_json_locked` | live | locked json state write: budget.json (budget_enforcer) and circuit_breaker.json (circuit_breaker.record_outcome:151) |
| `hooks/_run_dir.py:33` | budget,circuit_breaker,accounting | read | `update_json_locked` | live | shared locked JSON read-modify-write read, used for budget/circuit_breaker/accounting sidecars |
| `hooks/_run_dir.py:73` | budget,accounting | read | `read_json_locked` | live | locked json state read: budget.json, and the accounting sidecar (budget_enforcer.py:213) |
| `hooks/_run_dir.py:75` | budget,circuit_breaker,accounting | read | `read_json_locked` | live | shared locked JSON reader, used for budget/circuit_breaker/accounting sidecars |
| `hooks/budget_enforcer.py:120` | budget | write | `_write_budget_atomic` | live | atomically rewrites budget.json with updated call counters |
| `hooks/budget_enforcer.py:204` | accounting | write | `_write_accounting_failure` | live | atomically rewrites <run>.accounting_failures.json sidecar |
| `hooks/budget_enforcer.py:217` | accounting | write | `_record_alias_refusal` | live | rewrites accounting sidecar, appending an alias-refusal entry |
| `hooks/inject_system_skill_description.py:26` | NOT:corpus | read | `read_description` | host | reads a system's skills/<system>/SKILL.md to get its description |
| `hooks/record_lead.py:47` | lead_claim | mkdir | `claim_lead` | live | creates gather_raw dir before writing the lead's claim sidecar |
| `hooks/record_lead.py:63` | lead_claim | write | `claim_lead` | live | exclusive-creates gather_raw/<lead>.lead.json claim sidecar |
| `hooks/record_lead.py:83` | lead_claim | unlink | `claim_lead` | live | removes the lead-claim sidecar after fdopen failed post-create |
| `hooks/record_lead.py:97` | lead_claim | unlink | `claim_lead` | live | removes the lead-claim sidecar after a write failure |
| `learning/_pydantic_stage.py:62` | NOT:corpus | read | `build_stage_agent` | n-a | reads the stage's role prompt file before building the agent |
| `learning/author/branch.py:115` | NOT:repo | mkdir | `start_batch` | n-a | mkdir git worktree base dir for author batch |
| `learning/author/branch.py:185` | NOT:repo | write | `cleanup` | n-a | unlink scrub verdict sidecar beside a removed author worktree |
| `learning/author/branch.py:195` | NOT:repo | write | `revert_lesson_pr` | n-a | rmtree stale revert worktree before re-adding it |
| `learning/author/branch.py:204` | NOT:repo | mkdir | `revert_lesson_pr` | n-a | mkdir git worktree base dir for revert worktree |
| `learning/author/drain.py:164` | NOT:corpus | write | `_put_back` | n-a | unlink an untracked non-lesson file put back under corpus dir |
| `learning/author/drain.py:300` | NOT:queue | read | `retire` | n-a | reads queue rows to bump/retire by id |
| `learning/author/drain.py:347` | NOT:queue | append | `_bump_rows` | n-a | appends retired rows to a channel's graveyard file |
| `learning/author/drain.py:428` | NOT:queue | read | `_tick` | n-a | reads a channel's queue file for this tick's batch |
| `learning/author/drain.py:1054` | NOT:corpus | write | `_restore_unapproved_files` | n-a | unlink a corpus file the tick created, restoring pre-tick state |
| `learning/author/drain.py:1056` | NOT:corpus | read | `_restore_unapproved_files` | n-a | reads a corpus file's bytes to check against tick-start snapshot |
| `learning/author/drain.py:1057` | NOT:corpus | write | `_restore_unapproved_files` | n-a | guarded_mkdir parent dir restoring a corpus file's pre-tick bytes |
| `learning/author/drain.py:1058` | NOT:corpus | write | `_restore_unapproved_files` | n-a | restores an unapproved corpus file to its pre-tick bytes |
| `learning/author/drain.py:1075` | NOT:corpus | write | `_restore_from_snapshot` | n-a | guarded_mkdir parent dir restoring corpus file from tick snapshot |
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
| `learning/author/drain.py:1562` | NOT:corpus | write | `_restore_corpus` | n-a | unlink a corpus file not in the pre-agent snapshot |
| `learning/author/drain.py:1565` | NOT:corpus | read | `_restore_corpus` | n-a | reads a corpus file's current bytes to check against the snapshot |
| `learning/author/drain.py:1566` | NOT:corpus | write | `_restore_corpus` | n-a | guarded_mkdir parent dir restoring corpus file to snapshot bytes |
| `learning/author/drain.py:1567` | NOT:corpus | write | `_restore_corpus` | n-a | restores a corpus file to its pre-agent snapshot bytes |
| `learning/author/lessons/run.py:111` | source_refs | read | `disposition_for` | end | reads a cited run's source_refs.yaml normalized_disposition |
| `learning/author/lessons/run.py:145` | NOT:queue | mkdir | `invoke_agent` | n-a | mkdir host-side _pending queue dir before curator spawn |
| `learning/author/questioner/run.py:151` | NOT:queue | mkdir | `invoke_agent` | n-a | mkdir host-side _pending queue dir before curator spawn |
| `learning/author/shared.py:157` | NOT:corpus | mkdir | `assert_clean_corpus_dir` | n-a | mkdir corpus_dir before checking it is git-clean |
| `learning/author/shared.py:304` | NOT:queue | mkdir | `invoke_repair` | n-a | mkdir host-side _pending queue dir before repair curator spawn |
| `learning/author/shared.py:457` | NOT:queue | mkdir | `write_disposition_report` | n-a | mkdir host-side _pending queue dir before writing disposition report |
| `learning/author/shared.py:461` | NOT:queue | append | `write_disposition_report` | n-a | appends a line naming what a tick declined, beside _pending |
| `learning/author/verify_forward/checks.py:72` | forward_check_trace | names | `_verify` | end | names the forward-check verifier's wire trace written into <cited_run_dir>/wire_logs/<prefix>.<stem>.<n>.trace.jsonl, the CITED run's own dir |
| `learning/author/verify_forward/forward.py:30` | source_refs | read | `load_run_context` | end | reads a cited case's source_refs.yaml disposition for forward-check |
| `learning/author/verify_forward/forward.py:37` | investigation | read | `load_run_context` | end | reads a cited case's investigation.md transcript for forward-check |
| `learning/branch/archive.py:117` | family_stamp | read | `read_family_stamp` | later | bound.read of provenance.json, the episode-root family stamp |
| `learning/branch/archive.py:265` | archive_proj | write | `_screen_destinations` | later | unlink stale occupant at a worlds/<X>/ archive destination name |
| `learning/branch/archive.py:309` | archive_proj | write | `archive_episode` | later | guarded_mkdir the worlds/<X> archive destination dir before copying |
| `learning/branch/archive.py:314` | archive_proj | copy | `archive_episode` | end | copies a sibling's seven single-file roles into worlds/<label>/ |
| `learning/branch/archive.py:330` | archive_proj | copy | `archive_episode` | end | copies gather_summaries/ into worlds/<label>/gather_summaries |
| `learning/branch/archive.py:347` | archive_proj | write | `archive_episode` | end | writes the worlds/<label>/ text pointer naming the source run dir |
| `learning/branch/capture.py:133` | served | append | `prime_base` | host | appends primed family-tier rows into the episode's served/base.jsonl |
| `learning/branch/capture.py:180` | gather_raw | read | `_captured_call` | host | reads the source run's captured payload to prime the base |
| `learning/branch/cli.py:302` | served | write | `prepare_episode` | later | guarded_mkdir episode served/ dir before priming |
| `learning/branch/cli.py:305` | priming_lock | write | `prepare_episode` | host | creates served/.priming lock (<episode>/served/.priming) so only one launcher primes an episode; cleared by hand after a crashed launcher |
| `learning/branch/cli.py:339` | served | write | `prepare_episode` | host | writes an empty served/base.jsonl when the source captured nothing |
| `learning/branch/cli.py:350` | priming_lock | write | `prepare_episode` | later | unlink served/.priming claim on every prime exit |
| `learning/branch/cli.py:707` | episode_runs | mkdir | `start_family` | host | creates <episode>/runs/ for the siblings |
| `learning/branch/cli.py:776` | scrub_verdict | read | `_scrub_ran` | end | reads a sibling run's scrub-verdict sidecar to check the reap scan ran |
| `learning/branch/cli.py:1039` | archive_proj | mkdir | `verify_family` | end | creates <episode>/worlds/ before archiving |
| `learning/branch/cli.py:1101` | family_stamp | write | `_write_family_stamp` | end | writes the episode's family stamp provenance.json |
| `learning/branch/cli.py:1409` | staged | write | `_run_episode` | host | creates the empty staged.yaml comment header before any name is staged |
| `learning/branch/cli.py:1429` | archive_proj | write | `_run_episode` | later | guarded_mkdir episode worlds/ dir after a rejected episode |
| `learning/branch/cli.py:1586` | samples | write | `write_questioner_samples` | host | writes the episode's samples.yaml corpus-sample document |
| `learning/branch/cli.py:1725` | investigation | read | `_fence_count` | host | reads the source run's investigation.md to count fences at the branch point |
| `learning/branch/cli.py:1764` | alert | read | `_alert_document` | host | reads the source run's alert.json for the questioner prompt |
| `learning/branch/episode.py:102` | review_yaml | read | `_recorded_outcome` | later | bound.read of review.yaml for the episode's recorded outcome |
| `learning/branch/episode.py:152` | archive_proj | read | `_archived_labels` | later | entries listing of episode worlds/ dir for archived world labels |
| `learning/branch/episode.py:214` | report | read | `_verdicts` | later | bound.read of worlds/<label>/report.md verdict headline |
| `learning/branch/episode.py:288` | served | read | `_answers` | end | reads a world's or base served ledger file into a key-to-answer map |
| `learning/branch/ledger.py:102` | served | names | `<module>` | live | names the family's base.jsonl capture filename under served/ |
| `learning/branch/ledger.py:338` | served | names | `for_world` | live | builds served/<world_id>.jsonl path for a sibling's own ledger |
| `learning/branch/ledger.py:361` | served | write | `declare` | later | mkdir served/ parent dir declaring a world's empty ledger file |
| `learning/branch/ledger.py:362` | served | append | `declare` | host | creates the sibling's empty served/<world_id>.jsonl ledger at world setup |
| `learning/branch/ledger.py:450` | served | read | `_absorb` | host | folds base/world served rows into the in-memory memo |
| `learning/branch/ledger.py:526` | served | append | `record` | live | appends one served call's row to the sibling's own ledger during the run |
| `learning/branch/questioner/__init__.py:157` | NOT:corpus | read | `_prompt` | n-a | reads a shipped questioner prompt file |
| `learning/branch/questioner/__init__.py:262` | NOT:corpus | read | `_questioner_lessons_section` | n-a | reads a defender/lessons-questioner/ candidate lesson file |
| `learning/branch/questioner/__init__.py:513` | investigation | read | `read_frontier` | host | reads the source run's investigation.md to build the questioner's frontier prefix |
| `learning/branch/review.py:134` | NOT:tmp | read | `base_rows` | n-a | reads the review's scratch base file outside the episode |
| `learning/branch/review.py:153` | NOT:tmp | mkdir | `scratch_ledger` | n-a | mkdir served/ under a fresh host scratch temp tree for replay |
| `learning/branch/review.py:161` | NOT:tmp | write | `scratch_ledger` | n-a | creates an empty scratch base file for the review replay |
| `learning/branch/review.py:297` | served | read | `review` | live | reads the episode's real served/base.jsonl capture to find drifted keys |
| `learning/branch/review.py:320` | NOT:tmp | write | `review` | n-a | rmtree the review replay's scratch temp tree |
| `learning/branch/seams.py:77` | stage_trace | names | `model_seam` | host | names the episode wire_logs trace file for the questioner's LLM call |
| `learning/branch/staging.py:376` | staged | read | `read_staged` | later | bound.read of episode staged.yaml record |
| `learning/branch/staging.py:414` | staged | write | `record_staged` | later | guarded_mkdir episode dir before appending a staged.yaml row |
| `learning/branch/staging.py:419` | staged | append | `record_staged` | host | appends one durable, fsynced row to the episode's staged.yaml |
| `learning/branch/staging.py:606` | review_yaml | read | `merge_review` | end | reads existing review.yaml before merging a new block |
| `learning/branch/staging.py:616` | review_yaml | write | `merge_review` | later | guarded_mkdir parent dir before rewriting merged review.yaml |
| `learning/branch/staging.py:617` | review_yaml | write | `merge_review` | end | writes the merged review.yaml document |
| `learning/branch/timing.py:96` | timing | write | `record` | live | rewrites the episode's timing.json after each completed step |
| `learning/branch/timing.py:149` | timing | read | `read_stage_timings` | later | bound.read of episode timing.json recorded steps |
| `learning/core/config.py:282` | NOT:queue | names | `for_batch` | n-a | names the corpus-curator's wire trace under <state_root>/_pending/wire_logs/<batch_id>.<pid>.trace.jsonl; written by run_stage's RequestLogger, operator-debug only reader |
| `learning/core/drains.py:188` | NOT:queue | read | `_pending_queue_counts` | n-a | counts authorable vs held rows in a queue file for the wake gate |
| `learning/core/drains.py:290` | NOT:queue | read | `_drain_one_curator` | n-a | reads channel rows to record a stuck fault when a curator faults |
| `learning/core/drains.py:354` | NOT:queue | write | `_requeue_or_drop` | n-a | unlink an inflight lead-claim marker after hand-back |
| `learning/core/drains.py:414` | NOT:queue | write | `apply` | n-a | unlink a served lead-claim marker after delivery |
| `learning/core/drains.py:645` | NOT:queue | mkdir | `_record_pending_delivery` | n-a | creates the _pending_delivery dir |
| `learning/core/drains.py:662` | NOT:queue | read | `_pending_deliveries` | n-a | reads a pending-delivery record json under _pending_delivery |
| `learning/core/drains.py:693` | NOT:queue | write | `_deliver_pending` | n-a | unlink a pending-delivery marker once delivered |
| `learning/core/markers.py:15` | NOT:queue | mkdir | `_enqueue_marker` | n-a | mkdir a run/lead queue dir before writing a marker |
| `learning/core/markers.py:17` | NOT:queue | write | `_enqueue_marker` | n-a | writes a run-keyed marker into a LoopPaths queue dir |
| `learning/core/markers.py:34` | NOT:queue | mkdir | `enqueue_case_for_curation` | n-a | mkdir author queue dir before writing a curation marker |
| `learning/core/markers.py:36` | NOT:queue | write | `enqueue_case_for_curation` | n-a | writes a case-keyed curation marker into the author queue |
| `learning/core/markers.py:46` | NOT:queue | write | `rewrite_marker` | n-a | rewrites a queue marker's spec atomically |
| `learning/core/markers.py:65` | NOT:queue | mkdir | `requeue_marker` | n-a | mkdir queue marker's parent dir before staging a requeue |
| `learning/core/markers.py:68` | NOT:queue | write | `requeue_marker` | n-a | stages a re-queue marker before hard-linking it into the slot |
| `learning/core/markers.py:70` | NOT:queue | write | `requeue_marker` | n-a | hard-link a staged temp file onto the queue marker name |
| `learning/core/markers.py:76` | NOT:queue | write | `requeue_marker` | n-a | unlink the staged temp file after the requeue link |
| `learning/core/markers.py:141` | NOT:queue | mkdir | `claim_markers` | n-a | mkdir queue's inflight/ dir before claiming markers |
| `learning/core/markers.py:148` | NOT:queue | write | `claim_markers` | n-a | os.replace a queue marker into inflight/ to claim it |
| `learning/core/markers.py:185` | NOT:queue | read | `_read_spec` | n-a | reads a claimed marker's spec row |
| `learning/core/markers.py:200` | NOT:queue | mkdir | `quarantine_marker` | n-a | mkdir queue's failed/ dir before parking a failed marker |
| `learning/core/markers.py:203` | NOT:queue | write | `quarantine_marker` | n-a | writes an unreadable marker into the queue's failed/ dead-letter dir |
| `learning/core/markers.py:205` | NOT:queue | write | `quarantine_marker` | n-a | unlink the original queue marker once quarantined |
| `learning/core/persist.py:74` | NOT:queue | read | `_rewrite_queue` | n-a | reads current queue rows before merging the rewrite |
| `learning/core/persist.py:76` | NOT:queue | write | `_rewrite_queue` | n-a | rewrites the queue file wholesale with survivors |
| `learning/core/persist.py:86` | NOT:queue | append | `_rewrite_queue` | n-a | appends consumed rows to a channel's consumed sidecar |
| `learning/core/persist.py:100` | NOT:queue | mkdir | `rotate_queue_locked` | n-a | mkdir pending queue file's parent dir before locked rewrite |
| `learning/core/persist.py:304` | NOT:queue | append | `append_pitfalls` | n-a | appends failing rows verbatim to the pitfalls queue |
| `learning/core/persist.py:308` | NOT:queue | read | `read_pitfalls` | n-a | reads all pitfalls queue rows |
| `learning/core/persist.py:321` | NOT:queue | read | `rotate_pitfalls` | n-a | reads pitfalls queue rows to select this batch's consumed set |
| `learning/core/quarantine.py:51` | NOT:quarantine | write | `_archive_tree` | n-a | tarfile.open w:gz writing a tainted worktree's gzipped archive |
| `learning/core/quarantine.py:64` | NOT:quarantine | read | `_tree_verdict` | n-a | reads a quarantined worktree's own scrub-verdict sidecar |
| `learning/core/quarantine.py:115` | NOT:quarantine | mkdir | `preserve_tainted_tree` | n-a | mkdir the tainted-worktree quarantine dir |
| `learning/core/quarantine.py:131` | NOT:quarantine | write | `preserve_tainted_tree` | n-a | unlink a half-written tainted-worktree tarball on archive failure |
| `learning/core/quarantine.py:135` | NOT:quarantine | write | `preserve_tainted_tree` | n-a | writes the quarantine manifest json beside the tar archive |
| `learning/frontend/build.py:534` | NOT:viz_out | write | `main` | n-a | writes lessons.json posture view alongside lessons.html |
| `learning/frontend/build.py:537` | NOT:viz_out | write | `main` | n-a | writes lessons.html rendered posture page |
| `learning/frontend/build.py:544` | NOT:viz_out | write | `main` | n-a | writes queues.json alongside queues.html |
| `learning/frontend/build.py:546` | NOT:viz_out | write | `main` | n-a | writes queues.html rendered queue page |
| `learning/frontend/serialize.py:217` | NOT:viz_out | write | `main` | n-a | writes lessons.json posture contract |
| `learning/frontend/serialize_queues.py:160` | NOT:queue | read | `_rows` | n-a | tolerant read of a queue/graveyard/stuck file for the queue page |
| `learning/frontend/serialize_queues.py:209` | NOT:queue | read | `_json_files` | n-a | reads *.json records from a pending-delivery-like dir for the queue page |
| `learning/judge/__init__.py:315` | judge_draw | mkdir | `_prepare_world_prompt` | end | creates worlds/<label>/judge/ |
| `learning/judge/__init__.py:345` | stage_trace | names | `_run_world_draws` | end | names the episode wire_logs trace file for one judge draw's LLM call |
| `learning/judge/__init__.py:383` | judge_draw | write | `_run_world_draws` | later | unlink an earlier pass's worlds/<X>/judge/<n>.yaml on malformed reply |
| `learning/judge/__init__.py:396` | judge_draw | write | `_run_world_draws` | end | writes one judge draw worlds/<label>/judge/<n>.yaml |
| `learning/judge/__init__.py:436` | stage_trace | write | `_write_wire_log` | end | writes the judge's one-line wire-log summary record |
| `learning/judge/__init__.py:706` | judge_draw | mkdir | `_grade_bound_episode` | end | creates worlds/family/judge/ |
| `learning/judge/__init__.py:908` | judge_yaml | write | `_write_judge_yaml` | end | writes the episode's judge.yaml grade record |
| `learning/judge/enqueue.py:225` | NOT:queue | read | `_append_validated_rows` | n-a | reads a findings queue to count malformed rows, no-op append |
| `learning/judge/enqueue.py:229` | NOT:queue | write | `_append_validated_rows` | n-a | guarded_mkdir findings queue's parent dir before appending rows |
| `learning/judge/enqueue.py:235` | NOT:queue | read | `_append_validated_rows` | n-a | reads findings queue rows before dedup append |
| `learning/judge/enqueue.py:255` | NOT:queue | read | `_append_validated_rows` | n-a | checks findings queue's trailing byte before append |
| `learning/judge/enqueue.py:257` | NOT:queue | read | `_append_validated_rows` | n-a | read last byte of pending findings queue file before append |
| `learning/judge/enqueue.py:259` | NOT:queue | append | `_append_validated_rows` | n-a | appends new finding rows to a findings queue |
| `learning/judge/enqueue.py:490` | judge_draw | read | `draws_on_disk_report` | end | reads a judge draw worlds/<X>/judge/<n>.yaml on the bare re-enqueue path |
| `learning/judge/family.py:158` | family,judge_yaml | read | `screened_yaml_mapping` | later | bound.read shared by family.yaml manifest and judge.yaml grade readers |
| `learning/judge/family.py:184` | review_yaml | read | `_default_review_reader` | later | bound.read of episode review.yaml |
| `learning/judge/family.py:218` | samples | read | `_default_samples_reader` | later | bound.read of episode samples.yaml |
| `learning/judge/family.py:615` | gather_summaries | read | `lead_chain` | later | world.read of worlds/<X>/gather_summaries/<lead_id>.md |
| `learning/judge/family.py:648` | alert,archive_proj | read | `json_mapping` | later | shared bound.read for worlds/<X> alert.json, provenance.json, run_end.json |
| `learning/judge/family.py:873` | gather_summaries | read | `summary_lead_ids` | later | entries listing of worlds/<X>/gather_summaries/ for lead ids |
| `learning/judge/family.py:907` | served | read | `_read_world_ledger` | later | read_jsonl of episode served/<world>.jsonl decision ledger |
| `learning/judge/family.py:1031` | investigation | read | `_read_archived_text` | later | bound.read of worlds/<world>/investigation.md |
| `learning/judge/family.py:1065` | gather_summaries | read | `_check_gather_summaries` | later | entries listing of worlds/<X>/gather_summaries/ dir |
| `learning/judge/family.py:1155` | served | names | `world_ledger_name` | live | the relative spelling of a world's served/<token>.jsonl ledger name |
| `learning/judge/family.py:1182` | report | read | `read_archived_report` | later | bound.read of worlds/<X>/report.md |
| `learning/judge/family.py:1306` | gather_summaries | read | `_archive_notes` | later | entries listing of worlds/<X>/gather_summaries/ dir |
| `learning/judge/family.py:1328` | served | read | `_missing_required_input` | later | entries listing of episode served/ dir for the ledger file |
| `learning/judge/family.py:1332` | archive_proj | read | `_missing_required_input` | later | entries listing of worlds/<label> archive dir for report.md |
| `learning/judge/family.py:1635` | archive_proj | read | `_repository_leads` | later | entries listing of worlds/<label> archive dir for leads |
| `learning/judge/render.py:376` | alert | read | `_sibling_row` | later | run.read of a sibling run dir's alert.json |
| `learning/judge/render.py:430` | alert | read | `sibling_union` | later | entries listing of runs base dir to find alert siblings |
| `learning/judge/render.py:699` | lessons_loaded | read | `_render_bound_world` | later | world.read_jsonl of worlds/<X>/lessons_loaded.jsonl |
| `learning/lead_repository.py:203` | lead_claim | read | `load_leads` | end | reads gather_raw/<lead>.lead.json claim sidecar |
| `learning/lead_repository.py:253` | queries | read | `load_queries_report` | end | reads executed_queries.jsonl table rows |
| `learning/lead_repository.py:487` | gather_raw | read | `corpus_samples` | host | reads a query's raw payload for a corpus document sample |
| `learning/lead_repository.py:547` | queries,source_refs | write | `stage_tables` | later | mkdir learning run dir before copying executed_queries and source_refs |
| `learning/lead_repository.py:552` | queries | read | `stage_tables` | end | copies executed_queries.jsonl into the learning run dir's table (copies the run's record out to the staging/archive dir) |
| `learning/lead_repository.py:563` | gather_raw | read | `stage_tables` | end | copies gather_raw/ tree into the learning run dir's table (copies the run's record out to the staging/archive dir) |
| `learning/lead_repository.py:593` | gather_raw | read | `_copy` | end | per-entry copy during stage_tables' gather_raw copytree (copies the run's record out to the staging/archive dir) |
| `learning/lead_repository.py:714` | investigation | read | `narration_crosscheck_from_run` | end | reads investigation.md for narration crosscheck |
| `learning/leads/_lead_spine.py:32` | NOT:queue | mkdir | `_spawn_author_agent` | n-a | mkdir lead-author pending queue dir before spawning agent |
| `learning/leads/draft_synthesis.py:330` | NOT:corpus | write | `synthesize_drafts` | n-a | guarded_mkdir catalog dir before writing a synthesized draft skill |
| `learning/leads/draft_synthesis.py:331` | NOT:corpus | write | `synthesize_drafts` | n-a | writes a new draft query template under the catalog's _draft/ dir |
| `learning/leads/lead_author/__init__.py:129` | lead_author | write | `_write_state` | later | mkdir run_dir/lead_author/ before writing the done sentinel |
| `learning/leads/lead_author/__init__.py:130` | lead_author | write | `_write_state` | end | writes a lead_author/ stage output file under a run |
| `learning/leads/lead_author/_handoff.py:231` | NOT:corpus | read | `_draft_contradicts_skill` | n-a | reads a system-skill draft file's contradicts_skill flag |
| `learning/leads/lead_author/_rules.py:78` | NOT:corpus | read | `_frontmatter_id` | n-a | reads a catalog or skills file's frontmatter id |
| `learning/leads/lead_render.py:36` | NOT:corpus | read | `render_query` | n-a | reads a gather query catalog template to render its query body |
| `learning/leads/pitfalls_curator.py:337` | NOT:corpus | read | `_readable_pair` | n-a | reads the pitfalls reducer skill doc to compare against HEAD |
| `learning/leads/pitfalls_curator.py:647` | NOT:queue | append | `_graveyard_dropped_rows` | n-a | appends terminally-dropped pitfalls rows to the pitfalls graveyard |
| `learning/ops/trace_lesson.py:142` | lessons_loaded | read | `in_context_cases` | end | path to a run's lessons_loaded.jsonl, read next for exposures |
| `learning/ops/trace_lesson.py:204` | NOT:corpus | read | `main` | n-a | reads a lesson markdown file from defender/lessons |
| `run_common.py:73` | run_end | unlink | `materialize_run_dir` | host | clears a stale run_end sidecar before materializing the run dir |
| `run_common.py:79` | gather_raw | mkdir | `materialize_run_dir` | host | creates gather_raw dir while materializing the run directory |
| `run_common.py:80` | alert | copy | `materialize_run_dir` | host | copies the alert into the new run dir as alert.json |
| `run_common.py:212` | NOT:eval_case | read | `held_out_alert_digests` | n-a | reads held-out fixture alert.json bytes to digest |
| `run_common.py:220` | alert | read | `is_held_out_alert_copy` | end | reads the run's alert.json bytes to check held-out status |
| `run_common.py:286` | alert | read | `enqueue_curation` | end | reads the run's alert.json bytes to derive case_id |
| `runtime/bash_exec.py:579` | NOT:tmp | read | `_run_one_pipeline` | n-a | reads captured stderr from an anonymous tempfile, not a run record |
| `runtime/bash_policy.py:21` | NOT:corpus | read | `_load_policy` | n-a | reads bash_policy.json deny-list corpus file |
| `runtime/box/_docker.py:250` | NOT:sysfile | read | `_own_container_ids` | host | NOT: reads host /etc/hostname to identify this container |
| `runtime/box/_docker.py:253` | NOT:sysfile | read | `_own_container_ids` | host | NOT: reads host /proc/self/mountinfo for the container's full id |
| `runtime/box/_lifecycle.py:73` | box_sentinel | write | `_plant` | host | writes .box-sentinel token host-side before the box starts |
| `runtime/box/_lifecycle.py:100` | box_sentinel | unlink | `_probe_sentinel` | host | removes a per-mount sentinel after a failed readback probe |
| `runtime/box/_lifecycle.py:102` | box_sentinel | unlink | `_probe_sentinel` | host | removes the sentinel after a successful readback probe |
| `runtime/branch/__init__.py:208` | queries | read | `validate` | host | reads executed_queries.jsonl to check the source run captured evidence |
| `runtime/branch/_family.py:629` | family | read | `_read_document` | host | reads the episode's family.yaml manifest through the guarded lane |
| `runtime/branch/_family.py:651` | family | mkdir | `write_family` | host | creates the episode dir before writing family.yaml |
| `runtime/branch/_family.py:656` | family | write | `write_family` | host | writes family.yaml manifest into the episode dir |
| `runtime/branch/_family.py:669` | family | read | `manifest_digest` | host | re-reads family.yaml to compute/recheck its content digest |
| `runtime/branch/_frontier.py:321` | investigation | read | `frontier_at_branch` | host | reads source run's investigation.md to compute the frontier at branch point |
| `runtime/branch/_frontier.py:454` | queries | read | `_known_leads` | host | reads executed_queries.jsonl lead ids for the branch census |
| `runtime/branch/_seed.py:150` | investigation | read | `seed_investigation` | host | reads source run's investigation.md to cut the sibling's seed |
| `runtime/branch/_seed.py:205` | investigation | write | `seed_investigation` | host | writes the cut prefix as the sibling's investigation.md seed |
| `runtime/branch/_seed.py:251` | alert | write | `_inherit_evidence` | host | copies source run's alert.json bytes into the sibling run dir |
| `runtime/branch/_seed.py:251` | alert | read | `_inherit_evidence` | host | reads source run's alert bytes to seed a sibling's copy |
| `runtime/branch/_seed.py:264` | queries | read | `_inherit_evidence` | host | reads source executed_queries.jsonl rows, filtered by inherited leads |
| `runtime/branch/_seed.py:265` | queries | write | `_inherit_evidence` | host | writes filtered rows as the sibling's executed_queries.jsonl |
| `runtime/branch/_seed.py:308` | gather_raw | mkdir | `_inherit_lead_dir` | host | creates the sibling's gather_raw/ before inheriting the source's lead dirs |
| `runtime/branch/_seed.py:313` | gather_summaries | mkdir | `_inherit_lead_dir` | host | creates the sibling's gather_summaries/ before inheriting |
| `runtime/branch/_seed.py:339` | gather_raw | write | `_copy_artifact` | host | writes the inherited lead-dir entry into the sibling's gather_raw/ or gather_summaries/ |
| `runtime/branch/_seed.py:339` | gather_raw,gather_summaries | read | `_copy_artifact` | host | reads a source lead payload's bytes for a sibling copy |
| `runtime/branch/_spec.py:166` | session_pointer | read | `open_source_store` | host | reads session_store_pointer.json to resolve/verify the source store |
| `runtime/challenge_gate.py:167` | review_record | write | `write_review_record` | live | writes review_record.<turn>.json beside the run |
| `runtime/challenge_gate.py:289` | review_trace | mkdir | `_write_trace_row` | live | creates wire_logs dir before appending a review trace row |
| `runtime/challenge_gate.py:290` | review_trace | append | `_write_trace_row` | live | appends one metadata(+raw reply) row to review_<role>_trace.jsonl |
| `runtime/circuit_breaker.py:89` | circuit_breaker | read | `_load` | live | reads circuit_breaker.json breaker state for a system |
| `runtime/close_tool.py:431` | report | mkdir | `_commit` | end | creates run dir parent before writing report.md at close |
| `runtime/close_tool.py:432` | report | write | `_commit` | end | writes report.md with the close tool's rendered disposition |
| `runtime/driver/__init__.py:511` | alert | read | `_alert_doc_soft` | host | reads alert.json for item3's correlation-contract dispatch |
| `runtime/driver/__init__.py:709` | tool_trace | write | `run_investigation` | end | writes an empty tool_trace.jsonl fallback when write_trace itself failed |
| `runtime/driver/_build.py:263` | NOT:corpus | read | `_gather_instructions` | n-a | reads GATHER's skills/gather/SKILL.md system prompt |
| `runtime/driver/_build.py:334` | investigation | read | `_fold_decision` | live | reads investigation.md to decide whether to fold this turn |
| `runtime/driver/_prompts.py:48` | NOT:corpus | read | `_main_instructions` | n-a | reads MAIN's SKILL.md system prompt body |
| `runtime/lead_zero/__init__.py:256` | investigation | read | `_is_declared` | host | reads investigation.md to check whether a lead id is declared |
| `runtime/lead_zero/__init__.py:281` | alert | read | `resolve_lead_zero` | host | reads alert.json to resolve lead-0's correlation lead |
| `runtime/lead_zero/_capture.py:106` | queries | read | `_rows_for` | host | reads executed_queries.jsonl rows for one lead during lead-0 |
| `runtime/lead_zero/_capture.py:173` | gather_raw | read | `_capture_issue` | live | reads a gather_raw payload json to elide a captured document (correlation task runs concurrently with the agent, driver:675) |
| `runtime/lead_zero/_capture.py:241` | circuit_breaker | read | `_breaker_failures` | live | reads circuit_breaker.json to count system failures for item1 (correlation task runs concurrently with the agent, driver:675) |
| `runtime/lead_zero/_capture.py:379` | investigation | read | `_declare_l_finding` | host | reads investigation.md before appending lead-0's declaration |
| `runtime/lead_zero/_capture.py:389` | investigation | write | `_declare_l_finding` | host | writes lead-0's :L findings row into investigation.md |
| `runtime/observe.py:116` | wire_log,policy_denials | append | `__init__` | live | RequestLogger opens its log for append (wire log; policy denials via denial_logger, observe.py:245-252) |
| `runtime/observe.py:281` | stage_trace | mkdir | `stage_trace_path` | host | creates <root>/wire_logs/ for a stage trace |
| `runtime/observe.py:392` | tool_trace | write | `write_trace` | end | writes tool_trace.jsonl with usage/result events after the run |
| `runtime/orient.py:64` | alert | read | `_alert_signature` | host | reads alert.json to extract rule id for lessons signature |
| `runtime/orient.py:73` | alert | read | `_raw_alert` | host | reads alert.json raw text for the orientation prompt section |
| `runtime/orient.py:89` | NOT:corpus | read | `_invlang_grammar` | n-a | reads skills/invlang/SKILL.md grammar reference into the prompt |
| `runtime/permission/files.py:543` | investigation | read | `decide_write` | live | reads investigation.md baseline to gate an append-only write |
| `runtime/permission/files.py:582` | investigation | read | `_decide_investigation_write` | live | reads investigation.md baseline for the frames-suite gate wrapper |
| `runtime/review/__init__.py:34` | NOT:corpus | read | `role_prompt` | n-a | reads a review role's prompt .md file verbatim |
| `runtime/run_end.py:125` | run_end | write | `write_sidecar` | end | writes <run>.run-end.json sidecar beside the run dir |
| `runtime/scrub.py:139` | scrub_verdict | write | `_write_verdict` | end | writes <tree>.scrub-verdict.json beside the scanned tree |
| `runtime/scrub.py:162` | scrub_verdict | read | `tree_verified` | end | reads scrub verdict sidecar to check ran:true |
| `runtime/session_store.py:283` | session_db | open | `_bare_connect` | live | opens the lineage's SQLite store (every read and append goes through this connection) |
| `runtime/session_store.py:695` | session_db | mkdir | `open_store` | live | creates <sessions>/ beside the runs base |
| `runtime/session_store.py:750` | session_pointer | write | `write_case_pointer` | live | writes session_store_pointer.json naming the case/session |
| `runtime/session_store.py:754` | session_pointer | read | `resolve_store_path` | live | reads session_store_pointer.json for store_path |
| `runtime/session_store.py:765` | session_pointer | read | `resolve_session_id` | live | reads session_store_pointer.json for session_id |
| `runtime/tools/_bash.py:239` | tool_seam | mkdir | `_guarded_parents` | live | creates parents of a model-declared write path |
| `runtime/tools/_deps.py:251` | lessons_loaded | append | `_record_lesson_load` | live | appends a row to lessons_loaded.jsonl on a corpus read/push |
| `runtime/tools/_document.py:97` | investigation | read | `read_companion` | live | reads investigation.md once per model request via read_plain |
| `runtime/tools/_document.py:357` | investigation | write | `_tool_append_block` | live | writes an appended block onto investigation.md |
| `runtime/tools/_document.py:729` | investigation | write | `_tool_fix_row` | live | writes a repaired/deleted flagged row back into investigation.md |
| `runtime/tools/_files.py:54` | tool_seam | read | `_probe_read_text` | live | model-declared read-allowed path; read by read/edit-file tools |
| `runtime/tools/_files.py:157` | tool_seam | write | `_tool_write_file` | live | model-declared write_allow path (MAIN: investigation.md; curators: corpus targets) |
| `runtime/tools/_files.py:199` | tool_seam | write | `_tool_edit_file` | live | model-declared write_allow path, same target set as write_file |
| `runtime/tools_gather.py:427` | gather_summaries | mkdir | `_persist_gather_summary` | live | creates gather_summaries dir before writing a lead's summary |
| `runtime/tools_gather.py:428` | gather_summaries | write | `_persist_gather_summary` | live | writes gather_summaries/<lead_id>.md wrapped summary |
| `runtime/verb_roster.py:93` | NOT:corpus | mkdir | `generate_roster` | n-a | creates skills/<role>/ dir for the generated verb-roster.md |
| `runtime/verb_roster.py:94` | NOT:corpus | write | `generate_roster` | n-a | writes generated verb-roster.md under skills/<role>/ |
| `runtime/verb_roster.py:105` | NOT:corpus | read | `load_roster` | n-a | reads committed verb-roster.md under skills/<role>/ |
| `runtime/verb_roster.py:219` | NOT:corpus | read | `audit_read_surfaces` | n-a | reads SKILL.md/execution.md/query templates for a verb-mention audit |
| `runtime/verbs.py:544` | NOT:repo | read | `read_roster` | host | reads an adapter module's source bytes to parse verb names |
| `scripts/adapters/_stub_transport.py:110` | NOT:corpus | read | `_parse_env_file` | n-a | reads a system's knowledge/environment config.env file |
| `scripts/adapters/elastic_adapter.py:129` | NOT:corpus | read | `config_from` | n-a | reads knowledge/environment/systems/elastic/config.env |
| `scripts/adapters/tacit_knowledge_adapter.py:261` | NOT:corpus | read | `read_registry` | n-a | reads skills/<system>/registry.yaml tacit-knowledge registry |
| `scripts/case_history/case_ticket.py:89` | NOT:corpus | read | `_load_mapping` | n-a | reads knowledge/environment/systems/case-history mapping.yaml |
| `scripts/case_history/case_ticket.py:214` | alert | read | `read_case_record` | end | reads alert.json to derive the ticket signature_id |
| `scripts/case_history/ticket_writer.py:101` | alert | read | `open_case_ticket` | end | reads alert.json to build the open-ticket payload |
| `scripts/case_history/ticket_writer.py:280` | ticket_write | write | `_write_receipt` | end | writes the ticket_write.json receipt after posting |
| `scripts/gather_tools/record_query.py:223` | queries | read | `lead_rows` | live | reads executed_queries.jsonl rows for a lead |
| `scripts/gather_tools/record_query.py:267` | gather_raw | write | `persist_payload` | live | guarded_mkdir gather_raw/<lead_id>/ before writing the payload sidecar |
| `scripts/gather_tools/record_query.py:268` | gather_raw | write | `persist_payload` | live | writes the gather_raw payload sidecar for a query result |
| `scripts/gather_tools/record_query.py:367` | queries | append | `append_query_row` | live | appends a row to executed_queries.jsonl |
| `scripts/gather_tools/record_query.py:415` | queries | read | `system_for_payload_operands` | live | reads executed_queries.jsonl to attribute a payload's system |
| `scripts/gather_tools/sql.py:195` | NOT:tmp | write | `_run` | live | writes stdin payload to a scratch tempdir, not a run record |
| `scripts/gather_tools/sql.py:224` | NOT:stdio | write | `_run` | live | writes query result rows to stdout |
| `scripts/gather_tools/sql.py:233` | NOT:tmp | write | `_run` | n-a | rmtree the duckdb query's scratch temp dir |
| `scripts/lessons/lessons_fm.py:116` | NOT:corpus | read | `cmd_show` | n-a | reads a lesson .md file from the corpus for display |
| `scripts/lessons/lessons_frontier.py:781` | investigation | read | `main` | n-a | reads investigation.md given via --investigation CLI arg |
| `scripts/visualize/visualize_data.py:61` | investigation | read | `split_investigation_phases` | end | reads investigation.md to split into phases |
| `scripts/visualize/visualize_episode.py:83` | NOT:repo | read | `<module>` | n-a | reads the episode page's own stylesheet asset |
| `scripts/visualize/visualize_episode.py:780` | archive_proj | read | `_load_episode` | later | entries listing of episode worlds/ dir for archived dirs |
| `scripts/visualize/visualize_episode.py:823` | judge_draw | read | `_load_draws` | later | entries listing of worlds/<label> dir to find judge/ draws |
| `scripts/visualize/visualize_episode.py:870` | episode_runs | read | `_build_roster` | later | entries listing of episode runs/ dir for run-dir names |
| `scripts/visualize/visualize_episode.py:942` | tool_trace | read | `_result_event` | later | read_jsonl of a runs/<name>/tool_trace.jsonl result event |
| `scripts/visualize/visualize_episode.py:965` | investigation | read | `_load_world_archive` | later | bound.read of worlds/<label>/investigation.md |
| `scripts/visualize/visualize_episode.py:1003` | archive_proj | read | `_load_world_leads` | later | entries listing of worlds/<label> archive dir for leads |
| `scripts/visualize/visualize_episode.py:1053` | stage_trace | read | `_load_wire_logs` | later | entries listing of episode-root wire_logs/ dir |
| `scripts/visualize/visualize_episode.py:1065` | stage_trace | read | `_load_wire_logs` | later | read_jsonl of episode-root wire_logs/*_framed_trace.jsonl |
| `scripts/visualize/visualize_episode.py:1077` | stage_trace | read | `_load_wire_logs` | later | read_jsonl of episode-root wire_logs/*_trace.jsonl |
| `scripts/visualize/visualize_episode.py:1390` | learning_html | write | `_write_page` | end | writes learning.html at the episode root |
| `scripts/visualize/visualize_messages.py:34` | wire_log | read | `load_messages` | end | reads the run's wire log, with legacy fallback |
| `scripts/visualize/visualize_primitives.py:16` | NOT:repo | read | `<module>` | n-a | reads the shared stylesheet asset, not a run record |
| `scripts/visualize/visualize_primitives.py:143` | alert | read | `render_alert_block` | end | reads alert.json to render the alert block |
| `scripts/visualize/visualize_primitives.py:145` | alert | read | `render_alert_block` | end | fallback raw read of alert.json when JSON parse fails |
| `scripts/visualize/visualize_run.py:73` | runtime_html | write | `render_and_mirror` | end | writes runtime.html at the run root |
| `scripts/visualize/visualize_run.py:78` | NOT:viz_out | mkdir | `render_and_mirror` | n-a | mkdir run-visualizations/<run> mirror dir for the rendered page |
| `scripts/visualize/visualize_run.py:80` | NOT:viz_out | copy | `render_and_mirror` | end | mirrors runtime.html into run-visualizations/ outside the run dir |
| `scripts/visualize/visualize_run.py:289` | NOT:repo | read | `<module>` | n-a | reads the shared runtime.js asset, not a run record |
| `scripts/visualize/visualize_run.py:317` | policy_denials | read | `_render_policy_denials_section` | end | reads policy_denials.jsonl to render denial rows |
| `scripts/visualize/visualize_run.py:334` | tool_trace | read | `render_runtime_page` | end | reads tool_trace.jsonl for event stats |
| `scripts/visualize/visualize_runtime.py:403` | review_record | read | `_review_records` | end | reads each review_record.<n>.json attempt file |
| `scripts/visualize/visualize_runtime.py:429` | review_trace | read | `_review_trace` | end | reads a review_<role>_trace.jsonl wire log |
