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
- **Rendered pages outside a run or episode** (`queues.html`, `lessons.html`) and the checked-in
  `run-visualizations/` tree.
- The corpus curators' own wire traces under `_pending/wire_logs/`, learning state rather than a
  run record; the review step's scratch `served/` tree, which is not the episode's.
- Repo and worktree files, git plumbing, container identity files, stdio and subprocess pipes,
  scratch files.
