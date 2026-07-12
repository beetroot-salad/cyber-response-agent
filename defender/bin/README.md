# `defender/bin/` — agent invocation shims

Thin, stable wrappers the defender agent (orchestrator + gather subagents)
invokes by a single token — `defender-invlang enum types`,
`defender-<system> <verb> '<query>'`. A data-source adapter is run STANDALONE and captured
transparently in-process; the old `defender-record-query … -- defender-<system> …` passthrough
wrapper is not a form any agent runs (the gate denies it).

`defender-policy` is the odd one out: an OPERATOR tool (`show` / `explain` the gate), listed in
`hooks/_cmd_segments.OPERATOR_TOOLS` so that no agent's lane admits it — reading your own gate is
a map of what to attack.

## Why

The harness allowlist matches a Bash command on its **first token**, and it
splits compound commands (`cd … &&`, pipes, `bash -c '…'`) and re-gates each
part. Invoking a tool as `python3 -m defender.skills.invlang.cli …`,
`defender/.venv/bin/python3 …/elastic_cli.py …`, or `cd $run && python3 …`
produces a different leading token every time, which the permission gate would
have to special-case (issue #261).

Each shim collapses all those forms to one stable `defender-*` token that
`runtime/permission.py` allowlists in-process. `run_common.run_env` puts this
dir first on `PATH` and exports `DEFENDER_DIR` / `DEFENDER_RUNS_BASE`, so the
shims resolve from any cwd.

## Conventions

- Each shim `exec`s the venv python (`$DEFENDER_DIR/.venv/bin/python3`),
  falling back to `python3` on PATH when no venv is present (a sandbox that
  points `DEFENDER_DIR` at a tree with no `.venv` still runs).
- `defender-invlang` runs `-m defender.skills.invlang.cli` from REPO_ROOT
  (package-relative imports) and injects `DEFENDER_RUNS_BASE` as the corpus
  root, so the agent never passes a path.
- The data-source **adapter** shims (`defender-<system>`, one per data source)
  are clamped out of the main loop
  by `runtime/permission.py` (using the `block_main_loop_raw_access` predicates).
  Inside the gather subagent a standalone adapter call runs **directly** — the
  runtime captures it transparently (`tools._capture_adapter` → the queries
  table), so no `defender-record-query` wrapper is needed.
  The non-adapter shims (`defender-invlang`, `defender-record-query`,
  `defender-lessons`, `defender-sql`) stay allowed in the main loop.
  (`defender-sql` runs sandboxed SQL over a payload piped into it — the tier-2
  aggregation fallback for a source with no native aggregation; it queries no
  source.) The adapter vs.
  non-adapter split is defined once in `hooks/_cmd_segments.py`
  (`adapter_shims()` = all `defender-*` minus `NON_ADAPTER_SHIMS`) and is read by
  the in-process gate (`runtime/permission.py`), so a new adapter dropped in this
  dir auto-gates with no per-site edit.

To add a tool: drop a shim here following the same pattern; no allowlist edit
is needed (the `defender-*` glob covers it).
