# `defender/bin/` — agent invocation shims

Thin, stable wrappers the defender agent (orchestrator + gather subagents)
invokes by a single token — `defender-invlang enum types`, `cat <payload> | defender-sql '<SQL>'`.

**There is no data-source shim here, and there cannot be one (#611).** A system of record is
reached through the typed `query` tool (`runtime/query_tool.py` → the `VERBS` registry), never
through a program the model names: the seven `defender-<system>` shims and the
`defender-record-query` wrapper they were captured through are deleted, and the gate denies an
adapter-shaped command on every lane. What remains here is local computation over payloads the
harness already wrote to disk.

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
- The surviving shims (`defender-invlang`, `defender-lessons`, `defender-sql`) are the
  NON-adapter set (`hooks/_cmd_segments.NON_ADAPTER_SHIMS`) and stay allowed on the reader
  lane. `defender-sql` runs sandboxed SQL over a payload piped into it — the tier-2
  aggregation fallback for a source with no native aggregation; it queries no source, which
  is exactly why it is still a command.
- An **adapter-shaped** command (`defender-<system>`, or a `<system>_cli.py` path) is still
  CLASSIFIED — `hooks/_cmd_segments` / `permission/command_shape` — but only so the gate can
  deny it with a reason that names the `query` tool. The classification outlived the route.

To add a data source: do NOT drop a shim here — export a `VERBS` mapping from
`scripts/adapters/{system}_cli.py` (see `runtime/verbs.py`). To add a local tool: drop a shim
following the same pattern and add it to `NON_ADAPTER_SHIMS` *and* `grant._SHIM_FLAGS` (a shim
in one but not the other degrades to a free-text shape that silently widens what it accepts).
