# `defender/bin/` — agent invocation shims

Thin, stable wrappers the defender agent (orchestrator + gather subagents)
invokes by a single token — `defender-invlang enum types`,
`defender-elastic query '<kql>' --raw`, `defender-record-query … -- defender-elastic …`.

## Why

The harness allowlist matches a Bash command on its **first token**, and it
splits compound commands (`cd … &&`, pipes, `bash -c '…'`) and re-gates each
part. Invoking a tool as `python3 -m defender.skills.invlang.cli …`,
`defender/.venv/bin/python3 …/elastic_cli.py …`, or `cd $run && python3 …`
produces a different leading token every time, so an unattended `claude -p`
run trips "requires approval" on legitimate first-party calls (issue #261).

Each shim collapses all those forms to one allowlisted token (`Bash(defender-* *)`
in `run-settings.json`). `run.py` puts this dir first on `PATH` and exports
`DEFENDER_DIR` / `DEFENDER_RUNS_BASE`, so the shims resolve from any cwd.

## Conventions

- Each shim `exec`s the venv python (`$DEFENDER_DIR/.venv/bin/python3`),
  falling back to `python3` on PATH when no venv is present (e.g. the
  `tests/gather_invocation` sandbox, which runs stub CLIs under system python).
- `defender-invlang` runs `-m defender.skills.invlang.cli` from REPO_ROOT
  (package-relative imports) and injects `DEFENDER_RUNS_BASE` as the corpus
  root, so the agent never passes a path.
- The data-source **adapter** shims (`defender-elastic`, `defender-cmdb`,
  `defender-identity`, `defender-host-state`, `defender-threat-intel`,
  `defender-change-mgmt`, `defender-ticket`) are clamped out of the main loop
  by `hooks/block_main_loop_raw_access.py`, and inside the gather subagent they
  must be **wrapped** in `defender-record-query` — `hooks/block_unwrapped_adapter_calls.py`
  denies a bare adapter call there so every query lands in the queries table.
  The non-adapter shims (`defender-invlang`, `defender-record-query`,
  `defender-data-source-debug`) stay allowed in the main loop. The adapter vs.
  non-adapter split is defined once in `hooks/_cmd_segments.py`
  (`adapter_shims()` = all `defender-*` minus `NON_ADAPTER_SHIMS`) and is read by
  all three gate hooks (`approve_shim_invocations.py`,
  `block_unwrapped_adapter_calls.py`, `block_main_loop_raw_access.py`), so a new
  adapter dropped in this dir auto-gates everywhere with no per-hook edit.

To add a tool: drop a shim here following the same pattern; no allowlist edit
is needed (the `defender-*` glob covers it).
