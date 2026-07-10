# `connect` — the MCP path

Read this when the interview routes to a system reached through an MCP
server the maintainer already has (or is willing to) configure. The other
path is `cli-adapter.md`. `SKILL.md` is the entrypoint and owns the
common steps (per-system knowledge, test, commit); this file is only the
MCP-specific build.

The MCP path is light by design: if a maintained server exists and is
configured, there is no adapter to write. Your job is to record how the
system is reached so the gather subagent and the defender can use it.

## What you do

1. **Confirm the server is configured.** MCP config is the maintainer's
   to manage — you do **not** write `.mcp.json` or their Claude config.
   Ask them to confirm the server is loaded, and which tools it exposes.

2. **Record the reach in the per-system skill.** In
   `skills/{system}/execution.md`, state that the system is reached via
   MCP server `<server-name>` and list the exact tool names the gather
   subagent should call (e.g. `mcp__splunk__query_spl`,
   `mcp__splunk__get_health`), with a one-line note on what each returns.
   The Visibility surface in `skills/{system}/SKILL.md` is written the
   same way as for any system (see `SKILL.md` → scaffold), independent of
   transport.

3. **Test by calling a tool.** Confirm reachability by invoking the
   health/status tool, then a minimal query tool, and show the maintainer
   the result — the same "do these results look right?" check as the CLI
   path.

## The cost to name out loud

MCP output is tagged for injection safety by the runtime, but it does
**not** flow through the `gather_raw/` capture path that the
queries table and the offline learning loop depend on. So an MCP-backed
system is thinner in the learning loop than a CLI-backed one: its queries
aren't captured as a re-runnable, by-ref record. Tell the maintainer this
when they choose the MCP path — it's a real trade-off, not a blocker.

## When to fall back to a CLI

If no maintained server exists, or the maintainer wants the capture path,
output control, or consistency with other adapters, take the CLI path
(`cli-adapter.md`) instead. The decision is the maintainer's; surface the
trade-off and don't steer.
