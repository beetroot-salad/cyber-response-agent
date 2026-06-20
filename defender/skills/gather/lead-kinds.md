# Gather — lead kinds

Most dispatches are **template leads** — one or more catalog templates, or a
coined-and-run measurement when none fits (§2). Two other lead kinds exist
as fallback methodology; the defender names them explicitly in the lead
description when they apply. Read this when it does.

## Composition leads

When the lead asks for a correlation across primitives — *was X followed by
Y?*, *who was logged in when Z happened?*, *did the auth session spawn
unusual processes?* — run the existing primitive templates that measure each
side, and **summarize the join in the return**. Do not mint a "bridge"
template that pretends the correlation is itself a primitive measurement.

Example: "did anyone modify /etc/passwd on host-7 in the last 24h, and who
was logged in then?" → run a `file-integrity-changes` template (filtered to
`/etc/passwd`, host `host-7`, 24h window) on the file-integrity system and a
`user-sessions` template on the host system, then summarize: which mtime,
which sessions overlap.

## Ad-hoc leads

This is **methodology, not bookkeeping** — how to search when no template
fits. You don't author anything; you find the query that answers the lead,
then run it under a coined `{system}.{kebab-name}` id (§2). The offline
lead-author turns that execution record into a draft and decides whether to
keep it.

1. Read `{defender_dir}/skills/{system}/SKILL.md` (and `{system}/execution.md`
   if present) for the CLI's query surface and field vocabulary.
2. Compose the narrowest query that answers the lead, run it (captured
   automatically), and read the result.
3. If it's empty/wrong-shaped, iterate (widen the window, drop a clause, try
   a sibling field — the same moves as the §3.5 validity check) until it
   answers the lead.
4. Run the final measurement as a standalone adapter call:

```bash
defender-{system} <query invocation> --raw
```

The harness records it as `{system}.{verb}` — pick a descriptive adapter
subcommand where the CLI allows it. A genuinely unnameable one-off probe
(e.g. "does this index have any rows at all?") still gets recorded for the
audit trail but isn't a catalog candidate.
