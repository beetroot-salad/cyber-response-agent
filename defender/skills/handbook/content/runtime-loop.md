# Runtime loop

The online investigation. `python3 defender/run.py <alert.json>` spawns
`claude -p` against `defender/SKILL.md`; the agent works through the loop in
a run dir and exits. `run.py` handles everything after (projection,
transcript, learning loop).

`defender/SKILL.md` is the authoritative spec. This file summarizes the
shape; read the SKILL for the exact discipline.

## The loop at a glance

```
ORIENT → PLAN → GATHER → ANALYZE ─┬─→ PLAN  (loop — only when the next move discriminates)
                                  └─→ REPORT
```

The common case is a few iterations of PLAN → GATHER → ANALYZE before
REPORT. Loop back from ANALYZE to PLAN when the next move is genuinely
discriminating; **don't loop to confirm.** Most cases resolve in one or two.

There is **no enforced state machine.** Phase discipline lives in the prompt,
not in a hook — consistent with the defender's learning-loop-first stance
(`content/design.md`). The agent can in principle skip or reorder phases;
when it does, that's signal for the learning loop, not a blocked write.

## Phases

- **ORIENT** — pull the cheap prologue out of the alert (who/what/where/when)
  as `:V`/`:E` blocks; state the triage question — what behavior is flagged
  and what disposition turns on. Enumerate the per-system SKILLs to discover
  what's reachable in this environment.
- **PLAN** — pick the next lead (or small batch). Write a free-form lead
  description (`goal` + `what to characterize`) and predict, in advance, the
  observation shape each competing explanation would produce — relative to
  the entity's baseline. Author `:H` (hypotheses + predictions) and `:L`
  (lead) blocks. PLAN does **not** pick a query template — that's gather's
  job. Read any relevant `lessons/` here before writing blocks.
- **GATHER** — dispatch the gather subagent (Haiku) per lead via `Task`. It
  picks a query template, binds params, runs the CLI through the capture
  wrapper, and returns a tight summary plus the `queries[]` it ran and the
  path to the raw payload. Multiple PLAN leads → parallel `Task` calls in
  one assistant message.
- **ANALYZE** — record what gather's summary showed and grade it against the
  PLAN predictions with `:R` blocks (`++`/`+`/`-`/`--`). Decide whether
  there's enough to disposition; if not, loop back to PLAN.
- **REPORT** — write `report.md`: YAML frontmatter (`case_id`,
  `disposition`, `confidence`) + one paragraph citing the leads that
  resolved it. `disposition` is a closed enum: `benign` | `inconclusive` |
  `malicious`. Stop after that — `run.py` runs the projector and visualizer.

## The gather-dispatch discipline

This is the load-bearing rule of the runtime loop:

- **The only way to query a data source is a `Task` → gather dispatch.** The
  main loop never runs the system CLIs (`scripts/tools/*_cli.py`) itself,
  and never redirects CLI output to a file it then reads — that's the same
  violation, renamed, and it leaves the query out of the audit trail.
- **Trust the return; don't re-derive from raw.** Gather's summary is the
  authoritative record. The main loop does not Read or Grep
  `gather_raw/*.json` to spot-check fields. If the summary is missing
  something, re-dispatch gather with a stricter `what_to_summarize` rather
  than pulling raw into the main context — that's what made the dispatch
  cheap. (ANALYZE may Grep a specific raw payload as a last resort when a
  summary is thin; Read it whole only if Grep doesn't narrow it.)
- **Haiku is the default** for gather because its job is mechanical (pick
  template, bind params, run CLI, summarize); the system CLIs enforce
  structural correctness. Escalate to Sonnet only when a dispatch genuinely
  needs multi-step reasoning — and prefer fixing the SKILL or CLI guardrails
  over routing more dispatches to the heavier model.
- **Absolute paths in the dispatch.** The subagent runs in a
  Claude-Code-managed worktree whose cwd is not under `DEFENDER_DIR`;
  relative paths silently resolve against the wrong tree. Use the absolute
  `DEFENDER_DIR` from the workspace map.

See `defender/skills/gather/SKILL.md` for the subagent's own contract and
`content/run-artifacts.md` for the two-table + by-ref payload shapes.

## Hooks

The defender has **three plumbing hooks** (registered in
`run-settings.json`), all PreToolUse:

| Hook | Matcher | Purpose |
|---|---|---|
| `record_lead.py` | `Task\|Agent` | Parses the gather dispatch YAML and writes the leads-table row `gather_raw/{lead_id}.lead.json` (goal + dimensions), claiming the `lead_id` with an atomic `O_CREAT|O_EXCL` create — a reused id fails the create and the hook exits 2 (an integrity gate, not just a shim) |
| `inject_system_skill_description.py` | `Task\|Agent` | Looks up the dispatch's `system` and appends that per-system SKILL's frontmatter `description:` to the subagent prompt, so gather confirms relevance then reads the full SKILL |
| `block_main_loop_raw_access.py` | `Bash\|Read\|Grep\|Glob` | Enforces the gather-dispatch discipline above — blocks the main loop from running the system CLIs directly or reading `gather_raw` to re-derive fields |

If a write or read is blocked, the fix is to dispatch gather — never to find
another path to the bytes.

## Worked examples

`defender/SKILL.md` carries one inline worked example (Example A — a FIM
checksum change). Two more live under `defender/examples/` and load on
demand: `example-b-parallel-iam-cmdb.md` (parallel registry leads,
indeterminate-authz forcing a second loop) and
`example-c-cumulative-escalation.md` (competing hypotheses where none
reaches `++` but the cumulative pattern justifies escalation).

Sources: `defender/SKILL.md`, `defender/run-settings.json`,
`defender/hooks/`.
