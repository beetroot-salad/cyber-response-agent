# Runtime loop

The online investigation. `python3 defender/run.py <alert.json>` runs the
in-process PydanticAI driver against `defender/SKILL.md`; the agent works through
the loop in a run dir and exits. `run.py` handles everything after (projection,
transcript, learning loop).

`defender/SKILL.md` is the authoritative spec. This file summarizes the
shape; read the SKILL for the exact discipline.

## The loop at a glance

```
ORIENT → PLAN → GATHER → ANALYZE ─┬─→ PLAN  (loop — only when the next move discriminates)
                                  └─→ REPORT ── close_investigation ──→ ⟦review gate⟧ ─┬─→ committed
                                                                                        └─→ back to PLAN
```

The common case is a few iterations of PLAN → GATHER → ANALYZE before
REPORT. Loop back from ANALYZE to PLAN when the next move is genuinely
discriminating; **don't loop to confirm.** Most cases resolve in one or two.

There is **no enforced state machine.** Phase discipline lives in the prompt,
not in a hook — consistent with the defender's learning-loop-first stance
(`content/design.md`). The agent can in principle skip or reorder phases;
when it does, that's signal for the learning loop, not a blocked write.

**The review gate is the exception, and it is not a phase.** It is enforced in
code, the investigator never occupies it, and it writes no `##` header into
`investigation.md` — see §The close is gated below.

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
  picks a query template, binds params, calls the typed `query` tool (the
  harness captures the payload), and returns a tight summary plus the `queries[]` it ran and the
  path to the raw payload. Multiple PLAN leads → parallel `Task` calls in
  one assistant message.
- **ANALYZE** — record what gather's summary showed and grade it against the
  PLAN predictions with `:R` blocks (`++`/`+`/`-`/`--`). Decide whether
  there's enough to disposition; if not, loop back to PLAN.
- **REPORT** — call `close_investigation(disposition=…)`. It is the **only**
  writer of `report.md`, which is not in the agent's write scope at all; the
  body is host-rendered from typed arguments, so there is nothing to compose.
  `disposition` is a closed enum: `benign` | `false-positive` |
  `inconclusive` | `malicious`. A confident close then passes the review gate
  (below) before anything is committed. Stop after that — `run.py` runs the
  projector and visualizer.

## The close is gated

`close_investigation` does not commit a **confident** disposition (anything but
`inconclusive`) on the agent's say-so. It runs a live write-time review first —
`runtime/challenge_gate.py`, dispatching into `runtime/review/`.

**Two blind lenses, then a composer.** The lenses read a *projection* of
`investigation.md` with the whole `:T` family (belief movement — resolutions,
weights, hypothesis status) pruned out. They see `:V`/`:E`/`:R`/`:H`/`:L` and
reconstruct what the observations support, so their agreement is independent
rather than an echo of the write-up. The **ablation** is the support lens
re-asked with one load-bearing edge withheld and never told anything was
removed — sensitivity measured by re-asking, not asserted. The **composer** runs
last, sees both readings plus the investigation's own account, and returns one
bit (`holds` | `gap`) plus prose and an optional `ask`.

**The reviewer never picks the outcome.** It reports a finding; the host routes
it, on turn count and raised-ask state no review role can see:

| Gate outcome | What happens | `report.md` |
|---|---|---|
| `stands` | the drafted disposition commits | `outcome: stands` |
| `challenged` | **nothing commits** — the ask comes back as discriminating material and the agent gets another ANALYZE/GATHER turn (`EXTRA_TURN_BOUND = 2`) | not written yet |
| `forced-inconclusive` | a gap with no measurable ask, a repeat ask that bought nothing, or the turn budget spent | `disposition: inconclusive` |
| `forced-inconclusive` + `failure_kind` | **fail closed** — a stage raised, timed out, replied unreadably, or no reviewer was bound | `failure_kind: timeout\|error\|unreadable` |

A challenged close is a **normal part of the loop, not an error.** A committed
close is terminal either way: re-closing is refused.

**What it writes.** `review_record.{turn}.json` per close attempt, plus
`review_{support,ablation,composer}_trace.jsonl` — see
`content/run-artifacts.md`. `runtime.html` renders these as § Review gate.

**Why it is not a phase.** The five phases are prompt-level with no enforced
state machine; this is enforced in code, and the model is never in it. It writes
no `##` header, so nothing in `investigation.md` marks it and the visualizer's
phase machinery (`_LOOP_VERBS`, `phase_color`) deliberately does not know it.

## The gather-dispatch discipline

This is the load-bearing rule of the runtime loop:

- **The only way to query a data source is a `Task` → gather dispatch.** The
  main loop never calls the query tool (the `query(system=…, verb=…)`
  dispatch backed by each system's `VERBS` registry) itself, and never
  redirects a query payload to a file it then reads — that's the same
  violation, renamed, and it leaves the query out of the audit trail.
- **Trust the return; don't re-derive from raw.** Gather's summary is the
  authoritative record. The main loop does not Read or Grep
  `gather_raw/*.json` to spot-check fields. If an obligation came back
  unaddressed, re-dispatch gather naming that obligation more sharply —
  never a field list or a filter, and never by pulling raw into the main
  context; that's what made the dispatch cheap. (ANALYZE may Grep a specific
  raw payload as a last resort when a summary is thin; Read it whole only if
  Grep doesn't narrow it.)
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

## Reliability gates

The runtime is the in-process PydanticAI driver, so these run **in-process**
(the `hooks/` modules supply the logic as libraries — they are no longer wired
as Claude Code PreToolUse hooks):

| Gate | Where | Purpose |
|---|---|---|
| `record_lead.claim_lead` | called in `runtime/tools.py` on gather dispatch | Writes the leads-table row `gather_raw/{lead_id}.lead.json` (goal + dimensions), claiming the `lead_id` with an atomic `O_CREAT|O_EXCL` create — a reused id raises (an integrity gate, not just a shim). Returns `CLAIMED` / `ALREADY_CLAIMED` / `NOT_CLAIMED`, and only `CLAIMED` dispatches: an unclaimed lead has no row for the reuse gate to refuse next time |
| `inject_system_skill_description.descriptor_catalog` | `runtime/tools.py` | Supplies the per-system SKILL `description:` catalog (progressive disclosure) so gather confirms relevance then reads the full SKILL |
| `runtime/permission.py` | called before each tool | Blocks the main loop from running system CLIs directly or reading `gather_raw` to re-derive fields (positive grant enumeration — main carries no `gather_raw` shape); raises `ModelRetry` on a deny |
| `challenge_gate.challenge_gate` | called inside `runtime/close_tool.py` on every **confident** close | The write-time review (§The close is gated). Fails closed: a stage that raises, times out or replies unreadably overrides the disposition to `inconclusive` rather than letting it commit silently |

If a write or read is blocked, the fix is to dispatch gather — never to find
another path to the bytes.

## Worked examples

`defender/SKILL.md` carries one inline worked example (Example A — a FIM
checksum change). Two more live under `defender/examples/` and load on
demand: `example-b-parallel-iam-cmdb.md` (parallel registry leads,
indeterminate-authz forcing a second loop) and
`example-c-cumulative-escalation.md` (competing hypotheses where none
reaches `++` but the cumulative pattern justifies escalation).

Sources: `defender/SKILL.md`, `defender/runtime/` (driver, tools, permission,
close_tool, challenge_gate, review/), `defender/hooks/`.
