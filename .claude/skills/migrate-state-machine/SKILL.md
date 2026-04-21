---
name: migrate-state-machine
description: Drive the migration of the investigate loop from a main-agent-driven skill prompt to a Python state-machine orchestrator (scripts/orchestrate.py) that dispatches one subagent per phase. Tracks migration goals, the per-phase playbook, and which phases have been cut over. Project-level dev skill — not part of the production soc-agent plugin.
argument-hint: "[status | next | plan <phase> | cutover <phase>]"
---

# State Machine Migration

Replace the LLM-driven investigation loop in `soc-agent/skills/investigate/SKILL.md`
with a Python orchestrator that owns phase transitions and dispatches a dedicated
subagent per phase. The orchestrator already exists as a skeleton at
`soc-agent/scripts/orchestrate.py` with stub handlers covered by
`soc-agent/tests/test_orchestrate.py`. Migration is **one phase at a time** —
each cutover replaces the skill's inline prompt for that phase with a
`claude --print` call wrapped in a `PhaseHandler`.

---

## Goals

1. **Move control flow out of the model.** The main agent currently reads
   `SKILL.md`, interprets the loop, and decides transitions. That reasoning is
   load-bearing but not load-varying — a state machine enforces it deterministically
   and frees context for actual investigation work.
2. **One subagent per phase.** Each phase already has (or will get) a dedicated
   subagent under `soc-agent/agents/`. After migration, the orchestrator is the
   only thing that spans phases; no single LLM context holds the whole loop.
3. **Structured handoff between phases.** `PhaseResult.payload` is the
   inter-phase contract. Each phase's output is a typed blob consumed by the
   next phase's handler, not re-read from `investigation.md` by the model.
4. **Preserve all hook-enforced safety.** The validator, state inference,
   CONCLUDE judges, budget enforcer, and audit hooks all continue to fire on
   subagent tool calls. Moving orchestration to Python must not regress any
   existing guarantee.
5. **Observable, testable per-phase behavior.** Every cutover lands with unit
   tests that stub the subagent call so the orchestrator path can be exercised
   without spending tokens, plus an end-to-end fixture run to confirm the real
   subagent still produces valid invlang.

Non-goals:
- Changing the invlang schema, archetype model, or any phase's semantics.
- Removing `investigation.md` — it remains the canonical audit artifact. The
  orchestrator just stops being the thing that writes it; subagents do.
- Replacing hook-based validation with Python checks inside the orchestrator.

---

## Architecture at a glance

```
/investigate $signature_id $alert_json
        │
        ▼
scripts/orchestrate.py:run(ctx, handlers)
        │
        ├── CONTEXTUALIZE → handler → claude --print agents/archetype-scan,ticket-context
        ├── SCREEN        → handler → claude --print agents/screen
        ├── HYPOTHESIZE   → handler → claude --print agents/hypothesize
        ├── GATHER        → handler → claude --print agents/gather | gather-composite
        ├── ANALYZE       → handler → claude --print agents/analyze
        └── CONCLUDE      → handler → claude --print agents/conclude
```

The orchestrator owns: phase transitions, `state.json` persistence, loop cap,
illegal-transition rejection, per-phase payload stashing, forced-CONCLUDE on
budget exhaustion. Handlers own: subagent invocation, prompt assembly, parsing
the subagent's output into the next-phase payload.

---

## Current state

**Orchestrator skeleton:** landed (`scripts/orchestrate.py` + tests). Handles
transitions, persistence, loop cap, error modes. Shared subagent wrapper at
`scripts/handlers/_subagent.py` dispatches plugin subagents via
`claude -p --system-prompt-file` (the `--agent` CLI flag doesn't route plugin
subagents). `scripts/handlers/__init__.py` exposes `default_handlers()`;
unwired phases loud-fail.

**Phase cutover status:**

| Phase          | Status   | Handler file | Subagent | Notes |
|----------------|----------|--------------|----------|-------|
| CONTEXTUALIZE  | done     | scripts/handlers/contextualize.py | archetype-scan, ticket-context, contextualize-prologue | PR #99. Handler fans out 3 Haiku subagents in parallel, composes section markdown, validates invlang via library import, routes to CONCLUDE/SCREEN/HYPOTHESIZE. Live e2e on rule-5710 passed. Follow-up: second-shape live run + SKILL.md prose removal (deferred until all phases migrated) |
| SCREEN         | done     | scripts/handlers/screen.py | screen.md, screen-invlang.md | PR #TBD. Two-subagent design: `screen` runs pattern match + leads; new Haiku `screen-invlang` transcribes to the invlang `gather:` block. Handler adds Python structural verifier (matched_pattern names a Screen row AND every lead in the row's Leads column appears in `leads_run` with a non-null observation) — downgrades malformed match claims to error. Empty-Screen short-circuit bypasses both subagents. `screen.md` tightened so classification + anchor lookups count as runs and every lead in the row's Leads column gets a `leads_run` entry. 31 unit tests + live e2e on rule-5710 (nagios/172.22.0.10 → monitoring-probe match). Path D (declarative lead-output frontmatter) filed as `tasks/declarative-lead-invlang-frontmatter.md` for long-term replacement of `screen-invlang` |
| HYPOTHESIZE    | pending  | —            | hypothesize.md | |
| GATHER         | pending  | —            | gather.md / gather-composite.md | Handler chooses single vs. composite |
| ANALYZE        | pending  | —            | analyze.md | Contract decision pending — see `analyze-pilot` skill |
| CONCLUDE       | done     | scripts/handlers/conclude.py | conclude.md | PR #99. Handler onto shared `_subagent` wrapper, 15 unit tests; `Context.ticket_id` + `Context.forced_conclude` first-class dataclass fields; orchestrator dispatches registered CONCLUDE handler before returning summary. Follow-up: live e2e run (deferred to next cutover) |

Update this table after each cutover. `status` values: `pending`, `doing`,
`done`, `deferred`.

---

## Per-phase cutover playbook

Each phase migration follows the same shape. Work through it sequentially —
skipping the tests or the fixture run has bitten us before.

1. **Confirm the subagent is production-ready.** Read the `agents/{phase}.md`
   file. Check it declares its own input contract (what the handler must pass
   in the prompt) and its output shape (what the handler must parse out).
   Most subagents emit a YAML block extracted by `extract_subagent_yaml.py`.
2. **Design the handler I/O.** What does `ctx.outputs[prev_phase]` look like
   for this handler's input? What `payload` does it emit for the next phase?
   Write these down in the handler's docstring before coding.
3. **Write the handler.** Create `soc-agent/scripts/handlers/{phase}.py`.
   Handler shape:
   ```python
   def handle(ctx: Context) -> PhaseResult:
       prompt = _assemble_prompt(ctx)
       raw = _invoke_subagent(prompt)  # claude --print wrapper
       payload = _parse_output(raw)
       next_phase = _route(payload, ctx)
       return PhaseResult(next_phase=next_phase, payload=payload)
   ```
4. **Unit-test the handler with a mocked subagent.** Tests patch
   `_invoke_subagent` to return canned output. Verify: prompt assembly uses the
   right context items, parsing handles well-formed + malformed output,
   routing picks the right next phase for each output shape.
5. **Wire the handler into the default handler map.** Add an entry to
   `scripts/handlers/__init__.py` (exposes `default_handlers()`). The investigate
   skill will eventually call `run(ctx, default_handlers())`.
6. **End-to-end fixture run.** Use `/testrun` against one real alert for the
   signature. Confirm:
   - `investigation.md` still validates against invlang.
   - `state.json` history matches expected phase order.
   - No hook regressions (check `runs/{run_id}/` logs for validator failures).
   - Token usage comparable or lower than pre-cutover.
7. **Remove the phase's prose from `skills/investigate/SKILL.md`.** Once the
   handler is live, the skill no longer needs instructions for that phase.
   Replace with a one-line pointer: "PHASE X is handled by the orchestrator;
   see `scripts/handlers/{phase}.py`."
8. **Update this skill's status table** and commit.

### Pilot phase: SCREEN

SCREEN is the smallest surface (boolean match + optional early CONCLUDE) and
already has a clean subagent boundary (`agents/screen.md`). Cut it over first
to shake out the handler pattern, the `claude --print` wrapper, and the
parsing conventions before taking on HYPOTHESIZE/GATHER/ANALYZE.

---

## Key risks to watch

- **Subagent context ≠ handler context.** The handler runs in Python; the
  subagent runs in its own Claude context. Anything the subagent needs must
  be in the prompt string. It is easy to pass `ctx` into the handler, look at
  a field, and forget to serialize it into the prompt.
- **Invlang writes are the subagent's job.** The handler must not write to
  `investigation.md` directly — the validator hook fires on the subagent's
  writes and we want those signals. Handler's job is to drive, not to write.
- **Composite phases.** CONTEXTUALIZE and GATHER can dispatch multiple
  subagents. The handler orchestrates them (parallel or sequential) and
  composes their outputs into a single payload. Don't be tempted to split
  one phase into two orchestrator states just because it fans out — the state
  machine stays aligned with the invlang phases.
- **Loop cap vs. subagent loops.** `MAX_LOOPS` counts HYPOTHESIZE + ANALYZE
  entries. A handler that internally retries a subagent does NOT count as an
  extra loop. Keep retry logic inside the handler.
- **Forced CONCLUDE reachability.** If a phase's transition set doesn't
  include CONCLUDE, the orchestrator raises on cap-hit (see orchestrate.py
  lines 99-111). HYPOTHESIZE has this property today — handlers that route
  into HYPOTHESIZE near the cap should consider routing to ANALYZE/CONCLUDE
  directly instead.

---

## Argument handling

- **`status`** (default) — print the cutover status table and list the next
  phase to migrate.
- **`next`** — recommend the next concrete action (usually "run the pilot
  SCREEN cutover" or "write handler for phase X").
- **`plan <phase>`** — walk the per-phase playbook for a specific phase,
  filling in the I/O shapes from that phase's subagent file.
- **`cutover <phase>`** — guide a live cutover: confirm preconditions, draft
  the handler, add tests, wire into the default map, run fixture, update
  status. Ask for confirmation before replacing skill prose.

If the arg is unclear, default to `status`.

---

## Key files

- `soc-agent/scripts/orchestrate.py` — the state machine.
- `soc-agent/schemas/state.py` — `Phase`, `TRANSITIONS`, `MAX_LOOPS`,
  `validate_transition`, `count_loops`.
- `soc-agent/tests/test_orchestrate.py` — orchestrator contract tests.
- `soc-agent/agents/*.md` — per-phase subagent definitions.
- `soc-agent/skills/investigate/SKILL.md` — the skill being migrated out.
- `soc-agent/hooks/scripts/extract_subagent_yaml.py` — the hook that parses
  subagent output into invlang; handlers must produce output compatible with
  this extractor or opt out of it.
