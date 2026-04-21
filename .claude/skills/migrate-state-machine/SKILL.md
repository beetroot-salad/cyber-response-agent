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
| SCREEN         | done     | scripts/handlers/screen.py | screen.md (merged) | PR #TBD. **Merged** (post-#101 optimization pass): one Sonnet `screen` subagent emits a single terminal YAML carrying both the pattern-match verdict AND the invlang `gather:` block — replaces the prior Haiku `screen` + Haiku `screen-invlang` split. Handler: prologue inlined in the prompt; structural verifier (matched_pattern names a Screen row + every lead in that row's Leads column appears in `leads_run` with non-null observation) runs after parse and drops the gather block on downgrade. Empty-Screen short-circuit bypasses the subagent. 30 unit tests green. `agents/screen-invlang.md` deleted. |
| CONCLUDE (screen fast-path) | done | scripts/handlers/conclude.py | — (mechanical) | PR #TBD. When SCREEN payload has `screen_result: match` + `matched_archetype` + `gather`, the CONCLUDE handler composes investigation.md `## CONCLUDE` + `conclude:` YAML and report.md (frontmatter + sections) entirely in Python. No subagent spawn. `validate_tier1(report_path)` runs as a library check post-write; Tier 2 Haiku judge is skipped (mechanical output doesn't drift). Subagent path still used for analyze-routed / forced-exhaustion / SCREEN-match without gather. Payload carries `compose_mode: "screen_mechanical" \| "subagent"` for telemetry. |
| HYPOTHESIZE    | done     | scripts/handlers/hypothesize.py | hypothesize.md | Handler dispatches Sonnet `hypothesize` subagent; detects block type (`hypothesize:` fork / `gather:` no-fork / `error:`); validates terminal trailer `{mode, selected_lead, loop_n}`; runs `validate_companion()` as library check; single retry with `resume_from_checkpoint=true` + validator errors passed as `remediation_notes`; always routes to GATHER. Subagent prompt gained checkpoint discipline (4 invlang-field milestones), terminal-trailer spec, and two §Discipline inserts targeting compound predictions + subsequent-event-as-peer anti-pattern. Validator rules 26 (compound-claim regex), 27 (evaluation-prefix regex on classification/name), 28 (leanness ≤2) landed alongside. Deferred: sibling-pair embedding-distance check (1/28 corpus rate doesn't pay for infra); `refutes_predictions: [pN]` schema extension (100% missing; needs migration plan). 26 handler unit tests + 30 validator-rule tests, error-analysis report at `docs/experiments/hypothesize-error-analysis.md`. |
| GATHER         | done     | scripts/handlers/gather.py | gather.md / gather-composite.md | PR #TBD. Handler stats vendor-template presence to choose single (Haiku) vs composite ad-hoc (Sonnet). Scope fields (vendor, reporting_agent, incident_start/end, entity_bindings) derived mechanically from alert + lead-template frontmatter — HYPOTHESIZE payload only carries `selected_lead` + `loop_n`. Escalate-trigger enum re-dispatches `gather-composite` in `redispatch` mode. Silent-termination recovery via `subagent_checkpoints/` (transcribe if `status: complete`, else resume). Always routes to ANALYZE — GATHER→HYPOTHESIZE edge stays in orchestrator transition table (for `test_gather_to_hypothesize_reentry`) but no handler path takes it; ANALYZE owns rollup-driven re-entry. 28 unit tests green, full non-llm suite (1106) green. |
| ANALYZE        | doing    | —            | analyze.md | Design landed (see §ANALYZE design below). Stress-tested (9/9 clean on rollup-drift, archetype-forcing, legitimacy-gate — `docs/experiments/analyze-subagent-pilot/stress-test/findings.md`). Validator rules 24–25 added to spec (v2.9) but not yet implemented. Subagent prompt alignment pending: analyze.md needs terminal-YAML trailer + invlang `conclude:` block emission + rule 24/25 semantics |
| CONCLUDE       | done     | scripts/handlers/conclude.py | conclude.md | PR #99. Handler onto shared `_subagent` wrapper, 15 unit tests; `Context.ticket_id` + `Context.forced_conclude` first-class dataclass fields; orchestrator dispatches registered CONCLUDE handler before returning summary. Subagent path covers analyze-routed + forced-exhaustion; SCREEN-match path now mechanical — see `CONCLUDE (screen fast-path)` row. |

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

## ANALYZE design (landed)

This section captures the design decisions for the ANALYZE cutover. Nothing
here is implemented yet; it's the plan the handler + prompt alignment work
must match.

### Phase-role split: ANALYZE owns termination, CONCLUDE is render-only

The state-machine migration makes an **implicit role re-split explicit**:

- **CONCLUDE's only job is writing `report.md`** from an already-terminal
  `investigation.md`. It does not decide when to stop, does not verify
  archetype disqualifiers, does not gate on legitimacy — by the time
  CONCLUDE runs, all of that is settled.
- **ANALYZE owns termination.** When ANALYZE routes to CONCLUDE, it must
  have produced an `investigation.md` that is **terminal-valid**: the
  `conclude:` block is complete (`termination.category`, `disposition`,
  `confidence`, `matched_archetype`, `trace`), every live-weight
  hypothesis's `legitimacy_contract` is either resolved or the escalation
  rationale justifies its unresolved state, and the `matched_archetype`
  claim has been self-verified against disqualifiers.

Consequence: the `validate_conclude.py` Haiku judges (A/B) currently fire
PreToolUse on CONCLUDE writes; conceptually they want to fire at the
**ANALYZE→CONCLUDE boundary** instead, because by CONCLUDE-write time the
contradictions they would catch are already committed upstream. Move is
filed as a follow-up task; not required for the cutover itself.

### Three-phase co-ownership of `gather[]` lead blocks

Each lead's invlang block has three writers across the loop:

- **HYPOTHESIZE** writes the skeleton: `id`, `mechanism_being_tested`,
  `predictions[]` (each with `id`, `if`, `read_as`, `advance_to`),
  `refutation_shape[]`, `new_hypotheses[]`.
- **GATHER** writes `outcome.observations`, `outcome.anomalies`,
  `trust_anchor_result`.
- **ANALYZE** writes `resolutions[]` (per-hypothesis grade updates with
  `matched_prediction_ids` / `matched_refutation_ids` citations), the
  terminal `conclude:` block when routing to CONCLUDE, and the routing
  decision itself.

First cutover keeps writer ownership clean: each subagent writes its own
section. If transient validator-invariant issues emerge at shared-block
boundaries, the tension point will surface and we can decide composition
ownership then (candidate: ANALYZE handler composes the full block from
GATHER + ANALYZE payloads in Python). Not preemptively split.

### Validator rules 24–25 (spec v2.9)

Two net-new rules added to `docs/investigation-language.md` to absorb
failure modes mechanically:

- **Rule 24 — Hypothesis persistence at CONCLUDE.** Every declared
  hypothesis must either reach final weight `--` or be cited in
  `conclude` (as the termination target, the matched archetype's
  mechanism, or a surviving-but-indeterminate hypothesis driving
  escalation). Closes silent-drop.
- **Rule 25 — Same-level sibling rollup (`matched_prediction_ids`).**
  Prediction IDs cited on a resolution for hypothesis H must be H's own
  declared predictions. Rule 5 already covers this for
  `matched_refutation_ids` on `--`; rule 25 closes the equivalent loophole
  for `matched_prediction_ids` on every weight.

Both rules need Python implementation in `hooks/scripts/invlang_validate.py`
and corresponding tests in `tests/test_invlang_validate.py`. Cost: small
(~40 LOC + tests each).

### Prompt alignment in `agents/analyze.md`

The subagent prompt must land two changes:

1. **Terminal YAML trailer**, matching the CONCLUDE subagent's pattern. The
   handler parses this deterministically to extract `next_action`,
   `disposition`, `confidence`, `matched_archetype`. Today `analyze.md`
   emits only Markdown; the handler cannot robustly parse routing from
   prose.
2. **Rule 24 / 25 semantics**, explicit. Current prompt says "no rollup
   across hypotheses" in prose; rewrite to reference the validator rules
   so failures surface as prompt instructions, not as mysterious blocks.
   Also: add hypothesis-persistence discipline — if a prior hypothesis is
   not addressed in the current resolution set, explain in the ANALYZE
   block why (not a silent omission).

### Stress-test baseline

Three targeted fixtures, 3 trials each, against the current
`agents/analyze.md`:

- **Rollup drift** (`?benign-automation` primed to upgrade on evidence
  ambiguous toward `?brute-force`): 3/3 clean. Sibling rollup did not
  occur; HYPOTHESIZE routing on unresolved legitimacy contract held in
  every trial.
- **Archetype disqualifier** (monitoring-probe with T+18s 5501 success):
  3/3 clean. `r3` (the pre-registered disqualifier) was named in every
  trial; no forced `matched_archetype: monitoring-probe` claim.
- **Legitimacy-gate bypass** (++ mechanism with unresolved contracts +
  22 prior benign precedents): 3/3 clean. HYPOTHESIZE in every trial;
  authority leads named precisely; precedent did not override
  per-instance authority.

Full findings: `docs/experiments/analyze-subagent-pilot/stress-test/findings.md`.
Caveats: N=3 per fixture, all 2-loop, stacked-circumstantial `++` (Example
2 trap) not covered. Those are the residual risk surface.

### Post-cutover: sensitivity probe (optional, deferred)

For the stacked-`++` residual risk not caught by validator rules: an
evidence-level counterfactual probe. Haiku reads ANALYZE output, picks the
highest-grade hypothesis, perturbs one observation, asks Sonnet to re-grade.
If the grade flips on minor perturbation, the `++` was brittle. Scope is
evidence perturbation only (never hypothesis generation — that's
HYPOTHESIZE's job). Single round, output into Self-report.

Not part of the initial cutover. Add only if post-merge observation
surfaces the failure mode.

### Information-preservation reversibility (eval, not runtime)

The reversibility test — can a cold reader reconstruct which observations
drove each grade from the ANALYZE block alone? — is an eval property, not a
runtime gate. Use it to sample N production ANALYZE outputs during the
post-cutover observation window; failures are prompt-clarity bugs to fix.

### Cutover sequencing

1. Implement validator rules 24 + 25 (~2 hours with tests).
2. Align `agents/analyze.md` prompt: terminal YAML trailer + rule 24/25
   language + invlang `conclude:` block emission contract.
3. Write `scripts/handlers/analyze.py` — handler parses terminal YAML,
   routes HYPOTHESIZE vs. CONCLUDE on `next_action`, passes payload to
   CONCLUDE handler (which becomes near-trivial: pre-determined verdict
   → report.md).
4. Unit-test handler with mocked subagent on routing paths (HYPOTHESIZE,
   CONCLUDE with each disposition).
5. Live e2e via `/testrun`. Verify invlang remains valid, state history
   matches, hook regressions zero.
6. Remove ANALYZE prose from `skills/investigate/SKILL.md`.

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
