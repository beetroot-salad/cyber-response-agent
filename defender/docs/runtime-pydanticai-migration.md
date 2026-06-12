# Runtime migration: `claude -p` → PydanticAI

**Status: design draft (2026-06-12). Spike not yet started.**

This is the high-level shape of the runtime change. The decision and its
cost evidence are recorded in the session memory
(`project_defender_runtime_pydanticai`); this doc is the engineering plan
the migration executes against. When this doc and the code disagree once
the migration lands, the code wins.

## Why

The runtime loop (`run.py` → `claude -p` → `SKILL.md`) is dominated by
carried-context I/O, not generation. Across 82 runtime runs:

- cache-write **47.7%** + cache-read **51.5%** = ~99% of cost
- output + thinking only **0.7%**

The loop re-sends the full transcript every turn — raw gather payloads,
predict/analyze scratch, tool chatter — and live context peaks at
**120–160K tokens**. But the investigation's *load-bearing* state is the
invlang frontier the agent already writes to `investigation.md`, which
sits at only **~7–9K tokens**. We are paying to re-read 120K when 8K
carries the belief state forward.

`claude -p` can't fix this: the Claude Code engine owns the transcript and
it is append-only — there is no caller hook to *replace* prior turns with
their compacted form. The Claude Agent SDK has the same limitation
(confirmed via docs). Deterministic per-loop compaction therefore forces
us to **own the message list**, which is what PydanticAI gives us.

Modeled saving from per-loop frontier compaction: **~45–60%** (sampled
51–64% on real runs). A separate, independent lever — raising the cache
TTL from 5 min to 1 h to kill churn-driven cache-writes — is also unlocked
by owning the API call.

## The headline mechanism: per-loop invlang compaction

The agent already produces, every loop, a compacted view of its own
reasoning: the invlang blocks in `investigation.md`
(`:V/:E/:H/:L/:R/:T`, the `++/+/-/--` assessment vocabulary). Today that
compaction is *write-only* — it lands on disk but the model keeps dragging
the raw form through context.

Owning the message list lets us close that loop:

```
loop N:
  run agent for one ORIENT/PLAN/GATHER/ANALYZE step
  → produces raw tool calls, gather payloads, thinking
  → agent commits the distilled belief movement to investigation.md (invlang)

before loop N+1:
  rewrite message_history:
    keep   — system prompt, alert.json, the invlang frontier (current
             investigation.md), the active task framing
    drop   — raw gather payloads, superseded predict/analyze turns,
             tool-result chatter from resolved leads
  reseed agent.run(..., message_history=compacted)
```

The frontier is *deterministic* (it's the file the agent wrote, not an
LLM re-summary), so compaction adds no model call and can't hallucinate
state. Raw payloads remain on disk (`gather_raw/{lead_id}/{seq}.json`) and
can be re-read by-ref if a later loop needs them — exactly the existing
by-ref contract.

PydanticAI surfaces this as caller-supplied `message_history` on each
`Agent.run()` plus a `before_model_request` hook — wrapped as
`capabilities=[ProcessHistory(fn)]` — that rewrites the message list
before every model request. The loop, not the engine, decides what
survives into the next turn. (The legacy `Agent(history_processors=[fn])`
kwarg is deprecated in 1.x and remapped onto `ProcessHistory`; use the
capability.) Crucially this is the *same* primitive as the
context-injection hook below — compaction and injection are one mechanism.

## Component mapping

| `claude -p` harness | PydanticAI target |
|---|---|
| `claude -p` subprocess (engine owns transcript) | `Agent.run()` / `Agent.iter()` with caller-owned `message_history` |
| `SKILL.md` read at runtime | `Agent` system prompt / `instructions` (SKILL body → static instructions; the per-run `build_prompt` context → first user message) |
| Task-tool gather subagent (Haiku) | nested PydanticAI `Agent` (own model = Haiku, own message list) invoked from a `gather` tool on the main agent |
| Adapter CLIs (`defender-elastic`, identity, cmdb…) | MCP servers (stdio) exposing the same verbs; attached via `MCPServerStdio` |
| stream-json `tool_trace.jsonl` | PydanticAI run messages → serialize to the same `tool_trace.jsonl` shape (keep the renderer unchanged) |
| `--model` / `--effort` flags | `AnthropicModel` + `AnthropicModelSettings` (thinking budget) |
| 5-min implicit cache | explicit `CachePoint()` after the stable preamble + `anthropic_cache_instructions` / `_tool_definitions`, 1 h TTL |

## Tools, schema, and Claude Code compatibility

**We define the tools; the protocol is open, the Claude Code tool *set* is
not.** Two layers, don't conflate them:

- The **Anthropic tool-use protocol is fully open** and is what PydanticAI
  speaks — any JSON-schema tool, the model emits `tool_use`, we execute.
  So any Claude Code *capability* (Bash, Read, Write, Grep, Task…) is
  reproducible. But the CC tool *set itself lives in the CC client*, not
  the API — there is no turnkey import. We re-implement only the tools we
  want.
- Anthropic also ships **server-defined tools** with fixed published
  schemas the model is post-trained on (`bash_20250124`, `text_editor_*`,
  web_search, code_execution, memory). PydanticAI 1.107's `native_tools`
  wraps WebSearch / WebFetch / CodeExecution / Memory / FileSearch / MCP —
  **no `bash` / `text_editor` wrapper** (verified). To get those exact
  schemas you pass a raw tool dict to the Anthropic model; otherwise define
  ordinary function tools.

**For defender this is a feature, not a burden.** We deliberately do *not*
want the main loop holding a generic Bash/Read/Write surface — that surface
is exactly what `block_main_loop_raw_access` exists to deny. A narrow tool
set (`write_investigation`, `write_report`, `gather`, `lessons`) *is* the
security boundary, which is why the access-denial hooks dissolve (below).
We'd only reach for the native `bash`/`text_editor` schema inside the
gather subagent if it runs raw shell — and even there MCP adapters are
preferred over raw bash.

## Native primitives: hook / skill / subagent

The three primitives the runtime needs all exist first-class in PydanticAI
1.107 (imports verified), so we build no new abstractions:

- **hook** — *control tool calls + inject context, transparent to the
  agent and deterministic.* → `capabilities=[Hooks(...)]`. The surface is a
  **superset of CC's Pre/PostToolUse**: `before_tool_execute` /
  `after_tool_execute` (intercept a call by name, mutate args, or deny),
  `before_model_request` (rewrite the whole request / inject context /
  short-circuit the model call), plus `tool_validate`, `event`, and
  run/node hooks. All run as deterministic Python and are invisible to the
  model (it sees only resulting messages). `RunContext.enqueue(...)` injects
  content mid-run with `asap` (steer in-flight) / `when_idle` (follow-up)
  priority.
- **skill** — *index → full-content files.* → `Capability(id=...,
  defer_loading=True)` + the framework `load_capability` tool: the model
  sees a compact catalog of capability ids + descriptions and pulls the
  full instructions/tools on demand. Framework-managed, cache-aware, and
  reconstructed from history on replay — a cleaner replacement for today's
  grep-frontmatter-then-Read lessons retrieval. (Use tool search /
  `search_tools` instead for a large *flat* tool catalog with no shared
  instructions.)
- **subagent** — *spawn other agents.* → agent delegation: a `@parent.tool`
  does `await gather_agent.run(..., usage=ctx.usage)`. Each subagent owns
  its own message list (which is what makes per-subagent compaction
  possible) and usage aggregates through `ctx.usage`. The Haiku gather
  subagent maps directly; no bash escape hatch needed.

## Hooks → re-homing

The 9 Pre/PostToolUse hooks are Claude-Code-specific. Owning the call
means re-homing each onto the `Hooks` capability above (or dissolving it
into the tool surface). None are lost; they move from "shell command the
engine fires" to "Python the loop runs".

| Hook (event) | Today | PydanticAI home |
|---|---|---|
| `record_lead.py` (PreToolUse Task) | parse gather dispatch YAML → leads table + `O_EXCL` id claim | inside the `gather` tool wrapper, before dispatch (keep the atomic-claim integrity gate) |
| `inject_system_skill_description.py` (PreToolUse Task) | append target system SKILL description to dispatch | `gather` tool builds the dispatch prompt; injection is just prompt assembly |
| `record_query.py` (gather capture wrapper) | execute query → queries table + by-ref payload | wrap the MCP adapter call in the gather agent's tool layer |
| `block_main_loop_raw_access.py` (PreToolUse Bash/Read) | deny main loop running CLIs / reading gather_raw | **structural**: main agent simply has no adapter tools and no raw-read tool. Enforced by tool surface, not a gate |
| `block_unwrapped_adapter_calls.py` (PreToolUse Bash) | force adapter calls through record-query | adapter access only via the capturing tool — same structural answer |
| `approve_shim_invocations.py` (PreToolUse) | auto-approve safe shims | N/A — no permission prompts when we own the loop |
| `invlang_validate.py` (PreToolUse Write/Edit) | block non-conforming `investigation.md` writes (exit 2) | `before_tool_validate` on `write_investigation`, or raise `ModelRetry` from the tool → model retries with the validator error |
| `tag_tool_results.py` (PostToolUse) | salted untrusted-data wrapping of tool output | `after_tool_execute` hook (or `ProcessHistory`) wrapping gather + MCP results before they enter context |
| `budget_enforcer.py` (PostToolUse) | per-run tool/spawn/wall-clock budget (warn) | `before_model_request` / node hook with a per-run counter (or `usage_limits` for a hard cap) |
| `record_lesson_load.py` (PostToolUse Read) | log lessons read into context | the `lessons` retrieval tool records loads itself |

Two themes: the *integrity-gate* hooks (`record_lead`, `record_query`,
`invlang_validate`) become tool wrappers / validators that keep their
guarantees; the *access-denial* hooks
(`block_main_loop_raw_access`, `block_unwrapped_adapter_calls`,
`approve_shim_invocations`) largely **dissolve** — when we choose the main
agent's tool surface, "the main loop can't touch raw adapters" stops being
a thing we police and becomes a thing that's simply absent.

## What does NOT change

- **Artifacts & the run-dir layout** — `investigation.md`, `report.md`,
  the two append-only tables (`executed_queries.jsonl` + `gather_raw/`),
  `tool_trace.jsonl`, `transcript.html`. The compaction operates on the
  *in-context* message list, not on disk.
- **The two-table contract** and `lead_repository.py` as the single
  read/join surface.
- **The learning loop** — it's SIEM-free, off-process, and reads the same
  run-dir artifacts. It is downstream of the runtime and untouched.
- **The invlang spec** (`skills/invlang/`) and its validator. It becomes
  *more* load-bearing (it's now the compaction frontier), so its
  structural guarantees matter more, not less.
- **The loop's mental model** — ORIENT → PLAN → GATHER → ANALYZE →
  REPORT. We're changing the engine under the loop, not the loop's shape.

## Migration path

**Reach parity *before* compaction.** Compaction is the payoff, but it's
also the part most likely to silently degrade the investigation. So we
isolate the variable: first stand up the full loop on PydanticAI with the
message history passed through *whole* (no trimming) and prove it produces
the same artifacts as `claude -p`; only then layer compaction on and
measure the saving as a clean A→B delta on the same fixtures. (Per
`feedback_isolate_one_variable_in_experiments` — don't bundle the engine
swap with the compaction change.)

### Phase A — parity (engine swap, no compaction)

1. **MCP adapter servers.** Wrap the existing adapter CLIs as stdio MCP
   servers (elastic first, then identity/cmdb/…). The verbs already exist;
   this is a transport reshape.
2. **Gather as a nested agent.** Port the Haiku gather subagent to a
   nested `Agent` (agent delegation) with the record-lead / record-query
   integrity gates moved into its tool wrappers / `Hooks`.
3. **Main loop + validators.** SKILL → `instructions`; per-system
   references → deferred `Capability` bundles; `invlang_validate` →
   `before_tool_validate` / `ModelRetry`; budget → run-level hook; tag →
   `after_tool_execute`. Pass `message_history` through **unmodified**.
4. **Cut over `run.py`.** Replace `spawn_claude()` with the PydanticAI
   driver; keep `materialize_run_dir`, `cross_check_tables`,
   `enqueue_learning`, `visualize` exactly as-is. Serialize PydanticAI run
   messages into the existing `tool_trace.jsonl` shape so the renderer is
   untouched.
5. **Parity gate.** Run the held-out + gtest fixtures through both engines;
   confirm matching dispositions and well-formed artifacts. This is the
   green light for Phase B — not the token number.

### Phase B — compaction (the measured payoff)

6. **Add `ProcessHistory`.** Rewrite `message_history` before each model
   request: keep system prompt + alert + the invlang frontier
   (`investigation.md`) + active task framing; drop raw gather payloads and
   superseded predict/analyze turns. Apply `CachePoint()` + 1 h TTL after
   the stable preamble.
7. **Measure actual tokens vs. the ~55% model** on the same fixtures as
   Phase A's parity gate — the A→B delta is the real saving. Decision to
   keep compaction rests on this number *and* unchanged dispositions, not
   on the model. (`feedback_verify_load_bearing_assumptions` — confirm the
   lever empirically.)

The `Subagents` port / `LoopPaths` DI seam
(`feedback_defender_loop_di_over_monkeypatch`) already anticipated this:
the learning-loop subagent layer was built as a swappable adapter for
exactly this kind of engine swap. The runtime side gets the same treatment
— the adapter owns all PydanticAI plumbing; orchestration/validators/
artifacts stay engine-agnostic.

## Open questions / risks

- **Compaction boundary correctness.** Dropping a resolved lead's raw
  turns is safe only if the invlang frontier truly carries the belief it
  produced. Phase B must confirm the agent doesn't regress when a dropped
  payload turns out to be needed (mitigated by the by-ref re-read path, but
  worth measuring against the Phase A parity baseline).
- **Tool-surface parity.** The access-denial hooks dissolving is only
  *safe* if the structural tool surface is genuinely tighter than the
  hooks. Audit that nothing the hooks blocked is reachable another way
  (incl. via a deferred `Capability`'s tools once loaded, or the gather
  subagent's MCP surface).
- **Cache accounting.** Bedrock's caching/cost telemetry was a reason to
  stay on the first-party Anthropic API; verify PydanticAI's Anthropic
  cost reporting matches raw API usage during Phase A.
- **`ProcessHistory` + cache interaction.** Rewriting history every request
  changes the cached prefix; the 1 h `CachePoint()` only helps if the kept
  preamble is byte-stable across loops. Confirm compaction doesn't
  inadvertently bust the cache it's meant to exploit.
- **Cost of the rebuild.** No turnkey skills/hooks — this is the accepted
  tradeoff. Keep the surface minimal; don't port hooks that dissolve.

## Dependency

Pinned as an optional group in `defender/pyproject.toml`:

```toml
[project.optional-dependencies]
runtime = ["pydantic-ai-slim[anthropic,mcp]>=1.107"]
```

Slim variant + `anthropic`/`mcp` extras only — no other model providers.
Kept out of core deps so learning-loop / CI installs stay lean. Install
the runtime stack with `uv pip install -e '.[runtime]'`.
