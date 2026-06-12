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
`Agent.run()` plus `history_processors` for the rewrite. The loop, not the
engine, decides what survives into the next turn.

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

## Hooks → re-homing

The 9 Pre/PostToolUse hooks are Claude-Code-specific. Owning the call
means re-homing each as an in-process construct. None are lost; they move
from "shell command the engine fires" to "Python the loop runs".

| Hook (event) | Today | PydanticAI home |
|---|---|---|
| `record_lead.py` (PreToolUse Task) | parse gather dispatch YAML → leads table + `O_EXCL` id claim | inside the `gather` tool wrapper, before dispatch (keep the atomic-claim integrity gate) |
| `inject_system_skill_description.py` (PreToolUse Task) | append target system SKILL description to dispatch | `gather` tool builds the dispatch prompt; injection is just prompt assembly |
| `record_query.py` (gather capture wrapper) | execute query → queries table + by-ref payload | wrap the MCP adapter call in the gather agent's tool layer |
| `block_main_loop_raw_access.py` (PreToolUse Bash/Read) | deny main loop running CLIs / reading gather_raw | **structural**: main agent simply has no adapter tools and no raw-read tool. Enforced by tool surface, not a gate |
| `block_unwrapped_adapter_calls.py` (PreToolUse Bash) | force adapter calls through record-query | adapter access only via the capturing tool — same structural answer |
| `approve_shim_invocations.py` (PreToolUse) | auto-approve safe shims | N/A — no permission prompts when we own the loop |
| `invlang_validate.py` (PreToolUse Write/Edit) | block non-conforming `investigation.md` writes (exit 2) | `output_validator` / tool-result validator on the `write_investigation` tool; re-raise → model retries (PydanticAI `ModelRetry`) |
| `tag_tool_results.py` (PostToolUse) | salted untrusted-data wrapping of tool output | `history_processor` / tool-output processor wrapping gather + MCP results before they enter context |
| `budget_enforcer.py` (PostToolUse) | per-run tool/spawn/wall-clock budget (warn) | loop-level counter around `Agent.iter()` — direct, no hook |
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

1. **Thin spike (next, gated).** One loop of one investigation in
   PydanticAI: gather via the elastic MCP server, emit the invlang
   frontier, reseed the next loop's `message_history` from it, apply
   `CachePoint()` + 1 h TTL after the preamble. **Measure actual tokens
   vs. the ~55% model.** Decision to proceed rests on this number, not the
   model. (See `feedback_verify_load_bearing_assumptions` — confirm the
   lever empirically before the full rewrite.)
2. **MCP adapter servers.** Wrap the existing adapter CLIs as stdio MCP
   servers (elastic first, then identity/cmdb/…). The verbs already exist;
   this is a transport reshape.
3. **Gather as a nested agent.** Port the Haiku gather subagent to a
   nested `Agent` with the record-lead / record-query integrity gates
   moved into its tool wrappers.
4. **Main loop + validators.** SKILL → instructions; `invlang_validate`
   → output validator; budget → loop counter; tag → output processor.
5. **Cut over `run.py`.** Replace `spawn_claude()` with the PydanticAI
   driver; keep `materialize_run_dir`, `cross_check_tables`,
   `enqueue_learning`, `visualize` exactly as-is.

The `Subagents` port / `LoopPaths` DI seam
(`feedback_defender_loop_di_over_monkeypatch`) already anticipated this:
the learning-loop subagent layer was built as a swappable adapter for
exactly this kind of engine swap. The runtime side gets the same treatment
— the adapter owns all PydanticAI plumbing; orchestration/validators/
artifacts stay engine-agnostic.

## Open questions / risks

- **Compaction boundary correctness.** Dropping a resolved lead's raw
  turns is safe only if the invlang frontier truly carries the belief it
  produced. The spike must confirm the agent doesn't regress when a
  dropped payload turns out to be needed (mitigated by the by-ref
  re-read path, but worth measuring).
- **Tool-surface parity.** The access-denial hooks dissolving is only
  *safe* if the structural tool surface is genuinely tighter than the
  hooks. Audit that nothing the hooks blocked is reachable another way.
- **Cache accounting.** Bedrock's caching/cost telemetry was a reason to
  stay on the first-party Anthropic API; verify PydanticAI's Anthropic
  cost reporting matches raw API usage on the spike.
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
