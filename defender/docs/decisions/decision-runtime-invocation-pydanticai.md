# Decision: Defender runtime → PydanticAI

**Status:** Accepted — 2026-06-12
**Scope:** Replace `claude -p` subprocess invocation in the defender runtime.

## Decision

Move the runtime to **PydanticAI on the first-party Anthropic API**, owning the
message list. Tools via **MCP** (the elastic/identity shims), with per-loop
**deterministic invlang compaction** — after each loop completes, replace its raw
predictions / gather results / analysis with the invlang blocks it already
produced, and reseed the next loop's `message_history` from that frontier.

## Why

- **Cost is ~99% carried-context I/O** (measured across 82 runtime runs:
  cache-write 47.7% + cache-read 51.5%; output + thinking only 0.7%).
- **Per-loop frontier compaction modeled at ~45–60% savings** (sample 51–64%).
  Live context peaks at 120–160K tokens; the invlang frontier is ~7–9K. Part of
  the write bucket is 5-minute-TTL churn, so 1h TTL is a separate cheap lever.
- Compaction requires **caller-controlled history pruning**. The **Claude Agent
  SDK cannot** do caller-supplied history replacement — the engine owns the
  transcript and it is append-only (`query()` takes a string; `resume`/`fork`
  only reference an existing session id). Therefore we must own the message list.
- **PydanticAI** gives message-history control + multi-vendor + MCP tools +
  native Logfire observability + Anthropic caching controls (`CachePoint`,
  1h TTL, `anthropic_cache_instructions` / `anthropic_cache_tool_definitions`).
  Production-stable (v1 since Sept 2025; v2 in beta).

## Rejected alternatives

- **Agent SDK / `claude -p`** — no deterministic compaction; per-loop spawns
  multiply engine cold-start.
- **LangChain / LangGraph** — heavy, rebuilds the tool surface anyway, no gain
  over the existing clean Python orchestration.
- **Raw `anthropic`** — viable floor; PydanticAI adds ergonomics, observability,
  and multi-vendor at little lock-in (it wraps the provider SDK thinly).
- **Amazon Bedrock** — model-generation lag, caching features trail the newest
  models, a possible ~32K cached-token cap, and buggy PydanticAI Bedrock cost
  telemetry. (Claude Platform on AWS is the AWS option if governance ever
  requires it — Anthropic-operated, same-day parity.)

## Tradeoff accepted

Rebuild the harness: tools → MCP, hooks (`budget_enforcer` / `record_lead`) →
tool wrappers, SKILL → system prompt. No turnkey skills/hooks.

## Next

Thin spike before committing to full migration — one loop of one investigation:
gather via the elastic MCP, emit the invlang frontier, reseed the next loop's
`message_history`; set `anthropic_cache_instructions='1h'` +
`anthropic_cache_tool_definitions='1h'` + a `CachePoint()` after the preamble;
**measure actual tokens against the ~55% model.**
