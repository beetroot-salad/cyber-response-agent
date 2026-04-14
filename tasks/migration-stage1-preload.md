---
title: Migration Stage 1: hook-based CONTEXTUALIZE preload (keep Opus main)
status: backlog
groups: sonnet, cost
---

Move ticket-context and precedent-scan subagents out of main-agent dispatch. A new hooks/scripts/contextualize_preload.py runs on SessionStart (or UserPromptSubmit), synchronously spawns two parallel claude --print subprocesses for ticket-context + precedent-scan, collects their results, and injects via additionalContext as "## Ticket Context" / "## Precedent Scan" sections.

Sub-tasks:
- Implement contextualize_preload.py with asyncio.gather or concurrent.futures.ProcessPoolExecutor, timeout handling, structured additionalContext output
- Register on SessionStart or UserPromptSubmit in plugin.json; hook must read alert JSON from alert.json or first user prompt
- Shorten SKILL.md CONTEXTUALIZE section — remove "dispatch these subagents in parallel" directive, replace with "preloaded sections are already in your context; integrate them"
- Keep ticket-context.md and precedent-scan.md subagent prompts (become subprocess input prompts)
- Measure: re-run evals. Expect -30-60s wall clock, -3 main-agent turns, -$0.15 to -$0.25 vs run #9

Side effect: Tier 1's check_ticket_context_spawned guard becomes dead code once hook-driven preload can't be skipped.
