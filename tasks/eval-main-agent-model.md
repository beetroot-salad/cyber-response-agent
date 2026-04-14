---
title: Main-agent baseline cost lever: --model flag in eval_run.sh
status: backlog
group: evaluation
---

eval_run.sh does not pass --model to claude, so the main investigation loop runs at whatever the harness default is (observed: claude-opus-4-6[1m]).

Sub-tasks:
- Add --model sonnet to the claude invocation in playground/scripts/eval_run.sh
- Run a matched eval pair (same alert, Opus vs Sonnet) and compare: disposition correctness, tool-call count, loop count, cost, wall clock
- If Sonnet is comparable on quality, promote it to the default. Document the finding in .claude/skills/evaluate/SKILL.md quirks.
