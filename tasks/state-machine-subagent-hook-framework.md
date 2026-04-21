---
title: Pre/post hook framework for subagent wrapper
status: backlog
groups: state-machine-migration, observability
---

Add lightweight Python-callable pre/post hooks around `scripts/handlers/_subagent.invoke_subagent` so we recover the plugin-hook capabilities we lose running subagents outside the Claude Code runtime. Motivated by heavier invlang phases (ANALYZE, CONCLUDE) where budget tracking and audit are load-bearing.

## Design

```python
# scripts/handlers/_subagent.py
PRE_INVOKE_HOOKS: list[Callable[[str, str], str | None]] = []
POST_INVOKE_HOOKS: list[Callable[[str, str, str], None]] = []

def invoke_subagent(agent, prompt, ...):
    for hook in PRE_INVOKE_HOOKS:
        modified = hook(agent, prompt)
        if modified is not None:
            prompt = modified
    # subprocess.run ...
    for hook in POST_INVOKE_HOOKS:
        try:
            hook(agent, prompt, stdout)
        except Exception as exc:
            # Hooks are advisory — log and continue.
            ...
    return stdout
```

- Hooks are plain Python callables, not shell scripts. Faster, testable, no JSON-over-stdin.
- Ordering is explicit (list order). Registration is a plain append.
- Post-hooks are wrapped in try/except so a buggy hook never crashes a handler.

## Hooks to port from plugin.json

Pre-invoke:
- `inject_env_context.py` — currently inlined in `_subagent._inject_env_context`. Move into a registered hook for consistency.
- Future: redaction (strip secrets from prompts), authz guard, per-call budget precheck.

Post-invoke:
- `extract_subagent_yaml.py` — append canonical YAML to a log file under `{run_dir}/subagent_outputs/`.
- `audit_tool_calls.py` — subagent-level accounting, append to `subagent_audit.jsonl`.
- `budget_enforcer.py` — tally tokens per invocation using `--output-format json`'s `usage` field; cap per run.

## What this does NOT cover

Hooks targeting the subagent's *internal* tool use (its Bash/Read calls) — those still fire natively in the subagent's Claude Code runtime session; our wrapper only sees the final stdout. If we need to intercept at that granularity later, the path is `--output-format stream-json --include-hook-events` + a stream parser. Defer until needed.

## When to do this

Not required for CONTEXTUALIZE migration. Pick up before ANALYZE or concurrent with the first heavy invlang phase where per-subagent budget tracking becomes a real concern.

## Risk

Low — hooks are additive, advisory-by-default, and the existing behavior remains the fallback when no hooks register.
