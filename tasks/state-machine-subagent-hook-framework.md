---
title: Recover plugin hooks for orchestrator-driven subagents
status: done
groups: state-machine-migration, observability
---

Recover the PreToolUse/PostToolUse hook surface we had in skill-mode now that the state-machine orchestrator invokes subagents via `claude -p`. Two layers: inner (hooks fire inside the subagent session via `--plugin-dir`) and outer (inline helpers around `invoke_subagent`).

## Inner layer — `--plugin-dir` loads plugin hooks wholesale

`claude -p --plugin-dir <path>` loads a plugin for the session, including its hooks. `${CLAUDE_PLUGIN_ROOT}` resolves to the plugin directory so no path surgery is needed. Verified by smoke tests:

- PreToolUse:Write hook registered via `--plugin-dir` exited 2, the write was blocked, `permission_denials` appeared in the result JSON.
- Real orchestrator-spawned subagent running a Bash call produced `tool_audit.jsonl` (from `audit_tool_calls.py`) and incremented `budget.json` (from `budget_enforcer.py`).

Every inner-tool hook in `plugin.json` — `invlang_validate`, `validate_conclude`, `validate_report`, `tag_tool_results`, `audit_tool_calls`, `infer_state`, `infer_state_pre`, `budget_enforcer` — now fires inside orchestrator-driven subagent sessions without modification. `plugin.json` stays the single source of truth; no generated settings file.

Implementation (`scripts/handlers/_subagent.py`):

1. `invoke_subagent` passes `--plugin-dir <SOC_AGENT_ROOT>` on every `claude -p` call.
2. A fresh UUID `--session-id` is generated per invocation and the session → run mapping is written to `{runs_dir}/.sessions/{uuid}.json` **before** the subprocess runs, so inner hooks (`audit_tool_calls`, `budget_enforcer`) resolve `run_dir` via the fast path instead of the racy mtime fallback.
3. `orchestrate.run()` exports `SOC_AGENT_RUN_DIR` and `SOC_AGENT_SIGNATURE_ID` so `_subagent` can discover them without threading `Context` through every handler.

## Outer layer — inline helpers in `invoke_subagent`

The orchestrator controls every subagent call, so there is no need for a registry, callable list, or dataclass context object. Call the helpers directly:

```python
def invoke_subagent(agent, prompt, *, model=None, timeout=...):
    body, frontmatter = _load_agent_definition(agent)
    prompt = _inject_env_context(agent, prompt)
    prompt = _tag_orchestrator_inputs(agent, prompt)   # defense-in-depth for inputs we supply

    result = subprocess.run([...], input=prompt, ...)

    _append_subagent_log(agent, prompt, result.stdout, run_dir)
    _audit_subagent_call(agent, result, run_dir)
    _enforce_run_budget(result.usage, run_dir)         # raises on hard cap

    return result.stdout
```

Add a new list entry here only when a second caller appears. Until then, inline beats indirection.

## What the outer layer owns (that the inner layer cannot)

- **Cross-subagent budget accounting.** Inner `budget_enforcer` sees one session at a time; the orchestrator's `_enforce_run_budget` sums `usage` across every subagent invocation in a run.
- **Terminal YAML logging.** `extract_subagent_yaml`-equivalent appended to `{run_dir}/subagent_outputs/` — the outer layer is the only place that sees the subagent's final stdout.
- **Env-context injection.** Already lives here (`_inject_env_context`); stays here because it mutates the prompt before the subagent session even starts.
- **Tagging orchestrator-supplied inputs.** Wrap alert JSON, archetype READMEs, and prior subagent YAML in salted delimiters before they enter the prompt. Does not cover content the subagent fetches itself via Bash/MCP — that is tagged by the inner `tag_tool_results` hook.

## What this does NOT cover

Nothing load-bearing, once the inner layer is wired. The earlier draft of this task worried about intercepting the subagent's internal tool calls from the wrapper — `--settings` makes that a non-issue. Stream-json with `--include-hook-events` stays on the shelf as passive observability if we ever want wrapper-level tracing on top of the hook logs.

## Work items

1. ~~Settings file generation~~ — superseded by `--plugin-dir`, which loads `plugin.json` directly.
2. ✅ `--plugin-dir` + forced `--session-id` threaded through `invoke_subagent` (`scripts/handlers/_subagent.py`).
3. ✅ Outer helpers inlined: `_append_subagent_log` (per-call prompt+stdout capture under `subagent_outputs/`) and `_append_subagent_audit` (spawn-event JSONL under `subagent_audit.jsonl`). `_inject_env_context` was already inline.
4. ✅ `orchestrate.run()` exports `SOC_AGENT_RUN_DIR` / `SOC_AGENT_SIGNATURE_ID`.
5. ✅ Unit tests in `tests/test_subagent_wrapper.py` (argv shape, session mapping written pre-invocation, outer artifacts, env-context injection, non-zero returncode audit).
6. ✅ Live smoke test confirmed inner hooks (`audit_tool_calls`, `budget_enforcer`) fire under `--plugin-dir` and resolve `run_dir` via the pre-written session mapping.

## Deferred

- `_tag_orchestrator_inputs` — delimiter-wrap orchestrator-supplied prompt content (alert JSON, archetype READMEs, prior subagent YAML). Not needed for v1 since inner `tag_tool_results` handles everything the subagent *fetches*. Pick up if prompt-injection audits flag gaps in orchestrator-supplied inputs.
- `_enforce_run_budget` on the outer layer — inner `budget_enforcer` covers tool calls per subagent session; cross-subagent accounting across a run is still owed. Pick up with the first heavy ANALYZE/CONCLUDE run where budget tracking becomes load-bearing.

## Risk

Low. Inner hooks are the same scripts already in production use. New surface: ~50 lines in `_subagent.py` (argv changes + two helpers) and one env-export block in `orchestrate.py`. All covered by unit tests.
