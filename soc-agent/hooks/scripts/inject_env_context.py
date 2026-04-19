#!/usr/bin/env python3
"""PreToolUse hook: inject environment SKILL content into env-gated subagents.

Fires on Task tool calls. When the spawned subagent_type is one of the
env-gated subagents that need vendor-specific query scaffolding, reads the
active adapter name from the environment (SOC_AGENT_SIEM_ADAPTER,
SOC_AGENT_TICKETING_ADAPTER) and appends the matching
`knowledge/environment/systems/{adapter}/SKILL.md` content to the Task's
`prompt` input.

This keeps subagent prompts environment-agnostic in the skill while giving
each spawned subagent the concrete query entrypoint, field mappings, and
examples it needs — without the subagent having to discover them itself.

Emits `hookSpecificOutput.updatedInput` to replace the tool_input with the
augmented prompt. Silent no-op on any missing/invalid configuration — the
subagent then proceeds with its generic prompt and will either succeed or
fail with its own error, but the hook never blocks the tool call.

Exit codes:
    0 — always (context injection must never block)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
SYSTEMS_DIR = SOC_AGENT_ROOT / "knowledge" / "environment" / "systems"

# subagent_type → env var naming the systems/ subdirectory to inject.
# Add entries here as more subagents become env-gated.
ENV_GATED_SUBAGENTS: dict[str, str] = {
    "soc-agent:ticket-context": "SOC_AGENT_SIEM_ADAPTER",
    "soc-agent:gather": "SOC_AGENT_SIEM_ADAPTER",
}


def resolve_adapter_skill(env_var: str) -> str | None:
    """Return the adapter SKILL.md content, or None if unresolvable."""
    adapter = os.environ.get(env_var, "").strip()
    if not adapter:
        return None
    skill_path = (SYSTEMS_DIR / adapter / "SKILL.md").resolve()
    try:
        skill_path.relative_to(SYSTEMS_DIR.resolve())
    except ValueError:
        return None  # path-traversal guard
    if not skill_path.is_file():
        return None
    return skill_path.read_text()


def build_augmented_prompt(original_prompt: str, env_var: str, content: str) -> str:
    """Append the env SKILL content to the original prompt with a clear boundary."""
    header = (
        f"\n\n---\n## Environment adapter (injected from {env_var})\n\n"
        "The active deployment's system SKILL.md follows. It names the query "
        "entrypoint, field mappings, and examples for this environment. Use "
        "it as your vendor-specific reference; do not discover it yourself.\n\n"
    )
    return f"{original_prompt}{header}{content}"


def main() -> int:
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        return 0

    if hook_data.get("tool_name") not in ("Task", "Agent"):
        return 0

    tool_input = hook_data.get("tool_input") or {}
    subagent_type = tool_input.get("subagent_type", "")
    env_var = ENV_GATED_SUBAGENTS.get(subagent_type)
    if env_var is None:
        return 0

    content = resolve_adapter_skill(env_var)
    if content is None:
        return 0

    original_prompt = tool_input.get("prompt", "") or ""
    augmented = build_augmented_prompt(original_prompt, env_var, content)

    updated = dict(tool_input)
    updated["prompt"] = augmented
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": updated,
        }
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
