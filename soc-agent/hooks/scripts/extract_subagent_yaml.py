#!/usr/bin/env python3
"""PostToolUse hook: extract canonical YAML from YAML-strict subagent output.

Fires after Task tool calls. When the spawned subagent_type is one of the
subagents whose protocol is "return exactly one fenced YAML block" (declared
in YAML_STRICT_SUBAGENTS), parses the tool_response text, extracts the
first fenced ```yaml block, and appends it as `additionalContext` so the
main agent has a clean canonical form even when the subagent leaked
preamble prose or emitted a duplicate block.

Claude Code PostToolUse cannot *replace* non-MCP tool output — only
`additionalContext` annotation is available on built-in tools like Task.
So we append rather than rewrite: the main agent sees both the raw
response and the canonical extract, and is instructed (in the investigate
skill) to prefer the extract.

If no fenced YAML block is found, the hook is a silent no-op — the main
agent falls back to whatever the subagent returned.

Exit codes:
    0 — always (extraction must never block)
"""

from __future__ import annotations

import json
import re
import sys

# subagent_type → short name used in the annotation header.
YAML_STRICT_SUBAGENTS: dict[str, str] = {
    "soc-agent:ticket-context": "ticket-context",
    "soc-agent:archetype-scan": "archetype-scan",
}

# Matches a ```yaml ... ``` fenced block. Non-greedy body so the first block
# wins when the subagent emitted duplicates.
YAML_FENCE_RE = re.compile(r"```ya?ml\s*\n(.*?)\n```", re.DOTALL)


def tool_response_text(tool_response) -> str:
    """Coerce Task's tool_response (various shapes) to a single text blob."""
    if isinstance(tool_response, str):
        return tool_response
    if isinstance(tool_response, list):
        parts: list[str] = []
        for block in tool_response:
            if isinstance(block, dict):
                parts.append(str(block.get("text", "") or block.get("content", "")))
            else:
                parts.append(str(block))
        return "\n".join(parts)
    if isinstance(tool_response, dict):
        for key in ("text", "content", "response", "output"):
            if key in tool_response:
                return tool_response_text(tool_response[key])
        return json.dumps(tool_response)
    return str(tool_response)


def extract_first_yaml_block(text: str) -> str | None:
    """Return the body of the first ```yaml fenced block, or None."""
    m = YAML_FENCE_RE.search(text)
    if not m:
        return None
    return m.group(1).strip() or None


def main() -> int:
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        return 0

    if hook_data.get("tool_name") not in ("Task", "Agent"):
        return 0

    tool_input = hook_data.get("tool_input") or {}
    subagent_type = tool_input.get("subagent_type", "")
    short_name = YAML_STRICT_SUBAGENTS.get(subagent_type)
    if short_name is None:
        return 0

    raw = tool_response_text(hook_data.get("tool_response"))
    yaml_body = extract_first_yaml_block(raw)
    if yaml_body is None:
        return 0

    annotation = (
        f"## Canonical {short_name} output\n\n"
        f"The subagent's declared protocol is to return a single fenced YAML "
        f"block. The first such block in its response has been extracted "
        f"below — parse this as the subagent's result and ignore any "
        f"preamble prose or duplicate blocks in the raw response above.\n\n"
        f"```yaml\n{yaml_body}\n```"
    )

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": annotation,
        }
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
