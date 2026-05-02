#!/usr/bin/env python3
"""PostToolUse hook: Log tool calls to audit and trace files.

Writes to two global JSONL files based on tool classification:
  - tool_audit.jsonl  — state-changing / external tools (Bash, Write, Edit, Agent, MCP)
  - tool_trace.jsonl  — read-only navigation tools (Read, Glob, Grep)

Both files are always written. The split supports different retention policies:
audit is the compliance/security record, trace is for post-mortem debugging.

Exit codes:
    0 - Always (logging should never block the agent)
"""

import json
import sys
from datetime import datetime, UTC
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.run_context import get_runs_dir  # noqa: E402

# Maximum length for any single field value in the audit entry.
# Prevents multi-MB Write/Edit content from bloating the log.
MAX_FIELD_LEN = 2000

# Read-only tools go to tool_trace.jsonl; everything else to tool_audit.jsonl.
TRACE_TOOLS = {"Read", "Glob", "Grep"}


def truncate(value: str, max_len: int = MAX_FIELD_LEN) -> str:
    """Truncate a string value, appending a marker if truncated."""
    if len(value) <= max_len:
        return value
    return value[:max_len] + f"... [truncated, {len(value)} chars total]"


def sanitize_tool_input(tool_input: dict) -> dict:
    """Truncate large values in tool_input to keep the log manageable."""
    sanitized = {}
    for key, value in tool_input.items():
        if isinstance(value, str):
            sanitized[key] = truncate(value)
        else:
            serialized = json.dumps(value)
            if len(serialized) > MAX_FIELD_LEN:
                sanitized[key] = truncate(serialized)
            else:
                sanitized[key] = value
    return sanitized


def main():
    try:
        raw = sys.stdin.read()
        hook_data = json.loads(raw)
    except Exception:
        # If we can't parse input, silently exit — never block the agent.
        sys.exit(0)

    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "session_id": hook_data.get("session_id"),
        "tool_name": hook_data.get("tool_name"),
        "tool_input": sanitize_tool_input(hook_data.get("tool_input", {})),
        "tool_use_id": hook_data.get("tool_use_id"),
    }

    response = hook_data.get("tool_response")
    if response is not None:
        if isinstance(response, str):
            entry["tool_response"] = truncate(response)
        else:
            serialized = json.dumps(response, ensure_ascii=False)
            entry["tool_response"] = (
                response if len(serialized) <= MAX_FIELD_LEN else truncate(serialized)
            )

    # Include subagent context if present.
    if hook_data.get("agent_id"):
        entry["agent_id"] = hook_data["agent_id"]
        entry["agent_type"] = hook_data.get("agent_type")

    tool_name = hook_data.get("tool_name", "")
    filename = "tool_trace.jsonl" if tool_name in TRACE_TOOLS else "tool_audit.jsonl"
    out_path = get_runs_dir() / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    sys.exit(0)


if __name__ == "__main__":
    main()
