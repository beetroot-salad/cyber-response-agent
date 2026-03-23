#!/usr/bin/env python3
"""PostToolUse hook: Log every tool call to an audit trail.

Records what tools were invoked, with what inputs, by whom, and when.
Writes JSONL entries to runs/tool_audit.jsonl.

Exit codes:
    0 - Always (audit logging should never block the agent)
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent

# Maximum length for any single field value in the audit entry.
# Prevents multi-MB Write/Edit content from bloating the log.
MAX_FIELD_LEN = 2000


def get_runs_dir() -> Path:
    """Get the runs directory. Configurable via SOC_AGENT_RUNS_DIR env var."""
    return Path(os.environ.get("SOC_AGENT_RUNS_DIR", str(SOC_AGENT_ROOT / "runs")))


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
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": hook_data.get("session_id"),
        "tool_name": hook_data.get("tool_name"),
        "tool_input": sanitize_tool_input(hook_data.get("tool_input", {})),
        "tool_use_id": hook_data.get("tool_use_id"),
    }

    # Include subagent context if present.
    if hook_data.get("agent_id"):
        entry["agent_id"] = hook_data["agent_id"]
        entry["agent_type"] = hook_data.get("agent_type")

    audit_path = get_runs_dir() / "tool_audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with open(audit_path, "a") as f:
        f.write(json.dumps(entry) + "\n")

    sys.exit(0)


if __name__ == "__main__":
    main()
