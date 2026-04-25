#!/usr/bin/env python3
"""PostToolUse hook: Save raw tool output to disk for matched tools.

Fires on Bash and MCP tool calls. Allowlist-matched calls have their full
result body written verbatim to:

    {run_dir}/raw_query_outputs/{loop_n}-{nonce}.{ext}

A manifest entry is appended to {run_dir}/raw_query_outputs/manifest.jsonl
with the agent_id, tool_use_id, schema, and path so a downstream extractor
can correlate manifest entries to a spawning subagent invocation.

The hook returns an additionalContext annotation telling the calling
subagent the raw was saved — reinforces "don't paste raw into output YAML".

Allowlist lives in save_raw_tool_output.allowlist.yaml next to this file.

Exit codes:
    0 - Always (must never block the agent).
"""

import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

import yaml

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.run_context import get_runs_dir, resolve_run_dir  # noqa: E402


ALLOWLIST_PATH = Path(__file__).with_name("save_raw_tool_output.allowlist.yaml")
MAX_NONCE_RETRIES = 5
COMMAND_SUMMARY_LEN = 200


def load_allowlist() -> list[dict]:
    if not ALLOWLIST_PATH.exists():
        return []
    try:
        doc = yaml.safe_load(ALLOWLIST_PATH.read_text())
    except yaml.YAMLError:
        return []
    if not isinstance(doc, dict):
        return []
    entries = doc.get("entries") or []
    return [e for e in entries if isinstance(e, dict)]


def match_entry(tool_name: str, tool_input: dict, allowlist: list[dict]) -> dict | None:
    """Return the first allowlist entry matching this tool call, or None."""
    if tool_name == "Bash":
        command = (tool_input or {}).get("command", "") or ""
        for entry in allowlist:
            if entry.get("kind") != "bash":
                continue
            pattern = entry.get("pattern") or ""
            if pattern and re.search(pattern, command):
                return entry
        return None
    if tool_name.startswith("mcp__"):
        for entry in allowlist:
            if entry.get("kind") != "mcp":
                continue
            pattern = entry.get("pattern") or ""
            if pattern and fnmatch(tool_name, pattern):
                return entry
        return None
    return None


def derive_loop_n(run_dir: Path) -> int:
    """Count GATHER entries in state.json history. Falls back to 0."""
    state_path = run_dir / "state.json"
    if not state_path.exists():
        return 0
    try:
        state = json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError):
        return 0
    history = state.get("history") or []
    if not isinstance(history, list):
        return 0
    return sum(1 for entry in history if entry == "GATHER")


def extract_body(tool_name: str, tool_response) -> str:
    """Coerce tool_response into a string body to write verbatim.

    Bash: tool_response is a dict with {stdout, stderr, interrupted, ...} —
    we save stdout. Stderr is dropped (small + already in audit logs).

    MCP: tool_response is whatever the server returns — typically a dict or
    list of content blocks. Serialize as JSON.
    """
    if tool_name == "Bash":
        if isinstance(tool_response, dict):
            return tool_response.get("stdout") or ""
        return str(tool_response or "")
    if isinstance(tool_response, (dict, list)):
        return json.dumps(tool_response, indent=2)
    return str(tool_response or "")


def make_nonce() -> str:
    """4-char base36 random id from 20 random bits."""
    n = secrets.randbits(20)
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    chars = []
    for _ in range(4):
        chars.append(alphabet[n % 36])
        n //= 36
    return "".join(chars)


def save_payload(run_dir: Path, loop_n: int, ext: str, body: str) -> Path:
    """Write body verbatim to {run_dir}/raw_query_outputs/{loop_n}-{nonce}.{ext}.

    Retries on nonce collision up to MAX_NONCE_RETRIES.
    """
    out_dir = run_dir / "raw_query_outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    for _ in range(MAX_NONCE_RETRIES):
        path = out_dir / f"{loop_n}-{make_nonce()}.{ext}"
        if not path.exists():
            path.write_text(body)
            return path
    path = out_dir / f"{loop_n}-{make_nonce()}-{secrets.token_hex(4)}.{ext}"
    path.write_text(body)
    return path


def write_manifest_entry(run_dir: Path, entry: dict) -> None:
    manifest = run_dir / "raw_query_outputs" / "manifest.jsonl"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def build_command_summary(tool_name: str, tool_input: dict) -> str:
    if tool_name == "Bash":
        cmd = (tool_input or {}).get("command", "") or ""
        return cmd[:COMMAND_SUMMARY_LEN]
    return tool_name[:COMMAND_SUMMARY_LEN]


def context_annotation(path: Path) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                f"[raw-saved] Verbatim tool output written to {path}. "
                "Do not paste raw output into your YAML envelope — "
                "the path is mechanically injected downstream."
            ),
        }
    }


def main() -> None:
    try:
        hook_data = json.loads(sys.stdin.read())
    except Exception:
        sys.exit(0)

    tool_name = hook_data.get("tool_name", "") or ""
    tool_input = hook_data.get("tool_input", {}) or {}

    allowlist = load_allowlist()
    matched = match_entry(tool_name, tool_input, allowlist)
    if matched is None:
        sys.exit(0)

    session_id = hook_data.get("session_id") or ""
    try:
        runs_dir = get_runs_dir()
    except RuntimeError:
        sys.exit(0)
    run_dir, _signature_id = resolve_run_dir(session_id, runs_dir)
    if run_dir is None:
        sys.exit(0)

    body = extract_body(tool_name, hook_data.get("tool_response"))
    if not body:
        sys.exit(0)

    loop_n = derive_loop_n(run_dir)
    ext = matched.get("ext") or "txt"
    schema = matched.get("schema") or "unknown"

    try:
        path = save_payload(run_dir, loop_n, ext, body)
    except OSError:
        sys.exit(0)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "tool_use_id": hook_data.get("tool_use_id"),
        "agent_id": hook_data.get("agent_id"),
        "agent_type": hook_data.get("agent_type"),
        "tool_name": tool_name,
        "schema": schema,
        "loop_n": loop_n,
        "path": str(path),
        "bytes": len(body.encode("utf-8")),
        "command_summary": build_command_summary(tool_name, tool_input),
    }
    try:
        write_manifest_entry(run_dir, entry)
    except OSError:
        pass

    print(json.dumps(context_annotation(path)))
    sys.exit(0)


if __name__ == "__main__":
    main()
