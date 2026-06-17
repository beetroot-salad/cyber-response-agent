#!/usr/bin/env python3
"""PreToolUse hook: require the capture wrapper for adapter calls in gather.

The queries table (`executed_queries.jsonl`) is generated *live* by the
capture wrapper (`scripts/tools/record_query.py`, invoked as
`defender-record-query … -- defender-<system> …`). It runs the adapter
query, persists the raw payload by-ref, and appends the queries-table row.
A data-source query that skips the wrapper produces no row and no payload —
it silently escapes the audit trail.

Until now that was enforced only by the gather subagent's *discipline*: the
SKILL tells it to wrap, but nothing blocked a bare `defender-elastic query …`.
The sibling leads table already has a hard integrity gate (`record_lead.py`,
`O_CREAT|O_EXCL`); this hook closes the asymmetry for the queries table.

Scope: the **gather subagent only** (`agent_id` present). The main loop is
denied adapter calls outright by `block_main_loop_raw_access.py`; the gather
subagent is *supposed* to run adapters, just always through the wrapper. So
here we deny an adapter call iff it is **unwrapped**.

Detection: decompose the Bash command (strip a leading `timeout`/`bash -c`,
split on `&&`/`||`/`|`/`;` outside quotes), then deny if any segment is an
unwrapped adapter invocation — its leading token is an adapter shim
(`defender-elastic`, …) or it names an adapter `*_cli.py` path — and the
segment is not itself a `defender-record-query` wrapper. The wrapped form
`defender-record-query … -- defender-elastic …` is allowed because the
segment's leading token is `defender-record-query`; the adapter appears only
after `--`, never as a segment head.

Known limitation (acceptable — gather is a first-party agent; this is an
integrity gate against accidental unrecorded queries, not an adversarial-
evasion control): an adapter hidden in a `$(...)`/backtick substitution
(`echo $(defender-elastic …)`) is not caught by the head check. Injection
safety is handled separately (`tag_tool_results.py`).

Exit codes:
    0 — allow (not a gather subagent / not an adapter / wrapped / parse skip).
    2 — deny; the remediation on stderr is fed back to the agent.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Sibling-import the shared command-decomposition + shim-taxonomy helpers.
# Inserting our own dir covers the importlib-loaded test path; running as a
# script adds it. Mirrors tag_tool_results.py's _run_dir import.
_HOOK_DIR = Path(__file__).resolve().parent
if str(_HOOK_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOK_DIR))
from _cmd_segments import (  # noqa: E402
    ADAPTER_CLI_RE,
    adapter_shims,
    split_segments,
    unwrap,
)

# The capture wrapper, recognized in *command position* (segment head), so a
# bare adapter whose arguments merely mention the wrapper token — e.g. an
# elastic query for the literal string `defender-record-query` — is still a bare
# call, not a wrapped one. Matched at the head, never as a free substring.
_WRAPPER_SHIM = "defender-record-query"
_WRAPPER_SCRIPT_RE = re.compile(r"(?:^|/)record_query\.py$")
_INTERP_RE = re.compile(r"(?:^|/)python[0-9.]*$")

DENY_REASON = (
    "Blocked: route this data-source query through the capture wrapper so it "
    "lands in the queries table (executed_queries.jsonl) with its raw payload. "
    "A bare adapter call escapes the audit trail. Re-run it as:\n"
    "  defender-record-query --lead <l-NNN> "
    "--query-id <{system}.{template}|ad-hoc> -- <adapter call>\n"
    "(--run-dir defaults from $DEFENDER_RUN_DIR and --system is derived from the "
    "adapter; pass either only to override.) Use --query-id ad-hoc for a one-off "
    "probe with no catalog candidacy."
)


def _is_subagent(hook_data: dict) -> bool:
    """True inside a Task subagent (gather): its PreToolUse payload carries
    `agent_id`; the main loop has none. Matches
    block_main_loop_raw_access._is_main_session (inverted)."""
    return bool(hook_data.get("agent_id"))


def _is_wrapper_segment(parts: list[str]) -> bool:
    """True if the capture wrapper is the command being RUN at the segment head
    (`defender-record-query …`, or an interpreter running `…/record_query.py`),
    so the adapter token after `--` is wrapped. A wrapper token merely appearing
    in an argument does NOT count."""
    if not parts:
        return False
    head = parts[0]
    if head == _WRAPPER_SHIM or _WRAPPER_SCRIPT_RE.search(head):
        return True
    if _INTERP_RE.search(head):
        return any(_WRAPPER_SCRIPT_RE.search(p) for p in parts[1:])
    return False


def _is_adapter_segment(parts: list[str], adapters: set) -> bool:
    """True if the segment EXECUTES a data-source adapter: its head is an adapter
    shim, the head is itself an adapter `*_cli.py` path, or an interpreter at the
    head runs one. A `*_cli.py` path appearing only as an argument (e.g.
    `cat …/elastic_cli.py`) is a read, not an execution, and is not flagged."""
    if not parts:
        return False
    head = parts[0]
    if head in adapters:
        return True
    if ADAPTER_CLI_RE.search(head):
        return True
    if _INTERP_RE.search(head):
        return any(ADAPTER_CLI_RE.search(p) for p in parts[1:])
    return False


def _has_unwrapped_adapter(cmd: str) -> bool:
    inner = unwrap(cmd)
    if inner is None:
        return False
    adapters = adapter_shims()
    for parts in split_segments(inner):  # each a shlex token list (one command)
        if not parts:
            continue
        if _is_wrapper_segment(parts):
            continue  # the capture wrapper — the adapter after `--` is wrapped
        if _is_adapter_segment(parts, adapters):
            return True
    return False


def main() -> int:
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        return 0
    if hook_data.get("tool_name") != "Bash":
        return 0
    if not _is_subagent(hook_data):
        return 0  # main loop — block_main_loop_raw_access.py owns adapter calls

    cmd = str((hook_data.get("tool_input") or {}).get("command", ""))
    if not cmd.strip():
        return 0

    if _has_unwrapped_adapter(cmd):
        print(DENY_REASON, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
