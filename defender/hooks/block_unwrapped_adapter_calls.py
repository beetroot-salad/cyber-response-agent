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

# A segment that carries one of these is the capture wrapper itself, so an
# adapter token inside it is wrapped (appears after `--`), not a bare call.
_WRAPPER_MARKERS = ("defender-record-query", "record_query.py")

DENY_REASON = (
    "Blocked: route this data-source query through the capture wrapper so it "
    "lands in the queries table (executed_queries.jsonl) with its raw payload. "
    "A bare adapter call escapes the audit trail. Re-run it as:\n"
    "  defender-record-query --run-dir $DEFENDER_RUN_DIR --lead <l-NNN> "
    "--system <system> --query-id <{system}.{template}|ad-hoc> -- <adapter call>\n"
    "Use --query-id ad-hoc for a one-off probe with no catalog candidacy."
)


def _is_subagent(hook_data: dict) -> bool:
    """True inside a Task subagent (gather): its PreToolUse payload carries
    `agent_id`; the main loop has none. Matches
    block_main_loop_raw_access._is_main_session (inverted)."""
    return bool(hook_data.get("agent_id"))


def _has_unwrapped_adapter(cmd: str) -> bool:
    inner = unwrap(cmd)
    if inner is None:
        return False
    adapters = adapter_shims()
    for raw in split_segments(inner):
        seg = raw.strip()
        if not seg:
            continue
        if any(m in seg for m in _WRAPPER_MARKERS):
            continue  # this segment is the capture wrapper — adapter is wrapped
        head = seg.split(None, 1)[0]
        if head in adapters or ADAPTER_CLI_RE.search(seg):
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
