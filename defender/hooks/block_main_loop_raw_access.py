#!/usr/bin/env python3
"""PreToolUse hook: keep raw evidence behind the gather subagent boundary.

defender SKILL §Principles: every data-source query goes through gather,
which returns a summary the main loop treats as authoritative. The main
loop must not handle raw payloads. This hook enforces that structurally,
blocking two equivalent main-loop moves:

  1. Reading `gather_raw/` (Bash/Read/Grep/Glob) — spot-checking or
     re-deriving fields gather already summarized.
  2. Running an adapter CLI directly (`scripts/tools/*_cli.py` via Bash)
     — querying a data source itself instead of dispatching gather, then
     reading its own dump. Same violation, renamed, and it escapes the
     executed_queries audit trail.

Both are denied (exit 2, reason fed back to the agent) only in the main
session. The remediation for both is identical: dispatch the gather
subagent.

### Why scope to the main session

The gather subagent legitimately does both — it runs the adapter CLI
(through record_query.py) and reads `gather_raw/` (§3.5/§4). A session-wide
permission-deny rule can't tell the two apart and would break gather, so
the scoping lives here.

The discriminator is `agent_id`: Claude Code includes it (and `agent_type`)
in the PreToolUse payload ONLY when the hook fires inside a Task subagent;
the top-level loop has neither. cwd does NOT work — run.py spawns the
orchestrator and every gather subagent in-process at the same cwd
(REPO_ROOT), so a `cwd == REPO_ROOT` test flags gather subagents as the
main loop and wrongly denies their legitimate gather_raw reads. We deny
only when `agent_id` is absent (main loop); any subagent fails **open**
(allow) — losing enforcement is acceptable, breaking gather is not. This
clamp is a backstop: the primary defense is keeping gather_raw paths out
of the orchestrator's context so it never reaches for them (see issue #264).

Exit codes:
    0 — allow.
    2 — deny; the reason on stderr is fed back to the agent.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Sibling-import the shared command-decomposition + shim-taxonomy helpers so the
# adapter/non-adapter split is defined once (hooks/_cmd_segments.py) and a newly
# onboarded adapter auto-gates here too. defender/hooks/<this>.py → parents[2]
# is the repo root, so `defender.hooks.*` resolves whether imported or run as a script.
if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)
from defender.hooks._cmd_segments import ADAPTER_CLI_RE, adapter_shims  # noqa: E402

RAW_MARKER = "gather_raw"
# `ADAPTER_CLI_RE` (a `scripts/tools/<name>_cli.py` path) is imported from the
# shared taxonomy. `record_query.py` / `data_source_debug.py` are NOT `_cli.py`,
# and the invlang CLI has no `scripts/tools/` path, so both stay allowed.


def _adapter_shim_re() -> re.Pattern | None:
    """Regex matching a `defender-<system>` ADAPTER shim in command position.

    Built per-call from the shared `adapter_shims()` (every `defender-*` shim in
    defender/bin minus the non-adapter ones: invlang, record-query,
    data-source-debug), so onboarding an adapter needs no edit here. The
    `(?<![-\\w/])` anchor keeps it from false-matching `defender-runs` in a
    runs-base path or `--defender-dir`, and names are enumerated (NOT an open
    `defender-[a-z-]*`) for the same reason. Returns None if no adapters are
    discoverable (fail open — never block on an empty roster)."""
    names = sorted(s[len("defender-"):] for s in adapter_shims())
    if not names:
        return None
    return re.compile(r"(?<![-\w/])defender-(?:" + "|".join(map(re.escape, names)) + r")\b")

RAW_DENY_REASON = (
    "Blocked: the main loop must not read gather_raw/. Gather's returned "
    "summary is the authoritative record (defender SKILL §Principles). If a "
    "field you need is missing, re-dispatch gather with a stricter "
    "what_to_summarize — do not Read/Grep/jq the raw payload from the main "
    "loop; that defeats the subagent isolation."
)
ADAPTER_DENY_REASON = (
    "Blocked: the main loop must not run data-source CLIs directly. Querying "
    "a data source — and then reading your own dump — is gather's job, and "
    "doing it here leaves the query out of the audit trail (defender SKILL "
    "§Principles). Dispatch the gather subagent (Task) with a lead instead; "
    "it runs the query and returns a summary."
)


def _read_target(tool_name: str, tool_input: dict) -> str:
    """Location-bearing fields for the gather_raw check (where the call points)."""
    if tool_name == "Bash":
        return str(tool_input.get("command", ""))
    if tool_name == "Read":
        return str(tool_input.get("file_path", ""))
    if tool_name == "Grep":
        return f"{tool_input.get('path', '')} {tool_input.get('glob', '')}"
    if tool_name == "Glob":
        return f"{tool_input.get('path', '')} {tool_input.get('pattern', '')}"
    return ""


def _is_main_session(hook_data: dict) -> bool:
    """True for the top-level agent loop, False for a Task subagent.

    The discriminator is `agent_id`: the PreToolUse payload carries it (plus
    `agent_type`) ONLY when the hook fires inside a subagent call; the main loop
    has neither (per the hooks reference, confirmed empirically). cwd is NOT
    usable — run.py spawns the orchestrator and every gather subagent in-process
    at the same cwd (REPO_ROOT), so a `cwd == REPO_ROOT` test flags gather
    subagents as the main loop and wrongly blocks their legitimate gather_raw
    reads. Absence of `agent_id` → main loop → apply the clamps."""
    return not hook_data.get("agent_id")


def main() -> int:
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        return 0

    tool_name = hook_data.get("tool_name")
    if tool_name not in ("Bash", "Read", "Grep", "Glob"):
        return 0
    if not _is_main_session(hook_data):
        return 0

    tool_input = hook_data.get("tool_input") or {}

    if RAW_MARKER in _read_target(tool_name, tool_input):
        # Exempt gather's own payload tools. data-source-debug RECEIVES a
        # gather_raw payload path as input (reading it is its whole job) and
        # record_query WRITES there; both legitimately name gather_raw paths on
        # the command line. The clamp targets the main loop spot-checking raw
        # payloads (Read/Grep/Glob, or bash cat/jq/cp on the file), not these
        # tools — without this, a `defender-data-source-debug --payload
        # .../gather_raw/...` call is wrongly denied (surfacing as a confusing
        # "hook error") whenever the cwd discriminator flags the subagent as the
        # main session. Mirrors the record_query exemption on the adapter clamp.
        cmd = str(tool_input.get("command", "")) if tool_name == "Bash" else ""
        gather_payload_tool = any(t in cmd for t in (
            "data_source_debug", "defender-data-source-debug",
            "record_query", "defender-record-query"))
        if not gather_payload_tool:
            print(RAW_DENY_REASON, file=sys.stderr)
            return 2

    # Adapter-CLI clamp. Exempt commands wrapped in record_query.py: that
    # wrapper is gather's path (and audits the query), so this stays robust
    # even if a gather subagent ever runs at REPO_ROOT — it can't break
    # gather's own queries, only the main loop's direct, unwrapped calls.
    if tool_name == "Bash":
        cmd = str(tool_input.get("command", ""))
        shim_re = _adapter_shim_re()
        is_adapter = bool(ADAPTER_CLI_RE.search(cmd)) or bool(shim_re and shim_re.search(cmd))
        wrapped = "record_query.py" in cmd or "defender-record-query" in cmd
        if is_adapter and not wrapped:
            print(ADAPTER_DENY_REASON, file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
