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

The discriminator is `cwd`: run.py spawns the main loop with
`cwd=REPO_ROOT`, while gather subagents land in a Claude-Code-managed
worktree whose cwd is *not* under REPO_ROOT (the same fact run.py relies
on when it passes `--add-dir REPO_ROOT`). We deny only when cwd resolves
to REPO_ROOT; anything else fails **open** (allow) — losing enforcement
is acceptable, breaking gather is not.

Exit codes:
    0 — allow.
    2 — deny; the reason on stderr is fed back to the agent.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Hook lives at <repo>/defender/hooks/this_file.py → parents[2] is the repo
# root, matching run.py's REPO_ROOT (DEFENDER_DIR.parent).
REPO_ROOT = Path(__file__).resolve().parents[2]

RAW_MARKER = "gather_raw"
# An adapter CLI invocation: a path under scripts/tools/ ending in _cli.py.
# Matches both `defender/scripts/tools/elastic_cli.py` and the absolute form.
# `record_query.py` / `data_source_debug.py` are NOT `_cli.py` and are not
# matched; the invlang CLI (`-m defender.skills.invlang.cli`) has no
# `scripts/tools/` path and no `_cli.py`, so it stays allowed.
ADAPTER_CLI_RE = re.compile(r"scripts/tools/\w+_cli\.py\b")
# The `defender/bin/defender-*` invocation shims hide the `scripts/tools/*_cli.py`
# path behind a bare token, so the path regex above no longer sees a main-loop
# adapter call. Match the adapter shims by name too — every `defender-*` shim
# EXCEPT the three non-adapter ones (invlang = corpus query, record-query =
# gather's capture wrapper, data-source-debug = gather's helper), which the main
# loop is allowed to run. Keep this exempt set in sync with defender/bin/.
# The data-source ADAPTER shims (the `*_cli.py` wrappers) — the main loop must
# not run these directly. Enumerated explicitly (NOT `defender-[a-z-]*`) because
# an open pattern also matches `defender-runs` in the runs-base path
# `/tmp/defender-runs-v2/...` and `defender-dir` in `--defender-dir`, both of
# which appear in legitimate gather commands. Keep in sync with defender/bin/:
# the non-adapter shims (invlang, record-query, data-source-debug) are excluded.
# `(?<![-\w/])` anchors the match to command position, not a flag/path substring.
_ADAPTER_SHIMS = ("elastic", "cmdb", "identity", "host-state",
                  "threat-intel", "change-mgmt", "ticket")
ADAPTER_SHIM_RE = re.compile(
    r"(?<![-\w/])defender-(?:" + "|".join(_ADAPTER_SHIMS) + r")\b"
)

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


def _is_main_session(cwd: str | None) -> bool:
    """True only when cwd resolves to REPO_ROOT. Missing/odd cwd → False
    (fail open: never block a gather subagent)."""
    if not cwd:
        return False
    try:
        return Path(cwd).resolve() == REPO_ROOT
    except (OSError, ValueError):
        return False


def main() -> int:
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        return 0

    tool_name = hook_data.get("tool_name")
    if tool_name not in ("Bash", "Read", "Grep", "Glob"):
        return 0
    if not _is_main_session(hook_data.get("cwd")):
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
        is_adapter = ADAPTER_CLI_RE.search(cmd) or ADAPTER_SHIM_RE.search(cmd)
        wrapped = "record_query.py" in cmd or "defender-record-query" in cmd
        if is_adapter and not wrapped:
            print(ADAPTER_DENY_REASON, file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
