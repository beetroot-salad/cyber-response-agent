#!/usr/bin/env python3
"""PreToolUse hook: auto-approve safe shim + read-only Bash invocations.

The `defender/bin/defender-*` shims give the agent one stable token per
first-party tool, allowlisted in run-settings.json as `Bash(defender-* *)`.
But the static allowlist matches on the command's first token, so it can't
express two shapes the agent reaches for naturally in an unattended run:

  1. `bash -c '<shim invocation>'` — the command's first token is `bash`,
     not `defender-*`, and a settings glob can't anchor inside the quoted
     `-c` payload without also green-lighting `bash -c 'rm -rf /; defender-x'`.
  2. read-only compounds the agent uses to inspect run-dir JSON, e.g.
     `tail -1 x.jsonl | jq '.'` — each pipe segment is gated separately.

This hook approves a Bash command iff it is composed *entirely* of safe
tokens — the `defender-*` shims plus a small read-only utility set — after
unwrapping an optional leading `timeout <n>` and a single `bash -c`/`sh -c`.
Anything with an unrecognized command, a redirect to a file, an env-var
assignment prefix (the credential-groping vector), or a `$(...)`/backtick
substitution falls through untouched (exit 0, no decision) to the normal
permission flow.

Clamp-aware: in the main session (no `agent_id`) the data-source adapter
shims (`defender-elastic`, `defender-cmdb`, …) are NOT in the safe set, so
this hook never approves a main-loop adapter call — that stays the job of
`block_main_loop_raw_access.py`. Approving here only ever *adds* permission
for shapes the allowlist can't express; it never overrides the clamp.

Exit codes:
    0 — always (with or without an `allow` decision on stdout).
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
    NON_ADAPTER_SHIMS,
    all_defender_shims as _all_defender_shims,
    split_segments as _split_segments,
    unwrap as _unwrap,
)

# Read-only utilities safe to approve in any composition. Deliberately small:
# viewers/filters over already-materialized files, plus navigation. No `env`,
# `printenv`, `export`, `python3`, `netstat`, `docker`.
READONLY_TOOLS = frozenset(
    {"jq", "cat", "tail", "head", "ls", "wc", "echo", "cd", "grep", "sort", "uniq", "true"}
)

# Extra read-only tools the GATHER subagent gets but the main loop does not:
# `find` for query-template discovery under skills/gather/queries/. The main loop
# is oriented by the injected workspace map and stays without it (least privilege).
# `find` is read-only ONLY without its action flags — `-exec`/`-execdir`/`-ok`/
# `-okdir` run a command, `-delete` removes files, `-fprint*`/`-fls` write files —
# so those are rejected by _FIND_DANGER_RE wherever find is allowed.
GATHER_READONLY_TOOLS = frozenset({"find"})

_FIND_DANGER_RE = re.compile(
    r"(?<!\S)-(?:execdir|exec|okdir|ok|delete|fprintf|fprint0|fprint|fls)\b"
)

# find must not be a back door around the read denylist: it can't run a command
# or write (above), and it can't be used to *locate* secrets / ground truth /
# the held-out manifest either (the files decide_read denies outright). Mirrors
# permission._READ_DENY_SUBSTR + _READ_DENY_DIR — a find naming any of these
# falls through (unapproved) even though its action flags are clean.
_FIND_SENSITIVE_RE = re.compile(
    r"(\.env|credentials|ground[-_]truth|cases\.json|\.ssh)", re.IGNORECASE
)

# Benign stderr redirects — discard (`2>/dev/null`) or merge (`2>&1`) of stderr.
# The agent appends these reflexively; they don't write a file or exfiltrate
# (the harness captures stderr regardless), so strip them BEFORE the unsafe-token
# check rather than denying the whole command. A *stdout* file redirect
# (`> out`, `1> out`, `&> out`) is NOT matched here and stays denied.
# The trailing `(?=\s|$)` anchors the match to a complete token so a redirect to
# a *different* target sharing the prefix (e.g. `2>/dev/nullX`, a real stderr→file
# write) is NOT stripped — it keeps its `>` and trips _UNSAFE_TOKEN_RE below.
_BENIGN_STDERR_RE = re.compile(r"\s*2>\s*(?:/dev/null|&1)(?=\s|$)")

# Tokens that make a command unsafe to approve regardless of leading word:
# output redirects, command substitution, env-assignment prefixes. If any
# segment carries one, fall through to the normal flow. Over-cautious by design
# (a `>` inside a quoted jq filter trips it) — a false passthrough is harmless,
# a false approval is not.
_UNSAFE_TOKEN_RE = re.compile(r"(\$\(|`|>|<|\bexport\b|^[A-Za-z_][A-Za-z0-9_]*=)")


def _is_main_session(hook_data: dict) -> bool:
    """Main loop = no `agent_id`; a Task subagent's PreToolUse payload carries it
    (and `agent_type`). cwd is NOT usable — v2 runs the orchestrator and every
    gather subagent in-process at the same cwd. Matches
    block_main_loop_raw_access._is_main_session."""
    return not hook_data.get("agent_id")


def _all_segments_safe(script: str, safe_leading: frozenset) -> bool:
    for raw in _split_segments(script):
        # Drop benign stderr redirects first (2>/dev/null, 2>&1) — they're not a
        # file write or exfil vector, just noise the agent appends. A real stdout
        # redirect still carries a bare `>` and trips _UNSAFE_TOKEN_RE below.
        seg = _BENIGN_STDERR_RE.sub("", raw).strip()
        if not seg:
            continue
        if _UNSAFE_TOKEN_RE.search(seg):
            return False
        head = seg.split(None, 1)[0]
        if head not in safe_leading:
            return False
        # `find` is read-only only without its action flags (-exec/-delete/…),
        # and must not be a locator for denied-read files (secrets / ground truth).
        # Reject either wherever find is in safe_leading (gather); in the main loop
        # find isn't in the set, so the head check above already denied it.
        if head == "find" and (_FIND_DANGER_RE.search(seg) or _FIND_SENSITIVE_RE.search(seg)):
            return False
    return True


def main() -> int:
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        return 0
    if hook_data.get("tool_name") != "Bash":
        return 0
    cmd = str((hook_data.get("tool_input") or {}).get("command", "")).strip()
    if not cmd:
        return 0

    # Never approve anything the main-loop clamp (block_main_loop_raw_access.py)
    # would deny — a `gather_raw` reference or an adapter call. Declining to
    # approve (passthrough) keeps the two hooks from ever contradicting,
    # independent of hook-precedence semantics.
    main_session = _is_main_session(hook_data)
    if main_session and "gather_raw" in cmd:
        return 0

    # Build the safe leading-token set. Adapter shims are safe only outside the
    # main session — in the main loop they must reach the clamp, not be approved.
    safe = set(READONLY_TOOLS) | set(NON_ADAPTER_SHIMS)
    if not main_session:
        # Subagent context: any defender-* shim is fine (gather runs adapters),
        # plus the gather-only read-only tools (find, for template discovery).
        safe |= _all_defender_shims() | GATHER_READONLY_TOOLS

    inner = _unwrap(cmd)
    if inner is None:
        return 0
    if not _all_segments_safe(inner, frozenset(safe)):
        return 0

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": "safe shim / read-only invocation",
        }
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
