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

Clamp-aware: in the main session (cwd == REPO_ROOT) the data-source adapter
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
import shlex
import sys
from pathlib import Path

# Hook lives at <repo>/defender/hooks/this_file.py → parents[2] is the repo
# root, matching run.py's REPO_ROOT and block_main_loop_raw_access.py.
REPO_ROOT = Path(__file__).resolve().parents[2]

# Read-only utilities safe to approve in any composition. Deliberately small:
# viewers/filters over already-materialized files, plus navigation. No `env`,
# `printenv`, `export`, `source`, `find`, `python3`, `netstat`, `docker`.
READONLY_TOOLS = frozenset(
    {"jq", "cat", "tail", "head", "ls", "wc", "echo", "cd", "grep", "sort", "uniq", "true"}
)

# Non-adapter shims the main loop is allowed to run (corpus query + gather's
# own wrappers). Keep in sync with block_main_loop_raw_access.ADAPTER_SHIM_RE.
NON_ADAPTER_SHIMS = frozenset(
    {"defender-invlang", "defender-record-query", "defender-data-source-debug"}
)

# Tokens that make a command unsafe to approve regardless of leading word:
# output redirects, command substitution, env-assignment prefixes. If any
# segment carries one, fall through to the normal flow. Over-cautious by design
# (a `>` inside a quoted jq filter trips it) — a false passthrough is harmless,
# a false approval is not.
_UNSAFE_TOKEN_RE = re.compile(r"(\$\(|`|>|<|\bexport\b|^[A-Za-z_][A-Za-z0-9_]*=)")


def _split_segments(script: str) -> list[str]:
    """Split on shell operators (`&&`, `||`, `|`, `;`) that are OUTSIDE quotes.
    A naive regex split would cut a `|` inside a jq filter (`jq '.a | .b'`)."""
    segs: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i, n = 0, len(script)
    while i < n:
        c = script[i]
        if quote is not None:
            buf.append(c)
            if c == quote:
                quote = None
            i += 1
        elif c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
        elif script.startswith("&&", i) or script.startswith("||", i):
            segs.append("".join(buf)); buf = []; i += 2
        elif c in "|;":
            segs.append("".join(buf)); buf = []; i += 1
        else:
            buf.append(c)
            i += 1
    segs.append("".join(buf))
    return segs


def _is_main_session(hook_data: dict) -> bool:
    """Main loop = no `agent_id`; a Task subagent's PreToolUse payload carries it
    (and `agent_type`). cwd is NOT usable — v2 runs the orchestrator and every
    gather subagent in-process at the same cwd. Matches
    block_main_loop_raw_access._is_main_session."""
    return not hook_data.get("agent_id")


def _unwrap(cmd: str) -> str | None:
    """Strip a leading `timeout <n>` and a single `bash -c`/`sh -c`, returning
    the inner script. Returns the command unchanged if there is nothing to
    unwrap, or None if the `-c` payload can't be cleanly extracted."""
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return None
    if not tokens:
        return None
    # Drop a leading `timeout <n>` / `timeout -k <n> <n>` prefix.
    i = 0
    if tokens[i] == "timeout":
        i += 1
        while i < len(tokens) and (tokens[i].startswith("-") or tokens[i].replace(".", "").isdigit()):
            i += 1
    if i < len(tokens) and tokens[i] in ("bash", "sh") and "-c" in tokens[i:]:
        c_idx = tokens.index("-c", i)
        if c_idx + 1 < len(tokens):
            return tokens[c_idx + 1]  # the quoted script payload
        return None
    return cmd


def _all_segments_safe(script: str, safe_leading: frozenset) -> bool:
    for raw in _split_segments(script):
        seg = raw.strip()
        if not seg:
            continue
        if _UNSAFE_TOKEN_RE.search(seg):
            return False
        head = seg.split(None, 1)[0]
        if head not in safe_leading:
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
        # Subagent context: any defender-* shim is fine (gather runs adapters).
        safe |= _all_defender_shims()

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


def _all_defender_shims() -> set:
    """All `defender-*` shim names from defender/bin/ (cheap dir read). Falls
    back to the known set if the dir is unreadable."""
    bin_dir = REPO_ROOT / "defender" / "bin"
    try:
        return {p.name for p in bin_dir.iterdir() if p.name.startswith("defender-")}
    except OSError:
        return set(NON_ADAPTER_SHIMS)


if __name__ == "__main__":
    sys.exit(main())
