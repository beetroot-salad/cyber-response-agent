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
# The `datamash` + coreutils filters (`cut`/`comm`/`join`/`tr`/`paste`/`nl`) are
# the pure-transform analysis suite the gather SKILL §4 self-test step runs bare
# (e.g. `jq -r '…|@tsv' f | sort | datamash …`) before recording the value
# through `defender-record-summary`; they have no exec/network/write surface.
READONLY_TOOLS = frozenset(
    {"jq", "cat", "tail", "head", "ls", "wc", "echo", "cd", "grep", "sort", "uniq",
     "true", "datamash", "cut", "comm", "join", "tr", "paste", "nl"}
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

# A leading `VAR=value` env-assignment prefix (the credential-groping vector) —
# matched against the first token of a segment only.
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


# Shell-operator metacharacters. `shlex(punctuation_chars=True)` returns a RUN of
# these as one standalone token, but only when UNQUOTED (a `>`/`|` inside a quoted
# jq filter stays inside its word-token). After `split_segments` consumes the
# top-level separators (`|`/`||`/`&&`/`;`), the only all-operator tokens left in a
# segment are redirects (`>`, `>>`, `<`, `>&`, `&>`), a bare background `&`, and the
# FUSED forms shlex emits but the splitter does NOT separate (`>|`, `|&`, `&>|`).
# Any such token is unsafe to auto-approve (except a benign stderr redirect). We
# test set-membership, not specific spellings, so a new fused operator can't slip
# through a hardcoded list (the bug a `set(tok) <= {"<",">","&"}` redirect-only
# check had: `>|`/`|&` carry a `|` and were silently treated as safe word tokens).
_OPERATOR_CHARS = frozenset("<>|&")


def _is_benign_stderr(toks: list[str], i: int) -> bool:
    """Is the redirect token at `toks[i]` a benign stderr redirect — `2>/dev/null`
    (discard) or `2>&1` (merge into stdout)? Tokenized as `2 > /dev/null` /
    `2 >& 1`. These don't write a file or exfiltrate (the harness captures stderr
    regardless), so they don't disqualify an otherwise read-only command. Any other
    redirect (a stdout `>`, `1>`, a stderr write to a real file — including `2>1`,
    a write to a file literally named `1`, whose operator token is a bare `>`, not
    the `>&` of the merge) is NOT benign."""
    prev = toks[i - 1] if i > 0 else None
    nxt = toks[i + 1] if i + 1 < len(toks) else None
    if prev != "2":
        return False
    return (toks[i] == ">" and nxt == "/dev/null") or (toks[i] == ">&" and nxt == "1")


def _segment_unsafe(toks: list[str]) -> bool:
    """True if a command's token list carries a construct unsafe to auto-approve:
    a (non-benign) redirect or other shell operator (`>|`, `|&`, a bare background
    `&`, …), a command substitution (`$(`/backtick), an `export`, or a leading
    `VAR=` assignment. Quote-correct: a `>`/`<` inside a quoted jq filter is token
    content (it's a char of a larger word-token, not an all-operator token), so jq
    comparisons don't trip this — the false positive that hard-denied valid summary
    computations in the in-process gate. A real redirect/substitution still does.
    Conservative on the rare single-quoted `$(`/backtick literal (flagged though
    inert) — a false passthrough, never a false approval."""
    for i, t in enumerate(toks):
        # An all-operator token (see _OPERATOR_CHARS): a redirect, a bare `&`, or a
        # fused operator the splitter left in place. Unsafe unless benign stderr.
        if t and set(t) <= _OPERATOR_CHARS:
            if _is_benign_stderr(toks, i):
                continue
            return True
        # An UNQUOTED `(`/`)` is its own token (punctuation_chars) — a subshell or
        # `$(…)` command substitution. Quoted parens inside a jq filter stay inside
        # their token and never appear here, so jq `select(…)` is unaffected.
        if t in ("(", ")"):
            return True
        # `$(…)`/backtick that survived as a single token (the quoted form, e.g.
        # `"$(cmd)"`, which the shell still evaluates).
        if "$(" in t or "`" in t:
            return True
        if t == "export":
            return True
        if i == 0 and _ENV_ASSIGN_RE.match(t):
            return True
    return False


def _is_main_session(hook_data: dict) -> bool:
    """Main loop = no `agent_id`; a Task subagent's PreToolUse payload carries it
    (and `agent_type`). cwd is NOT usable — v2 runs the orchestrator and every
    gather subagent in-process at the same cwd. Matches
    block_main_loop_raw_access._is_main_session."""
    return not hook_data.get("agent_id")


def _all_segments_safe(script: str, safe_leading: frozenset) -> bool:
    for toks in _split_segments(script):
        if not toks:
            continue
        if _segment_unsafe(toks):
            return False
        head = toks[0]
        if head not in safe_leading:
            return False
        # `find` is read-only only without its action flags (-exec/-delete/…),
        # and must not be a locator for denied-read files (secrets / ground truth).
        # Reject either wherever find is in safe_leading (gather); in the main loop
        # find isn't in the set, so the head check above already denied it.
        if head == "find":
            joined = " ".join(toks)
            if _FIND_DANGER_RE.search(joined) or _FIND_SENSITIVE_RE.search(joined):
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
