#!/usr/bin/env python3
"""Shared Bash-command decomposition + `defender-*` shim taxonomy.

Two PreToolUse hooks reason about the same things — how a Bash command
decomposes into shell segments, and which `defender-*` shims are
data-source *adapters* (must be routed through the capture wrapper) vs.
*non-adapter* tooling. Keeping that logic in one place means a newly
onboarded adapter shim auto-gates everywhere with no per-hook edit.

Consumers:
  - ``approve_shim_invocations.py`` — auto-approve safe shim / read-only
    compositions.
  - ``block_unwrapped_adapter_calls.py`` — deny an adapter call inside the
    gather subagent unless it's wrapped in ``defender-record-query``.

This module is pure (parsing + a cheap ``bin/`` dir read); no IO beyond
listing ``defender/bin``.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

# This file lives at <repo>/defender/hooks/_cmd_segments.py → parents[2] is the
# repo root, matching run.py's REPO_ROOT and the hook modules.
REPO_ROOT = Path(__file__).resolve().parents[2]

# Non-adapter shims: corpus query + gather's own wrappers. Everything else
# under defender/bin/ that starts with `defender-` is a data-source adapter.
# This is the single source of truth for the split — all three gate hooks
# (approve_shim_invocations, block_unwrapped_adapter_calls,
# block_main_loop_raw_access) derive their adapter set from here.
# `defender-lessons` is read-only corpus tooling (frontmatter grep / tag
# enumeration); it queries no data source, so it stays a non-adapter and
# remains allowed in the main loop.
NON_ADAPTER_SHIMS = frozenset(
    {"defender-invlang", "defender-record-query", "defender-data-source-debug",
     "defender-lessons"}
)

# A raw adapter-CLI path form (`scripts/tools/<name>_cli.py`), i.e. the shim's
# underlying script invoked directly rather than via its `defender-*` token.
# `record_query.py` / `data_source_debug.py` are NOT `_cli.py` and don't match.
# Kept in sync with block_main_loop_raw_access.ADAPTER_CLI_RE.
ADAPTER_CLI_RE = re.compile(r"scripts/tools/\w+_cli\.py\b")


def all_defender_shims() -> set[str]:
    """All `defender-*` shim names from defender/bin/ (cheap dir read). Falls
    back to the known non-adapter set if the dir is unreadable."""
    bin_dir = REPO_ROOT / "defender" / "bin"
    try:
        return {p.name for p in bin_dir.iterdir() if p.name.startswith("defender-")}
    except OSError:
        return set(NON_ADAPTER_SHIMS)


def adapter_shims() -> set[str]:
    """The data-source adapter shims = every `defender-*` shim minus the
    non-adapter tooling. These are the calls that must be captured."""
    return all_defender_shims() - set(NON_ADAPTER_SHIMS)


def unwrap(cmd: str) -> str | None:
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
    if i > 0:
        # A `timeout <n>` prefix was stripped but no `bash -c` followed — return
        # the remainder so callers see the real command at the head, not
        # `timeout`. (Re-quote only this stripped case; leave a plain command's
        # original text untouched to avoid spurious quoting differences.)
        return shlex.join(tokens[i:])
    return cmd


def split_segments(script: str) -> list[str]:
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
            segs.append("".join(buf))
            buf = []
            i += 2
        elif c in "|;":
            segs.append("".join(buf))
            buf = []
            i += 1
        else:
            buf.append(c)
            i += 1
    segs.append("".join(buf))
    return segs
