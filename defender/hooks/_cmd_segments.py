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
    {"defender-invlang", "defender-record-query", "defender-record-summary",
     "defender-data-source-debug", "defender-lessons"}
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


# Shell command separators: a `;`/`|`/`||`/`&&` at top level ends one command and
# begins the next. (A bare `&` background operator is intentionally NOT a separator
# here, preserving the prior splitter's behavior.) `shlex(punctuation_chars=True)`
# emits these — and redirects like `>` — as their own tokens, but only when they
# are OUTSIDE quotes; a `|`/`>` inside a jq filter stays part of its token.
_SEGMENT_SEPARATORS = frozenset({"|", "||", "&&", ";"})


def tokenize(script: str) -> list[str] | None:
    """Shell tokens via stdlib `shlex` (POSIX + `punctuation_chars`): quotes and
    backslash escapes are resolved by the tokenizer, and shell operators
    (`|`/`||`/`&&`/`;`/`&`/redirects) come back as their own tokens. Returns the
    token list, or None on unbalanced quotes (callers fail closed). Replaces the
    hand-rolled quote/escape state machine this module used to carry."""
    lex = shlex.shlex(script, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        return None


def split_segments(script: str) -> list[list[str]]:
    """Decompose a command into per-command token lists, split on top-level shell
    separators (`|`/`||`/`&&`/`;`). Tokenization is `shlex`'s job, so a `|`/`;`/an
    escaped `\\"` inside a jq filter is token content, not a separator (the false
    splits the old char-scanner made on a stray `\\"` are gone). Returns a list of
    token lists (each the argv of one command, with redirect/operator tokens kept
    in place); on unbalanced quotes, the whole script comes back as a single opaque
    token so the head/safety checks refuse it rather than mis-parsing."""
    toks = tokenize(script)
    if toks is None:
        return [[script]]
    segs: list[list[str]] = [[]]
    for t in toks:
        if t in _SEGMENT_SEPARATORS:
            segs.append([])
        else:
            segs[-1].append(t)
    return segs
