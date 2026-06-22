#!/usr/bin/env python3
"""Shared Bash-command decomposition + `defender-*` shim taxonomy.

The in-process gate reasons about the same things — how a Bash command
decomposes into shell segments, and which `defender-*` shims are
data-source *adapters* (captured transparently by the gather bash tool) vs.
*non-adapter* tooling. Keeping that logic in one place means a newly
onboarded adapter shim auto-gates everywhere with no per-site edit.

Consumers (all via `runtime/permission.py`, which imports these predicates):
  - ``approve_shim_invocations`` — auto-approve safe shim / read-only
    compositions.
  - ``block_main_loop_raw_access`` — clamp adapters / `gather_raw` out of
    the main loop.

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
# This is the single source of truth for the split — the in-process gate
# (runtime/permission.py, via the approve_shim_invocations +
# block_main_loop_raw_access predicates) derives its adapter set from here.
# `defender-lessons` is read-only corpus tooling (frontmatter grep / tag
# enumeration); it queries no data source, so it stays a non-adapter and
# remains allowed in the main loop.
# `defender-sql` aggregates a payload piped into it on stdin (the tier-2
# fallback for a source with no native aggregation); it queries no source and
# is self-sandboxed (no file/network access), so it is a non-adapter too.
NON_ADAPTER_SHIMS = frozenset(
    {"defender-invlang", "defender-record-query",
     "defender-lessons", "defender-sql"}
)

# A raw adapter-CLI path form (`scripts/adapters/<name>_cli.py`), i.e. the
# shim's underlying script invoked directly rather than via its `defender-*`
# token. The `_cli.py` suffix IS the structural marker for an adapter: every
# non-adapter script deliberately avoids it (`record_query.py`, `sql.py`) so it
# can't be misread as an adapter here.
# Kept in sync with block_main_loop_raw_access.ADAPTER_CLI_RE.
ADAPTER_CLI_RE = re.compile(r"scripts/adapters/\w+_cli\.py\b")


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
    """Strip a leading `timeout <n>` and an exact `bash -c`/`sh -c` wrapper,
    returning the inner script. The `-c` must be the token IMMEDIATELY after
    `bash`/`sh` (a `bash <script> -c …` form runs the script, not the payload) and
    the payload must be the sole remaining token. Returns the command unchanged if
    there is nothing to unwrap, or None if the `-c` payload can't be cleanly
    extracted (wrong form, missing payload, or a trailing command)."""
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
    if i < len(tokens) and tokens[i] in ("bash", "sh"):
        # Real shell semantics: the first non-option word after `bash`/`sh` is the
        # SCRIPT FILE, and a `-c` after it is just a positional arg to that script
        # (`bash evil.sh -c '…'` RUNS evil.sh). Only the exact `bash -c <payload>`
        # inline form is the wrapper we unwrap: require `-c` to be the IMMEDIATE
        # next token and the payload to be the sole remaining token. Anything
        # AFTER the payload (`bash -c '…' ; rm`, `… && curl`, a trailing newline +
        # command) is a SEPARATE command the OUTER shell runs but the gate would
        # never inspect. Anything else — `bash <script> …`, a missing payload, a
        # trailing command — fails closed.
        if i + 1 < len(tokens) and tokens[i + 1] == "-c":
            if i + 2 == len(tokens) - 1:
                return tokens[i + 2]  # the quoted script payload
            return None  # missing payload OR a trailing command
        return None  # `bash <script> …` / bare `bash` — not the inline `-c` form
    if i > 0:
        # A `timeout <n>` prefix was stripped but no `bash -c` followed — return the
        # remainder so callers see the real command at the head, not `timeout`. Strip
        # the prefix off the ORIGINAL text rather than `shlex.join`-ing the remaining
        # tokens: join would quote operators (`|` → `'|'`, hiding a pipeline from the
        # splitter) and collapse a newline into a space (hiding a second command the
        # shell still runs). The prefix tokens are simple unquoted words, so consume
        # them off the raw string verbatim.
        rest = cmd.lstrip(" \t")
        for tok in tokens[:i]:
            if not rest.startswith(tok):
                return None  # prefix didn't sit at the head as parsed — fail closed
            rest = rest[len(tok):].lstrip(" \t")
        return rest
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
    # Disable comment stripping (shlex defaults `commenters="#"`). The shell only
    # starts a comment at a `#` that begins a word; shlex would strip from ANY
    # unquoted `#` to end-of-line, silently truncating a query value/pattern/path
    # that contains a `#` (e.g. `grep INC#1234 f.json` -> `['grep','INC']`). The
    # old `shlex.split`-based path disabled comments too; keep that parity.
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:
        return None


def split_segments(script: str) -> list[list[str]]:
    """Decompose a command into per-command token lists, split on top-level shell
    separators (`|`/`||`/`&&`/`;` AND an unquoted newline). Tokenization is `shlex`'s
    job, so a `|`/`;`/an escaped `\\"` inside a jq filter is token content, not a
    separator (the false splits the old char-scanner made on a stray `\\"` are gone).
    Returns a list of token lists (each the argv of one command, with redirect/
    operator tokens kept in place); on unbalanced quotes, the whole script comes back
    as a single opaque token so the head/safety checks refuse it rather than
    mis-parsing."""
    segs: list[list[str]] = [[]]
    # A shell treats an unquoted newline as a command separator, but `shlex`
    # (whitespace_split) swallows it as ordinary whitespace — so `jq x⏎rm -rf /`
    # would tokenize to ONE command and the `rm` would hide as args behind a safe
    # head. Tokenize per physical line so the newline boundary survives as a split.
    # A quote that spans a newline makes a line untokenizable → opaque (fail closed);
    # an inline multi-line quoted arg has a single-line rewrite and isn't worth a hole.
    for line in script.split("\n"):
        toks = tokenize(line)
        if toks is None:
            return [[script]]
        for t in toks:
            if t in _SEGMENT_SEPARATORS:
                segs.append([])
            else:
                segs[-1].append(t)
        segs.append([])  # the newline itself ends this command
    return segs
