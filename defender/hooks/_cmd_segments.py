#!/usr/bin/env python3
"""Shared command unwrapping + `defender-*` shim taxonomy.

Two concerns the gate shares: how to strip a leading `timeout`/`bash -c`
wrapper off a command (`unwrap`/`tokenize`), and which `defender-*` shims are
data-source *adapters* (captured transparently by the gather bash tool) vs.
*non-adapter* tooling. Keeping the taxonomy in one place means a newly
onboarded adapter shim auto-gates everywhere with no per-site edit.

Consumers:
  - ``runtime/bash_exec`` — the no-shell executor (`unwrap`/`tokenize`).
  - ``runtime/permission`` — the in-process gate (the taxonomy + `unwrap`).
  - ``block_main_loop_raw_access`` — the main-loop adapter/raw deny reasons.

The argv-stage decomposition the gate validates against now lives with the
executor (`bash_exec.parse`), so validator and executor share one decomposition
(#379) — this module no longer splits commands into segments.

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


def is_main_session(hook_data: dict) -> bool:
    """True for the top-level agent loop, False for a Task subagent.

    The discriminator is `agent_id`: the PreToolUse payload carries it (plus
    `agent_type`) ONLY when the hook fires inside a subagent call; the main loop
    has neither (per the hooks reference, confirmed empirically). cwd is NOT
    usable — run.py spawns the orchestrator and every gather subagent in-process
    at the same cwd (REPO_ROOT), so a `cwd == REPO_ROOT` test flags gather
    subagents as the main loop and wrongly blocks their legitimate gather_raw
    reads. Absence of `agent_id` → main loop → apply the clamps."""
    return not hook_data.get("agent_id")

# Non-adapter shims: corpus query + gather's own wrappers. Everything else
# under defender/bin/ that starts with `defender-` is a data-source adapter.
# This is the single source of truth for the split — the in-process gate
# (runtime/permission.py) derives its adapter set from here.
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

# OPERATOR tools: a `defender-*` binary that is neither an adapter NOR a shim any agent may
# run. `defender-policy` (the gate's audit CLI) is the first: it is for a HUMAN reading a
# policy, and it must reach no agent's lane — a read of its own gate is a map of what to
# attack, and for the judge a map of exactly which grants stand between it and the answer key.
#
# It needs its own category because the taxonomy above is a BINARY split with a dangerous
# default: "every `defender-*` that is not a listed shim is a data-source adapter". Dropping a
# new binary into `defender/bin/` therefore hands it to gather — which may run adapters, and
# would capture its output into the queries table as if it were evidence. Being in neither set
# is what makes it deny for everyone (no grant claims it, and no adapter route rescues it).
OPERATOR_TOOLS = frozenset({"defender-policy"})

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
    """The data-source adapter shims = every `defender-*` shim minus the non-adapter tooling
    and the operator tools. These are the calls that must be captured."""
    return all_defender_shims() - set(NON_ADAPTER_SHIMS) - set(OPERATOR_TOOLS)


def _skip_timeout_prefix(tokens: list[str]) -> int:
    """Index of the first token past a leading `timeout <n>` / `timeout -k <n>
    <n>` prefix (0 if there is none). The prefix is `timeout` followed by its
    option flags / numeric durations."""
    i = 0
    if tokens[i] == "timeout":
        i += 1
        while i < len(tokens) and (tokens[i].startswith("-") or tokens[i].replace(".", "").isdigit()):
            i += 1
    return i


def _unwrap_bash_c(tokens: list[str], i: int) -> str | None:
    """Extract the inline `bash -c <payload>` / `sh -c <payload>` script payload,
    where `tokens[i]` is the `bash`/`sh` token. Returns the payload, or None if
    it can't be cleanly extracted (wrong form, missing payload, or a trailing
    command)."""
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


def _strip_prefix_from_raw(cmd: str, prefix_tokens: list[str]) -> str | None:
    """Return `cmd` with `prefix_tokens` (a stripped `timeout <n>` prefix) consumed
    off the head of the ORIGINAL text — not `shlex.join`-ed from the remaining
    tokens: join would quote operators (`|` → `'|'`, hiding a pipeline from the
    splitter) and collapse a newline into a space (hiding a second command the
    shell still runs). The prefix tokens are simple unquoted words, so consume
    them off the raw string verbatim. Returns None if the prefix didn't sit at the
    head as parsed (fail closed)."""
    rest = cmd.lstrip(" \t")
    for tok in prefix_tokens:
        if not rest.startswith(tok):
            return None  # prefix didn't sit at the head as parsed — fail closed
        rest = rest[len(tok):].lstrip(" \t")
    return rest


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
    i = _skip_timeout_prefix(tokens)
    if i < len(tokens) and tokens[i] in ("bash", "sh"):
        return _unwrap_bash_c(tokens, i)
    if i > 0:
        # A `timeout <n>` prefix was stripped but no `bash -c` followed — return the
        # remainder so callers see the real command at the head, not `timeout`.
        return _strip_prefix_from_raw(cmd, tokens[:i])
    return cmd


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
