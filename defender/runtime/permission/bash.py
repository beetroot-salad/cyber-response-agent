
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from defender.hooks._cmd_segments import unwrap
from defender.runtime import bash_exec

from . import command_shape
from .decision import Decision
from .files import RESOLVE_ERRORS, denylisted, names_wire_log_dir
from .grant import OPENS_NOTHING, PROGRAMS, Grant, Route, rm_target_files
from .policy import AgentPolicy


ADAPTER_RETIRED_REASON = (
    "Blocked: data-source adapters are not runnable from bash. Reach the system through the "
    "`query` tool instead — `query(system=…, verb=…, params={…}, query_id=…)`; it validates the "
    "verb's params against the registry, captures the payload to the queries table, and hands "
    "you the path. To aggregate that payload afterwards: "
    "`cat <ABSOLUTE payload path> | defender-sql '<SQL>'`."
)

_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass(frozen=True)
class BashDecision(Decision):

    pipelines: tuple[bash_exec.Pipeline, ...] | None = None
    grants: tuple[Grant, ...] = ()


def _stage_unsafe(argv: list[str]) -> bool:
    for i, t in enumerate(argv):
        if t in ("(", ")"):
            return True
        if "$(" in t or "`" in t:
            return True
        if t == "export":
            return True
        if i == 0 and _ENV_ASSIGN_RE.match(t):
            return True
    return False


EMBEDDED_NUL_REASON = (
    "Blocked: the command contains a NUL byte (U+0000), which no command can carry — it "
    "cannot cross the box wire, and it makes an operand unresolvable. Re-send the command "
    "without it."
)
"""Denied on the WHOLE command string, ahead of the parse, because the two places that would
otherwise catch a NUL each miss half the surface. `_in_scope`'s `RESOLVE_ERRORS` arm only runs
for a program whose extractor OPENS something, so every `OPENS_NOTHING` grant (grep/echo/wc/
python3/rm/the `defender-*` shims) passes with a NUL in its argv — and `encode_request` then
raises a bare `ValueError` out of `BoxExecutor.run_parsed` that nothing up to `run.py::main`
catches, killing the investigation instead of refusing one command. `_claim`, meanwhile, cannot
tell a NUL a token really carries from the `_TOKEN_SPACE` sentinel it substitutes for an
intra-token space; the two collapse in the very string every grant pattern is `fullmatch`ed
against. Refusing outright closes both, and is free: no legitimate command carries one."""


#: The whole of what the agent is told about this refusal, and the only place the full list
#: lives — deliberately paid once on the (rare) failure rather than standing in `SKILL.md`, the
#: always-on system prompt, so this string has to be complete on its own.
#:
#: `skills/advisory/SKILL.md` still carries a one-line "send it as ONE physical line" note: it
#: is loaded ON DEMAND while its own very long invocation is composed, so it costs no standing
#: context and preempts the round-trip rather than explaining it afterwards.
#:
#: Every cause below is pinned by `test_the_lexing_reason_names_every_way_a_command_can_fail_
#: to_parse` — the guard against this list drifting from what `parse`/`unwrap` actually refuse.
UNTOKENIZABLE_REASON = (
    "Blocked: the command could not be parsed. There is no shell here, so each PHYSICAL LINE "
    "is lexed on its own and every stage runs as a bare argv. The causes, all of which fail "
    "even when the command is otherwise allowed:\n"
    "(1) An unbalanced quote, or a newline INSIDE a quoted argument — a quoted string cannot "
    "span lines, so a pretty-printed SQL/JSON argument must be collapsed onto one line.\n"
    "(2) A trailing `\\` — it continues nothing, because there are no lines to join.\n"
    "(3) A `|`/`&&`/`||` at a line boundary (`A |` then `B`, or `A` then `| B`) — refused, "
    "not joined. Rewrite as a SINGLE line.\n"
    "(4) A `|` without a complete command on BOTH sides, or an `&&`/`||` left with no command "
    "at all to its right on its own line, WITHIN one line — `A | ; B`, `A | | B`, "
    "`A | 2>/dev/null`, `A && ;`, `A && 2>/dev/null`. Each would drop the connector and leave "
    "a stage reading nothing, so one line is already the fix and re-sending it on one line "
    "will not help; give every connector one complete command on each side.\n"
    "(5) A wrapper that does not unwrap to a single command string: anything other than "
    "exactly `bash -c '<one command string>'` (a bare `bash`, `bash script.sh`, `sh -lc …`, a "
    "stray word after the string), or a `timeout …` prefix whose own words are quoted.\n"
    "Redirects (`>`, `>>`), background `&`, and `$(...)` substitution are a separate matter: "
    "they are not part of this surface at all, and are refused as capability, not syntax."
)


def _parse(cmd: str) -> list[bash_exec.Pipeline] | None:
    inner = unwrap(cmd)
    if inner is None:
        # A LEXING failure, not a capability one: `unwrap` returns None on an unbalanced quote
        # (shlex raises), on a `bash`/`sh` wrapper that is not exactly one command string, and
        # on a `timeout` prefix it cannot strip back off the raw text (its words were quoted).
        # Raising here keeps them on `UNTOKENIZABLE_REASON` (whose cause (5) names them all)
        # rather than the caller's generic "not permitted for this agent" — a CAPABILITY message
        # for a QUOTING mistake tells the model to reach for another tool when what it needed was
        # to close its quote.
        raise bash_exec.UntokenizableCommand(
            "command could not be unwrapped to a single command string"
        )
    try:
        return bash_exec.parse(inner)
    except bash_exec.UntokenizableCommand:
        raise
    except bash_exec.BashExecError:
        # NOT a lexing refusal — an unexpected redirect or operator token. The command lexed
        # fine and says something this surface does not offer (a write, a background job), so
        # it stays on the policy deny reason, which is what teaches the lane's real capability.
        return None


def require_anchor_root(what: str, p: Path) -> None:
    p = Path(p)
    if not p.is_absolute() or len(p.parts) < 2 or ".." in p.parts:
        raise ValueError(
            f"{what} must be an absolute non-root path with no '..' segment, got {p!r} — a "
            "relative, filesystem-root, or ..-collapsing anchor would open reads to the CWD / "
            "whole filesystem."
        )
    if any(ch.isspace() for ch in str(p)):
        raise ValueError(
            f"{what} must not contain whitespace (a path shape's segments admit none), got {p!r}"
        )


def _allow(
    pipelines: list[bash_exec.Pipeline], *, grants: tuple[Grant, ...] = (),
) -> BashDecision:
    return BashDecision(True, pipelines=tuple(pipelines), grants=grants)


_TOKEN_SPACE = "\x00"


def _claim(argv: list[str], policy: AgentPolicy) -> Grant | None:
    joined = " ".join(t.replace(" ", _TOKEN_SPACE) for t in argv)
    for g in policy.bash_allow:
        if g.route is Route.PLAIN and g.pattern.fullmatch(joined):
            return g
    return None


def _in_scope(argv: list[str], grant: Grant, *, run_dir: Path | None) -> bool:
    extract = PROGRAMS[grant.program]
    if extract is OPENS_NOTHING and not grant.resolve_operand:
        return True
    if extract is OPENS_NOTHING and grant.resolve_operand:
        # This grant opted IN to a resolve()+scope recheck on its own operand (e.g. the curator's
        # `rm`, whose PROGRAM-level extractor stays OPENS_NOTHING for every other rm grant) — a
        # symlink inside the corpus pointing outside it must be caught by resolving the operand,
        # not merely by the pattern matching the pre-resolution text.
        extract = rm_target_files
    files = extract(argv)
    if files is None:
        return False
    if run_dir is None:
        return False
    cwd = run_dir
    for f in files:
        try:
            p = Path(f)
            rp = (p if p.is_absolute() else cwd / p).resolve()
        except RESOLVE_ERRORS:
            return False
        if denylisted(rp) or names_wire_log_dir(rp):
            return False
        if not any(shape.fullmatch(str(rp)) for shape in grant.scope):
            return False
    return True


def _decide_readers(
    pipelines: list[bash_exec.Pipeline], policy: AgentPolicy, *, run_dir: Path | None,
) -> BashDecision | None:
    stages = command_shape.flat_stages(pipelines)
    if not stages:
        return None
    claimed: list[Grant] = []
    for st in stages:
        g = _claim(st, policy)
        if g is None:
            return None
        claimed.append(g)
    if any(_stage_unsafe(s) for s in stages):
        return BashDecision(False, policy.deny_reason)
    pairs = zip(stages, claimed, strict=True)
    if not all(_in_scope(st, g, run_dir=run_dir) for st, g in pairs):
        return BashDecision(False, policy.deny_reason)
    return _allow(pipelines, grants=tuple(claimed))


def decide_bash(
    command: str, *, policy: AgentPolicy,
    run_dir: Path | None = None, defender_dir: Path | None = None,
    cwd_anchor: Path | None = None,
) -> BashDecision:
    # `bash_exec.BLANKS`, not a bare `.strip()`: `str.strip()` is a UNICODE predicate and
    # strips every character that set was deliberately narrowed to KEEP inside its word —
    # `\r`, NBSP, `\x0b`, `\x85`, U+2003. Trimming them here re-opens #955 F-50 one layer up:
    # `cat <run_dir>/report.md<NBSP>` was checked and RUN as `cat <run_dir>/report.md`, an argv
    # the model did not write, authorised on the rewritten one. The two trims have to be one
    # rule, so this one is told which set to use rather than trusted to agree.
    cmd = command.strip(bash_exec.BLANKS)
    if not cmd:
        return BashDecision(True)

    if "\x00" in cmd:
        return BashDecision(False, EMBEDDED_NUL_REASON)

    try:
        pipelines = _parse(cmd)
    except bash_exec.UntokenizableCommand:
        return BashDecision(False, UNTOKENIZABLE_REASON)
    if pipelines is None:
        return BashDecision(False, policy.deny_reason)

    reader = _decide_readers(
        pipelines, policy, run_dir=cwd_anchor if cwd_anchor is not None else run_dir,
    )
    if reader is not None:
        return reader

    if command_shape.has_adapter(pipelines):
        return BashDecision(False, ADAPTER_RETIRED_REASON)

    return BashDecision(False, policy.deny_reason)
