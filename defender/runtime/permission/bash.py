
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
"""#851 F-07/F-10. Denied on the WHOLE command string, ahead of the parse, because the two
places that would otherwise catch a NUL each miss half the surface. `_in_scope`'s
`RESOLVE_ERRORS` arm only runs for a program whose extractor OPENS something — every
`OPENS_NOTHING` grant (grep/echo/wc/python3/rm/the `defender-*` shims) was ALLOWED with a NUL
in its argv, and `encode_request` then raised a bare `ValueError` out of `BoxExecutor.run_parsed`
that no handler between there and `run.py::main` catches, killing the whole investigation instead
of refusing one command. And `_claim` cannot tell a NUL a token really carries from the
`_TOKEN_SPACE` sentinel it substitutes for an intra-token space — the two collapse in the very
string every grant pattern is `fullmatch`ed against. Refusing the whole command outright closes
both, and is free: no legitimate command carries one."""


UNTOKENIZABLE_REASON = (
    "Blocked: the command could not be tokenized — an unbalanced quote, a trailing "
    "`\\`, or a `|`/`&&`/`||` without a complete command on BOTH sides. Each PHYSICAL LINE "
    "is lexed on its own (there is no shell to join them), so a `\\` line-continuation, a "
    "newline inside a quoted argument, and a connector that opens or closes a line (`A |` "
    "then `B`, or `A` then `| B`) all fail here, even when the command is otherwise "
    "allowed — rewrite those as a SINGLE line. A connector whose other side is empty "
    "WITHIN one line fails for the same reason and rewriting it as one line will not help: "
    "`A | ; B`, `A | | B`, `A && ;`, `A | 2>/dev/null` each drop the connector and leave a "
    "stage running on nothing. Give every `|`/`&&`/`||` one complete command on each side."
)


def _parse(cmd: str) -> list[bash_exec.Pipeline] | None:
    inner = unwrap(cmd)
    if inner is None:
        return None
    try:
        return bash_exec.parse(inner)
    except bash_exec.UntokenizableCommand:
        raise
    except bash_exec.BashExecError:
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
        # #691 MD-3: this grant opted IN to a resolve()+scope recheck on its own operand (e.g.
        # the curator's `rm`, whose PROGRAM-level extractor stays OPENS_NOTHING for every other
        # rm grant) — a symlink inside the corpus pointing outside it must be caught by resolving
        # the operand, not merely by the pattern matching the pre-resolution text.
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
    cmd = command.strip()
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
