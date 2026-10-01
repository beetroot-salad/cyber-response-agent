
from __future__ import annotations

import dataclasses
import re
from defender._model import model
from pathlib import Path

from defender.runtime import bash_exec

from . import command_shape
from .decision import Decision
from .files import RESOLVE_ERRORS, denylisted, names_run_provenance, names_wire_log_dir
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


@model(frozen=True)
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
"""Denied on the whole command string, ahead of the parse. Otherwise an `OPENS_NOTHING` grant
would pass a NUL through to `encode_request`, whose `ValueError` kills the investigation, and
`_claim` would confuse a real NUL with its `_TOKEN_SPACE` sentinel. No legitimate command
carries one."""


#: Everything the agent is told about this refusal; it lives here rather than in the always-on
#: `SKILL.md` so the cost is paid only on failure, which means it must be complete on its own.
#: A test pins every cause against what `parse` actually refuses.
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
    "Redirects (`>`, `>>`), background `&`, and `$(...)` substitution are not part of this "
    "surface at all, and are refused as capability, not syntax. Neither is `bash`/`sh`: there "
    "is no shell to invoke, so `bash -c '<cmd>'` is refused as an ungranted program — send "
    "`<cmd>` on its own."
)


def _parse(cmd: str) -> list[bash_exec.Pipeline] | None:
    try:
        return bash_exec.parse(cmd)
    except bash_exec.UntokenizableCommand:
        raise
    except bash_exec.BashExecError:
        # Lexed fine but asks for something this surface does not offer (a redirect, a
        # background job), so it gets the policy deny reason, not the lexing one.
        return None


def _is_blank(cmd: str) -> bool:
    """Is `cmd` nothing but bash's own blanks (the allowed no-op)? Uses the scanner's
    `bash_exec.BLANKS`, not `str.strip()`, which removes 26 characters the scanner keeps."""
    return all(c in bash_exec.BLANKS for c in cmd)


#: The 26 characters `str.strip()` removes that the scanner never treats as a blank. Frozen
#: rather than derived to avoid a ~80ms Unicode sweep at import; the test corpus carries the
#: derivation this tuple must equal.
_DIVERGENT_BLANK_CODEPOINTS = (
    0x000B, 0x000C, 0x000D, 0x001C, 0x001D, 0x001E, 0x001F, 0x0085,
    0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
    0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F,
    0x205F, 0x3000,
)
_DIVERGENT_BLANKS = frozenset(chr(cp) for cp in _DIVERGENT_BLANK_CODEPOINTS)


def _strip_unquoted(text: str, target: str, replacement: str) -> str:
    """`text` with every bare occurrence of `target` replaced by `replacement`. Quoted ones
    are untouched; a backslash-escaped one is deleted with its escape left standing. Used only
    to build the counterfactual `_core_decide` compares against.

    The caller passes a space, not `""`: deleting a `\\r` could glue `2` to `>` in
    `cat P 2<CR>>/dev/null` into an allowed fd-2 redirect.

    Known gap: the reason text says "remove the invisible character" while the edit tested is
    replacement by a space, so e.g. `cat<CR>/run/report.md` is named but removing the character
    still fails."""
    out: list[str] = []
    quote: str | None = None
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if quote is None:
            if c == "\\" and i + 1 < n:
                nxt = text[i + 1]
                if nxt == target:
                    # Escaped: the scanner never splits here, so the only meaningful
                    # counterfactual is the character's absence; the backslash stays.
                    out.append(c)
                    i += 2
                    continue
                out.append(c)
                out.append(nxt)
                i += 2
                continue
            if c in ("'", '"'):
                quote = c
                out.append(c)
                i += 1
                continue
            if c == target:
                out.append(replacement)
                i += 1
                continue
            out.append(c)
            i += 1
            continue
        if c == "\\" and quote == '"' and i + 1 < n and text[i + 1] in ('"', "\\", "$", "`"):
            out.append(c)
            out.append(text[i + 1])
            i += 2
            continue
        if c == "\n" or c == quote:
            # A newline closes the quote because `parse` lexes each physical line separately;
            # this walker must agree with the scanner.
            quote = None
        out.append(c)
        i += 1
    return "".join(out)


def _core_decide(command: str, policy: AgentPolicy, run_dir: Path | None) -> BashDecision:
    """The whole decision ladder. The invisible-character counterfactual reruns this same
    function on an edited command, so both sides of the comparison always agree on everything
    but the edit."""
    if _is_blank(command):
        return BashDecision(True)
    if "\x00" in command:
        return BashDecision(False, EMBEDDED_NUL_REASON)
    try:
        pipelines = _parse(command)
    except bash_exec.UntokenizableCommand:
        return BashDecision(False, UNTOKENIZABLE_REASON)
    if pipelines is None:
        return BashDecision(False, policy.deny_reason)
    reader = _decide_readers(pipelines, policy, run_dir=run_dir)
    if reader is not None:
        return reader
    if command_shape.has_adapter(pipelines):
        return BashDecision(False, ADAPTER_RETIRED_REASON)
    return BashDecision(False, policy.deny_reason)


def _decision_key(decision: BashDecision) -> tuple[bool, str]:
    """What a counterfactual is compared on: the answer and its reason."""
    return decision.allow, decision.reason


#: The one divergent blank that is an ordinary character everywhere in a word, not a
#: separator, so its responsibility check covers the unquoted interior. Other divergent blanks
#: are checked only at the command's ends; checking them everywhere would flag a glued interior
#: character such as `echo a<NBSP>b`.
_CR = "\r"


def _blanks_removed(command: str, chars: str) -> str:
    """`command` with `chars` removed from both ends and, for `\\r` alone, replaced anywhere
    unquoted.

    The strip set includes `bash_exec.BLANKS` so an ordinary trailing newline cannot shield an
    invisible character behind it; this is verdict-neutral because the scanner skips edge
    blanks. It strips whole runs, since pastes often carry several. The strip must run before
    the `\\r` edit, or a leading `\\r` would stop the strip and hide what follows it."""
    out = command.strip(chars + bash_exec.BLANKS)
    return _strip_unquoted(out, _CR, " ") if _CR in chars else out


def _name_responsible_divergent_char(
    command: str, policy: AgentPolicy, run_dir: Path | None, decision: BashDecision,
) -> str | None:
    """A reason naming, by codepoint, the invisible character(s) that cause `command`'s
    refusal, or `None` if none is responsible.

    Responsibility is checked by removing the character (see `_blanks_removed`) and re-running
    the decision. Checked per character first, then jointly, since a command with two
    different edge blanks (`<VT>cat P<FF>`) has no single responsible character."""
    # Runs on every deny, so keep the common no-candidate case cheap.
    candidates = sorted(_DIVERGENT_BLANKS.intersection(command))
    if not candidates:
        return None
    current = _decision_key(decision)
    responsible = [
        c for c in candidates
        if (variant := _blanks_removed(command, c)) != command
        and _decision_key(_core_decide(variant, policy, run_dir)) != current
    ]
    if not responsible and len(candidates) > 1:
        joint = _blanks_removed(command, "".join(candidates))
        if joint != command and _decision_key(_core_decide(joint, policy, run_dir)) != current:
            # Name only what the joint edit actually removed: a blank inside a word is data.
            # Counted, not re-probed, since some are reachable only jointly
            # (`<VT><NBSP>cat P`).
            responsible = [c for c in candidates if joint.count(c) != command.count(c)]
    if not responsible:
        return None
    names = ", ".join(f"U+{ord(c):04X}" for c in responsible)
    return (
        "Blocked: this command is refused because of a character that renders as nothing on "
        f"screen ({names}) sitting where it changes which word the text names to bash — the "
        "command can look on screen exactly like one that works. Remove the invisible "
        f"character and re-send it. ({decision.reason})"
    )


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
        # Opted-in resolve+scope recheck (e.g. the curator's `rm`), so a symlink pointing out
        # of the corpus is caught.
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
        # Mirrors `decide_read`: the judge's `cat` scope `under(run, TREE)` would otherwise
        # admit these.
        if denylisted(rp) or names_wire_log_dir(rp) or names_run_provenance(rp, run_dir):
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
    # No trim: the parser gets the model's text byte for byte, so the argv checked is the argv
    # run. A Unicode trim would strip characters the scanner keeps inside a word.
    effective_run_dir = cwd_anchor if cwd_anchor is not None else run_dir

    decision = _core_decide(command, policy, effective_run_dir)
    if decision.allow or decision.reason == EMBEDDED_NUL_REASON:
        # The NUL reason already names its character, and no counterfactual removes a NUL.
        return decision

    named = _name_responsible_divergent_char(command, policy, effective_run_dir, decision)
    return decision if named is None else dataclasses.replace(decision, reason=named)
