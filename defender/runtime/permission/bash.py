
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

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
#: to_parse` — the guard against this list drifting from what `parse` actually refuses.
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
        # NOT a lexing refusal — an unexpected redirect or operator token. The command lexed
        # fine and says something this surface does not offer (a write, a background job), so
        # it stays on the policy deny reason, which is what teaches the lane's real capability.
        return None


def _is_blank(cmd: str) -> bool:
    """Is `cmd` nothing but bash's own blanks — the allowed no-op, ahead of the parse
    (#959 M4/F1/FK4). Reads `bash_exec.BLANKS`, the scanner's own set, rather than owning a
    second opinion about what a blank is: `str.strip()` removes 26 characters the scanner does
    not, and answering the falsy/whitespace-only command from THAT predicate authorised an argv
    the text did not name. The falsy member (`""`) is `all()` over nothing, which is `True`."""
    return all(c in bash_exec.BLANKS for c in cmd)


#: The 26 characters `str.strip()` removed that the scanner never treats as a blank (claim a1;
#: #959's own frozen corpus, `defender/tests/_baseline_959.py`, carries the derivation this
#: tuple must equal). Frozen here, not derived at import time, purely for cost: the derivation
#: is a full Unicode sweep and this module is on the hot path of every bash decision.
_DIVERGENT_BLANK_CODEPOINTS = (
    0x000B, 0x000C, 0x000D, 0x001C, 0x001D, 0x001E, 0x001F, 0x0085,
    0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
    0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F,
    0x205F, 0x3000,
)
_DIVERGENT_BLANKS = frozenset(chr(cp) for cp in _DIVERGENT_BLANK_CODEPOINTS)


def _strip_unquoted(text: str, target: str, replacement: str) -> str:
    """`text` with every BARE occurrence of `target` replaced by `replacement`. A quoted one is
    left untouched, matching the fact that quoting suppresses separator recognition
    unconditionally, and a backslash-ESCAPED one is deleted with its escape left standing, for
    the reason spelled out at that arm below (#959 FK6). Used only to build the counterfactual
    `_raw_decide` compares against.

    `replacement` is the caller's, with no default: the ONE caller passes a real space,
    because `\\r` (M6) used to be a WORD SEPARATOR rather than a removed character, and simple
    deletion would also close a raw-text adjacency gap (`_is_fd_prefix`'s glue test) that has
    nothing to do with #959 and was never a separator question at all."""
    out: list[str] = []
    quote: str | None = None
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if quote is None:
            if c == "\\" and i + 1 < n:
                nxt = text[i + 1]
                if nxt == target:
                    # ESCAPED: the backslash STAYS and only the character goes. An escaped
                    # character was never a separator under either regime (`_literal_mask`
                    # marks it non-literal, so `_scan` has never split there), so "what if it
                    # were a separator" is not a question this position can be asked — the only
                    # counterfactual that means anything here is its plain ABSENCE, which is
                    # also exactly the edit the reason tells the model to make. Deleting the
                    # backslash with it modelled a split the scanner never performed, and named
                    # `\<CR>b` as CR-caused when nothing about it moved (a false accusation)
                    # while missing `\<CR>report.md`, where the CR really is the whole cause.
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
        if c == quote:
            quote = None
        out.append(c)
        i += 1
    return "".join(out)


def _raw_decide(command: str, policy: AgentPolicy, run_dir: Path | None) -> tuple[bool, str]:
    """The core decision `decide_bash` reaches, as a bare `(allow, reason)` — no codepoint
    naming. Used only as the comparison basis a counterfactual (a candidate character removed)
    is checked against; calling the real `decide_bash` here would recurse into the very naming
    logic this helper exists to feed."""
    if _is_blank(command):
        return True, "none"
    if "\x00" in command:
        return False, EMBEDDED_NUL_REASON
    try:
        pipelines = _parse(command)
    except bash_exec.UntokenizableCommand:
        return False, UNTOKENIZABLE_REASON
    if pipelines is None:
        return False, policy.deny_reason
    reader = _decide_readers(pipelines, policy, run_dir=run_dir)
    if reader is not None:
        return reader.allow, (reader.reason or "none")
    if command_shape.has_adapter(pipelines):
        return False, ADAPTER_RETIRED_REASON
    return False, policy.deny_reason


#: The one divergent-blank character whose behaviour changed EVERYWHERE a word can carry it,
#: not only at the two ends the deleted trim used to reach: `_BLANKS` carried `\r`
#: before M6, so a mid-word carriage return was a live separator then and is an ordinary
#: character now. Every other divergent blank was NEVER a separator anywhere but the two ends
#: (the deleted trim was the only old opinion that ever touched it), so its responsibility
#: check must stay confined to those ends — checking it everywhere would flag a glued interior
#: character (e.g. `echo a<NBSP>b`) that #959 never touched at all.
_CR = "\r"


def _edge_stripped(command: str, chars: str) -> str:
    """`command` with the leading and trailing RUNS of `chars` removed — the two positions the
    deleted trim (M4) used to affect, and it removed a RUN of them, not one character: a paste
    that carries two no-break spaces is the ordinary shape, and stripping only one leaves a
    counterfactual that still fails for the same reason and so names nothing at all. Quoting is
    irrelevant at a true edge of the raw command: nothing has opened a quote yet at position 0,
    and a quote opened earlier in a syntactically complete command is already closed by the
    end."""
    return command.strip(chars)


def _blanks_removed(command: str, chars: str) -> str:
    """`command` as it would read with `chars` gone from the positions #959 changed the
    treatment of — the two ends of the whole command (M4) and, for `\\r` alone, anywhere
    unquoted (M6)."""
    out = _strip_unquoted(command, _CR, " ") if _CR in chars else command
    return _edge_stripped(out, chars)


def _name_responsible_divergent_char(
    command: str, policy: AgentPolicy, run_dir: Path | None, base_reason: str,
) -> str | None:
    """A reason naming the divergent-blank character(s) that CAUSE `command`'s refusal — or
    `None` when no candidate character is actually responsible (#959 FK6, RC2/RC6/RC9/RC12).

    "Responsible" is checked, not asserted: for each divergent-blank character present in
    `command` at a position `#959` actually changed the treatment of — either end of the whole
    command (M4) or, for `\\r` alone, anywhere unquoted (M6) — remove it there and recompute the
    RAW decision; if it differs from the current one, this character's presence is what the
    current refusal turns on, and the model — which cannot see the character at all — is told
    which one by codepoint, the only way a reason can name a character that renders as nothing.

    Checked per character FIRST, so the usual single-character case names exactly the character
    responsible, and then JOINTLY over what is left: the trim removed every blank at both ends
    in one go, so a command carrying two DIFFERENT ones (`<VT>cat P<FF>`) has no single
    character whose removal changes anything, and testing one at a time reports nothing for the
    very paste-artifact shape the naming exists to explain."""
    candidates = sorted({c for c in command if c in _DIVERGENT_BLANKS}, key=ord)
    if not candidates:
        return None
    current = (False, base_reason)
    responsible = [
        c for c in candidates
        if (variant := _blanks_removed(command, c)) != command
        and _raw_decide(variant, policy, run_dir) != current
    ]
    if not responsible and len(candidates) > 1:
        joint = _blanks_removed(command, "".join(candidates))
        if joint != command and _raw_decide(joint, policy, run_dir) != current:
            responsible = candidates
    if not responsible:
        return None
    names = ", ".join(f"U+{ord(c):04X}" for c in responsible)
    return (
        "Blocked: this command is refused because of a character that renders as nothing on "
        f"screen ({names}) sitting where it changes which word the text names to bash — the "
        "command can look on screen exactly like one that works. Remove the invisible "
        f"character and re-send it. ({base_reason})"
    )


def _final_reason(
    command: str, policy: AgentPolicy, run_dir: Path | None, base: str,
) -> str:
    """The reason a DENY carries — named for a responsible invisible character (#959 FK6) when
    one is found, the plain `base` otherwise. `base` is required, not defaulted: the caller
    already knows which refusal it is answering, and re-coalescing `policy.deny_reason` here
    would put a second owner on that default (`defender/CLAUDE.md`, "Anchor a default in one
    place")."""
    named = _name_responsible_divergent_char(command, policy, run_dir, base)
    return named if named is not None else base


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
    # NO TRIM AT ALL here (#959 M4), where main narrowed the trim to `bash_exec.BLANKS`. Both
    # sides are answering the same defect — `str.strip()` is a UNICODE predicate and removed
    # `\r`, NBSP, `\x0b`, `\x85`, U+2003, every character the scanner was narrowed to KEEP
    # inside its word, so `cat <run_dir>/report.md<NBSP>` was checked and RUN as
    # `cat <run_dir>/report.md`, an argv the model did not write. Narrowing the trim closes
    # that; deleting it closes the class, because the parser is then handed the model's text
    # byte for byte and there is no second opinion left to disagree with the scanner. The
    # blank command is answered by `_is_blank`, which asks the scanner's own set.
    effective_run_dir = cwd_anchor if cwd_anchor is not None else run_dir

    if _is_blank(command):
        return BashDecision(True)

    if "\x00" in command:
        return BashDecision(False, EMBEDDED_NUL_REASON)

    try:
        pipelines = _parse(command)
    except bash_exec.UntokenizableCommand:
        # Through the naming step like every other deny (#959 FK6): a lexing refusal is exactly
        # where an invisible character lands, and the generic parse-failure text names none of
        # them, so the character that would fix the command has to be said out loud here.
        return BashDecision(
            False, _final_reason(command, policy, effective_run_dir, UNTOKENIZABLE_REASON),
        )
    if pipelines is None:
        return BashDecision(
            False, _final_reason(command, policy, effective_run_dir, policy.deny_reason),
        )

    reader = _decide_readers(pipelines, policy, run_dir=effective_run_dir)
    if reader is not None:
        if reader.allow:
            return reader
        # `_decide_readers` denies with the plain policy reason on its own two arms
        # (`_stage_unsafe`, an out-of-scope operand) without going through the naming step —
        # route it through here too, or a divergent-blank-caused scope mismatch (#959 FK6)
        # never gets named.
        return BashDecision(
            False, _final_reason(command, policy, effective_run_dir, reader.reason),
        )

    if command_shape.has_adapter(pipelines):
        return BashDecision(
            False, _final_reason(command, policy, effective_run_dir, ADAPTER_RETIRED_REASON),
        )

    return BashDecision(
        False, _final_reason(command, policy, effective_run_dir, policy.deny_reason),
    )
