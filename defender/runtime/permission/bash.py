
from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
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
#: tuple must equal). Frozen rather than derived, purely for cost — and the cost is IMPORT
#: time, not decision time: the derivation is a full Unicode sweep (~80ms, measured) and this is
#: a module-level constant, so deriving it would be paid once per process, not per command.
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
    `_core_decide` compares against.

    `replacement` is the caller's, with no default: the ONE caller passes a real space,
    because `\\r` (M6) used to be a WORD SEPARATOR rather than a removed character, and simple
    deletion would also close a raw-text adjacency gap (`_is_fd_prefix`'s glue test) that has
    nothing to do with #959 and was never a separator question at all.

    That second reason is the load-bearing one and it is CHECKED, not asserted: the frozen
    corpus's `neutral-cr-before-fd-marker` (`cat P 2<CR>>/dev/null`) is refused today, and
    DELETING the carriage return glues `2` to `>` into an fd-2 redirect that is allowed —
    an unenumerated verdict move, which is why the substitution stands.

    It is worth knowing what the substitution costs, because it is not free: the message this
    counterfactual feeds says "remove the invisible character", and removal is not the edit
    being tested. `wc -<CR>l` is refused while `wc -l` is allowed, yet the space variant
    `wc - l` is refused too, so the character that IS the whole problem is named nothing; and
    `cat<CR>/run/report.md` is named U+000D because `cat /run/report.md` is allowed, while the
    model that removes it gets `cat/run/report.md` and the same refusal again. Reconciling the
    two needs either a `\\r`-specific clause in the reason text ("replace it with a space") or a
    new enumerated member — both spec moves, neither a local edit."""
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
        if c == "\n" or c == quote:
            # A NEWLINE closes the quote here because it closes it for the parser: `parse`
            # splits on `\n` and hands each physical line its OWN `_literal_mask`, so a quote
            # opened on one line is not open on the next. Carrying it across made this walker
            # model a quoting the scanner never used, and the counterfactual it builds is only
            # worth anything while the two agree.
            quote = None
        out.append(c)
        i += 1
    return "".join(out)


def _core_decide(command: str, policy: AgentPolicy, run_dir: Path | None) -> BashDecision:
    """THE decision — the whole ladder, once. `decide_bash` is this plus the codepoint naming a
    deny carries, and the counterfactual that naming compares against is this same function over
    an edited command, so there is no second ladder to keep in step by hand.

    That mattered before it was one function: the counterfactual copy re-coalesced the reader
    arm's reason (`reader.reason or "none"`) where the caller passed it through raw, so the two
    sides of the comparison disagreed whenever a policy carried an empty `deny_reason` and every
    invisible character in the command was named as responsible for a refusal none of them
    caused. Anchoring the ladder in one place makes that class unreachable rather than
    currently-absent — `defender/CLAUDE.md`, "Anchor a default in one place", and the reason a
    later arm added to a decision cannot silently miss the copy that explains it."""
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
    """What a counterfactual is compared ON: the answer, and the identity of the reason that
    carries it. Read off the decision itself on BOTH sides of that comparison, so an unchanged
    decision can never compare unequal. (Not `_verdict` — `evals/harness_lead.py` already owns
    that name for an unrelated thing, and `lint_duplicate_helpers` is the gate that says so.)"""
    return decision.allow, decision.reason


#: The one divergent-blank character whose behaviour changed EVERYWHERE a word can carry it,
#: not only at the two ends the deleted trim used to reach: `_BLANKS` carried `\r`
#: before M6, so a mid-word carriage return was a live separator then and is an ordinary
#: character now. Every other divergent blank was NEVER a separator anywhere but the two ends
#: (the deleted trim was the only old opinion that ever touched it), so its responsibility
#: check must stay confined to those ends — checking it everywhere would flag a glued interior
#: character (e.g. `echo a<NBSP>b`) that #959 never touched at all.
_CR = "\r"


def _blanks_removed(command: str, chars: str) -> str:
    """`command` as it would read with `chars` gone from the positions #959 changed the
    treatment of — the two ends of the whole command (M4) and, for `\\r` alone, anywhere
    unquoted (M6).

    THE STRIP SET IS `chars` PLUS `bash_exec.BLANKS`, and the ordinary blanks are what make it
    reach. `str.strip` stops at the first character outside its set, so ONE ordinary space or
    newline sitting outside the invisible one hid it completely: `cat P<NBSP>` named U+00A0
    while `cat P<NBSP>\\n` — the same paste with the trailing newline a JSON tool argument
    routinely carries — named nothing at all, and the diagnostic appeared or vanished on a
    character the model has no reason to vary. Adding them back is verdict-neutral by
    construction: `_scan` skips a leading or trailing blank, so a counterfactual that also drops
    them parses to the same pipelines. It is also the trim being modelled — what `str.strip()`
    removed was a RUN OF ANY whitespace, so a divergent blank behind an ordinary one was always
    inside its reach.

    THE STRIP RUNS FIRST, and the order is load-bearing. Editing `\\r` ahead of it put a
    character outside `chars` at the head of the run, so the strip stopped there and every
    divergent blank behind it survived: `<CR><NBSP>cat P`, and every joint case whose edge run
    merely CONTAINS a carriage return, came back still refused and named nothing — exactly the
    multi-character paste artifact the joint arm exists to explain.

    A RUN, not one character: a paste that carries two no-break spaces is the ordinary shape,
    and stripping one leaves a counterfactual that still fails for the same reason and so names
    nothing either. Quoting is irrelevant at a true edge of the raw command: nothing has opened
    a quote yet at position 0, and a quote opened earlier in a syntactically complete command is
    already closed by the end. It is NOT irrelevant to `\\r`, which is why that arm goes through
    `_strip_unquoted`."""
    out = command.strip(chars + bash_exec.BLANKS)
    return _strip_unquoted(out, _CR, " ") if _CR in chars else out


def _name_responsible_divergent_char(
    command: str, policy: AgentPolicy, run_dir: Path | None, decision: BashDecision,
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
    # `frozenset.intersection` does in C what a per-character comprehension did in Python, and
    # this scan runs on EVERY deny — including the ones with nothing to find, which is nearly
    # all of them. `sorted` without `key=ord` is the same order: single-character strings
    # already compare by code point.
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
            # The characters the JOINT EDIT ACTUALLY REMOVED, not every candidate in the
            # command. `_blanks_removed` only reaches the two ends (and, for `\r`, the unquoted
            # interior), so a blank glued INSIDE a word survives the counterfactual untouched
            # and provably changed nothing — naming it sends the model to delete a character
            # that is part of the data it meant to send. Counted rather than re-probed one at a
            # time, because a character the joint strip reaches is not always one a strip of
            # ITSELF would reach: `<VT><NBSP>cat P` has no NBSP at index 0 until the `<VT>`
            # in front of it goes.
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
        # `names_run_provenance` joins them here rather than in `decide_read` alone, for the
        # reason the wire log does: the JUDGE holds a `cat` grant scoped `under(run, TREE)`,
        # which fullmatches a run-root file, so without this the bash lane would admit the very
        # stamp `decide_read` refuses it — two surfaces disagreeing about one path.
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
    # NO TRIM AT ALL here (#959 M4), where main narrowed the trim to `bash_exec.BLANKS`. Both
    # sides are answering the same defect — `str.strip()` is a UNICODE predicate and removed
    # `\r`, NBSP, `\x0b`, `\x85`, U+2003, every character the scanner was narrowed to KEEP
    # inside its word, so `cat <run_dir>/report.md<NBSP>` was checked and RUN as
    # `cat <run_dir>/report.md`, an argv the model did not write. Narrowing the trim closes
    # that; deleting it closes the class, because the parser is then handed the model's text
    # byte for byte and there is no second opinion left to disagree with the scanner. The
    # blank command is answered by `_is_blank`, which asks the scanner's own set.
    effective_run_dir = cwd_anchor if cwd_anchor is not None else run_dir

    decision = _core_decide(command, policy, effective_run_dir)
    if decision.allow or decision.reason == EMBEDDED_NUL_REASON:
        # The NUL refusal already names its own character by codepoint, and no counterfactual
        # below can remove a NUL, so the naming step could only pay a full re-decision for an
        # answer this reason already carries. Every OTHER deny goes through it — a lexing
        # refusal is exactly where an invisible character lands, and so is a scope mismatch on
        # an operand a blank corrupted (#959 FK6); the generic texts name none of them.
        return decision

    named = _name_responsible_divergent_char(command, policy, effective_run_dir, decision)
    return decision if named is None else dataclasses.replace(decision, reason=named)
