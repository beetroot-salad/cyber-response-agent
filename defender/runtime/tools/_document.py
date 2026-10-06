
from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from defender._model import model
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover — typing only; the runtime import stays lazy
    from defender.skills.invlang.validate import Diagnostic


from pydantic_ai.exceptions import ModelRetry

from defender._io import REFUSED_FAULT, bind
from defender._run_paths import RunPaths
from .. import compaction, permission

# The byte ruler the artifact bounds are measured with, so reported "bytes" match what the gate judges.
from defender._artifact_schema import _utf8_len
from ._deps import AgentDeps
from ._bash import _resolved
from ._files import _closed_for_investigation_write, _write_operand

_logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------------------
# The repair window. A warn-family `:R attr_updates` row lands instead of costing a whole
# re-emitted block, and then gates the next write until it is repaired.
#
# The window is derived from `investigation.md` on each read, never stored, so it cannot go
# stale or disagree with the file.
# --------------------------------------------------------------------------------------

def _investigation_path(deps: AgentDeps) -> Path:
    return RunPaths(deps.run_dir).investigation


def _investigation_name(deps: AgentDeps) -> str:
    """`investigation.md`'s name below the run dir, its trust root for the rooted core."""
    return _investigation_path(deps).relative_to(deps.run_dir).as_posix()


@model(frozen=True)
class CompanionRead:
    """One reading of `investigation.md`, handed to every gate that judges the document as it
    stands (repair window, the close's structure check, entry price, challenge review), so no
    two gates can decode the same file differently.

    Three answers:

      * never written — `text == ""`: no repair window, nothing to validate, full entry price owed.
      * read — `text` is the document, decoded strictly with universal newlines.
      * could not be read — `text is None`, `refusal` says why: an I/O fault, a non-plain entry
        at the name (the rooted core refuses planted links at the open), or non-UTF-8 bytes.
        The window derivation fails open, no gate judges a lenient decode (it would let a
        confident close commit against an unvalidated document), and the host's forced close
        proceeds off an empty body. The model's close turns on `retryable`: an I/O fault is a
        refusal to retry; a fault no retry changes is decided once as the host's `unresolved`.
        Overruling on an I/O fault would let one mount hiccup replace a settled verdict."""

    #: The document, `""` when never written, `None` when it could not be read.
    text: str | None
    #: Why it could not be read — set exactly when `text is None`.
    refusal: str | None = None
    #: Whether a later read might succeed — set exactly when `text is None`. True for an I/O
    #: fault; False for undecodable bytes or a planted entry (the document's state, not the mount's).
    retryable: bool = False


def read_companion(deps: AgentDeps) -> CompanionRead:
    """The one read, through the rooted core off the run dir. Never raises (it runs on every
    model request via `prepare=`, where a raise would wedge the run) and never logs (callers
    log where they act on the refusal). Retryable exactly when the core's refusal kind is a
    fault: a planted entry or undecodable bytes are the document's state, not the mount's, and
    the kind is the core's own judgement, not a match on message text."""
    with bind(deps.run_dir) as run_root:
        got = run_root.read(_investigation_name(deps))
    if got.absent:
        return CompanionRead(text="")
    if got.reason is not None:
        return CompanionRead(
            text=None, refusal=got.reason, retryable=got.refused_by == REFUSED_FAULT,
        )
    return CompanionRead(text=got.text)


def unreadable_write_refusal(verb: str, read: CompanionRead) -> str:
    """The write verbs' refusal over a companion that could not be read.

    Takes the same reading the verb derived its window from, so the gate and the write never see
    different bytes."""
    if read.retryable:
        return f"{verb} blocked: investigation.md could not be read ({read.refusal}); retry."  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    return (
        f"{verb} blocked: investigation.md cannot be read ({read.refusal}) and no write can "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
        f"repair that — close the investigation and the host will record what happened."
    )


def flagged_diagnostics(deps: AgentDeps) -> tuple[Diagnostic, ...]:
    """The run's currently-open repair window, re-derived from disk on every call.

    Fails open: turning an unreadable `investigation.md` into "every write and the close are
    refused" would make the run unclosable."""
    return flagged_in(read_companion(deps))


def flagged_in(read: CompanionRead) -> tuple[Diagnostic, ...]:
    """The repair window over one reading. An absent or unreadable document is an empty window.

    Diagnostics without a `locus` are excluded: the window is the rows `fix_row` can address, and
    a locus-less finding would block the append and close with nothing the model could clear."""
    from defender.skills.invlang.validate import warn_diagnostics

    if not read.text:
        return ()
    try:
        return _addressable(warn_diagnostics(read.text))
    except Exception as e:  # noqa: BLE001 — fail open; a wedged run is the worse failure
        _logger.warning(
            f"repair-window derivation failed, treating it as empty: {e!r}",
        )
        return ()


def committed_document_refusal(read: CompanionRead) -> str | None:
    """The close's structural verdict on `investigation.md` — the refusal text, or `None` when
    the document is publishable.

    Kept beside `flagged_in` so both agree on what "could not read" means. An unreadable
    document (`text is None`) returns `None`: the close decides that case once, before any gate.
    An absent document also returns `None`; that is the entry-price gate's question."""
    from defender._artifact_schema import committed_investigation_reason

    if not read.text:
        return None
    return committed_investigation_reason(read.text)


def repairable_diagnostics(deps: AgentDeps) -> tuple[Diagnostic, ...]:
    """Every row `fix_row` may address — the repair set, wider than the repair window.

    The window is warn-severity only, but an error-severity row blocks every write just as hard
    (a rule shipped after the bytes landed can make a committed row invalid). Leaving it out of
    the repair set would leave no legal move until the retry budget force-closes `unresolved`.
    `fix_row` still faces `decide_write`, so this cannot widen what the model may write.

    Excluded: diagnostics naming no row (no locus or empty `row_text` — `fix_row` reads an empty
    `old_row` as delete), and rows outside `:R attr_updates`. The block restriction widens
    severity, not scope: parse diagnostics exist for every block, and admitting them would put a
    committed `:V`/`:E` record in reach of a repair.

    Fails open. Validated with the document as its own baseline, as
    `committed_investigation_reason` does, so the set matches what the close reports."""
    return repairable_in(read_companion(deps))


def repairable_in(read: CompanionRead) -> tuple[Diagnostic, ...]:
    """`repairable_diagnostics` over one reading, so the rewrite uses the same bytes."""
    from defender.skills.invlang.validate import ATTR_UPDATES_LOCUS as REPAIRABLE_BLOCK
    from defender.skills.invlang.validate import diagnose

    text = read.text
    if not text:
        return ()
    try:
        return tuple(
            d for d in _addressable(diagnose(text, text))
            if d.locus is not None and d.locus.row_text
            and d.locus.block == REPAIRABLE_BLOCK
        )
    except Exception as e:  # noqa: BLE001 — fail open; a wedged run is the worse failure
        _logger.warning(
            f"repair-set derivation failed, treating it as empty: {e!r}",
        )
        return ()


def _addressable(diags: Iterable[Diagnostic]) -> tuple[Diagnostic, ...]:
    return tuple(d for d in diags if d.locus is not None)


def _flagged_rows(diags: tuple[Diagnostic, ...]) -> tuple[str, ...]:
    return tuple(d.locus.row_text for d in diags if d.locus is not None)


def flagged_write_refusal(
    verb: str, diags: tuple[Diagnostic, ...], *, offered_text: bool = True
) -> str:
    """The gate's refusal, naming every currently-flagged row and its `use:` alternatives.

    Lists the whole set because after a frontier fold the model may hold only a prefix of the
    document, so this refusal is how it sees rows below the cut.

    `offered_text=False` for the close, which proposed no bytes of its own. Both spellings lead
    with the same fragment so the model can tell a refusal from an accept by the first sentence."""
    from defender._artifact_schema import UNCHANGED_LEAD, UNCHANGED_NOTICE, render_diagnostic

    # The close's opening says no disposition was recorded, not "nothing was committed", which
    # would contradict "the row LANDED" below.
    opening = (
        UNCHANGED_NOTICE if offered_text
        else f"{UNCHANGED_LEAD} — no disposition was recorded for this run."
    )
    return (
        f"{opening} `{verb}` is blocked while investigation.md carries a flagged "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
        f"row. The row LANDED and is committed, so re-sending the block cannot help; repair "
        f"it in place with `fix_row(old_row, new_row)`, or delete it with "
        f'`fix_row(old_row, "")`.\n\n'
        + "\n".join(render_diagnostic(d) for d in diags)
        + "\n\nRepair every row above, then retry."
    )


def _warning_return(lead: str, diags: tuple[Diagnostic, ...]) -> str:
    """An accept that carries a warning. Leads with the bytes and never uses the
    unchanged-notice wording, so the model does not mistake it for a refusal and re-emit."""
    from defender._artifact_schema import render_diagnostic

    if not diags:
        return lead
    return (
        lead
        + "\n\nBut one or more rows are FLAGGED and now block the next write:\n\n"
        + "\n".join(render_diagnostic(d) for d in diags)
        + "\n\nRepair each flagged row with `fix_row(old_row, new_row)` — or delete it with "
        '`fix_row(old_row, "")` — before the next append_block or close_investigation.'
    )


def _tool_append_block(deps: AgentDeps, text: str) -> str:
    """Append to `investigation.md` — main's only write.

    No path, anchor or position: the document is validator-enforced append-only. The resulting
    full document faces the same `decide_write`, schema and post-close refusal as other writes."""
    p = _investigation_path(deps)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            "investigation.md is no longer writable: the close already committed a "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            "recorded disposition for this run, and a further append could silently "
            "move it. The case is closed."
        )
    # The validator walks the full proposed document, so a landed warn row would re-fire on
    # every later append anyway; gating here names it for repair. One reading feeds both the
    # window and the append, so the gate and the write see the same document.
    read = read_companion(deps)
    flagged = flagged_in(read)
    if flagged:
        raise ModelRetry(flagged_write_refusal("append_block", flagged))
    read_decision = permission.decide_read(
        p, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy
    )
    if not read_decision.allow:
        raise ModelRetry(read_decision.reason)
    if read.text is None:
        raise ModelRetry(unreadable_write_refusal("append_block", read))
    current = read.text
    # Existing bytes are never rewritten (not even trailing whitespace), so an append cannot
    # trip the append-only check. An empty append gets no separator.
    sep = "\n" if current and text and not current.endswith("\n") else ""
    new_text = current + sep + text
    decision = permission.decide_write(
        p, new_text, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    _write_operand(deps, p, p.name, new_text)
    deps.authored_paths.add(_resolved(p))
    # UTF-8 bytes, not characters: the size cap is in bytes and invlang rows carry multi-byte
    # symbols.
    lead = (
        f"appended {_utf8_len(text)} bytes to investigation.md "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
        f"({_utf8_len(new_text)} total)"
    )
    # The gate accepted a warn-only document without returning diagnostics, so derive them
    # again in memory over the bytes just written.
    warn = _warn_over(new_text)
    recall = _frontier_recall(deps, current, new_text)
    if warn:
        # Recall goes inside the warning return so the `fix_row` instruction — the only legal
        # next call — stays last.
        return _warning_return(f"{lead} — the block LANDED.{recall}", warn)
    return lead + recall


def _frontier_recall(deps: AgentDeps, before: str, after: str) -> str:
    """Lessons for what this write left open — appended to the return, or "".

    Keyed on the invlang frontier, not the alert signature: a lesson about a field matters once
    the field is in hand. Emitted only when the write moved the frontier and changed the top
    lessons, so the same block is not re-stapled to every write. Derivation is shared with the
    compaction fold's frontier row (`lessons_push`), so "moved from `before`" also means "moved
    from what the fold showed".

    Not gated by `permission.decide_read`: the corpus is a fixed internal path, and the model
    receives rendered text, not a read capability.

    Fails open: callers reach here after the bytes landed, so raising would report a failed tool
    call on a write that succeeded.
    """
    try:
        from defender._corpus import iter_lessons
        from defender.runtime.lessons_engine.lessons_frontier import (
            WRITE_RETURN_LEAD,
            match_loaded,
            render,
        )
        from defender.skills.invlang.frontier import frontier_from_text

        from .. import lessons_push

        corpus = lessons_push.corpus_dir(deps, lane="[tools]")
        if corpus is None:
            return ""
        # Cheap exact gate first: the parser reads only ```invlang fences, so an append adding no
        # fence delimiter cannot change the frontier (common for prose or empty appends). Only
        # applies to prefix extensions, i.e. `append_block`; `fix_row` rewrites in place. The
        # window reaches two bytes back into `before` so a delimiter straddling the seam is
        # still seen (the separator rule prevents that today; this keeps it correct regardless).
        if before and after.startswith(before) and "```" not in after[max(0, len(before) - 2):]:
            return ""
        now_frontier = frontier_from_text(after)
        was_frontier = frontier_from_text(before)
        if now_frontier == was_frontier:
            return ""
        if now_frontier.is_empty():
            return ""
        # Withheld on a write that advances the fold boundary under compaction: the next render
        # folds this return away before the model reads it, and the fold's frontier row carries
        # the same top lessons. Same decision the driver makes at the next render.
        if compaction.enabled() and (
            compaction.fold_boundary(after) > compaction.fold_boundary(before)
        ):
            return ""
        # One corpus walk for both frontiers; `iter_lessons` re-parses every file per call.
        lessons = list(iter_lessons(corpus))
        hits = match_loaded(now_frontier, lessons)
        # Quiet when the frontier moved but the lessons did not. Compared on the sorted
        # `(path, score)` shape, not `matched`: which frontier item wins a tie is arbitrary, and
        # flipping it would re-emit an identical block. Sorted because the spread re-orders hits
        # by `matched`. Since the fold derives from the same document, this also prevents the
        # fold row and the write return from double-pushing.
        if not hits or lessons_push.shape(hits) == lessons_push.shape(
            match_loaded(was_frontier, lessons)
        ):
            return ""
        # Rendered only past the gate, since rendering is the costly part.
        now = render(hits, lead=WRITE_RETURN_LEAD)
        lessons_push.record(deps, hits)
        return "\n\n" + now
    except Exception as e:  # noqa: BLE001 — fail open; the write already landed
        _logger.warning(f"frontier recall failed, omitting it: {e!r}")
        return ""


def _warn_over(text: str) -> tuple[Diagnostic, ...]:
    """The window over text held in memory. Fails open: callers derive after the bytes landed,
    so raising would report a failed tool call on a write that succeeded."""
    from defender.skills.invlang.validate import warn_diagnostics

    try:
        return _addressable(warn_diagnostics(text))
    except Exception as e:  # noqa: BLE001 — fail open; the write already landed
        _logger.warning(
            f"repair-window derivation failed, treating it as empty: {e!r}",
        )
        return ()


#: Every separator `str.splitlines()` honours — what the fence tokenizer splits rows on, so
#: `Locus.row_text` must be matched against lines split the same way (splitting on `\n` alone
#: would leave some flagged rows unaddressable and the run wedged). `\r` never reaches here
#: (universal newlines on read). Spelled as escapes: some are invisible line breaks. Captured
#: so untouched lines keep their original separator.
_LINE_SEP_RE = re.compile("([\n\v\f\x1c\x1d\x1e\x85\u2028\u2029])")


def _split_lines(text: str) -> tuple[list[str], list[str]]:
    """`text`'s lines as the tokenizer sees them, and the separator after each (`""` for the
    last). `lines[i] + seps[i]` reassembles the document byte for byte."""
    parts = _LINE_SEP_RE.split(text)
    return parts[0::2], parts[1::2] + [""]


def _attr_block_columns(text: str, row: str) -> int | None:
    """How many cells the `:R attr_updates` block carrying `row` declares, or `None`."""
    from defender.skills.invlang.parser import iter_blocks

    for block in iter_blocks(text):
        if block.name == "attr_updates" and block.columns and row in block.rows:
            return len(block.columns)
    return None


def _new_row_shape_reason(new_row: str, cells: int | None) -> str | None:
    """Why `new_row` is not one row of the same block, or `None` if it is.

    `fix_row` is the only verb that rewrites a line inside an open fence, and its other guards
    are on `old_row`, so this is the whole guard on what it writes. Nothing else catches a `:V`
    declaration substituted for a row, an embedded line break forging a second row, a fence
    delimiter closing the block early, or too few cells (silently padded). This keeps committed
    `:V`/`:E` records immutable."""
    from defender.skills.invlang._cells import _split_cells
    from defender.skills.invlang.parser import HEADER_RE

    # Every line break the parser honours, not just `\n`.
    lines = new_row.splitlines()
    if len(lines) != 1 or lines[0] != new_row:
        return "it spans more than one line"
    if "```" in new_row:
        return "it carries a fence delimiter (```), which would close the block early"
    if HEADER_RE.match(new_row.strip()):
        return "it is a block header, not a row"
    # An unlocatable block skips only the cell-count check, not the checks above.
    if cells is None:
        return None
    got = len(_split_cells(new_row))
    if got != cells:
        return f"it has {got} cells but the block declares {cells}"
    return None


def _tool_fix_row(deps: AgentDeps, old_row: str, new_row: str) -> str:
    """Repair one flagged row of `investigation.md` in place.

    `old_row` must be a row in the current repair set (`:R attr_updates` only), which keeps
    committed `:V`/`:E` records out of reach. An empty `new_row` deletes the line — always
    available, and the only move left at the size bound.

    The set is re-derived here: `prepare=` only filters offers, so this body is the guard. The
    result faces the same `decide_write` as every other write."""
    from defender._artifact_schema import UNCHANGED_LEAD, UNCHANGED_NOTICE

    p = _investigation_path(deps)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            f"{UNCHANGED_LEAD} — investigation.md is no longer writable: the close already "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            "committed a recorded disposition for this run, and a further repair could "
            "silently move it. The case is closed."
        )
    # The repair set, not the warn window: error-severity rows block writes too.
    read = read_companion(deps)
    diags = repairable_in(read)
    flagged = _flagged_rows(diags)
    if not flagged:
        # A repeated repair gets this same refusal; distinguishing it would need stored state.
        raise ModelRetry(
            f"{UNCHANGED_NOTICE} Nothing is currently flagged in investigation.md, so there "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"is no row to repair."
        )
    if old_row not in flagged:
        # Confined to the flagged set, not merely present in the document, so a committed
        # vertex row cannot be rewritten.
        raise ModelRetry(
            f"{UNCHANGED_NOTICE} `old_row` must be one of the rows currently flagged in "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"investigation.md, quoted exactly as the warning printed it."
            "\n\nCurrently flagged:\n"
            + "\n".join(f"  {row}" for row in flagged)
        )

    # The rewrite uses the same reading the flagged rows came from; non-empty `flagged` means
    # the document was read.
    assert read.text is not None
    current = read.text
    lines, seps = _split_lines(current)
    whole = [i for i, line in enumerate(lines) if line.strip() == old_row]
    if not whole:
        raise ModelRetry(
            f"{UNCHANGED_NOTICE} `old_row` matches no line in investigation.md."  # lint-run-records: ok — a message naming the record for the model or operator, not a path
        )
    # The repair applies to every flagged occurrence (a duplicated flagged row would otherwise be
    # unrepairable), but refuses if the text also stands as a whole line the window did not
    # flag. Whole-line, not substring: only whole lines are rewritten, and a substring count
    # would falsely refuse when a summary quotes the row or one row prefixes another.
    occurrences = flagged.count(old_row)
    if len(whole) != occurrences:
        raise ModelRetry(
            f"{UNCHANGED_NOTICE} That row's text also stands as a whole line the repair "
            f"window did not flag ({len(whole)} line(s) match, {occurrences} flagged), and "
            f"`fix_row` will not rewrite a line it never flagged."
        )

    if new_row:
        # Always checked, including when `cells is None`; that case skips only the cell count.
        cells = _attr_block_columns(current, old_row)
        reason = _new_row_shape_reason(new_row, cells)
        if reason is not None:
            raise ModelRetry(
                f"{UNCHANGED_NOTICE} `new_row` must be a single row of the same "
                f":R attr_updates block: {reason}. Send one row with the same columns, or "
                'an empty `new_row` to delete the line instead.'
            )

    # Rewrite the whole line, whitespace included: `old_row` matched the stripped text, and a
    # padded line would otherwise survive its own repair.
    hit = set(whole)
    if new_row:
        rebuilt = [
            (new_row if i in hit else line) + sep
            for i, (line, sep) in enumerate(zip(lines, seps, strict=True))
        ]
    else:
        rebuilt = [
            line + sep
            for i, (line, sep) in enumerate(zip(lines, seps, strict=True))
            if i not in hit
        ]
    new_text = "".join(rebuilt)

    decision = permission.decide_write(
        p, new_text, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    _write_operand(deps, p, p.name, new_text)
    deps.authored_paths.add(_resolved(p))
    verb = "deleted" if not new_row else "repaired"
    lead = (
        f"{verb} {len(whole)} flagged row(s) in investigation.md "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
        f"({_utf8_len(new_text)} bytes total) — the change LANDED."
    )
    # `fix_row` can move the frontier (`:R attr_updates` rows close slots; a delete reopens
    # one). Recall must run here: the next `append_block` would see the repair in `before`.
    return _warning_return(
        lead + _frontier_recall(deps, current, new_text), _warn_over(new_text)
    )
