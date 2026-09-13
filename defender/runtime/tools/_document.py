
from __future__ import annotations

import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover — typing only; the runtime import stays lazy
    from defender.skills.invlang.validate import Diagnostic


from pydantic_ai.exceptions import ModelRetry

from defender._io import read_text_utf8, write_guarded
from .. import permission

# The SAME byte ruler the artifact bounds are measured with — a write tool that reports
# "bytes" must report the number the gate will judge, not a codepoint count that under-reads it.
from defender._artifact_schema import _utf8_len
from ._deps import AgentDeps, _record_lesson_load
from ._bash import _guarded_parents, _resolved
from ._files import _closed_for_investigation_write


# --------------------------------------------------------------------------------------
# The repair window. A warn-family `:R attr_updates` row LANDS instead of costing a whole
# re-emitted block, and then gates the next write until it is repaired.
#
# The window is DERIVED, never stored: `warn_diagnostics` over whatever `investigation.md`
# holds right now IS the state. Nothing caches it and no `AgentDeps` field carries it, so it
# cannot go stale or disagree with the file.
# --------------------------------------------------------------------------------------

def _investigation_path(deps: AgentDeps) -> Path:
    return deps.run_dir / "investigation.md"


def flagged_diagnostics(deps: AgentDeps) -> tuple[Diagnostic, ...]:
    """The run's currently-open repair window, re-derived from disk on every call.

    FAILS OPEN on all three paths that read it (`prepare=`, the write gate, the close gate).
    An unreadable or undecodable `investigation.md` is an unrelated fault; converting it into
    "every write and the close are refused" would manufacture the unclosable run this mechanism
    exists to avoid. `append_block` still refuses an undecodable document for its own reason.

    A warn diagnostic carrying NO `locus` is not in the window: the window is the set of rows
    `fix_row` can address, so counting a locus-less finding would refuse the append AND the
    close with no row the repair verb could ever clear. No family emits one today; this keeps
    that from being load-bearing."""
    from defender.skills.invlang.validate import warn_diagnostics

    p = _investigation_path(deps)
    # ABSENCE is the ordinary "no window open" case, not a fault: `prepare=` runs on EVERY
    # model request, including turn 1 before any write verb has created the file.
    if not p.is_file():
        return ()
    try:
        return _addressable(warn_diagnostics(read_text_utf8(p)))
    except Exception as e:  # noqa: BLE001 — fail open; a wedged run is the worse failure
        print(
            f"[tools] repair-window derivation failed, treating it as empty: {e!r}",
            file=sys.stderr,
        )
        return ()


def committed_document_refusal(deps: AgentDeps) -> str | None:
    """The close's structural verdict on `investigation.md` as it stands — the refusal text,
    or `None` when the document is publishable. #961.

    Lives beside `flagged_diagnostics` and not in the close because the two are ONE reading of
    one document, taken at the same moment, and they have to agree about what "cannot look"
    means. Splitting them put that agreement in two files the first time and it did not
    survive the trip.

    THE READ IS STRICT, and that is the whole subtlety. Two conditions look alike from the
    close and are not:

      * the document DECODES and does not validate — the author wrote something malformed,
        the close is what publishes it, and it is refused (#961);
      * the document's BYTES do not decode — nothing can be derived from it at all. That is
        H7's condition, and #836 settled it: fail OPEN, because converting an unrelated read
        fault into an unclosable run is the wedge class that mechanism exists to remove.

    Reading leniently (`errors="replace"`) collapses the two and answers the second with the
    first: the replacement character lands mid-header, the validator reports a broken block
    the author never wrote, and the run can no longer close. So the strict read is what keeps
    this gate's `None` meaning "publishable" rather than "unreadable", and the fail-open arm
    below is what keeps H7 true. A document that never decodes is still gated on the way IN —
    `append_block` refuses it for its own pre-existing reason — so nothing gated can create
    one.

    ABSENCE is not a fault: a close on a run with no companion is the entry-price gate's
    question, not this one's, and it asks it separately."""
    from defender._artifact_schema import committed_investigation_reason

    p = _investigation_path(deps)
    if not p.is_file():
        return None
    try:
        text = read_text_utf8(p)
    except Exception as e:  # noqa: BLE001 — fail open (H7); a wedged run is the worse failure
        print(
            f"[tools] investigation.md could not be read for the close's structure check, "
            f"treating it as publishable: {e!r}",
            file=sys.stderr,
        )
        return None
    return committed_investigation_reason(text)


def repairable_diagnostics(deps: AgentDeps) -> tuple[Diagnostic, ...]:
    """Every row `fix_row` may address — the REPAIR set, which is wider than the repair WINDOW.

    `flagged_diagnostics` above is the warn-severity window: the rows whose presence BLOCKS an
    append and a close. This is the set the repair verb is allowed to touch, and the two are
    not the same question. An ERROR-severity row blocks just as hard — `append_block` validates
    the whole document, so a committed error refuses every later write — but it was not in the
    window, so `fix_row` refused it and was not even offered. That left a document carrying one
    with NO legal move: the close refuses and names `fix_row`, `fix_row` says nothing is
    flagged, `append_block` refuses the same bytes, and append-only puts them out of reach. The
    model then spends its whole retry budget before the framework force-closes `unresolved`,
    discarding the disposition the run actually reached.

    Reachable because a document valid when written can stop being valid later: a rule that
    ships after a run's bytes landed (#962 is exactly one) judges what is already committed.

    Widening the REPAIR set cannot widen what the model may write. `fix_row` still faces
    `decide_write` on the resulting document, so a repair that does not actually fix the row is
    refused like any other write.

    A diagnostic naming NO ROW stays out — no locus, and equally an EMPTY `row_text`. The
    empty case is not hypothetical: the repeated-lead-id family reports at block scope
    (`_warn(block, -1, "")`), so it carries a locus whose row is the empty string, and `fix_row`
    reads an empty `old_row` as DELETE. Admitting it would offer the model a repair that names
    nothing and deletes on sight, and it would quietly reverse #954's decision that a document
    holding that repeat is refused at every write verb with no legacy exemption. The rule is
    the one `flagged_diagnostics` already states for a locus-less finding: the set is the rows
    `fix_row` can ADDRESS, and a row nobody can quote back is not one.

    AND A ROW OUTSIDE `:R attr_updates` STAYS OUT, which is what keeps the widening a widening
    of SEVERITY and not of SCOPE. The warn window walks that block and nothing else, so every
    guard downstream of it inherited the scope for free: `_attr_block_columns` returns `None`
    for a row no `:R attr_updates` block holds — its own docstring says that "cannot happen for
    a flagged row" — and `_tool_fix_row` reads that `None` as "skip the shape guard", which is
    the guard that makes "no verb mutates or removes a committed `:V`/`:E` record" true by
    construction. Parse diagnostics carry a locus and a real row for EVERY block, so admitting
    them by severity alone would put a committed `:V` declaration inside the repair set with no
    shape guard in front of it — a `new_row` free to span lines, carry a fence delimiter, or be
    a block header. The severity partition and the block partition are two different questions;
    this widens exactly one of them.

    FAILS OPEN like its sibling, for the same reason and via the same reader — a wedged run is
    the worse failure. Read with the document as its OWN baseline, the reading
    `committed_investigation_reason` takes: the repair set has to be derived from the same
    verdict the close renders, or the verb is offered on findings the close never names."""
    from defender.skills.invlang.validate import ATTR_UPDATES_LOCUS as REPAIRABLE_BLOCK
    from defender.skills.invlang.validate import diagnose

    p = _investigation_path(deps)
    if not p.is_file():
        return ()
    try:
        text = read_text_utf8(p)
        return tuple(
            d for d in _addressable(diagnose(text, text))
            if d.locus is not None and d.locus.row_text
            and d.locus.block == REPAIRABLE_BLOCK
        )
    except Exception as e:  # noqa: BLE001 — fail open; a wedged run is the worse failure
        print(
            f"[tools] repair-set derivation failed, treating it as empty: {e!r}",
            file=sys.stderr,
        )
        return ()


def _addressable(diags: Iterable[Diagnostic]) -> tuple[Diagnostic, ...]:
    return tuple(d for d in diags if d.locus is not None)


def _flagged_rows(diags: tuple[Diagnostic, ...]) -> tuple[str, ...]:
    return tuple(d.locus.row_text for d in diags if d.locus is not None)


def flagged_write_refusal(
    verb: str, diags: tuple[Diagnostic, ...], *, offered_text: bool = True
) -> str:
    """The gate's refusal, naming EVERY currently-flagged row and its `use:` alternatives.

    It carries the whole set rather than the most recent row because after a frontier fold the
    model holds only a truncated PREFIX of the document (`driver._fold_decision`), so a flagged
    row below the cut is absent from its view and this refusal is the recovery channel.

    `offered_text=False` for the CLOSE, which proposed no `investigation.md` bytes of its own:
    the full notice's "does not contain your text" would be a claim about nothing. Both
    spellings LEAD with the same fragment, so the model still tells a refusal from an accept by
    the first sentence."""
    from defender._artifact_schema import UNCHANGED_LEAD, UNCHANGED_NOTICE, render_diagnostic

    # The close's opening states what the CLOSE did not do — no disposition recorded — never
    # "nothing was committed for this run", which flatly contradicts the next sentence ("the
    # row LANDED and is committed") and reads as "your whole investigation was discarded".
    opening = (
        UNCHANGED_NOTICE if offered_text
        else f"{UNCHANGED_LEAD} — no disposition was recorded for this run."
    )
    return (
        f"{opening} `{verb}` is blocked while investigation.md carries a flagged "
        f"row. The row LANDED and is committed, so re-sending the block cannot help; repair "
        f"it in place with `fix_row(old_row, new_row)`, or delete it with "
        f'`fix_row(old_row, "")`.\n\n'
        + "\n".join(render_diagnostic(d) for d in diags)
        + "\n\nRepair every row above, then retry."
    )


def _warning_return(lead: str, diags: tuple[Diagnostic, ...]) -> str:
    """An ACCEPT that carries a warning. It LEADS with the bytes and says the block landed, and
    never carries the unchanged-notice wording: a model that reads "warning" as "refusal"
    re-emits the whole block, which is the cost the repair window exists to remove."""
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

    No path: the run has one model-authored transcript and this is its writer, the way
    `close_investigation` is `report.md`'s. No anchor and no position either: the document is
    validator-enforced append-only (`_check_append_only` refuses a dropped fence, a dropped
    record, or an in-place mutation), so the anchored replace `edit_file` offers is a capability
    the artifact never had.

    Faces the identical gate the other two verbs do — same `decide_write`, same content schema,
    same RS15 post-close refusal — on the resulting full document."""
    p = _investigation_path(deps)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            "investigation.md is no longer writable: the close already committed a "
            "recorded disposition for this run, and a further append could silently "
            "move it. The case is closed."
        )
    # The gate is FORCED, not chosen: `_check_closed_vocab` walks the FULL proposed document,
    # so a landed warn row re-fires on every subsequent append anyway. Without the gate the
    # choices are grandfathering — which dead-letters the run at persist — or a wedged document.
    flagged = flagged_diagnostics(deps)
    if flagged:
        raise ModelRetry(flagged_write_refusal("append_block", flagged))
    read_decision = permission.decide_read(
        p, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy
    )
    if not read_decision.allow:
        raise ModelRetry(read_decision.reason)
    try:
        current = read_text_utf8(p) if p.is_file() else ""
    except UnicodeDecodeError:
        raise ModelRetry(
            "investigation.md is not valid UTF-8 text (binary or corrupt)"
        ) from None
    # Separate with a newline only when the document does not already end in one. Existing
    # bytes are never rewritten — not even trailing whitespace — so an append cannot itself
    # trip the append-only check it is about to face. An EMPTY append gets no separator: the
    # separator alone would be a byte the model never sent, on a call reporting zero bytes.
    sep = "\n" if current and text and not current.endswith("\n") else ""
    new_text = current + sep + text
    decision = permission.decide_write(
        p, new_text, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    _guarded_parents(deps, p)
    write_guarded(p, new_text)
    deps.authored_paths.add(_resolved(p))
    # UTF-8 BYTES, not characters: the SKILL tells the model this return IS a byte count, and
    # the 65536-byte cap it must stay under is measured the same way. invlang rows carry
    # `⟂ → ⟺` freely, so `len(str)` under-reports against the bound the gate applies.
    lead = (
        f"appended {_utf8_len(text)} bytes to investigation.md "
        f"({_utf8_len(new_text)} total)"
    )
    # The gate ACCEPTED a warn-only document and returned no text to reuse, so the warning can
    # only come from a SECOND derivation here, over the bytes just written. Deriving in memory
    # keeps it deterministic without a re-read.
    warn = _warn_over(new_text)
    recall = _frontier_recall(deps, current, new_text)
    if warn:
        # INSIDE the warning return, not stapled after it. `_warning_return` ends with the
        # `fix_row` instruction, and on this path that is the only legal next call — the next
        # `append_block` is hard-refused by `flagged_diagnostics`. Appending the lessons block
        # after it would put ~30 lines of precedent between the model and the one action it
        # can take.
        return _warning_return(f"{lead} — the block LANDED.{recall}", warn)
    return lead + recall


def _frontier_recall(deps: AgentDeps, before: str, after: str) -> str:
    """Lessons for what this append left OPEN — appended to the return, or "" (#919).

    Keyed on the invlang FRONTIER (`skills/invlang/frontier.py`), not on the alert
    signature. A lesson about what a field licenses is relevant once the field is in hand,
    which is a fact about the document at loop N, not about which rule fired at loop 0 —
    `runtime/orient.py` keys the cold-start block on the signature because at that point no
    document exists yet, and that is the only place the signature is the best available key.

    ON CHANGE, not on every write. The pre- and post-append documents are both already in
    hand here, so the diff costs nothing and needs no state to remember what was said last:
    the model gets a lessons block exactly when its own append moved the frontier, instead
    of the same three lines re-stapled to every write until it stops reading them.

    DERIVED, NEVER STORED, like the repair window above — nothing caches this, so it cannot
    go stale or disagree with the file.

    NOT gated by `permission.decide_read`, deliberately. The gate governs what the MODEL may
    read; this is the runtime composing text to hand it, the same way `runtime/orient.py`
    assembles the cold-start lessons block without one. The corpus is a fixed internal path
    under `defender_dir`, never an operand the model supplies, so there is no path here for
    it to steer — and the model receives rendered text, not a read capability it can reuse.

    FAILS OPEN, and that is not optional: every caller reaches here AFTER the bytes have
    landed, so an exception raised for a missing corpus or an unreadable frontier would
    surface to the model as a failed tool call on a write that actually succeeded — the
    exact lie `_warn_over` fails open to avoid.
    """
    try:
        from defender._corpus import iter_lessons
        from defender.scripts.lessons.lessons_frontier import (
            match_loaded,
            render,
        )
        from defender.skills.invlang.frontier import frontier_from_text

        corpus = deps.defender_dir / "lessons"
        if not corpus.is_dir():
            # LOUD, on the same terms `frontier_from_text` states: a corpus that is not there
            # produces the same silence as a corpus that matched nothing, and SKILL.md tells
            # the model to read that silence as "nothing NEW matched". A mis-resolved
            # `defender_dir` would otherwise disable the lane for the whole run with no
            # exception, no test red, and no operator signal.
            print(f"[tools] no lessons corpus at {corpus}; omitting recall", file=sys.stderr)
            return ""
        # THE FRONTIER is the cheap gate, and it is also the one SKILL.md states ("appears
        # only when your append *changed* what is open"). `Frontier` is a frozen dataclass of
        # tuples of frozen dataclasses, so `==` is exact, and `match_lessons`/`render` are
        # pure functions of `(frontier, corpus)` — an unchanged frontier cannot change the
        # block. Checking it first skips the corpus walk, which is the dominant cost here:
        # `iter_lessons` re-reads and re-YAML-parses every lesson file on every call. It skips
        # it on a MINORITY of appends, though, not "most" — `held` accumulates, so any append
        # declaring a `:V` row moves the frontier. Replaying the repo's own investigations
        # fence-by-fence, it fires on roughly half.
        #
        # The fence test below is the gate that actually is cheap, and it is exact:
        # `parse_dense_companion` reads ONLY ```invlang fences and ignores every other
        # byte, so an append that adds no fence delimiter cannot add, close, or alter one —
        # the parse, and therefore the frontier, is identical. Prose narration between blocks
        # is an ordinary shape on this loop and an empty `text` is an explicitly supported
        # one; both would otherwise pay two full parses of a document
        # growing toward the 65536-byte cap to discover they changed nothing. Guarded on
        # `after` EXTENDING `before` so it can only fire for `append_block` — `fix_row` rewrites
        # in place and is never a prefix extension.
        #
        # The window reaches TWO BYTES BACK into `before`, so a delimiter that straddled the
        # seam — an on-disk document ending in a truncated ``` and an append supplying the last
        # backtick — could not close a fence behind a gate that said it could not.
        #
        # BELT AND BRACES, not a live case: `_tool_append_block` inserts `sep = "\n"` whenever
        # `current` does not already end in a newline, so today no ``` can span the join at
        # all. The two bytes cost nothing and are what keeps this gate correct if that
        # separator rule is ever relaxed; do not read them as evidence the straddle happens.
        if before and after.startswith(before) and "```" not in after[max(0, len(before) - 2):]:
            return ""
        now_frontier = frontier_from_text(after)
        was_frontier = frontier_from_text(before)
        if now_frontier == was_frontier:
            return ""
        if now_frontier.is_empty():
            return ""
        # ONE walk for the two frontiers below. `iter_lessons` re-opens and re-YAML-parses
        # every file in the corpus per call, and it is the dominant cost here — the two scores
        # are pure functions of the same bytes, which cannot change between them.
        lessons = list(iter_lessons(corpus))
        hits = match_loaded(now_frontier, lessons)
        # The second gate is what keeps a MOVE that changed no lesson quiet — the frontier can
        # open a slot no selector speaks to, and re-stapling the same three lines then teaches
        # the model to stop reading them.
        #
        # Compared on `(path, score)` — WHICH lessons and in what order — rather than on the
        # rendered text, which would cost a `yaml.safe_dump` of three lessons' frontmatter plus
        # three `Path.resolve()` realpath syscalls built and thrown away one expression later,
        # on every frontier-moving write.
        #
        # NOT on `matched`, which is the trap: it names whichever frontier item won
        # `_best_match`'s `max`, and `max` returns the FIRST maximal element — so declaring a
        # second, equally-scoring vertex flips the winner and re-emits a block whose lesson set,
        # ranking and frontmatter are byte-identical. Executed against
        # `learning/runs/fresh-01/investigation.md`, fences 3 and 7 differ in exactly one line
        # (`matched v-003 compute class=ip-only/??/??` -> `matched v-004 compute
        # class=ip-only/??/known-corp`) and re-staple ~1.5KB of precedent the model already
        # holds — the churn this gate exists to prevent. `matched` still RENDERS, because it is
        # the model's only account of why a lesson was pushed; it just does not decide.
        #
        # SORTED, which is what keeps that true now that `_spread_over_items` exists (#935).
        # The ranked list used to be ordered by `(-score, name)` alone, so the ORDER of these
        # pairs was a function of the pairs themselves and comparing the list was already a
        # comparison of the multiset. The spread re-orders on `matched` — it groups hits by
        # which frontier item won `_best_match`'s `max` — so an unsorted comparison would let
        # exactly the flip described above decide emission through the back door: same
        # lessons, same scores, same frontmatter, re-stapled because one hit's `max` moved
        # from v-003 to v-004. Sorting restores "which lessons, and at what score" as the
        # whole question.
        shape = sorted((str(h.path), h.score) for h in hits)
        if not shape or shape == sorted(
            (str(h.path), h.score) for h in match_loaded(was_frontier, lessons)
        ):
            return ""
        now = render(hits)
        # RECORDED, on the same terms a Read is. `lessons_loaded.jsonl` is the loop's only
        # "was this lesson in context" signal and the post-merge control `learning/ops/
        # trace_lesson.py` reasons from — and this block puts a lesson's description and
        # dimensions in front of MAIN with enough to act on, since SKILL.md tells it to judge
        # relevance from `description` and NOT to open the file to decide. A push that left no
        # row would make a merged lesson look inert to the human reviewing its impact.
        for hit in hits:
            # RESOLVED, the same spelling `render` hands the model and the same one
            # `_gated_read` records (it passes the post-`_resolve_operand` path).
            # `record_lesson_load.lesson_name` gates on `p.parent.parent.name == "defender"`,
            # so an unresolved `defender_dir` carrying a symlink or a `..` shows the block and
            # writes no row — the lesson then reads as never-in-context to `trace_lesson`.
            _record_lesson_load(deps, hit.path.resolve())
        return "\n\n" + now
    except Exception as e:  # noqa: BLE001 — fail open; the write already landed
        print(f"[tools] frontier recall failed, omitting it: {e!r}", file=sys.stderr)
        return ""


def _warn_over(text: str) -> tuple[Diagnostic, ...]:
    """The window over text held in memory. FAILS OPEN for the same reason
    `flagged_diagnostics` does, and for one more: both call sites derive AFTER the bytes have
    landed, so a validator error raised here would surface as a failed tool call on a write
    that succeeded."""
    from defender.skills.invlang.validate import warn_diagnostics

    try:
        return _addressable(warn_diagnostics(text))
    except Exception as e:  # noqa: BLE001 — fail open; the write already landed
        print(
            f"[tools] repair-window derivation failed, treating it as empty: {e!r}",
            file=sys.stderr,
        )
        return ()


#: EVERY separator `str.splitlines()` honours, which is what `_tokenize_fence` splits a fence
#: body on — so it decides where a ROW ends, and therefore what `Locus.row_text` holds.
#: `split("\n")` alone left a row sitting after a `\v` `\f` `\x1c` `\x1d` `\x1e` `\x85`
#: `\u2028` or `\u2029` FLAGGED but UNADDRESSABLE: `old_row` matched no whole line, so the
#: repair refused while `append_block` and the close both refused for that same flagged row —
#: a permanently wedged run, reachable from one `append_block` carrying one of those bytes.
#: `\r\n` / `\r` never reach here: `read_text_utf8` translates them on read.
#: Spelled as ESCAPES, never literal codepoints: two of them are invisible line breaks and
#: would split THIS file for anything that reads it the way the tokenizer reads a fence.
#: Captured, not consumed, so every untouched line keeps the separator the model wrote.
_LINE_SEP_RE = re.compile("([\n\v\f\x1c\x1d\x1e\x85\u2028\u2029])")


def _split_lines(text: str) -> tuple[list[str], list[str]]:
    """`text` as the tokenizer sees it: its lines, and the separator that FOLLOWED each one
    (`""` for the last). `lines[i] + seps[i]` reassembles the document byte for byte."""
    parts = _LINE_SEP_RE.split(text)
    return parts[0::2], parts[1::2] + [""]


def _attr_block_columns(text: str, row: str) -> int | None:
    """How many cells the block carrying `row` declares. `None` when no `:R attr_updates`
    block holds it — which cannot happen for a flagged row, since that is the only block the
    warn family walks."""
    from defender.skills.invlang.parser import iter_blocks

    for block in iter_blocks(text):
        if block.name == "attr_updates" and block.columns and row in block.rows:
            return len(block.columns)
    return None


def _new_row_shape_reason(new_row: str, cells: int | None) -> str | None:
    """`new_row` is ONE row of the SAME block, or it is refused.

    `fix_row` is the only verb that rewrites a line INSIDE an already-open fence, and every
    other guard on it is on `old_row` — so without this, `new_row` is the whole write surface.
    Not belt-and-braces: `_check_append_only` never inspects `:R` rows, so a `:V` declaration
    substituted for a flagged row draws ZERO diagnostics; an embedded newline forges a
    well-formed second row; a fence delimiter makes the injected row vanish by closing the
    block early; and one cell too FEW is silently padded. Only "too many cells" is caught
    anywhere else, and by the parser rather than a guard. This is what makes "no verb mutates
    or removes a committed :V/:E record" true by construction."""
    from defender.skills.invlang._cells import _split_cells
    from defender.skills.invlang.parser import HEADER_RE

    # EVERY line break `str.splitlines()` honours, not just `\n`: a `new_row` carrying a \v \f
    # \x1c \x1d \x1e or \x85 is a SECOND row (or a whole second block) to the parser while
    # looking like one line to a `"\n" in ...` check, and its pipe count is unchanged so the
    # cell-count arm never fires either.
    lines = new_row.splitlines()
    if len(lines) != 1 or lines[0] != new_row:
        return "it spans more than one line"
    if "```" in new_row:
        return "it carries a fence delimiter (```), which would close the block early"
    if HEADER_RE.match(new_row.strip()):
        return "it is a block header, not a row"
    # `cells is None` means the declaring block could not be located. Only the CELL-COUNT arm
    # needs it, so an unlocatable block narrows the guard by one check instead of switching
    # the whole write surface off.
    if cells is None:
        return None
    got = len(_split_cells(new_row))
    if got != cells:
        return f"it has {got} cells but the block declares {cells}"
    return None


def _tool_fix_row(deps: AgentDeps, old_row: str, new_row: str) -> str:
    """Repair ONE flagged row of `investigation.md` in place.

    No path and no free-form anchor: `old_row` must be one of the rows the repair window is
    currently open on, which puts every committed `:V`/`:E` record out of reach (the warn
    family walks `:R attr_updates` blocks and nothing else). An empty `new_row` DELETES the
    line — the always-available escape that keeps the window closable, and the only move left
    when the document is at its size bound.

    The window is re-derived here at call time. Being OFFERED the verb is never evidence the
    window is still open: `prepare=` filters per-request offers and is ergonomics, so the body
    is the guard. The resulting full document faces the same `decide_write` chain every other
    write on this artifact faces."""
    from defender._artifact_schema import UNCHANGED_LEAD, UNCHANGED_NOTICE

    p = _investigation_path(deps)
    if _closed_for_investigation_write(deps, p):
        raise ModelRetry(
            f"{UNCHANGED_LEAD} — investigation.md is no longer writable: the close already "
            "committed a recorded disposition for this run, and a further repair could "
            "silently move it. The case is closed."
        )
    # The REPAIR set, not the warn window: an error-severity row blocks every write just as
    # hard and used to be unreachable by the one verb that could clear it. See
    # `repairable_diagnostics`.
    diags = repairable_diagnostics(deps)
    flagged = _flagged_rows(diags)
    if not flagged:
        # Deliberately the SAME refusal a never-flagged `old_row` earns once the window has
        # emptied: a repeated identical repair is idempotent-safe by construction, and a
        # "you already did this" branch would need stored state this design avoids.
        raise ModelRetry(
            f"{UNCHANGED_NOTICE} Nothing is currently flagged in investigation.md, so there "
            f"is no row to repair."
        )
    if old_row not in flagged:
        # Scope, not merely match: `old_row` is confined to the flagged set, and the flagged
        # set is `:R attr_updates`-only. A verb that refused only when the text was ABSENT
        # would happily rewrite a committed vertex row that is present.
        raise ModelRetry(
            f"{UNCHANGED_NOTICE} `old_row` must be one of the rows currently flagged in "
            f"investigation.md, quoted exactly as the warning printed it."
            "\n\nCurrently flagged:\n"
            + "\n".join(f"  {row}" for row in flagged)
        )

    current = read_text_utf8(p)
    lines, seps = _split_lines(current)
    whole = [i for i, line in enumerate(lines) if line.strip() == old_row]
    if not whole:
        raise ModelRetry(
            f"{UNCHANGED_NOTICE} `old_row` matches no line in investigation.md."
        )
    # The repair applies to EVERY flagged occurrence — a flagged row whose text is not unique
    # would otherwise be neither repairable nor deletable, and with the write gate the run
    # would be unclosable. The rider keeps that safe: if the text also stands as a WHOLE LINE
    # the window did not flag, the repair refuses rather than rewriting that too.
    #
    # WHOLE-LINE, not substring. The rebuild below only touches lines where
    # `line.strip() == old_row`, so a line that merely CONTAINS the row is already out of reach
    # and a substring count guards nothing — while refusing on one wedges the window shut (a
    # `:T conclude` summary quoting its own flagged row makes both `fix_row(row, new)` and
    # `fix_row(row, "")` refuse) and fires falsely when one flagged row's text is a PREFIX of
    # another (`…|owner|svc` inside `…|owner|svc2`).
    occurrences = flagged.count(old_row)
    if len(whole) != occurrences:
        raise ModelRetry(
            f"{UNCHANGED_NOTICE} That row's text also stands as a whole line the repair "
            f"window did not flag ({len(whole)} line(s) match, {occurrences} flagged), and "
            f"`fix_row` will not rewrite a line it never flagged."
        )

    if new_row:
        # UNCONDITIONALLY, `cells is None` included. `_new_row_shape_reason` is written for
        # that case — an unlocatable declaring block narrows the guard by one arm (the cell
        # count) instead of switching the whole write surface off — and short-circuiting it
        # here inverted that: the one shape the caller could not vouch for was the one shape
        # the guard never saw, so a `new_row` spanning lines, carrying a fence delimiter, or
        # spelling a block header went through untested.
        cells = _attr_block_columns(current, old_row)
        reason = _new_row_shape_reason(new_row, cells)
        if reason is not None:
            raise ModelRetry(
                f"{UNCHANGED_NOTICE} `new_row` must be a single row of the same "
                f":R attr_updates block: {reason}. Send one row with the same columns, or "
                'an empty `new_row` to delete the line instead.'
            )

    # The whole on-disk LINE is what gets rewritten — leading/trailing whitespace included —
    # because `old_row` is matched against the STRIPPED row text the warning printed, and a
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
    _guarded_parents(deps, p)
    write_guarded(p, new_text)
    deps.authored_paths.add(_resolved(p))
    verb = "deleted" if not new_row else "repaired"
    lead = (
        f"{verb} {len(whole)} flagged row(s) in investigation.md "
        f"({_utf8_len(new_text)} bytes total) — the change LANDED."
    )
    # `fix_row` is a first-class FRONTIER MUTATOR, not a cosmetic repair: the window is
    # `:R attr_updates`-only, and those rows are exactly what closes an open slot — so a
    # repair can close one and a delete re-opens it. Without this the move goes unannounced
    # AND unannounceable: the next `append_block` reads the repair as part of its `before`,
    # the two frontiers match, and the block is suppressed for good.
    return _warning_return(
        lead + _frontier_recall(deps, current, new_text), _warn_over(new_text)
    )
