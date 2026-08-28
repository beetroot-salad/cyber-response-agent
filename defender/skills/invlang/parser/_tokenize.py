"""The invlang tokenizer: which bytes of a document are invlang content, and how they cut into blocks and rows.

Split out of `parser.py` (#god-file). The layering runs one way — this module knows
nothing of records or of the projector; both import from here."""


from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache

from .._cells import (
    _row_cells,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _split_cells,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _split_quoted,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _split_subcells,  # noqa: F401 — re-export: invlang tests import it from `parser`
    is_conclude_empty_marker,  # noqa: F401 — re-export: parser is this name's public home
)
from .._types import Block

INVLANG_FENCE_RE = re.compile(r"```invlang\n(.*?)\n```", re.DOTALL)
HEADER_RE = re.compile(
    r"^:(?P<tag>[A-Z])\s+(?P<name>[A-Za-z0-9_.\-]+)"
    r"(?:\s*\[(?P<cols>[^\]]*)\])?\s*$"
)
_STORY_HEADER_RE = re.compile(r"^###\s+story\s+(h-[\w\-]+)\s*$")
#: A line the author MEANT as a block header — the `:<TAG>` opening of `HEADER_RE`, whether or
#: not the rest of the line is one `HEADER_RE` accepts. The FIRST TOKEN of the same grammar,
#: which is what makes "the author was opening a block here" decidable on a line the header
#: rule rejects. Two arms of `_tokenize_fence` read it, both to bound a silent drop: prose in a
#: `### story h-NNN` section is discarded without a warning, and a run of orphan lines would
#: otherwise be bounded only by the next ACCEPTED header.
_HEADER_ATTEMPT_RE = re.compile(r"^:[A-Z]")
_LEAD_PREFIX_RE = re.compile(r"^l-(?P<id>[A-Za-z0-9]+)\.(?P<sub>.+)$")


@dataclass
class ParseWarning:
    block: str
    row_index: int
    row: str
    reason: str
    file_path: str = ""
    #: The ids this warning DELETED from the companion, when it deleted any and the rows
    #: were still readable enough to name them — so a consumer need not re-parse the prose.
    #: Populated by whole-block rejections; a row-level failure already carries its row,
    #: and the id is that row's first cell.
    dropped_ids: tuple[str, ...] = ()

    def format(self) -> str:
        loc = self.file_path or "(unknown file)"
        return (
            f"{loc}: {self.block} row {self.row_index}: {self.reason} "
            f"| row={self.row[:200]!r}"
        )




#: `ParseWarning.block` for a line the tokenizer could file under no block at all — the absence
#: of a `Block` IS the defect. Deliberately not header-shaped: `deferred_hypothesis_ids`
#: matches declaration blocks by name, and a warning that dropped no declaration must not be
#: mistaken for one that did.
NO_OPEN_BLOCK = "(no open block)"


def _orphan_warning(lines: list[str]) -> ParseWarning:
    """The lines a rejected header takes down with it, as ONE warning naming the header.

    `HEADER_RE` anchors `\\s*$` immediately after the optional `[cols]`, so ANYTHING trailing a
    header makes the match fail — a `# loop 2 wrap-up` comment, a `(loop 3)` note, a dropped
    `]`, a missing space after the tag. The line then reads as a row, and with no block open it
    would be discarded together with every row beneath it in silence, against this module's
    rule that every drop earns a `ParseWarning`. (A fence headed `:T conclude   # loop 2` then
    parses to an EMPTY companion with `warnings == []`, so the benign write gate never runs.)

    Reached whenever no block is OPEN: the first header of a fence (the ordinary authoring
    path — `append_block` carries one block per fence), a header under a `### story h-NNN`
    section, and every rejected header after the first. With a block still open the same line
    lands as a ROW and draws a cell-count error instead.

    ONE warning per RUN of orphan lines: repairing the rejected header repairs the rows under
    it, so a seven-row `:T conclude` would otherwise cost eight errors for one trailing
    comment. The count of what followed is carried in the message, so nothing vanishes unnamed.

    A run ends at the next header ATTEMPT, not only at the next ACCEPTED header — otherwise two
    rejected headers fold into one warning naming only the first, and repairing that one does
    not repair the second (it opens a block, and the second lands in it as a bad ROW).
    """
    head, rest = lines[0], lines[1:]
    tail = (
        f", and with it the {len(rest)} line(s) under it, which had no block to land in"
        if rest
        else ""
    )
    return ParseWarning(
        block=NO_OPEN_BLOCK,
        row_index=-1,
        row=head,
        reason=(
            f"this line is not a block header and no block is open, so it was dropped{tail}. "
            f"A header is `:<TAG> <name>` with an optional `[col|col]` and NOTHING after it — "
            f"no trailing comment, note or stray bracket. Re-send the block with its header on "
            f"a line of its own."
        ),
    )


def _header_block(m: re.Match[str]) -> Block:
    """The empty `Block` a matched header opens — its declared columns, and how many of them a
    row has to carry. This is where a trailing `?` stops being a character and becomes
    `required_cells`."""
    cols_raw = m.group("cols")
    declared = (
        [c.strip() for c in cols_raw.split("|")] if cols_raw is not None else None
    )
    return Block(
        tag=m.group("tag"),
        name=m.group("name"),
        columns=[c.rstrip("?") for c in declared] if declared is not None else None,
        required_cells=(
            max(
                (i + 1 for i, c in enumerate(declared) if not c.endswith("?")),
                default=0,
            )
            if declared is not None
            else 0
        ),
    )


def _flush_orphans(orphans: list[str], warnings: list[ParseWarning]) -> None:
    """Discharge the run of orphan lines in hand as ONE warning, and reset the run.

    Module-level rather than a closure so the four call sites can be read for WHERE a run ends:
    a story heading, an accepted header, the next rejected one, end of fence."""
    if orphans:
        warnings.append(_orphan_warning(orphans))
        orphans.clear()


def _tokenize_fence(body: str) -> tuple[list[Block], list[ParseWarning]]:
    blocks: list[Block] = []
    warnings: list[ParseWarning] = []
    cur: Block | None = None
    in_story = False
    # Lines reached with no block open. They LAND here rather than being dropped, and
    # `_flush_orphans` turns each run of them into one warning.
    orphans: list[str] = []

    for raw in body.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue

        if _STORY_HEADER_RE.match(stripped):
            _flush_orphans(orphans, warnings)
            in_story = True
            cur = None
            # A state transition, not a row: the line consumed IS the heading, so there is
            # nothing here to land and nothing a warning could name. (The flush above
            # discharges the run that ENDED here; it says nothing about this line.)
            continue  # lint-row-drop: ok — the story heading itself, not a row

        m = HEADER_RE.match(stripped)
        if m:
            _flush_orphans(orphans, warnings)
            in_story = False
            cur = _header_block(m)
            blocks.append(cur)
            continue

        if in_story and not _HEADER_ATTEMPT_RE.match(stripped):
            # A `### story h-NNN` section is narrative by construction, so there is no row
            # here to land and nothing a warning could name.
            continue  # lint-row-drop: ok — prose inside a story section, not a row

        if in_story or cur is None:
            if _HEADER_ATTEMPT_RE.match(stripped):
                # A header the header RULE rejected does two things. It ENDS any story section
                # above it — otherwise `### story h-001` over a `:T conclude  # loop 2`
                # swallows the header and every row beneath it in silence. And it opens its OWN
                # orphan run, because repairing the PREVIOUS run's header does not repair this
                # one; see `_orphan_warning`.
                _flush_orphans(orphans, warnings)
                in_story = False
            orphans.append(stripped)
            continue
        cur.rows.append(stripped)
    _flush_orphans(orphans, warnings)
    return blocks, warnings




@dataclass(frozen=True)
class FenceScan:
    """What a document's ```invlang fences enclose, AND what they leave out.

    THE ONE PLACE that answers "which bytes are invlang content". Three readers had derived
    it independently — the tokenizer, the frontier's prefix rebuild, and the turn-N seed
    slicer — each restating in prose that fences are the content and the rest is ignored,
    and each blind to the same thing in the same way. Ignoring the rest is correct; ignoring
    it SILENTLY is what let a run's whole PLAN section sit outside a fence, parse to nothing,
    and clear every hypothesis-side rule vacuously (#932).

    So the complement rides along with the content and cannot be taken without it. `bodies`
    and `spans` are what the fences hold; `orphaned_headers` is the accounting — lines that
    open a block (`_HEADER_ATTEMPT_RE`) while sitting outside every fence, which is content
    the author wrote and no reader will ever see.

    **This type reports; it does not refuse.** Whether an orphan is an error, and for whom,
    is policy: `validate._check_surface` refuses only the orphans a given WRITE introduces,
    because `investigation.md` is append-only and bytes already committed cannot be fenced
    after the fact. Raising here instead would wedge every later write on a document already
    broken, and would turn the frontier and seed readers — which must never raise — into
    paths that do.

    A TRAILING UNTERMINATED ```invlang counts as open to end-of-document (`open_tail`). That
    is a write cut off mid-block: the next append closes it and the rows parse, a shape
    `tests/test_frontier_recall_919.py` fixes as accepted by design. Rows orphaned after a
    CLOSED fence are permanent — no later append reaches back to wrap committed bytes — so
    only those are reported."""

    #: The text inside each fence, in document order — `INVLANG_FENCE_RE`'s group(1).
    bodies: tuple[str, ...]
    #: `(start, end)` of each FULL fence — the ```invlang delimiter through the closing
    #: ``` — against the original text. Full, not the enclosed region: the turn-N seed
    #: slicer cuts a document at `spans[n-1][1]` and an inner bound would drop the closing
    #: delimiter.
    spans: tuple[tuple[int, int], ...]
    #: Block-opening lines that fell outside every fence, as the author wrote them. Matched
    #: on the STRIPPED line, the way `_tokenize_fence` matches the same regex — an indented
    #: `:H` is a header the tokenizer would open a block on, so outside a fence it is
    #: orphaned content and not prose.
    orphaned_headers: tuple[str, ...]
    #: Offset of the ```invlang delimiter that opens a trailing UNTERMINATED fence, or
    #: `None`. Everything from here to end-of-document is a block the author is still in the
    #: middle of writing, so nothing under it counts as orphaned. `validate._check_surface`
    #: reads it off the BASELINE too: with the on-disk document mid-block, the next append's
    #: own ```invlang gets paired with the open one by `INVLANG_FENCE_RE` and the new block
    #: reads as orphaned, which would refuse the only continuation `append_block` can send.
    open_tail: int | None


#: The opener, as a whole line. A prose MENTION of ```invlang — the repair instruction
#: `_check_surface` prints contains one — must not open a phantom region to end-of-document
#: and swallow every orphan under it, so the test is the stripped LINE, not `str.find`.
_FENCE_OPEN_LINE = "```invlang"


@lru_cache(maxsize=8)
def scan_fences(text: str) -> FenceScan:
    """Split `text` into what the ```invlang fences enclose and what they orphan.

    Never raises and never refuses — see `FenceScan`. Every reader of fenced content goes
    through here so that the complement is accounted for once, in the open, rather than
    dropped on the floor three times.

    MEMOIZED because it is not free and one `validate.diagnose` calls it seven times over the
    same two documents — `_check_surface`, `_check_append_only` and `parse_dense_companion`
    each on the proposal and the baseline. Pure function of `text`, so the cache can only
    return what a re-scan would; the bound is small because the strings it pins are whole
    investigation documents (64 KiB each at the cap)."""
    matches = list(INVLANG_FENCE_RE.finditer(text))
    spans = tuple(m.span() for m in matches)
    open_tail: int | None = None
    orphans: list[str] = []
    offset = 0
    for line in text.split("\n"):
        start, end = offset, offset + len(line)
        offset = end + 1
        inside = any(a <= start and end <= b for a, b in spans)
        stripped = line.strip()
        if not inside and stripped == _FENCE_OPEN_LINE:
            # An opener the regex could not pair: the fence it starts runs to EOF.
            open_tail = start if open_tail is None else open_tail
            continue
        if inside or (open_tail is not None and start >= open_tail):
            continue
        if _HEADER_ATTEMPT_RE.match(stripped):
            orphans.append(line)
    return FenceScan(
        bodies=tuple(m.group(1) for m in matches),
        spans=spans,
        orphaned_headers=tuple(orphans),
        open_tail=open_tail,
    )


def iter_fence_blocks(text: str) -> Iterator[list[Block]]:
    """Every FENCE's blocks, grouped by the fence that holds them, in document order.

    The grouping is what `iter_blocks` below throws away, and a check whose rule is about ONE
    WRITE needs it: `append_block` sends one ```invlang fence per call, and a fence carries as
    many `:X` blocks as the author put in it (the prologue's `:V` and `:L` ride in one). A
    rule scoped to the parsed BLOCK therefore answers "one atomic write" wrong by exactly the
    reformatting that splits a block in two — same fence, same write, two maps, nothing said.

    Blocks only, for the reason `iter_blocks` states: a line that reached no block has no
    block to quote it under."""
    for body in scan_fences(text).bodies:
        yield _tokenize_fence(body)[0]


def iter_blocks(text: str) -> Iterator[Block]:
    """Every invlang `Block` in `text`, in document order, with its DECLARED header and its
    rows as the author wrote them.

    The projection `parse_dense_companion` builds is lossy on purpose — it folds rows into
    records and drops the header. A check that has to quote a row back, or substitute one cell
    of it, needs this layer underneath: rebuilding a row from the folded record means assuming
    a column order the grammar does not enforce.

    Flattens `iter_fence_blocks` rather than re-walking the fences, so the two readings of
    "the blocks of this document" cannot drift.

    Kept out of the companion deliberately: carrying per-row provenance on the records inflated
    the parsed body by up to 25%, and that body is projected into the review lens prompts."""
    for blocks in iter_fence_blocks(text):
        yield from blocks