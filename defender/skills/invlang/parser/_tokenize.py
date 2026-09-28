"""The invlang tokenizer: which bytes of a document are invlang content, and how they cut into blocks and rows."""


from __future__ import annotations

import re
from collections.abc import Iterator
from functools import lru_cache

from defender._model import model

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
#: A line the author meant as a block header (`:<TAG>`), whether or not `HEADER_RE` accepts
#: it. Used to bound silent drops: it ends a story section and starts a new orphan run.
_HEADER_ATTEMPT_RE = re.compile(r"^:[A-Z]")
_LEAD_PREFIX_RE = re.compile(r"^l-(?P<id>[A-Za-z0-9]+)\.(?P<sub>.+)$")


@model
class ParseWarning:
    block: str
    row_index: int
    row: str
    reason: str
    file_path: str = ""
    #: The ids this warning dropped from the companion, when the rows were readable enough to
    #: name them. Set by whole-block rejections; a row-level failure's id is its row's first
    #: cell.
    dropped_ids: tuple[str, ...] = ()

    def format(self) -> str:
        loc = self.file_path or "(unknown file)"
        return (
            f"{loc}: {self.block} row {self.row_index}: {self.reason} "
            f"| row={self.row[:200]!r}"
        )




#: `ParseWarning.block` for a line filed under no block. Not header-shaped, so
#: `deferred_hypothesis_ids` cannot mistake it for a dropped declaration.
NO_OPEN_BLOCK = "(no open block)"


def _orphan_warning(lines: list[str]) -> ParseWarning:
    """The lines a rejected header takes down with it, as one warning naming the header.

    `HEADER_RE` rejects anything trailing a header (a comment, a stray bracket), and with no
    block open the line and every row beneath it would otherwise be dropped silently, leaving
    an empty companion with no warnings. One warning per run of orphan lines, since fixing the
    header fixes the rows; a run ends at the next header attempt, so each rejected header is
    named.
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
    """The empty `Block` a matched header opens. A trailing `?` marks a column optional, which
    sets `required_cells`."""
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
    """Emit the current run of orphan lines as one warning, and reset the run."""
    if orphans:
        warnings.append(_orphan_warning(orphans))
        orphans.clear()


def _tokenize_fence(body: str) -> tuple[list[Block], list[ParseWarning]]:
    blocks: list[Block] = []
    warnings: list[ParseWarning] = []
    cur: Block | None = None
    in_story = False
    # Lines reached with no block open; each run becomes one warning.
    orphans: list[str] = []

    for raw in body.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue

        if _STORY_HEADER_RE.match(stripped):
            _flush_orphans(orphans, warnings)
            in_story = True
            cur = None
            continue  # lint-row-drop: ok — the story heading itself, not a row

        m = HEADER_RE.match(stripped)
        if m:
            _flush_orphans(orphans, warnings)
            in_story = False
            cur = _header_block(m)
            blocks.append(cur)
            continue

        if in_story and not _HEADER_ATTEMPT_RE.match(stripped):
            continue  # lint-row-drop: ok — prose inside a story section, not a row

        if in_story or cur is None:
            if _HEADER_ATTEMPT_RE.match(stripped):
                # A rejected header ends any story section (which would otherwise swallow it
                # silently) and starts its own orphan run.
                _flush_orphans(orphans, warnings)
                in_story = False
            orphans.append(stripped)
            continue
        cur.rows.append(stripped)
    _flush_orphans(orphans, warnings)
    return blocks, warnings




@model(frozen=True)
class FenceScan:
    """What a document's ```invlang fences enclose, and what they leave out.

    The one place that decides which bytes are invlang content. The complement is reported
    alongside the content so no reader can drop it silently: content outside a fence never
    reaches the tokenizer, so it cannot even raise a `ParseWarning`.

    Reports, never refuses: `validate._check_surface` refuses only orphans a given write
    introduces, since committed bytes cannot be fenced after the fact, and the frontier and
    seed readers must never raise. A trailing unterminated fence counts as open to the end of
    the document (a write cut off mid-block, which the next append closes)."""

    #: The text inside each fence, in document order.
    bodies: tuple[str, ...]
    #: `(start, end)` of each full fence, delimiters included, so slicing at `spans[n-1][1]`
    #: keeps the closing delimiter.
    spans: tuple[tuple[int, int], ...]
    #: Block-opening lines outside every fence, as written. Matched on the stripped line, as
    #: the tokenizer matches headers.
    orphaned_headers: tuple[str, ...]
    #: Offset of the delimiter opening a trailing unterminated fence, or `None`; nothing after
    #: it counts as orphaned. `validate._check_surface` also reads it off the baseline, where
    #: the next append's own opener would otherwise pair with it and read as orphaned.
    open_tail: int | None


#: The opener, matched as a whole stripped line so a prose mention of it cannot open a phantom
#: region.
_FENCE_OPEN_LINE = "```invlang"


@lru_cache(maxsize=8)
def scan_fences(text: str) -> FenceScan:
    """Split `text` into what the ```invlang fences enclose and what they orphan.

    Never raises. Memoized because one `validate.diagnose` scans the same two documents
    several times; the bound is small because each key is a whole document."""
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
    """Every fence's blocks, grouped by fence, in document order.

    A fence is one `append_block` write, so rules about a single write need this grouping."""
    for body in scan_fences(text).bodies:
        yield _tokenize_fence(body)[0]


def iter_blocks(text: str) -> Iterator[Block]:
    """Every invlang `Block` in `text`, in document order, with its DECLARED header and its
    rows as the author wrote them.

    For checks that quote or rewrite a row: the parsed companion is lossy and drops headers.
    Per-row provenance is not kept on the companion because it would inflate the review lens
    prompts."""
    for blocks in iter_fence_blocks(text):
        yield from blocks