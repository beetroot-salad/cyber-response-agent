
from __future__ import annotations

from ._types import Block, RowError


def _split_quoted(
    s: str, sep: str, *, unescape_delim: bool = False, keep_empty: bool = False
) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    in_q = False
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            # ONE branch decides what an escape pair means: `\<sep>` unescapes when asked,
            # every OTHER pair is consumed verbatim, 2 bytes at a time. Falling through on
            # unclaimed pairs would let the `"` of a `\"` reach the quote toggle below, so a
            # row with an odd number of `\"` before its last cell flips into "inside a quote",
            # swallows the remaining `|`s, and `_row_cells` pads the short record with empty
            # strings — cells silently merged, no RowError. `_has_unbalanced_quote` skips the
            # pair the same way.
            if unescape_delim and s[i + 1] == sep:
                cur.append(sep)
                i += 2
                continue
            cur.append(s[i : i + 2])
            i += 2
            continue
        if ch == '"':
            in_q = not in_q
            cur.append(ch)
            i += 1
            continue
        if ch == sep and not in_q:
            tok = "".join(cur).strip()
            if keep_empty or tok:
                parts.append(tok)
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    tok = "".join(cur).strip()
    if keep_empty or tok:
        parts.append(tok)
    return parts


def _split_cells(row: str) -> list[str]:
    return _split_quoted(row, "|", unescape_delim=True, keep_empty=True)


def _split_subcells(cell: str) -> list[str]:
    return _split_quoted(cell, ";")


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1].replace('\\"', '"')
    return s


#: What the format writes where a row has nothing to say (`docs/dense-investigation-
#: format.md`: these "carry `none` / `n/a`" unless the run terminated on a ceiling). A list row
#: holding it projects as absence, so a reader tests `conclude.get("ceiling_test")` rather than
#: filtering a sentinel back out.
#:
#: Lives at this layer rather than beside the conclude projection because `_row_cells` is a
#: SECOND reader: `none` is also how an empty TABLE is written (`:T conclude.surviving`
#: carrying one `none` row), and a one-cell row under a two-column header is exactly the shape
#: the required-cell check refuses. One owner, so the two readings cannot drift apart.
_CONCLUDE_EMPTY_MARKERS: frozenset[str] = frozenset({"none", "n/a"})


def is_conclude_empty_marker(value: object) -> bool:
    """Does this conclude row value spell "nothing to say"? THE membership test for the
    vocabulary above, beside the vocabulary.

    A SCALAR row keeps the marker — only the list branch drops it — so a gate that asks
    "did the run state a defect" has to ask this rather than `value.strip()`: `detection_notes
    none` is the row that explicitly says there is no defect, and it is not blank.

    `_unquote`d, because every OTHER reader of a cell sees through the author's quoting and
    this one has to agree with them. A block whose single row is `"none"` is the empty-TABLE
    marker written by an author who quotes uniformly; read raw, it lands as a RECORD whose id
    is `"none"` — an `lp*` that fails four of rule #18's arms, an undeclared `h-*` at
    `:T conclude.surviving`'s reference site — and the refusal never says the author wrote the
    marker. Unquoting an already-unquoted cell is identity, so this is the read every caller
    wanted.
    """
    return (
        isinstance(value, str)
        and _unquote(value.strip()).strip().lower() in _CONCLUDE_EMPTY_MARKERS
    )


def _count_unescaped_quotes(s: str) -> int:
    """How many `"` the tokenizer will TOGGLE on — escape pairs skipped, exactly as
    `_split_quoted` consumes them."""
    quotes = 0
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            i += 2
            continue
        if s[i] == '"':
            quotes += 1
        i += 1
    return quotes


def _has_unbalanced_quote(s: str) -> bool:
    """True when a row opens a `"` it never closes — the multi-line author's signature.

    invlang is line-oriented: `_tokenize_fence` makes ONE row per line for every block, so a
    value written across two lines keeps line one (quote dangling) and reparses the rest as
    fresh rows. Parity is the test, not a leading `"`: `summary  "sensu" login is sanctioned`
    is a valid one-line row that starts with a quote, and denying it would block a conclusion
    the author cannot rewrite into anything the check likes better.
    """
    return _count_unescaped_quotes(s) % 2 == 1


def _strip_quote_wrapper(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def _quotes_wrap_whole_values(cell: str) -> bool:
    """Does every `"` in this cell WRAP a value, rather than open mid-token?

    Row parity is not enough: `bastion"/internal|bastion"-01` carries an EVEN number of quotes,
    so `_has_unbalanced_quote` stays silent, yet the first one opens a quoted span that
    swallows the `|` between them. Every cell after it shifts left and the optional trailing
    column absorbs the shift, so the count check cannot see it either — an `attrs` value slides
    into `ident`, where nothing gates it.

    A quote is legal wrapping the whole cell (`"free text with a | in it"`), a whole
    `;`-subcell, or the whole right-hand side of a `k=v` (`flags="EXE_WRITABLE|EXE_LOWER"`).
    That is every shape the shipped corpus uses. Anything else is a quote opening inside a
    token, which is the malformation; an inner quote that is meant literally spells itself
    `\\"` and never reaches the toggle.

    Rows in blocks that declare no `[a|b|c]` header never arrive here — `:T conclude` and
    `:T resolutions` carry free text with bare quotes and are projected by their own readers,
    not by cell splitting.
    """
    if _count_unescaped_quotes(cell) == 0:
        return True
    if _count_unescaped_quotes(_strip_quote_wrapper(cell)) == 0:
        return True
    for sub in _split_subcells(cell):
        if _count_unescaped_quotes(sub) == 0:
            continue
        if _count_unescaped_quotes(_strip_quote_wrapper(sub)) == 0:
            continue
        _key, sep, value = sub.partition("=")
        if sep and _count_unescaped_quotes(_strip_quote_wrapper(value)) == 0:
            continue
        return False
    return True


def _row_cells(block: Block, row: str, expected: int) -> list[str]:
    cells = _split_cells(row)
    # Before either count check, because a bad count is usually this defect's SYMPTOM and
    # the author needs the cause named: a quote that opens mid-token merged the cells.
    for cell in cells:
        if not _quotes_wrap_whole_values(cell):
            raise RowError(
                f"cell {cell!r} opens a `\"` inside a token — a quote may only wrap a "
                f"whole cell, a whole `;`-subcell or the whole value of a `k=v`, and "
                f"anything else silently merges this row's remaining cells; write a "
                f"literal quote as `\\\"`"
            )
    if len(cells) > expected:
        header = f" for [{'|'.join(block.columns)}]" if block.columns else ""
        raise RowError(
            f"row has {len(cells)} cells but {expected} expected{header} "
            f"(check for unescaped `|` inside an attrs/value cell)"
        )
    # "Empty arrays render as a single `none` row" (`docs/dense-investigation-format.md`), so
    # a lone marker is a COMPLETE row saying the table is empty — not a truncated one.
    if len(cells) == 1 and is_conclude_empty_marker(cells[0]):
        return cells + [""] * (expected - 1)
    if len(cells) < block.required_cells:
        header = f" for [{'|'.join(block.columns)}]" if block.columns else ""
        raise RowError(
            f"row has {len(cells)} cells but the header requires "
            f"{block.required_cells}{header} — only a `?` column may be omitted "
            f"(an unbalanced `\"` inside a cell merges the cells after it: quote the "
            f"whole cell, or escape the quote as `\\\"`)"
        )
    if len(cells) < expected:
        cells = cells + [""] * (expected - len(cells))
    return cells


def _row_dict(
    block: Block, row: str, default_cols: list[str] | None = None
) -> dict[str, str]:
    cols = block.columns or default_cols or []
    cells = _row_cells(block, row, len(cols))
    return dict(zip(cols, cells, strict=False))


def _require(rec: dict[str, str], *keys: str, msg: str) -> None:
    if not all(rec.get(k) for k in keys):
        raise RowError(msg)


def _parse_attrs(cell: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not cell:
        return out
    for kv in _split_subcells(cell):
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        out[k.strip()] = _unquote(v.strip())
    return out


def _split_csv(s: str) -> list[str]:
    return [t.strip() for t in s.split(",") if t.strip()] if s else []


def _split_csv_or_semi(s: str) -> list[str]:
    if not s:
        return []
    sep = ";" if ";" in s else ","
    return [t.strip() for t in s.split(sep) if t.strip()]
