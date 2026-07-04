"""Schema-free cell/row tokenizer for the invlang dense-companion format.

A pure dense-row lexer: it splits `|`-delimited rows (honoring quoted spans
and `\\|` escapes) and `;`-delimited sub-cells into tokens, pads/strict-checks
against a column count, and zips onto column names. It carries essentially no
schema knowledge — every function here works on raw strings and the generic
`Block`/`RowError` types from `_types.py`, so it can be unit-tested in isolation.

Schema-aware cell helpers (`_parse_auth`, the `:R` resolution canonicalization)
deliberately stay in `parser.py`; keeping them out of here lets this module
avoid any `schema.py` import.
"""

from __future__ import annotations

from ._types import Block, RowError


def _split_quoted(
    s: str, sep: str, *, unescape_delim: bool = False, keep_empty: bool = False
) -> list[str]:
    """Split `s` on `sep`, honoring double-quoted spans (a `sep` inside a
    `"..."` span is not a delimiter). Each token is `.strip()`ped.

    Two knobs capture the only differences between the cell (`|`) and
    sub-cell (`;`) tokenizers:

    - `unescape_delim`: when True, `\\<sep>` collapses to a literal `sep`
      and any *other* backslash is an ordinary character (so it can still
      let a following `"` toggle the quote state). When False, *any*
      `\\X` pair passes through verbatim (a `\\"` therefore does NOT
      toggle the quote).
    - `keep_empty`: when True, empty tokens are retained (the cell form
      needs them for the strict cell-count check); when False they are
      dropped.
    """
    parts: list[str] = []
    cur: list[str] = []
    in_q = False
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            if not unescape_delim:
                cur.append(s[i : i + 2])
                i += 2
                continue
            if s[i + 1] == sep:
                cur.append(sep)
                i += 2
                continue
            # unescape_delim, but the next char isn't the delimiter: the
            # backslash is an ordinary char (and may precede a quote).
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
    """Split a row on `|`, honoring two ways to escape:

    - `\\|` inside a cell: passes through as a literal `|`.
    - `|` inside a double-quoted span: not a delimiter.

    The quoted-span form is the LLM-friendly one and is what the
    current schema expects (`flags="EXE_WRITABLE|EXE_LOWER_LAYER"`).
    The backslash form is retained because it's free and harmless.
    """
    return _split_quoted(row, "|", unescape_delim=True, keep_empty=True)


def _split_subcells(cell: str) -> list[str]:
    """Top-level semicolon-split that honors double-quoted spans."""
    return _split_quoted(cell, ";")


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1].replace('\\"', '"')
    return s


def _row_cells(block: Block, row: str, expected: int) -> list[str]:
    """Strict cell-count check: too many cells = RowError (the typical
    LLM hiccup is an unescaped `|` inside an attrs value). Short rows
    are right-padded — that's not a hiccup, just trailing-optional cells.
    """
    cells = _split_cells(row)
    if len(cells) > expected:
        header = f" for [{'|'.join(block.columns)}]" if block.columns else ""
        raise RowError(
            f"row has {len(cells)} cells but {expected} expected{header} "
            f"(check for unescaped `|` inside an attrs/value cell)"
        )
    if len(cells) < expected:
        cells = cells + [""] * (expected - len(cells))
    return cells


def _row_dict(
    block: Block, row: str, default_cols: list[str] | None = None
) -> dict[str, str]:
    """The shared record-projector preamble: tokenize `row` to cells,
    pad/strict-check against the column count, and zip onto the column
    names. `block.columns` wins; `default_cols` (possibly empty) is the
    fallback when the block carried no `[...]` header.
    """
    cols = block.columns or default_cols or []
    cells = _row_cells(block, row, len(cols))
    return dict(zip(cols, cells, strict=False))


def _require(rec: dict[str, str], *keys: str, msg: str) -> None:
    """Raise `RowError(msg)` unless every named key is present and truthy."""
    if not all(rec.get(k) for k in keys):
        raise RowError(msg)


def _parse_attrs(cell: str) -> dict[str, str]:
    """Parse a `key=value;key=value` attrs cell.

    Splits on `;` outside double-quoted spans (so a value can contain
    `;`), and unquotes values whose form is `key="value"`. The cell-
    level row tokenizer already handles the `|` escape, so by this
    point we're working on a single cell's contents.
    """
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
    """Split on `;` if present, else `,`. Drops empties, trims."""
    if not s:
        return []
    sep = ";" if ";" in s else ","
    return [t.strip() for t in s.split(sep) if t.strip()]
