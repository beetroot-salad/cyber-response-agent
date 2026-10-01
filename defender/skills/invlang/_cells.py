
from __future__ import annotations

from ._types import Block, RowError


def _split_quoted(
    s: str,
    sep: str,
    *,
    unescape_delim: bool = False,
    keep_empty: bool = False,
    strip: bool = True,
) -> list[str]:
    """The cell tokenizer. `strip=False` returns raw spans; a knob rather than a second
    scanner, so `_split_cells_raw` always finds the same boundaries as `_split_cells`."""
    parts: list[str] = []
    cur: list[str] = []
    in_q = False
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            # Every escape pair is consumed whole (`\<sep>` unescaped when asked), so the `"` of
            # a `\"` never reaches the quote toggle and silently merges cells.
            # `_count_unescaped_quotes` skips pairs the same way.
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
            tok = "".join(cur)
            tok = tok.strip() if strip else tok
            if keep_empty or tok:
                parts.append(tok)
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    tok = "".join(cur)
    tok = tok.strip() if strip else tok
    if keep_empty or tok:
        parts.append(tok)
    return parts


def _split_cells(row: str) -> list[str]:
    return _split_quoted(row, "|", unescape_delim=True, keep_empty=True)


def _split_cells_raw(row: str) -> list[str]:
    """Cell boundaries only, every byte preserved (no strip, no unescape).

    Cell N here is cell N of `_split_cells`, so a caller can replace one cell and rejoin with
    `"|"` leaving the others byte-identical; rebuilding from `_split_cells` output would lose
    padding and corrupt escaped pipes."""
    return _split_quoted(row, "|", keep_empty=True, strip=False)


def _split_subcells(cell: str) -> list[str]:
    return _split_quoted(cell, ";")


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1].replace('\\"', '"')
    return s


#: What the format writes where a row has nothing to say. A list row holding it projects as
#: absence. Also the empty-table marker (a single `none` row), which `_row_cells` must accept,
#: hence this layer.
_CONCLUDE_EMPTY_MARKERS: frozenset[str] = frozenset({"none", "n/a"})


def is_conclude_empty_marker(value: object) -> bool:
    """Does this value spell "nothing to say" (`none` / `n/a`, quoted or not, any case)?

    A scalar row keeps the marker, so gates asking "did the run state something" must use
    this rather than a blank test: `detection_notes none` is not blank.
    """
    return (
        isinstance(value, str)
        and _unquote(value.strip()).strip().lower() in _CONCLUDE_EMPTY_MARKERS
    )


def _count_unescaped_quotes(s: str) -> int:
    """How many `"` the tokenizer toggles on, skipping escape pairs as `_split_quoted` does."""
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
    """True when a row opens a `"` it never closes, the sign of a value spilled across lines.

    Tested by parity, not a leading `"`: `summary  "sensu" login is sanctioned` is valid.
    """
    return _count_unescaped_quotes(s) % 2 == 1


def _strip_quote_wrapper(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def _quotes_wrap_whole_values(cell: str) -> bool:
    """Does every `"` in this cell WRAP a value, rather than open mid-token?

    Row parity is not enough: `bastion"/internal|bastion"-01` has balanced quotes but the span
    swallows a `|`, shifting later cells silently. A quote may wrap a whole cell, a whole
    `;`-subcell, or the whole value of a `k=v`; a literal inner quote is written `\\"`.
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
    # Before the count checks: a bad count is usually this defect's symptom.
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
    # A lone `none` row is the complete empty-table marker, not a truncated row.
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
