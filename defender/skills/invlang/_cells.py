
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
            if not unescape_delim:
                cur.append(s[i : i + 2])
                i += 2
                continue
            if s[i + 1] == sep:
                cur.append(sep)
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


def _row_cells(block: Block, row: str, expected: int) -> list[str]:
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
