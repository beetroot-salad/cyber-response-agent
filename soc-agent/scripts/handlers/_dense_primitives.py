r"""Shared line-grammar primitives for the dense investigation format.

Single source of truth for the per-cell, per-row, and per-block tokenization
rules described in `docs/dense-investigation-format.md`. Four consumers
build on these primitives:

  - `_dense_parser.py`     — on-disk `\`\`\`invlang` fence walker (validator
                             + corpus loader)
  - `_prologue_dense.py`   — CONTEXTUALIZE subagent stdout parser
  - `_predict_dense.py`    — PREDICT subagent stdout parser
  - `_conclude_dense.py`   — REPORT handler-authored emit + parse

Each consumer adds its own phase-specific shape rules and raises its own
error class (so agent-retry prompts can quote a phase-tagged message). The
primitives accept an `error_cls` parameter so error type is the caller's
choice; the literal error-message substrings are preserved across the
migration so existing test matchers (`match="missing required cell"`,
`match="bare token"`, etc.) keep passing.

Public surface:

    DenseBlock              tokenized block (tag, name, columns, rows)
    DenseTokenizeError      default error class for primitives

    HEADER_RE               regex matching `:<TAG> <name> [col1|col2|...]`
    INVLANG_FENCE_RE        regex matching `\`\`\`invlang` fenced spans

    split_cells             pipe-split a row, honoring `\\|` as escape
    split_subcells          semicolon-split a packed cell (quote-aware)
    parse_attrs             `key=value;key=value` → dict
    parse_auth              `kind:source` → {kind, source}
    unquote                 strip surrounding double quotes (with `\\"`)
    split_csv               `,`-split, drop empties
    split_csv_or_semi       `;` if present else `,`, drop empties

    row_cells               split a row + pad/error against block columns
    row_record              row → {column: cell} dict
    tokenize_blocks         walk a body string → list[DenseBlock]
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from collections.abc import Iterable


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class DenseTokenizeError(ValueError):
    """Raised on a structural violation in the line grammar.

    Consumers typically pass their own `error_cls` (e.g.
    `PrologueOutputError`) to the primitives so the raised exception
    matches the phase-specific contract; this class is the default.
    """


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------


HEADER_RE = re.compile(
    r"^:(?P<tag>[A-Z])\s+(?P<name>[A-Za-z0-9_.\-]+)"
    r"(?:\s*\[(?P<cols>[^\]]*)\])?\s*$"
)

INVLANG_FENCE_RE = re.compile(r"```invlang\n(.*?)\n```", re.DOTALL)


# ---------------------------------------------------------------------------
# Block dataclass
# ---------------------------------------------------------------------------


@dataclass
class DenseBlock:
    tag: str                    # one letter, e.g. V|E|H|L|R|T|G|P
    name: str                   # e.g. "prologue.vertices", "conclude.surviving"
    columns: list[str] | None   # column names with `?` stripped; None = no `[...]`
    rows: list[str]             # raw row lines, no header, no blanks
    fence_index: int = 0        # which fence this block came from (debug aid)


# ---------------------------------------------------------------------------
# Cell-level helpers
# ---------------------------------------------------------------------------


def split_cells(row: str) -> list[str]:
    """Split a row on `|`, honoring `\\|` as an escaped pipe inside a cell.

    Cells are stripped of surrounding whitespace.
    """
    parts: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(row):
        ch = row[i]
        if ch == "\\" and i + 1 < len(row) and row[i + 1] == "|":
            cur.append("|")
            i += 2
            continue
        if ch == "|":
            parts.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur).strip())
    return parts


def split_subcells(cell: str) -> list[str]:
    """Split a packed cell on `;` at the top level.

    Honors `;` only outside of double-quoted spans so claims with embedded
    semicolons (e.g. `"a; b"`) stay intact.

    Escape semantics differ from `split_cells`: this splitter only treats
    `\\` as a literal-pass marker (next char is appended verbatim,
    backslash included) rather than unescaping `\\;` → `;`. Callers that
    need an embedded `;` form a quoted claim and let `unquote` handle
    `\\"`. The asymmetry with `split_cells` (which unescapes `\\|`) is
    intentional: the spec's only first-class escape inside sub-cells is
    `\\"` for embedded quotes.
    """
    out: list[str] = []
    cur: list[str] = []
    in_q = False
    i = 0
    while i < len(cell):
        ch = cell[i]
        if ch == "\\" and i + 1 < len(cell):
            cur.append(cell[i:i + 2])
            i += 2
            continue
        if ch == '"':
            in_q = not in_q
            cur.append(ch)
            i += 1
            continue
        if ch == ";" and not in_q:
            tok = "".join(cur).strip()
            if tok:
                out.append(tok)
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    tok = "".join(cur).strip()
    if tok:
        out.append(tok)
    return out


def parse_attrs(
    cell: str, error_cls: type[Exception] = DenseTokenizeError
) -> dict[str, str]:
    """Parse a `key=value;key=value` attrs cell.

    Empty cell → empty dict. Bare token without `=` raises `error_cls`.
    """
    out: dict[str, str] = {}
    if not cell:
        return out
    for kv in cell.split(";"):
        kv = kv.strip()
        if not kv:
            continue
        if "=" not in kv:
            raise error_cls(
                f"attrs cell has bare token without `=`: {kv!r}"
            )
        k, v = kv.split("=", 1)
        k = k.strip()
        if not k:
            raise error_cls(f"attrs cell has empty key: {kv!r}")
        out[k] = v.strip()
    return out


def parse_auth(
    cell: str, error_cls: type[Exception] = DenseTokenizeError
) -> dict[str, str]:
    """Parse an `auth_kind:source` cell — colon-split, both sides required."""
    if ":" not in cell:
        raise error_cls(
            f"auth_kind:source cell missing `:`: {cell!r}"
        )
    kind, source = cell.split(":", 1)
    kind = kind.strip()
    source = source.strip()
    if not kind or not source:
        raise error_cls(
            f"auth_kind:source cell has empty kind or source: {cell!r}"
        )
    return {"kind": kind, "source": source}


def unquote(s: str) -> str:
    """Strip surrounding double quotes if present, unescape `\\\"`."""
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1].replace('\\"', '"')
    return s


def split_csv(s: str) -> list[str]:
    """Split a comma-separated cell, dropping empties and trimming."""
    if not s:
        return []
    return [tok.strip() for tok in s.split(",") if tok.strip()]


def split_csv_or_semi(s: str) -> list[str]:
    """Split on `;` if present, else `,`. Drops empties, trims."""
    if not s:
        return []
    sep = ";" if ";" in s else ","
    return [tok.strip() for tok in s.split(sep) if tok.strip()]


# ---------------------------------------------------------------------------
# Row helpers (block-aware)
# ---------------------------------------------------------------------------


def row_cells(
    block: DenseBlock,
    row: str,
    error_cls: type[Exception] = DenseTokenizeError,
) -> list[str]:
    """Split a row against `block.columns`, padding with `""` for missing
    cells and raising `error_cls` if there are more cells than columns.
    """
    cells = split_cells(row)
    cols = block.columns or []
    if len(cells) < len(cols):
        cells = cells + [""] * (len(cols) - len(cells))
    elif len(cells) > len(cols):
        raise error_cls(
            f":{block.tag} {block.name}: row has more cells than columns "
            f"(expected {len(cols)}, got {len(cells)}): {row!r}"
        )
    return cells


def row_record(
    block: DenseBlock,
    row: str,
    error_cls: type[Exception] = DenseTokenizeError,
) -> dict[str, str]:
    """Return `{column: cell}` for a row. Pads short rows with empty cells."""
    cells = row_cells(block, row, error_cls)
    return dict(zip(block.columns or [], cells))


# ---------------------------------------------------------------------------
# Block tokenizer
# ---------------------------------------------------------------------------


def tokenize_blocks(
    body: str,
    *,
    valid_tags: Iterable[str] | None = None,
    error_cls: type[Exception] = DenseTokenizeError,
    fence_index: int = 0,
    allow_passthrough: bool = False,
) -> list[DenseBlock]:
    r"""Walk `body` line-by-line and return tokenized `DenseBlock`s.

    Parameters
    ----------
    body
        Block-grammar text — no fences, no markdown headers. Callers that
        walk a ```invlang fence pass the fence body; callers parsing
        subagent stdout pass the stripped envelope.
    valid_tags
        Optional whitelist (e.g. {"V", "E"} for prologue). If `None`, any
        single uppercase letter is accepted as a tag.
    error_cls
        Exception class raised on tokenization errors.
    fence_index
        Recorded on each block for diagnostic attribution.
    allow_passthrough
        When True, lines that don't match a header *and* don't start with
        `:<letter>` are appended to the current block as-is (used by the
        predict parser, which accepts story prose between blocks). When
        False, content before the first header raises.

    Errors
    ------
    Header validation: `:X` where `X` is lowercase or not in `valid_tags`,
    or `:<TAG><no-space>name` typos, raise `error_cls`.
    """
    out: list[DenseBlock] = []
    cur: DenseBlock | None = None
    valid = frozenset(valid_tags) if valid_tags is not None else None

    for raw in body.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        m = HEADER_RE.match(stripped)
        if m:
            tag = m.group("tag")
            if valid is not None and tag not in valid:
                raise error_cls(
                    f"unknown dense block tag :{tag} in {stripped!r} "
                    f"(valid: {sorted(valid)})"
                )
            cols_raw = m.group("cols")
            cols = (
                [c.strip().rstrip("?") for c in cols_raw.split("|")]
                if cols_raw is not None
                else None
            )
            cur = DenseBlock(
                tag=tag,
                name=m.group("name"),
                columns=cols,
                rows=[],
                fence_index=fence_index,
            )
            out.append(cur)
            continue

        # Reject `:X ...` looking lines that didn't match the header regex —
        # catches typos like `:foo` (lowercase) or `:V[no-space]name`.
        if stripped.startswith(":") and re.match(r"^:[A-Za-z]", stripped):
            raise error_cls(
                f"malformed dense block header: {stripped!r} "
                f"(expected `:<TAG> <name> [col1|col2|...]`)"
            )

        if cur is None:
            if allow_passthrough:
                continue
            raise error_cls(
                f"dense row appears before any block header: {stripped!r}"
            )
        cur.rows.append(stripped)

    return out
