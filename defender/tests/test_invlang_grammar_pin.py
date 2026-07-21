"""Pin: the ```invlang column grammar documented in `skills/invlang/SKILL.md`
must match the parser's column constants.

`SKILL.md` is injected verbatim as the authoring surface — it tells the agent
which columns to write, in which order (`:V [id|type|class|ident|attrs?]`). The
parser reads those same rows positionally against its column constants
(`_VERTEX_COLS` etc.). The two are a hand-maintained pair: if a column is
added / reordered / renamed in one and not the other, the agent writes a
surface the parser rejects — and for the 9-col `:H` header that's a *whole-block*
rejection (`_is_current_hyp_header`), i.e. a `ModelRetry` storm at runtime.

This test pins the doc to the constants so that drift fails in CI (cheap, early)
instead of at runtime (expensive, late). It compares the live constants, not a
saved snapshot, so neither side can move alone.

Coverage: the surfaces that have a fixed parser column constant —
`:V`/`:E` rows, the `:H hypothesize.hypotheses` header, and the `:H h-NNN.<sub>`
sub-blocks. `:L findings` and `:R …` blocks read their columns from the block's
own header (no fixed constant), so they are out of scope here.
"""

from __future__ import annotations

import re
from pathlib import Path

from defender.skills.invlang import parser

_SKILL_MD = (
    Path(__file__).resolve().parents[1] / "skills" / "invlang" / "SKILL.md"
)

_HEADER_RE = re.compile(
    r"^:(?P<tag>[A-Z])\s+(?P<name>[\w.\-]+)\s+\[(?P<cols>[^\]]+)\]"
)


def _cols(raw: str) -> list[str]:
    """Split a `[a|b|c?]` header body into columns, dropping the optional `?`."""
    return [c.strip().rstrip("?") for c in raw.split("|")]


def _documented_headers() -> list[tuple[str, str, list[str]]]:
    """Every `(tag, name, columns)` bracketed block header in SKILL.md."""
    out: list[tuple[str, str, list[str]]] = []
    for line in _SKILL_MD.read_text().splitlines():
        m = _HEADER_RE.match(line.strip())
        if m:
            out.append((m["tag"], m["name"], _cols(m["cols"])))
    return out


def _expected(tag: str, name: str) -> list[str] | None:
    """The parser column constant a documented `(tag, name)` block must match,
    or None when the block has no fixed constant (`:L`/`:R`/dynamic-header)."""
    if tag == "V":
        return parser._VERTEX_COLS
    if tag == "E":
        return parser._EDGE_COLS
    if tag == "H":
        if name == "hypothesize.hypotheses":
            return sorted(parser._HYP_HEADER_COLS)
        if name.endswith(".preds"):
            return parser._HYP_PRED_COLS
        if name.endswith(".attr_preds"):
            return parser._HYP_ATTR_PRED_COLS
        if name.endswith(".refuts"):
            return parser._HYP_REFUT_COLS
        if name.endswith(".authz"):
            return parser._HYP_AUTHZ_COLS
    return None


def test_skill_md_grammar_matches_parser_constants():
    documented = _documented_headers()
    pinned_tags: set[str] = set()
    for tag, name, cols in documented:
        expected = _expected(tag, name)
        if expected is None:
            continue
        if tag == "H" and name == "hypothesize.hypotheses":
            assert sorted(cols) == expected, (
                f":{tag} {name} header {cols} != parser _HYP_HEADER_COLS"
            )
        else:
            assert cols == expected, (
                f":{tag} {name} header {cols} != parser constant {expected}"
            )
        pinned_tags.add(tag)

    assert {"V", "E", "H"} <= pinned_tags, (
        f"expected to pin :V/:E/:H grammar headers from SKILL.md, "
        f"found tags {sorted(pinned_tags)} — extraction may have broken"
    )
