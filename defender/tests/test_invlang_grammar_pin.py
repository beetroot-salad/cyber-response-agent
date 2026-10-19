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


def _is_hyp_declaration(tag: str, name: str) -> bool:
    """The two sites that DECLARE a hypothesis, as opposed to hanging a sub-block off one."""
    return bool(parser.HYP_DECLARATION_BLOCK_RE.match(f":{tag} {name}"))


def _expected(tag: str, name: str) -> list[str] | None:
    """The parser column constant a documented `(tag, name)` block must match,
    or None when the block has no fixed constant (`:L`/`:R`/dynamic-header)."""
    if tag == "V":
        return parser._VERTEX_COLS
    if tag == "E":
        return parser._EDGE_COLS
    if _is_hyp_declaration(tag, name):
        return sorted(parser._HYP_HEADER_COLS)
    if tag == "H":
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
    pinned_names: set[str] = set()
    for tag, name, cols in documented:
        expected = _expected(tag, name)
        if expected is None:
            continue
        if _is_hyp_declaration(tag, name):
            assert sorted(cols) == expected, (
                f":{tag} {name} header {cols} != parser _HYP_HEADER_COLS"
            )
        else:
            assert cols == expected, (
                f":{tag} {name} header {cols} != parser constant {expected}"
            )
        pinned_tags.add(tag)
        pinned_names.add(name)

    assert {"V", "E", "H"} <= pinned_tags, (
        f"expected to pin :V/:E/:H grammar headers from SKILL.md, "
        f"found tags {sorted(pinned_tags)} — extraction may have broken"
    )
    assert "hypothesize.hypotheses" in pinned_names, (
        "SKILL.md no longer documents a `:H hypothesize.hypotheses` header"
    )
    assert any(n.endswith(".new_hypotheses") for n in pinned_names), (
        f"SKILL.md must document the mid-run fork's `:H l-NNN.new_hypotheses` "
        f"header for this pin to cover it; pinned names {sorted(pinned_names)}"
    )
