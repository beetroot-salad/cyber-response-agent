"""Direct pins of the canonical frontmatter grammar (defender/_frontmatter.py).

These are the CENTER of #591: the five folded sites route through this one
grammar, so the grammar itself is pinned here directly rather than transitively
through the site tests (spec_graph_591 d_canonical_grammar_pin, rejected
alternative: "rely on the five site tests to pin the grammar transitively"). This
file is GREEN against HEAD — the canonical parser already exists; the fold does
not change it.

CRLF and non-UTF8 are exercised at the *parser* level here (strings constructed
in-test, so no ``read_text`` newline translation can mask them); the site tests
use binary fixtures.
"""
from __future__ import annotations

import pytest

from defender._frontmatter import (
    FrontmatterError,
    parse_frontmatter,
    parse_frontmatter_or_none,
    split_frontmatter,
)


def test_d_canonical_grammar_pin():
    fm, raw, body = split_frontmatter("---\r\nk: v\r\n---\r\nB\r\n")
    assert fm == {"k": "v"}
    assert raw == "k: v"
    assert body == "B"

    with pytest.raises(FrontmatterError):
        split_frontmatter("--- \nk: v\n---\nB\n")
    with pytest.raises(FrontmatterError):
        split_frontmatter("----\nk: v\n---\nB\n")

    for closer_doc in (
        "---\nk: v\n----\nB\n",
        "---\nk: v\n---text\nB\n",
        "---\nk: v\n--- \nB\n",
    ):
        fm2, _raw2, body2 = split_frontmatter(closer_doc)
        assert fm2 == {"k": "v"}, closer_doc
        assert body2 == "B", closer_doc

    fm3, _r3, body3 = split_frontmatter("---\nk: v\n---")
    assert fm3 == {"k": "v"}
    assert body3 == ""

    with pytest.raises(FrontmatterError):
        split_frontmatter("---\n---\n")

    _fm4, _r4, body4 = split_frontmatter("---\nk: v\n---\n\n  B middle  \n\n")
    assert body4 == "B middle"

    fm5, raw5, body5 = split_frontmatter("---\nk: v\n---\nbody\n---\nlater: x\n---\n")
    assert fm5 == {"k": "v"}
    assert raw5 == "k: v"
    assert body5 == "body\n---\nlater: x\n---"

    assert issubclass(FrontmatterError, ValueError)

    fm6, body6 = parse_frontmatter("---\nk: v\n---\nB\n")
    assert fm6 == {"k": "v"}
    assert body6 == "B"

    assert parse_frontmatter_or_none("no leading fence") is None
    assert parse_frontmatter_or_none("--- \nk: v\n---\nB\n") is None
    assert parse_frontmatter_or_none("---\n---\n") is None
    assert parse_frontmatter_or_none("---\nk: v\n---\nB\n") == {"k": "v"}
