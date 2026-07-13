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


# demand: d_canonical_grammar_pin
def test_d_canonical_grammar_pin():
    # --- CRLF is normalized FIRST (constructed in-test, not read from disk) ---
    fm, raw, body = split_frontmatter("---\r\nk: v\r\n---\r\nB\r\n")
    assert fm == {"k": "v"}
    assert raw == "k: v"          # raw is the text BETWEEN the fences, CRLF normalized
    assert body == "B"

    # --- opener grammar: strict '---\n' ---
    # '--- \n' (trailing space) is REJECTED (the loose-regex laxity #591 kills)
    with pytest.raises(FrontmatterError):
        split_frontmatter("--- \nk: v\n---\nB\n")
    # '----\n' (four dashes) is REJECTED
    with pytest.raises(FrontmatterError):
        split_frontmatter("----\nk: v\n---\nB\n")

    # --- closer grammar: a plain substring search '\n---' (loose closers OK) ---
    for closer_doc in (
        "---\nk: v\n----\nB\n",       # '\n----'
        "---\nk: v\n---text\nB\n",    # '\n---text'
        "---\nk: v\n--- \nB\n",       # '\n--- ' (trailing space)
    ):
        fm2, _raw2, body2 = split_frontmatter(closer_doc)
        assert fm2 == {"k": "v"}, closer_doc
        assert body2 == "B", closer_doc

    # closer as the last line with NO trailing newline is accepted; body is empty
    fm3, _r3, body3 = split_frontmatter("---\nk: v\n---")
    assert fm3 == {"k": "v"}
    assert body3 == ""

    # --- '---\n---' (empty mapping) raises (no YAML mapping between fences) ---
    with pytest.raises(FrontmatterError):
        split_frontmatter("---\n---\n")

    # --- body is .strip()'d on BOTH sides ---
    _fm4, _r4, body4 = split_frontmatter("---\nk: v\n---\n\n  B middle  \n\n")
    assert body4 == "B middle"

    # a second fence block in the body does NOT re-open the frontmatter — raw is
    # the text up to the FIRST closer only, the rest stays in body verbatim
    fm5, raw5, body5 = split_frontmatter("---\nk: v\n---\nbody\n---\nlater: x\n---\n")
    assert fm5 == {"k": "v"}
    assert raw5 == "k: v"
    assert body5 == "body\n---\nlater: x\n---"

    # --- FrontmatterError is a ValueError (c_narrow_except's canonical anchor) ---
    assert issubclass(FrontmatterError, ValueError)

    # --- parse_frontmatter is the two-value view of the same contract ---
    fm6, body6 = parse_frontmatter("---\nk: v\n---\nB\n")
    assert fm6 == {"k": "v"} and body6 == "B"

    # --- parse_frontmatter_or_none absorbs FrontmatterError -> None, nothing else ---
    assert parse_frontmatter_or_none("no leading fence") is None
    assert parse_frontmatter_or_none("--- \nk: v\n---\nB\n") is None   # bad opener
    assert parse_frontmatter_or_none("---\n---\n") is None             # empty mapping
    assert parse_frontmatter_or_none("---\nk: v\n---\nB\n") == {"k": "v"}
