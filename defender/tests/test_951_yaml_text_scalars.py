"""Pins for `defender._yaml.value_texts` / `compose` (#951).

The oracle-golden mechanical checks are text containment — "is this literal a whole value or
a token of what the projection emitted" — and they were run over a document `yaml.safe_load`
had already TYPED: an unquoted `2026-07-25T07:48:37.065Z` became a `datetime` whose `str()`
is `2026-07-25 07:48:37.065000+00:00`, `yes` became `True`, `0755` became `493`. The fix
reads the model's spelling from where it still exists — the composed node tree, one step
before construction — and leaves every typed reader in the repo exactly as it was. Nothing
here subclasses a loader or touches a resolver table, so there is no process-wide hazard to
pin; what is pinned is that the walk returns the spelling, skips keys, and survives the
graphs `compose` can build.
"""
from __future__ import annotations

import pytest
import yaml

from defender._yaml import compose, value_texts


def _texts(text: str) -> list[str]:
    return value_texts(compose(text))


# every plain scalar comes back as the text it was written as

@pytest.mark.parametrize("spelling", [
    "2026-07-25T07:48:37.065Z",     # probe-006's millisecond instant
    "2026-07-24T07:45:35.000Z",     # `.000` — `isoformat()` would drop it
    "2026-07-25T07:40:00Z",
    "2026-07-25T07:48:37+00:00",
    "2026-07-25 07:48:37",          # the space-separated form is a YAML timestamp too
    "2026-07-25",                   # a bare date
    "22",
    "-3",
    "0755",                         # YAML 1.1 octal
    "0x1F",
    "1_000",
    "12:30",                        # sexagesimal
    "1.5",
    "1.50",
    "1.0e+3",                       # `1e3` is a STRING to YAML 1.1 — no exponent sign
    ".inf",
    "true",
    "false",
    "yes",
    "no",
    "on",
    "off",
])
def test_a_plain_scalar_is_the_exact_string_it_was_written_as(spelling):
    """Equality with the `str` is the whole assertion — and the fixture self-check that
    plain `safe_load` does NOT give the string is what makes it exercise anything."""
    assert _texts(f"a: {spelling}") == [spelling]
    assert not isinstance(yaml.safe_load(f"a: {spelling}")["a"], str), spelling


def test_a_shape_valid_but_calendar_invalid_instant_is_text_not_an_error():
    """PyYAML's timestamp resolver matches on SHAPE and hands the fields to `datetime`,
    which raises a bare `ValueError` on `2001-02-30` — at CONSTRUCTION, which the walk
    never reaches."""
    assert _texts("a: 2001-02-30") == ["2001-02-30"]
    assert _texts("a: 2001-12-14t25:59:43.10-05:00") == ["2001-12-14t25:59:43.10-05:00"]


@pytest.mark.parametrize(("tagged", "literal"), [
    ("!!timestamp 2026-07-25T07:48:37.065Z", "2026-07-25T07:48:37.065Z"),
    ("!!int 0755", "0755"),
    ("!!bool yes", "yes"),
    ("!!float 1.50", "1.50"),
    ("!!str 22", "22"),
])
def test_an_explicitly_tagged_scalar_is_its_text_too(tagged, literal):
    """The other way YAML types a scalar. A tag is a construction instruction and the walk
    constructs nothing, so it is the spelling either way (the adversary's F2 against the
    first cut of this fix, which only dropped the implicit resolvers)."""
    assert _texts(f"a: {tagged}") == [literal]


def test_a_python_tag_is_inert_in_the_walk_and_refused_by_safe_load():
    """`compose` never constructs, so a `!!python/object/apply` node is a scalar with a
    tag and nothing runs; the caller's own `safe_load` of the same text is what refuses it,
    which `score._measured` runs first."""
    text = "a: !!python/object/apply:os.system ['echo pwned']\n"
    assert _texts(text) == ["echo pwned"]
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load(text)


def test_quoted_scalars_come_back_unquoted_as_safe_load_gives_them():
    assert _texts("a: '22'\nb: \"yes\"\nc: '2026-07-25T07:48:37.065Z'\nd: ''") == [
        "22", "yes", "2026-07-25T07:48:37.065Z", ""]


def test_block_scalars_are_their_folded_text():
    assert _texts("d: >-\n  the leads investigate\n  the wrong host\n") == [
        "the leads investigate the wrong host"]
    assert _texts("d: |\n  2026-07-25T07:48:37.065Z\n") == ["2026-07-25T07:48:37.065Z\n"]


@pytest.mark.parametrize("text", ["a: ~", "a: null", "a:", "a: "])
def test_a_null_is_whatever_was_written_which_the_index_then_discards(text):
    """No special case: `~` is the text `~` and an empty value is `""`. The scorer's index
    drops `""`, and no author forbids `~`."""
    (value,) = _texts(text)
    assert value == text.partition(":")[2].strip()


# structure: keys skipped, every value reached, in document order

def test_mapping_keys_are_never_values():
    """The leak check must not read a schema field name (`user.name`) as a leak."""
    assert _texts("user.name: admin\nsource.ip: 10.0.0.1") == ["admin", "10.0.0.1"]
    assert "user.name" not in _texts("user.name: admin")


def test_nested_collections_are_walked_to_every_leaf_in_order():
    text = (
        "projections:\n"
        "  - lead_id: l-001\n"
        "    events:\n"
        "      - '@timestamp': 2026-07-25T07:48:37.065Z\n"
        "        destination.port: 22\n"
        "        tags: [1, x, ~]\n"
        "        nested: {n: 0755, m: [yes, 'yes']}\n"
        "      - <standard environment noise>\n"
    )
    assert _texts(text) == [
        "l-001", "2026-07-25T07:48:37.065Z", "22", "1", "x", "~", "0755", "yes", "yes",
        "<standard environment noise>",
    ]


def test_an_alias_is_counted_once_where_its_anchor_sits():
    """`&c` and `*c` are ONE node in the composed graph; the identity-keyed visited set
    reaches it once. The text is the same, and the checks index a set."""
    assert _texts("a: &c [root]\nb: *c") == ["root"]


def test_a_merge_key_reaches_the_merged_mapping_through_its_anchor():
    """`<<:` is a key like any other to the walk — skipped — and what it merges is the
    anchored mapping, already walked where it is defined. Nothing is lost and nothing is
    doubled; `safe_load` (which the scorer runs for structure) does the merge itself."""
    text = "_c: &c {must_not_emit: [root]}\nexpectation: {<<: *c, no_suppression: all}"
    assert _texts(text) == ["root", "all"]
    assert yaml.safe_load(text)["expectation"] == {"must_not_emit": ["root"],
                                                   "no_suppression": "all"}


def test_a_self_containing_anchor_terminates():
    """`a: &x {b: *x}` composes into a cyclic graph; a recursive walk would not return."""
    assert _texts("a: &x {b: *x, c: leaf}") == ["leaf"]


def test_an_empty_document_has_no_values():
    assert _texts("") == []
    assert _texts("# nothing but a comment\n") == []


def test_malformed_text_raises_a_yaml_error():
    with pytest.raises(yaml.YAMLError):
        _texts("a: [unclosed")
