"""Pins for `defender._yaml.safe_load_text_scalars` (#951).

The oracle-golden mechanical checks are text containment — "is this literal a whole value or
a token of what the projection emitted" — and they were run over a document `yaml.safe_load`
had already TYPED: an unquoted `2026-07-25T07:48:37.065Z` became a `datetime` whose `str()`
is `2026-07-25 07:48:37.065000+00:00`, `yes` became `True`, `0755` became `493`. The fix
reads the projection ONCE, with a loader that is `safe_load` in every structural respect and
hands every scalar back as its spelling. What is pinned is the two halves of that contract:
every scalar is its text (implicit type, explicit tag, quoted, block, null), and everything
else — merges, aliases, last-key-wins, the safe loader's refusals, the error translation —
is exactly what `safe_load` does to the same text. And that the loader is a subclass with
no class-level table of its own touched, so `yaml.safe_load` elsewhere still types.
"""
from __future__ import annotations

import pytest
import yaml

from defender._yaml import safe_load, safe_load_text_scalars


# every scalar comes back as the text it was written as

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
    assert safe_load_text_scalars(f"a: {spelling}") == {"a": spelling}
    assert not isinstance(yaml.safe_load(f"a: {spelling}")["a"], str), spelling


def test_a_shape_valid_but_calendar_invalid_instant_is_text_not_an_error():
    """PyYAML's timestamp resolver matches on SHAPE and hands the fields to `datetime`,
    which raises a bare `ValueError` on `2001-02-30` — at construction, which this loader
    skips for a scalar. (`safe_load` of the same text is a `YAMLError`, translated.)"""
    assert safe_load_text_scalars("a: 2001-02-30") == {"a": "2001-02-30"}
    assert safe_load_text_scalars("a: 2001-12-14t25:59:43.10-05:00") == {
        "a": "2001-12-14t25:59:43.10-05:00"}
    with pytest.raises(yaml.YAMLError):
        safe_load("a: 2001-02-30")


@pytest.mark.parametrize(("tagged", "literal"), [
    ("!!timestamp 2026-07-25T07:48:37.065Z", "2026-07-25T07:48:37.065Z"),
    ("!!int 0755", "0755"),
    ("!!bool yes", "yes"),
    ("!!float 1.50", "1.50"),
    ("!!str 22", "22"),
])
def test_an_explicitly_tagged_scalar_is_its_text_too(tagged, literal):
    """The other way YAML types a scalar. A tag is a construction instruction and scalar
    construction is the one step overridden, so it is the spelling either way (the
    adversary's F2 against the first cut of this fix, which only dropped the implicit
    resolvers)."""
    assert safe_load_text_scalars(f"a: {tagged}") == {"a": literal}


def test_a_python_tag_on_a_scalar_is_inert_and_on_a_collection_is_refused():
    """A `!!python/name:…` scalar constructs nothing — its text comes back and nothing
    runs. A `!!python/object/apply` node is a SEQUENCE, so it reaches the safe constructor,
    which refuses it exactly as `safe_load` does."""
    assert safe_load_text_scalars("a: !!python/name:os.system") == {"a": ""}
    text = "a: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(yaml.YAMLError):
        safe_load_text_scalars(text)
    with pytest.raises(yaml.YAMLError):
        safe_load(text)


def test_quoted_scalars_come_back_unquoted_as_safe_load_gives_them():
    assert safe_load_text_scalars(
        "a: '22'\nb: \"yes\"\nc: '2026-07-25T07:48:37.065Z'\nd: ''") == {
        "a": "22", "b": "yes", "c": "2026-07-25T07:48:37.065Z", "d": ""}


def test_block_scalars_are_their_folded_text():
    assert safe_load_text_scalars("d: >-\n  the leads investigate\n  the wrong host\n") == {
        "d": "the leads investigate the wrong host"}
    assert safe_load_text_scalars("d: |\n  2026-07-25T07:48:37.065Z\n") == {
        "d": "2026-07-25T07:48:37.065Z\n"}


@pytest.mark.parametrize("text", ["a: ~", "a: null", "a:", "a: "])
def test_a_null_is_whatever_was_written(text):
    """No special case: `~` is the text `~` and an empty value is `""`. The scorer's index
    drops `""`, and no author forbids `~`."""
    assert safe_load_text_scalars(text) == {"a": text.partition(":")[2].strip()}


def test_mapping_keys_are_text_too():
    """`1:` and `"1":` are two keys to `safe_load` and one here. No document read this way
    has typed keys; what matters is that the collapse is `safe_load`'s own last-wins."""
    assert safe_load_text_scalars("1: x\n'1': y") == {"1": "y"}
    assert safe_load("1: x\n'1': y") == {1: "x", "1": "y"}


# everything else is `safe_load`: one reading, with `safe_load`'s structure

def test_a_repeated_key_collapses_to_its_last_value_as_safe_load_does():
    """The point of ONE reading. A second walk of the node tree that took the FIRST
    `events:` scanned a different list from the one the typed document (and the judge)
    carried — a leak in the honoured list was missed."""
    text = "events: [{user.name: admin}]\nevents: [{user.name: root}]\n"
    assert safe_load_text_scalars(text) == safe_load(text) == {
        "events": [{"user.name": "root"}]}


def test_a_merge_key_merges_as_safe_load_does():
    """Tag resolution is untouched, so `<<:` is still the merge tag and the merged mapping's
    keys land in the row — the first cut dropped the resolvers and left a literal `<<` key;
    the second cut's tree walk looked the key up by name and never saw merged events."""
    text = "_d: &d {events: [{user.name: root}]}\nprojections:\n  - lead_id: l-001\n    <<: *d\n"
    assert safe_load_text_scalars(text)["projections"] == safe_load(text)["projections"] == [
        {"lead_id": "l-001", "events": [{"user.name": "root"}]}]


def test_an_alias_resolves_to_the_same_object_as_safe_load_gives():
    doc = safe_load_text_scalars("a: &c [root]\nb: *c")
    assert doc == {"a": ["root"], "b": ["root"]}
    assert doc["a"] is doc["b"]


def test_a_self_containing_anchor_loads_as_safe_load_does():
    """`a: &x {b: *x}` composes into a cyclic graph; `safe_load` builds the recursive
    structure and so does this."""
    doc = safe_load_text_scalars("a: &x {b: *x, c: leaf}")
    assert doc["a"]["c"] == "leaf"
    assert doc["a"]["b"] is doc["a"]


def test_an_empty_document_is_none():
    assert safe_load_text_scalars("") is None
    assert safe_load_text_scalars("# nothing but a comment\n") is None


def test_malformed_text_raises_a_yaml_error():
    with pytest.raises(yaml.YAMLError):
        safe_load_text_scalars("a: [unclosed")


def test_a_document_too_deep_to_parse_is_a_yaml_error_not_a_recursion_error():
    """The same translation `safe_load` makes, from the same function: a caller that
    catches `YAMLError` for malformed input must not get an interpreter error instead."""
    with pytest.raises(yaml.YAMLError, match="nested too deeply"):
        safe_load_text_scalars("a: " + "[" * 20000)


def test_the_loader_leaks_nothing_into_safe_load():
    """The first cut's process-wide hazard: a subclass that WROTE a class-level resolver
    table shared with `SafeLoader`. This one overrides a method only. After any number of
    text loads, `yaml.safe_load` in the same process still types."""
    for _ in range(3):
        safe_load_text_scalars("a: 2026-07-25T07:48:37.065Z\nb: 22\nc: yes")
    typed = yaml.safe_load("a: 2026-07-25T07:48:37.065Z\nb: 22\nc: yes")
    assert not isinstance(typed["a"], str)
    assert typed["b"] == 22
    assert typed["c"] is True
