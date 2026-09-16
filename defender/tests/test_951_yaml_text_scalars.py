"""Pins for `defender._yaml.safe_load_typed_and_spelled` (#951).

The oracle-golden mechanical checks are text containment — "is this literal a whole value or
a token of what the projection emitted" — and they were run over a document `yaml.safe_load`
had already TYPED: an unquoted `2026-07-25T07:48:37.065Z` became a `datetime` whose `str()`
is `2026-07-25 07:48:37.065000+00:00`, `yes` became `True`, `0755` became `493`. The fix
parses the projection ONCE and constructs two readings from that one node tree: `typed`,
which is `safe_load`'s document, and `spelled`, which has the same shape exactly with every
VALUE scalar as its text. What is pinned is the contract of the spelled half — every value
scalar is its text (implicit type, explicit tag, quoted, block, null), and everything else —
the shape, keys included, merges, aliases, last-key-wins, the safe loader's refusals, the
error translation — is exactly what `safe_load` does to the same text; that the typed half
IS `safe_load`; and that the constructor is a subclass with no class-level table of its own
touched, so `yaml.safe_load` elsewhere still types.
"""
from __future__ import annotations

from datetime import date

import pytest
import yaml

from defender._yaml import safe_load, safe_load_typed_and_spelled


def spelled(text: str):
    return safe_load_typed_and_spelled(text).spelled


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
    assert spelled(f"a: {spelling}") == {"a": spelling}
    assert not isinstance(yaml.safe_load(f"a: {spelling}")["a"], str), spelling


def test_a_shape_valid_but_calendar_invalid_instant_is_refused_as_safe_load_refuses_it():
    """PyYAML's timestamp resolver matches on SHAPE and hands the fields to `datetime`,
    which raises a bare `ValueError` on `2001-02-30`. The spelled half alone would carry it
    as text, but the pair is one reading of one document and its typed half is `safe_load`
    — so the document is refused, translated, exactly as `safe_load` refuses it. (A
    projection carrying an impossible date is malformed, and was before #951.)"""
    with pytest.raises(yaml.YAMLError, match="could not be constructed"):
        safe_load_typed_and_spelled("a: 2001-02-30")
    with pytest.raises(yaml.YAMLError, match="could not be constructed"):
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
    assert spelled(f"a: {tagged}") == {"a": literal}


@pytest.mark.parametrize("text", [
    "a: !!python/name:os.system",                       # a scalar
    "a: !!python/object/apply:os.system ['echo pwned']\n",  # a sequence
])
def test_a_python_tag_is_refused_wherever_it_sits_as_safe_load_refuses_it(text):
    """The typed half is the safe constructor, which has no constructor for a `!!python/…`
    tag on a scalar OR a collection, so the pair refuses the document before anything is
    constructed from it — the same refusal `safe_load` gives. (A scalar's spelled half alone
    would have been inert text; it is never produced without the typed half.)"""
    with pytest.raises(yaml.YAMLError):
        safe_load_typed_and_spelled(text)
    with pytest.raises(yaml.YAMLError):
        safe_load(text)


def test_quoted_scalars_come_back_unquoted_as_safe_load_gives_them():
    assert spelled(
        "a: '22'\nb: \"yes\"\nc: '2026-07-25T07:48:37.065Z'\nd: ''") == {
        "a": "22", "b": "yes", "c": "2026-07-25T07:48:37.065Z", "d": ""}


def test_block_scalars_are_their_folded_text():
    assert spelled("d: >-\n  the leads investigate\n  the wrong host\n") == {
        "d": "the leads investigate the wrong host"}
    assert spelled("d: |\n  2026-07-25T07:48:37.065Z\n") == {
        "d": "2026-07-25T07:48:37.065Z\n"}


@pytest.mark.parametrize("text", ["a: ~", "a: null", "a:", "a: "])
def test_a_null_is_whatever_was_written(text):
    """No special case: `~` is the text `~` and an empty value is `""`. The scorer's index
    drops `""`, and no author forbids `~`."""
    assert spelled(text) == {"a": text.partition(":")[2].strip()}


def test_mapping_keys_stay_typed_so_both_readings_keep_the_same_pairs():
    """`1:` and `'1':` are two keys to `safe_load`, so they are two keys here. A text key
    would merge them and drop one of the two VALUES — a value the judge is shown (typed)
    that the containment index (spelled) never saw (the review's finding against the fourth
    cut). The reading spells values; the shape, keys included, is the typed one."""
    assert spelled("1: x\n'1': y") == {1: "x", "1": "y"} == safe_load("1: x\n'1': y")
    # a typed key with a spelled value: the key is the `date` safe_load makes of it
    assert spelled("2026-07-25: 22") == {date(2026, 7, 25): "22"}


@pytest.mark.parametrize("text", ["null", "~", "22", "false", "2026-07-25"])
def test_a_bare_scalar_document_is_typed_in_both_readings(text):
    """Nobody's value. A caller asking "is this document a mapping" must get one answer for
    both readings — the fourth cut's `readings.spelled or {}` guard let the truthy text
    `"null"` through to `.get` (the review's finding)."""
    readings = safe_load_typed_and_spelled(text)
    assert readings.spelled == readings.typed == safe_load(text)


# the typed half is `safe_load`, and both halves come from one tree

@pytest.mark.parametrize("text", [
    "a: 2026-07-25T07:48:37.065Z\nb: 22\nc: yes\nd:\n",
    "1: x\n'1': y",
    "_d: &d {events: [{user.name: root}]}\nprojections:\n  - lead_id: l-001\n    <<: *d\n",
    "",
])
def test_the_typed_half_is_exactly_safe_load(text):
    """The readers that never wanted a spelling — the integrity and grammar checks, the
    judge's rendering — are handed `typed`, and it must be what they were handed before
    #951 to the byte, or the judge's input moves under an unchanged prompt tag."""
    assert safe_load_typed_and_spelled(text).typed == safe_load(text)


def _shape(value, seen=None):
    """A document's shape with the leaves erased: containers, keys, lengths, and where an
    alias points back. Two readings of one tree must have the same one."""
    seen = {} if seen is None else seen
    if isinstance(value, dict):
        if id(value) in seen:
            return ("cycle", seen[id(value)])
        seen[id(value)] = len(seen)
        return ("map", tuple((k, _shape(v, seen)) for k, v in value.items()))
    if isinstance(value, list):
        if id(value) in seen:
            return ("cycle", seen[id(value)])
        seen[id(value)] = len(seen)
        return ("seq", tuple(_shape(v, seen) for v in value))
    return "leaf"


@pytest.mark.parametrize("text", [
    "a: 2026-07-25T07:48:37.065Z\nb: 22\nc: yes\nd:\n",
    "1: x\n'1': y\n2026-07-25: z\ntrue: w",
    "_d: &d {events: [{user.name: root}]}\nprojections:\n  - lead_id: l-001\n    <<: *d\n",
    "a: &c [root]\nb: *c",
    "a: &x {b: *x, c: leaf}",
    "events: &e\n  - user.name: root\n    self: *e\n",
    "projections:\n  - lead_id: l-001\n    events: [{n: 1}]\n    events: [{n: 2}]\n",
    "a: [1, [2, {3: 4}], {}, []]",
])
def test_both_readings_have_exactly_one_shape(text):
    """One parse: the two readings can differ only in what a VALUE scalar became — never in
    which containers hold which keys, how many pairs survive, or where an alias points. A
    repeated `events:` collapses to the same LAST list in both; a self-containing anchor is
    the same cycle in both."""
    readings = safe_load_typed_and_spelled(text)
    assert _shape(readings.spelled) == _shape(readings.typed) == _shape(safe_load(text))


# everything else in the spelled half is `safe_load`'s structure

def test_a_repeated_key_collapses_to_its_last_value_as_safe_load_does():
    """The point of ONE reading. A second walk of the node tree that took the FIRST
    `events:` scanned a different list from the one the typed document (and the judge)
    carried — a leak in the honoured list was missed."""
    text = "events: [{user.name: admin}]\nevents: [{user.name: root}]\n"
    assert spelled(text) == safe_load(text) == {
        "events": [{"user.name": "root"}]}


def test_a_merge_key_merges_as_safe_load_does():
    """Tag resolution is untouched, so `<<:` is still the merge tag and the merged mapping's
    keys land in the row — the first cut dropped the resolvers and left a literal `<<` key;
    the second cut's tree walk looked the key up by name and never saw merged events."""
    text = "_d: &d {events: [{user.name: root}]}\nprojections:\n  - lead_id: l-001\n    <<: *d\n"
    assert spelled(text)["projections"] == safe_load(text)["projections"] == [
        {"lead_id": "l-001", "events": [{"user.name": "root"}]}]


def test_an_alias_resolves_to_the_same_object_as_safe_load_gives():
    doc = spelled("a: &c [root]\nb: *c")
    assert doc == {"a": ["root"], "b": ["root"]}
    assert doc["a"] is doc["b"]


def test_a_self_containing_anchor_loads_as_safe_load_does():
    """`a: &x {b: *x}` composes into a cyclic graph; `safe_load` builds the recursive
    structure and so does this."""
    doc = spelled("a: &x {b: *x, c: leaf}")
    assert doc["a"]["c"] == "leaf"
    assert doc["a"]["b"] is doc["a"]


def test_an_empty_document_is_none():
    assert spelled("") is None
    assert spelled("# nothing but a comment\n") is None


def test_malformed_text_raises_a_yaml_error():
    with pytest.raises(yaml.YAMLError):
        spelled("a: [unclosed")


def test_a_document_too_deep_to_parse_is_a_yaml_error_not_a_recursion_error():
    """The same translation `safe_load` makes, from the same function: a caller that
    catches `YAMLError` for malformed input must not get an interpreter error instead."""
    with pytest.raises(yaml.YAMLError, match="nested too deeply"):
        spelled("a: " + "[" * 20000)


def test_the_spelled_constructor_leaks_nothing_into_safe_load():
    """The first cut's process-wide hazard: a subclass that WROTE a class-level resolver
    table shared with `SafeLoader`. This one overrides a method only. After any number of
    spelled reads, `yaml.safe_load` in the same process still types."""
    for _ in range(3):
        spelled("a: 2026-07-25T07:48:37.065Z\nb: 22\nc: yes")
    typed = yaml.safe_load("a: 2026-07-25T07:48:37.065Z\nb: 22\nc: yes")
    assert not isinstance(typed["a"], str)
    assert typed["b"] == 22
    assert typed["c"] is True
