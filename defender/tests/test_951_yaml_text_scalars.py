"""Pins for `defender._yaml.load_text_scalars` (#951, design M1 / C7).

The oracle-golden mechanical checks are text containment — "is this literal a whole value or
a token of what the projection emitted" — and they were run over a document `yaml.safe_load`
had already TYPED: an unquoted `2026-07-25T07:48:37.065Z` became a `datetime` whose `str()`
is `2026-07-25 07:48:37.065000+00:00`, `yes` became `True`, `0755` became `493`. The loader
pinned here reads the text as written: a `SafeLoader` whose only implicit resolver is `null`,
so `~` / `null` / an empty value still construct as `None` (the `or {}` / `or []` idioms in
`score.py` depend on it) and EVERY other plain scalar constructs as the string it was spelled
as. Quoted scalars are strings as always; structure is untouched.

The one hazard is process-wide: `yaml_implicit_resolvers` is a class-level dict of lists
shared with `yaml.SafeLoader`, and a subclass that edits it in place strips typing from every
`yaml.safe_load` in the process (executed, design C14). The last tests here import and USE the
loader, then ask the process-wide reader to type a date, an int and a boolean.

The loader is imported inside each test rather than at module top, so the rest of the file
collects — and fails on the missing symbol — until the implementation lands.
"""
from __future__ import annotations

import threading
from datetime import UTC, date, datetime

import pytest
import yaml


def _load(text: str):
    from defender._yaml import load_text_scalars
    return load_text_scalars(text)


# every other plain scalar is the text it was written as (the C7 table)

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
    "1e3",
    ".inf",
    "true",
    "false",
    "yes",
    "no",
    "on",
    "off",
])
def test_a_plain_scalar_constructs_as_the_exact_string_it_was_written_as(spelling):
    """Equality with the `str` is the whole assertion: a `datetime`, `int`, `float` or
    `bool` is never equal to it, and neither is a re-spelling."""
    assert _load(f"a: {spelling}") == {"a": spelling}


def test_a_shape_valid_but_calendar_invalid_instant_is_a_string_not_an_error():
    """PyYAML's timestamp resolver matches on SHAPE and hands the fields to `datetime`,
    which raises a bare `ValueError` on `2001-02-30`. With the resolver gone the text is
    text — the reason `defender._yaml.safe_load`'s `ValueError` fold is not needed here,
    and the reason a post-hoc `datetime`-to-string fix would not be equivalent."""
    assert _load("a: 2001-02-30") == {"a": "2001-02-30"}
    assert _load("a: 2001-12-14t25:59:43.10-05:00") == {"a": "2001-12-14t25:59:43.10-05:00"}


@pytest.mark.parametrize("text", ["a: ~", "a: null", "a: Null", "a: NULL", "a:", "a: "])
def test_null_and_an_empty_value_still_construct_as_none(text):
    """`score.py` reads `manifest.get("expectation") or {}` and `proj.get("projections")
    or []`; an `expectation:` left empty must stay `None`, not become `""` or `"~"`."""
    assert _load(text) == {"a": None}


def test_an_empty_document_is_none_as_it_is_for_safe_load():
    """`_measured` does `load(...) or {}` on every file — an empty file must not be a
    string."""
    assert _load("") is None
    assert _load("# nothing but a comment\n") is None


def test_quoted_scalars_are_the_strings_they_always_were():
    assert _load("a: '22'\nb: \"yes\"\nc: '2026-07-25T07:48:37.065Z'\nd: ''") == {
        "a": "22", "b": "yes", "c": "2026-07-25T07:48:37.065Z", "d": ""}


def test_flow_and_block_collections_keep_their_structure_with_text_leaves():
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
    assert _load(text) == {"projections": [{
        "lead_id": "l-001",
        "events": [
            {"@timestamp": "2026-07-25T07:48:37.065Z", "destination.port": "22",
             "tags": ["1", "x", None],
             "nested": {"n": "0755", "m": ["yes", "yes"]}},
            "<standard environment noise>",
        ],
    }]}


def test_block_scalars_are_unaffected():
    assert _load("d: >-\n  the leads investigate\n  the wrong host\n") == {
        "d": "the leads investigate the wrong host"}
    assert _load("d: |\n  2026-07-25T07:48:37.065Z\n") == {"d": "2026-07-25T07:48:37.065Z\n"}


def test_safe_dump_of_the_result_renders_each_scalar_quoted_in_its_original_spelling():
    """O3's rendering: the judge's `<projection>` block is `yaml.safe_dump` of the loaded
    document. Each string dumps QUOTED (the emitter knows plain text would re-resolve), in
    the spelling the file carried — and a plain `safe_load` of that dump reads the strings
    back, not the types."""
    doc = _load("a: 2026-07-25T07:48:37.065Z\nb: 2026-07-25\nc: 22\nd: true\ne: 0755\n"
                "f: 12:30\ng: yes\nh: 1.5\ni: ~\n")
    dumped = yaml.safe_dump(doc, sort_keys=False)
    for spelling in ("2026-07-25T07:48:37.065Z", "2026-07-25", "22", "true", "0755",
                     "12:30", "yes", "1.5"):
        assert f"'{spelling}'" in dumped, dumped
    assert "07:48:37.065000+00:00" not in dumped
    assert yaml.safe_load(dumped) == doc
    assert doc["i"] is None


# explicit tags: the other way YAML types a scalar

@pytest.mark.parametrize(("tagged", "literal"), [
    ("!!timestamp 2026-07-25T07:48:37.065Z", "2026-07-25T07:48:37.065Z"),
    ("!!timestamp 2026-07-25", "2026-07-25"),
    ("!!int 0755", "0755"),
    ("!!int 22", "22"),
    ("!!float 1.50", "1.50"),
    ("!!bool yes", "yes"),
    ("!!bool true", "true"),
    ("!!str 22", "22"),
])
def test_an_explicitly_tagged_scalar_is_its_text_too(tagged, literal):
    """The resolver decides what an UNTAGGED scalar is; a `!!timestamp` tag skips it and
    goes straight to the constructor. Both are "how YAML would have typed it" (O1), and a
    loader that neutralised only the first would re-open the fail-open one tag away."""
    assert _load(f"a: {tagged}") == {"a": literal}


def test_an_explicitly_tagged_calendar_invalid_instant_is_text_not_a_bare_value_error():
    """Deck #677's shape: a value that makes the CONSTRUCT call raise must not escape as a
    bare `ValueError` a caller's `except yaml.YAMLError` cannot see. With the timestamp
    constructor gone there is nothing left to raise — the text is the value."""
    assert _load("a: !!timestamp 2001-02-30") == {"a": "2001-02-30"}


def test_null_keeps_its_explicit_tag_and_python_tags_are_refused():
    """The loader is a SAFE loader: `!!null` is still `None`, and a `!!python/...` tag —
    the tag that makes `yaml.UnsafeLoader` execute a projection file — is a `YAMLError`,
    never a constructed object and never a command run."""
    assert _load("a: !!null ''") == {"a": None}
    with pytest.raises(yaml.YAMLError):
        _load("a: !!python/object/apply:os.system ['true']")
    with pytest.raises(yaml.YAMLError):
        _load("a: !!python/name:os.system")
    with pytest.raises(yaml.YAMLError):
        _load("a: !!python/tuple [1, 2]")


# errors keep the wrapper's contract

def test_malformed_text_raises_a_yaml_error():
    with pytest.raises(yaml.YAMLError):
        _load("a: [")
    with pytest.raises(yaml.YAMLError):
        _load("a: b\n c: d\n")


def test_a_document_nested_too_deeply_raises_a_yaml_error_not_a_recursion_error():
    """Mirrors `defender._yaml.safe_load`: PyYAML's composer recurses per nesting level, and
    an interpreter `RecursionError` escaping a loader is not a parse failure a caller's
    `except yaml.YAMLError` can act on."""
    with pytest.raises(yaml.YAMLError):
        _load("[" * 5000 + "]" * 5000)


# the M1 hazard: the process-wide loader stays typed

def test_using_the_text_loader_leaves_yaml_safe_load_typed():
    """Executed for the design: an in-place edit of `yaml_implicit_resolvers` on a
    `SafeLoader` subclass makes `yaml.safe_load("a: 2026-07-25")` return a `str`. The
    loader is USED first, in this process, on every scalar family it de-types."""
    assert _load("a: 2026-07-25T07:48:37.065Z\nb: 2026-07-25\nc: 1\nd: yes\ne: 1.5\n") == {
        "a": "2026-07-25T07:48:37.065Z", "b": "2026-07-25", "c": "1", "d": "yes", "e": "1.5"}
    assert yaml.safe_load("a: 2026-07-25")["a"] == date(2026, 7, 25)
    assert yaml.safe_load("a: 2026-07-25T07:48:37.065Z")["a"] == datetime(
        2026, 7, 25, 7, 48, 37, 65000, tzinfo=UTC)
    assert yaml.safe_load("a: 1")["a"] == 1
    assert yaml.safe_load("a: 1")["a"] is not True
    assert yaml.safe_load("a: yes")["a"] is True
    assert yaml.safe_load("a: 1.5")["a"] == 1.5
    assert yaml.safe_load("a: ~")["a"] is None


def test_a_concurrent_safe_load_stays_typed_while_the_text_loader_runs():
    """The hazard is process-wide and so is the pin: a loader that stripped the shared
    resolver table in place and restored it afterwards passes a before/after check and
    still mistypes every `yaml.safe_load` that overlaps it — `score.py` parses judge output
    under a thread pool. The text loader chews a large document in one thread while this
    one keeps asking the process-wide reader for a date; with a private table the answer
    never changes."""
    big = "".join(f"k{i}: 2026-07-25T07:48:37.{i % 1000:03d}Z\n" for i in range(20000))
    done = threading.Event()

    def chew():
        try:
            for _ in range(3):
                assert _load(big)["k0"] == "2026-07-25T07:48:37.000Z"
        finally:
            done.set()

    worker = threading.Thread(target=chew)
    worker.start()
    mistyped = 0
    while not done.is_set():
        if not isinstance(yaml.safe_load("a: 2026-07-25")["a"], date):
            mistyped += 1
    worker.join()
    assert mistyped == 0


def test_the_error_translating_wrapper_still_types_scalars():
    """`defender._yaml.safe_load` is the repo's typed reader and the new loader sits BESIDE
    it, not inside it: a shared resolver table edited for one would silently change the
    other."""
    from defender._yaml import safe_load
    _load("a: 2026-07-25")
    assert safe_load("a: 2026-07-25")["a"] == date(2026, 7, 25)
    assert safe_load("a: 22")["a"] == 22
