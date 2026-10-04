"""The two parse caches the catalog walk and the run start lean on: `parse_query_template`
(memoized on its `(text, path)` inputs) and `load_dispositions` (memoized on the path and the
exact text it read). Each must answer a repeat from the cache, never answer changed input from a
stale entry, and never store a refusal."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender._corpus import parse_query_template
from defender.runtime.verb_dispositions import (
    DispositionError,
    DispositionWarning,
    load_dispositions,
)

_TEMPLATE = """---
id: {tid}
status: established
---
## Goal
find it

## Query
q
"""


def test_a_repeated_template_parse_is_served_from_the_cache(tmp_path: Path) -> None:
    path = tmp_path / "cmdb" / "probe.md"
    text = _TEMPLATE.format(tid="cmdb.probe")
    first = parse_query_template(text, path)
    assert first[0] is not None, first[1]
    assert parse_query_template(text, path) is first


def test_changed_template_text_or_path_is_parsed_afresh(tmp_path: Path) -> None:
    path = tmp_path / "cmdb" / "probe.md"
    before, _ = parse_query_template(_TEMPLATE.format(tid="cmdb.before"), path)
    after, _ = parse_query_template(_TEMPLATE.format(tid="cmdb.after"), path)
    assert before is not None
    assert after is not None
    assert (before.id, after.id) == ("cmdb.before", "cmdb.after")
    # Same text under another system's folder: the location facts are the path's.
    moved, _ = parse_query_template(_TEMPLATE.format(tid="cmdb.before"),
                                    tmp_path / "identity" / "probe.md")
    assert moved is not None
    assert (before.system, moved.system) == ("cmdb", "identity")
    assert moved.path == tmp_path / "identity" / "probe.md"


def test_a_malformed_template_answers_the_same_reason_every_time(tmp_path: Path) -> None:
    path = tmp_path / "cmdb" / "broken.md"
    first = parse_query_template("no frontmatter here\n", path)
    assert first[0] is None
    assert first[1].startswith("malformed template:")
    assert parse_query_template("no frontmatter here\n", path) == first


_GOOD = ("dispositions:\n  alpha:\n    health-check:\n      roles: [gather]\n"
         "    lookup:\n      roles: [gather]\n")


def _gather_pairs(rows: tuple) -> set[tuple[str, str]]:
    return {(d.system, d.verb) for d in rows if "gather" in d.roles}


def test_a_repeated_table_load_is_served_from_the_cache(tmp_path: Path) -> None:
    table = tmp_path / "verb-grants.yaml"
    table.write_text(_GOOD, encoding="utf-8")
    first = load_dispositions(table)
    assert load_dispositions(table) is first


def test_a_same_size_edit_within_one_mtime_is_read_again(tmp_path: Path) -> None:
    """The cache is keyed on the text read, not on file metadata: an edit that keeps the size
    and the mtime (two writes inside one timestamp tick) is still seen."""
    edited = _GOOD.replace("lookup:\n      roles: [gather]", "lookup:\n      roles: [xxxxxx]")
    assert len(edited) == len(_GOOD)
    table = tmp_path / "verb-grants.yaml"
    table.write_text(_GOOD, encoding="utf-8")
    stamp = table.stat().st_mtime_ns
    assert _gather_pairs(load_dispositions(table)) == {("alpha", "health-check"),
                                                      ("alpha", "lookup")}
    table.write_text(edited, encoding="utf-8")
    os.utime(table, ns=(stamp, stamp))
    with pytest.raises(DispositionError, match="'xxxxxx' is not a role"):
        load_dispositions(table)


def test_a_refused_table_is_refused_again_and_never_stored(tmp_path: Path) -> None:
    table = tmp_path / "verb-grants.yaml"
    table.write_text("dispositions: {}\n", encoding="utf-8")
    with pytest.raises(DispositionError) as first:
        load_dispositions(table)
    with pytest.raises(DispositionError) as second:
        load_dispositions(table)
    assert str(second.value) == str(first.value)
    table.write_text(_GOOD, encoding="utf-8")
    assert _gather_pairs(load_dispositions(table)) == {("alpha", "health-check"),
                                                      ("alpha", "lookup")}


def test_a_cached_load_still_warns(tmp_path: Path) -> None:
    """The health-check warning is owed on every load, the cached one included."""
    table = tmp_path / "verb-grants.yaml"
    table.write_text("dispositions:\n  alpha:\n    lookup:\n      roles: [gather]\n",
                     encoding="utf-8")
    for _ in range(2):
        with pytest.warns(DispositionWarning, match="alpha"):
            load_dispositions(table)
