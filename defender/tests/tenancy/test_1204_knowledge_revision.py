"""#1204: a run stamp's `knowledge` wire value — what reads back, what folds to `None`.

#1108 P4 retired the reader that took that value from the tenant clone's `.git`
(`capture_knowledge`): the run process reads nothing of the clone, and a run's knowledge stamp
is the export it copied (`tests/tenancy/tenant_1108_p4/test_run_start.py::test_o_b_the_stamp_
is_the_export_copied_never_the_clones_head`). The wire value it wrote stays pinned here.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from defender.records import _provenance
from defender.records._provenance import RunProvenance
from defender.tests.support.shared._fixture_uuid import fixture_uuid


#: A record with EVERY field set to a non-default value, so "everything else intact" is a claim
#: about eleven fields rather than about two.
RICH: dict[str, Any] = {
    "commit": "a" * 40, "dirty": True, "dirty_paths": ["x.md", "y.md"], "dirty_path_count": 3,
    "unavailable": "git status: a note beside the dirt", "scope": "defender", "model": "m-1",
    "tenant_id": fixture_uuid("tenant:acme"), "world_id": fixture_uuid("world:knowledge-revision:b"),
    "parent_run_id": fixture_uuid("run:knowledge-revision:source"), "fork_turn": 59,
    "started_at": "2026-07-28T16:18:45+00:00", "alert_label": "fresh-case",
}

SHA = "b" * 40

#: Every malformed knowledge value, by name. Each must fold to `knowledge=None` and leave the
#: rest of the record exactly as it was.
MALFORMED: dict[str, Any] = {
    "empty commit": {"commit": ""},
    "blank commit": {"commit": "   "},
    "both keys": {"commit": SHA, "unavailable": "x"},
    "non-hex commit": {"commit": "nothex" + "0" * 34},
    "uppercase commit": {"commit": SHA.upper()},
    "abbreviated commit": {"commit": SHA[:7]},
    "39-hex commit": {"commit": SHA[:39]},
    "41-hex commit": {"commit": SHA + "b"},
    "63-hex commit": {"commit": "c" * 63},
    "65-hex commit": {"commit": "c" * 65},
    "int commit": {"commit": 42},
    "null commit": {"commit": None},
    "list commit": {"commit": [SHA]},
    "int reason": {"unavailable": 42},
    "null reason": {"unavailable": None},
    "empty object": {},
    "unknown extra key beside a commit": {"commit": SHA, "dirty": False},
    "unknown key alone": {"revision": SHA},
    "a list": [SHA],
    "another string": "versioned",
    "unversioned, shouted": "UNVERSIONED",
    "an int": 42,
    "a bool": True,
}

#: Every valid wire value. Each reads back as itself.
VALID: dict[str, Any] = {
    "a 40-hex commit": {"commit": SHA},
    "a 64-hex commit": {"commit": "c" * 64},
    "unversioned": "unversioned",
    "unavailable": {"unavailable": "reftable refs are not read here"},
}


def _without_knowledge() -> dict[str, Any]:
    return json.loads(json.dumps(RICH))


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_1204_a_malformed_knowledge_value_folds_to_none_and_keeps_every_other_field(
        tmp_path, name):
    """O4/D2."""
    doc = {**_without_knowledge(), "knowledge": MALFORMED[name]}
    record = RunProvenance.from_obj(doc)
    assert record is not None, "a bad knowledge value voided the whole stamp"
    assert record.knowledge is None, record.knowledge
    assert json.loads(record.as_json()) == {**RICH, "knowledge": None}
    assert record == RunProvenance.from_obj(_without_knowledge())

    path = tmp_path / "provenance.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert _provenance.read(path) == record


@pytest.mark.parametrize("name", sorted(VALID))
def test_1204_each_valid_knowledge_value_reads_back_as_itself(tmp_path, name):
    """The positive control for the folding above, on the same record."""
    doc = {**_without_knowledge(), "knowledge": VALID[name]}
    record = RunProvenance.from_obj(doc)
    assert record is not None
    assert record.knowledge is not None
    assert record.knowledge.as_wire() == VALID[name]
    assert json.loads(record.as_json()) == {**RICH, "knowledge": VALID[name]}

    path = tmp_path / "provenance.json"
    _provenance.write(path, record)
    assert json.loads(path.read_text(encoding="utf-8"))["knowledge"] == VALID[name]
    assert _provenance.read(path) == record


def test_1204_a_stamp_that_does_not_say_writes_null_and_an_old_stamp_reads_as_none():
    """D2."""
    on_disk = json.loads(RunProvenance(commit="a" * 40, dirty=False).as_json())
    assert "knowledge" in on_disk, on_disk
    assert on_disk["knowledge"] is None, on_disk
    for old in (_without_knowledge(), {**_without_knowledge(), "knowledge": None}):
        record = RunProvenance.from_obj(old)
        assert record is not None
        assert record.knowledge is None
        assert json.loads(record.as_json()) == {**RICH, "knowledge": None}
