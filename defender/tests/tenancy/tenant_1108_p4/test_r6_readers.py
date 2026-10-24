"""#1108 P4 round 6 — what the readers of a run's knowledge source accept (each case was a
wrong-but-green production variant): a host record of the wrong shape is unreadable, never fresh;
a run with no stamp and no record is a pre-P4 run (shows nothing)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.records._knowledge_status import (
    UNREADABLE,
    KnowledgeStatus,
    knowledge_status,
    read_knowledge_status,
)

OID = "0123456789abcdef0123456789abcdef01234567"
OID256 = OID + "0123456789abcdef01234567"


def _record(**fields) -> str:
    base = {"kind": "fresh", "commit": OID, "stale_kind": None, "reason": None}
    return json.dumps({**base, **fields})


GOOD = {
    "fresh": (_record(), KnowledgeStatus("fresh", OID)),
    "fresh-sha256": (_record(commit=OID256), KnowledgeStatus("fresh", OID256)),
    "pinned": (_record(kind="pinned"), KnowledgeStatus("pinned", OID)),
    "stale-transient": (_record(kind="stale", stale_kind="transient", reason="down"),
                        KnowledgeStatus("stale", OID, "transient", "down")),
    "stale-operator": (_record(kind="stale", stale_kind="operator"),
                       KnowledgeStatus("stale", OID, "operator", None)),
}

BAD = {
    "empty-object": "{}",
    "not-an-object": "[]",
    "null": "null",
    "unknown-kind": _record(kind="unknown"),
    "kind-with-space": _record(kind="fresh "),
    "kind-capitalised": _record(kind="Fresh"),
    "kind-missing": json.dumps({"commit": OID}),
    "commit-missing": json.dumps({"kind": "fresh"}),
    "commit-junk": _record(commit="zzz"),
    "commit-short": _record(commit=OID[:12]),
    "commit-upper": _record(commit=OID.upper()),
    "commit-41": _record(commit=OID + "0"),
    "commit-not-string": _record(commit=12345),
    "fresh-with-stale-kind": _record(stale_kind="transient"),
    "pinned-with-stale-kind": _record(kind="pinned", stale_kind="operator"),
    "stale-without-stale-kind": _record(kind="stale"),
    "stale-unknown-stale-kind": _record(kind="stale", stale_kind="weird"),
    "reason-not-string": _record(kind="stale", stale_kind="operator", reason=5),
}


@pytest.mark.parametrize("case", sorted(GOOD))
def test_r6_a_well_formed_host_record_is_read_as_it_says(case):
    text, expected = GOOD[case]
    assert knowledge_status(text, stamp_names_source=False) == expected


@pytest.mark.parametrize("case", sorted(BAD))
def test_r6_a_host_record_of_the_wrong_shape_is_unreadable_never_fresh(case):
    got = knowledge_status(BAD[case], stamp_names_source=False)
    assert got == UNREADABLE, f"{BAD[case]} was read as {got}"
    assert got.stale and got.stale_kind == "operator" and got.commit is None


def test_r6_a_run_with_no_record_and_no_stamp_is_a_pre_p4_run_that_shows_nothing(tmp_path):
    assert read_knowledge_status(tmp_path / "x.knowledge-source.json", tmp_path / "provenance.json") is None
    (tmp_path / "provenance.json").write_text(json.dumps({"model": "m"}), encoding="utf-8")
    assert read_knowledge_status(tmp_path / "x.knowledge-source.json", tmp_path / "provenance.json") is None
    (tmp_path / "provenance.json").write_text(json.dumps({"knowledge_source": {"kind": "fresh"}}),
                                              encoding="utf-8")
    assert read_knowledge_status(tmp_path / "x.knowledge-source.json",
                                 tmp_path / "provenance.json") == UNREADABLE


def test_r6_a_host_record_whose_kind_is_not_a_scalar_is_unreadable_not_a_crash():
    """EXPECTED RED on honest code (production defect, reported): `kind not in KINDS` raises
    `TypeError: unhashable type: 'list'` for `"kind": ["fresh"]` (or a dict), so a reader of the
    run (page, ticket, API) crashes on a corrupt record instead of reading it as unreadable."""
    for kind in (["fresh"], {"a": 1}):
        assert knowledge_status(_record(kind=kind), stamp_names_source=False) == UNREADABLE
