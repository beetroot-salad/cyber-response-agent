"""#1108 P4: what the readers of a run's knowledge source accept: a host record of the wrong
shape is unreadable, never fresh; a run with no stamp and no record is a pre-P4 run (shows
nothing)."""
from __future__ import annotations

import json

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
    # 1618 K9 (was: `.stale` with stale_kind operator): an unreadable record reads `unreadable`, never stale.
    assert (got.kind, got.stale_kind, got.commit) == ("unreadable", None, None)
    assert not got.stale


def test_r6_a_run_with_no_record_and_no_stamp_is_a_pre_p4_run_that_shows_nothing(tmp_path):
    assert read_knowledge_status(tmp_path / "x.knowledge-source.json", tmp_path / "provenance.json") is None
    (tmp_path / "provenance.json").write_text(json.dumps({"model": "m"}), encoding="utf-8")
    assert read_knowledge_status(tmp_path / "x.knowledge-source.json", tmp_path / "provenance.json") is None
    (tmp_path / "provenance.json").write_text(json.dumps({"knowledge_source": {"kind": "fresh"}}),
                                              encoding="utf-8")
    assert read_knowledge_status(tmp_path / "x.knowledge-source.json",
                                 tmp_path / "provenance.json") == UNREADABLE


def test_r6_a_host_record_whose_kind_is_not_a_scalar_is_unreadable_not_a_crash():
    """An unhashable `kind` (a list or dict) must not crash every reader of the run (page,
    ticket, API) with a `TypeError` on the `kind not in KINDS` check."""
    for kind in (["fresh"], {"a": 1}):
        assert knowledge_status(_record(kind=kind), stamp_names_source=False) == UNREADABLE


# --- #1618 K9/D7: a missing or garbled record reads `unreadable`; stored stale reads back as stored ---------------------

def test_k9_a_missing_record_whose_stamp_names_a_source_reads_unreadable_not_stale():
    """No record while the run's stamp names a knowledge source reads `unreadable` (no commit, no stale kind), no reader claiming fresh. (K9, D6)"""
    got = knowledge_status(None, stamp_names_source=True)
    assert (got.kind, got.commit, got.stale_kind) == ("unreadable", None, None)
    assert knowledge_status(None, stamp_names_source=False) is None, "control: a pre-P4 run still shows nothing"


@pytest.mark.parametrize("case", ["stale-transient", "stale-operator"])
def test_k9_a_stored_stale_record_reads_back_as_stored_with_its_kind_and_reason(case):
    """A record written before this change, `stale` with its kind (and reason), is read as written: not coerced to `unreadable`. (K9, D7)"""
    text, expected = GOOD[case]
    got = knowledge_status(text, stamp_names_source=False)
    assert got == expected
    assert (got.kind, got.stale_kind) == ("stale", expected.stale_kind)


def test_k9_the_api_shape_of_an_unreadable_record_is_unreadable_with_no_commit_and_no_stale_kind():
    """`api_knowledge` answers `unreadable` for a missing or garbled record, with a null commit and stale kind: the word `stale` is not in it. (K9)"""
    from defender.records._knowledge_status import api_knowledge

    for text in (None, "{}", "[]"):
        shaped = api_knowledge(knowledge_status(text, stamp_names_source=True))
        assert shaped == {"status": "unreadable", "commit": None, "stale_kind": None}, (text, shaped)


def test_k9_the_api_shape_of_a_stored_stale_record_is_still_stale_with_its_kind():
    """`api_knowledge` maps a stored stale record to `stale` with its stale kind and commit; a pinned one stays pinned. (K9, D7)"""
    from defender.records._knowledge_status import api_knowledge

    for kind, case in (("transient", "stale-transient"), ("operator", "stale-operator")):
        shaped = api_knowledge(knowledge_status(GOOD[case][0], stamp_names_source=False))
        assert shaped == {"status": "stale", "commit": OID, "stale_kind": kind}
    assert api_knowledge(knowledge_status(GOOD["pinned"][0], stamp_names_source=False)) == {
        "status": "pinned", "commit": OID, "stale_kind": None}
