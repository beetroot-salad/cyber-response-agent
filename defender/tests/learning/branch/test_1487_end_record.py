"""#1487 (design r5, Data model): the learning end record's optional `findings` field and the shared cap measure.
The envelope never looks inside `findings`: a record whose `findings` is any JSON value still reads (the worker then
refuses the findings, never the ending). No database."""
from __future__ import annotations

import json

import pytest

BASE = {"status": "completed", "reason": None, "message": None, "fork_message_id": "m-1", "stage": "judge",
        "findings_count": 0, "sibling_cost_usd": 0.0}
OK = {"state": "ok", "text": json.dumps({"finding": [], "questioner_finding": []})}


def _end():
    from defender.records.job_lane import LearningEnd

    return LearningEnd


def test_a_record_without_findings_still_reads_with_none():
    """The field is optional: an older record or a skipped/failed one reads, findings `None`. (Data model)"""
    end = _end().parse(json.dumps(BASE))
    assert end is not None and end.findings is None  # noqa: PT018


@pytest.mark.parametrize("found", [OK, {"state": "unreadable"}, {"state": "over_cap"}, {"state": "malformed"}])
def test_a_record_with_findings_round_trips_through_text_and_parse(found):
    """What the entry writes is what the worker reads. (Data model)"""
    cls = _end()
    end = cls(status="completed", reason=None, message=None, fork_message_id="m-1", stage="judge", findings=found)
    again = cls.parse(end.text())
    assert again is not None and again.findings == found  # noqa: PT018
    assert json.loads(end.text())["findings"] == found


@pytest.mark.parametrize("value", [None, "ok", 5, 1.5, True, [], [OK], {}, {"state": 1}, {"state": "ok", "text": 5},
                                   {"state": "bogus", "text": "x"}, {"state": "ok", "extra": 1, "text": "[]"},
                                   {"state": "ok", "text": "\ud800"}, {"a": {"b": [1, {"c": None}]}}])
def test_the_envelope_does_not_look_inside_findings(value):
    """Any JSON value of `findings` leaves the record readable. (P4: container side; O2: only an
    unreadable envelope is "no readable end record")"""
    end = _end().parse(json.dumps({**BASE, "findings": value}))
    assert end is not None, "the findings field made the whole ending unreadable"
    assert (end.status, end.reason) == ("completed", None)


def test_an_unknown_field_still_makes_the_record_unreadable():
    """The exact-fields rule stays for everything but `findings`. (Data model)"""
    assert _end().parse(json.dumps({**BASE, "findings": OK, "surprise": 1})) is None


def test_the_cap_is_eight_mib_of_utf8_bytes_measured_by_one_shared_function():
    """`FINDINGS_CAP_BYTES` is 8 MiB; `findings_text_bytes` counts UTF-8 bytes, not characters. (Data model)"""
    from defender.records.job_lane import FINDINGS_CAP_BYTES, findings_text_bytes

    assert FINDINGS_CAP_BYTES == 8 * 1024 * 1024
    assert [findings_text_bytes(t) for t in ("", "a", "é", "€", "\U0001F600", "aé€\U0001F600")] == [0, 1, 2, 3, 4, 10]
